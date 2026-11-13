"""Typer CLI for Actentra (`actentra`)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Annotated

import typer

from actentra import ActionBlockedError, Boundary
from actentra_core.checkpoints import (
    CheckpointError,
    generate_ed25519_keypair,
    load_checkpoint,
    sign_checkpoint,
    verify_checkpoint,
    write_checkpoint,
)
from actentra_core.envelope import EnvelopeError, ProvenanceItem, build_envelope
from actentra_core.policy import (
    PolicyEngine,
    PolicyPack,
    PolicyValidationError,
    lint_policy,
    load_policy_file,
    load_policy_yaml,
)
from actentra_core.receipts import ReceiptStore, export_jsonl, verify_log
from actentra_core.reporting import build_audit_summary, render_html_report
from actentra_core.verdict import Verdict
from actentra_executors.fs import LocalFSExecutor, ScopedFSTools
from actentra_gateway.http_service import serve_http
from actentra_gateway.mcp_proxy import serve_stdio

app = typer.Typer(
    name="actentra",
    help="Actentra — deterministic execution boundary for AI agents.",
    no_args_is_help=True,
)
policy_app = typer.Typer(help="Validate and inspect policy packs.")
app.add_typer(policy_app, name="policy")
checkpoint_app = typer.Typer(help="Sign and verify Ed25519 receipt checkpoints.")
app.add_typer(checkpoint_app, name="checkpoint")

_DEFAULT_STARTER_POLICY = """\
version: 1
policy_id: local-default
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default policy"

limits:
  - id: session-rate
    scope: session
    max_actions_per_minute: 60

rules:
  - id: allow-workspace-list
    match:
      tool: fs.list
      verb: read
      resource: "path:C:/work/**"
    verdict: allow
    reason: "Allow workspace directory listings"

  - id: allow-workspace-reads
    match:
      tool: fs.read
      verb: read
      resource: "path:C:/work/**"
    verdict: allow
    reason: "Allow workspace reads"

  - id: block-untrusted-egress
    match:
      tool: "http.*"
      taint: untrusted
      risk_any: [external-egress]
    verdict: deny
    reason: "Untrusted provenance cannot trigger external egress"
"""


@app.command()
def init(
    directory: Annotated[
        Path, typer.Argument(help="Target directory for starter policy.")
    ] = Path("."),
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite existing policy file.")
    ] = False,
) -> None:
    """Create a starter actentra.policy.yaml in the target directory."""
    target = directory / "actentra.policy.yaml"
    if target.exists() and not force:
        typer.echo(f"Policy file already exists: {target} (use --force to overwrite)", err=True)
        raise typer.Exit(code=1)
    directory.mkdir(parents=True, exist_ok=True)
    target.write_text(_DEFAULT_STARTER_POLICY, encoding="utf-8")
    typer.echo(f"Created starter policy: {target}")


@policy_app.command("check")
def policy_check(
    policy_path: Annotated[Path, typer.Argument(help="Path to YAML policy file.")],
) -> None:
    """Validate a policy YAML file and print its version hash and rule count."""
    try:
        pack = load_policy_file(policy_path)
    except PolicyValidationError as exc:
        typer.echo(f"INVALID policy ({policy_path}): {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(
        f"OK policy={pack.policy_id} mode={pack.mode} "
        f"version={pack.policy_version} rules={len(pack.rules)} limits={len(pack.limits)}"
    )
    for warning in lint_policy(pack):
        typer.echo(f"WARN: {warning}")


@app.command("verify-log")
def verify_log_cmd(
    db_path: Annotated[Path, typer.Argument(help="Path to SQLite receipt database.")],
) -> None:
    """Verify hash-chain integrity of an Actentra receipt database."""
    result = verify_log(db_path)
    if not result.ok:
        typer.echo(f"VERIFICATION FAILED ({result.total_records} records):", err=True)
        for err in result.errors:
            typer.echo(f"  - {err}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"OK verified {result.total_records} record(s); head={result.last_hash}")


@app.command("export-log")
def export_log_cmd(
    db_path: Annotated[Path, typer.Argument(help="Path to SQLite receipt database.")],
    out_path: Annotated[Path, typer.Argument(help="Output JSONL path.")],
) -> None:
    """Export all receipt records to a JSONL file."""
    count = export_jsonl(db_path, out_path)
    typer.echo(f"Exported {count} receipt record(s) to {out_path}")


@app.command("report")
def report_cmd(
    db_path: Annotated[Path, typer.Argument(help="Path to SQLite receipt database.")],
    html_out: Annotated[
        Path | None,
        typer.Option("--html", "-o", help="Optional output path for HTML report."),
    ] = None,
) -> None:
    """Generate an audit report and summary from an Actentra receipt database."""
    if not db_path.exists():
        typer.echo(f"Receipt database not found: {db_path}", err=True)
        raise typer.Exit(code=1)

    summary = build_audit_summary(db_path)
    status_str = "OK" if summary.integrity_ok else "FAILED"
    typer.echo(f"=== Actentra Audit Report: {db_path} ===")
    typer.echo(
        f"Integrity Status    : {status_str} "
        f"({summary.total_records} records, head={summary.head_hash[:19]}...)"
    )
    typer.echo(f"Evaluated Crossings : {summary.decision_count}")
    typer.echo(f"Verdicts            : {summary.verdict_counts}")
    typer.echo(f"Outcomes            : {summary.outcome_counts}")
    typer.echo(f"Top Risk Tags       : {summary.risk_tag_counts or 'None'}")

    if not summary.integrity_ok:
        typer.echo("Integrity Errors    :", err=True)
        for err in summary.integrity_errors:
            typer.echo(f"  - {err}", err=True)

    if html_out is not None:
        html_content = render_html_report(summary, title=f"Actentra Audit — {db_path.name}")
        html_out.parent.mkdir(parents=True, exist_ok=True)
        html_out.write_text(html_content, encoding="utf-8")
        typer.echo(f"Generated standalone HTML report: {html_out}")


@app.command()
def replay(
    corpus_path: Annotated[Path, typer.Argument(help="Path to JSONL action corpus.")],
    policy_path: Annotated[
        Path, typer.Option("--policy", "-p", help="Path to YAML policy file.")
    ],
) -> None:
    """Replay a JSONL corpus of actions against a policy and check expectations."""
    try:
        pack = load_policy_file(policy_path)
    except PolicyValidationError as exc:
        typer.echo(f"INVALID policy: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not corpus_path.exists():
        typer.echo(f"Corpus file not found: {corpus_path}", err=True)
        raise typer.Exit(code=1)

    engine = PolicyEngine(pack)
    total = 0
    mismatches = 0

    for line_no, raw_line in enumerate(
        corpus_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        total += 1
        item = json.loads(line)
        prov = [
            ProvenanceItem(source=p["source"], trust=p["trust"])
            for p in item.get("provenance", [])
        ]
        try:
            env = build_envelope(
                tool=item["tool"],
                verb=item["verb"],
                resource=item["resource"],
                params=item.get("params") or {},
                session_id=item.get("session_id", f"replay-{line_no}"),
                provenance=prov,
            )
            dec = engine.evaluate(env)
            actual = dec.verdict.value
            rule_id = dec.rule_id
        except EnvelopeError as exc:
            actual = Verdict.HOLD.value
            rule_id = f"envelope-error:{exc}"

        expected_any = item.get("expected_verdicts")
        expected_one = item.get("expected_verdict")
        if isinstance(expected_any, list):
            ok = actual in expected_any
        elif isinstance(expected_one, str):
            ok = actual == expected_one
        else:
            ok = True

        if not ok:
            mismatches += 1
            typer.echo(
                f"[FAIL] id={item.get('id', line_no)} actual={actual} "
                f"expected={expected_any or expected_one} rule={rule_id}",
                err=True,
            )

    typer.echo(f"Replay complete: total={total} passed={total - mismatches} failed={mismatches}")
    if mismatches:
        raise typer.Exit(code=1)


def _build_workspace_policy(workspace: Path, *, shadow: bool = False) -> PolicyPack:
    ws = workspace.resolve().as_posix()
    mode = "shadow" if shadow else "enforce"
    return load_policy_yaml(
        f"""
version: 1
policy_id: cli-run-workspace
mode: {mode}
defaults:
  verdict: deny
  reason: "Denied by default"
rules:
  - id: allow-ws-list
    match: {{ tool: fs.list, verb: read, resource: "path:{ws}/**" }}
    verdict: allow
    reason: "Allow workspace listing"
  - id: allow-ws-read
    match: {{ tool: fs.read, verb: read, resource: "path:{ws}/**" }}
    verdict: allow
    reason: "Allow workspace read"
  - id: ask-ws-write
    match: {{ tool: fs.write, verb: write, resource: "path:{ws}/**" }}
    verdict: ask
    reason: "Workspace writes require human approval"
  - id: deny-sensitive-files
    match: {{ risk_any: [privilege-escalation] }}
    verdict: deny
    reason: "Sensitive credential/system files are blocked"
  - id: deny-delete
    match: {{ tool: fs.delete, risk_any: [destructive] }}
    verdict: deny
    reason: "File deletion blocked in run demo"
"""
    )


@app.command()
def run(
    workspace: Annotated[
        Path | None,
        typer.Option(
            "--workspace",
            "-w",
            help="Workspace root (defaults to temporary directory).",
        ),
    ] = None,
    db_path: Annotated[
        Path | None,
        typer.Option(
            "--db",
            help="Receipt SQLite DB path (defaults inside temp dir if workspace omitted).",
        ),
    ] = None,
    shadow: Annotated[
        bool, typer.Option("--shadow", help="Run policy in shadow mode.")
    ] = False,
) -> None:
    """Run an end-to-end toy agent scenario through LocalFSExecutor + Boundary."""
    with tempfile.TemporaryDirectory(prefix="actentra-run-") as tmpdir:
        tmp = Path(tmpdir)
        ws = workspace.resolve() if workspace is not None else (tmp / "work")
        ws.mkdir(parents=True, exist_ok=True)
        if workspace is None:
            (ws / "readme.txt").write_text(
                "Actentra local-first execution boundary\n", encoding="utf-8"
            )
            (ws / ".env").write_text("SECRET_TOKEN=demo_only\n", encoding="utf-8")

        receipt_db = db_path if db_path is not None else (tmp / "receipts.db")
        policy = _build_workspace_policy(ws, shadow=shadow)
        store = ReceiptStore(receipt_db)
        boundary = Boundary(policy=policy, receipt_store=store, session_id="run-session")
        executor = LocalFSExecutor(ws)
        tools = ScopedFSTools(boundary, executor)

        # 1. Allowed list & read
        items = tools.list_dir(".")
        typer.echo(f"[ALLOW] fs.list -> {len(items)} entry(ies)")
        content = tools.read_file("readme.txt")
        typer.echo(f"[ALLOW] fs.read readme.txt -> {content.strip()!r}")

        # 2. Sensitive credential read (.env) -> blocked by privilege-escalation rule
        try:
            tools.read_file(".env")
        except ActionBlockedError as exc:
            typer.echo(f"[BLOCKED] fs.read .env -> {exc}")

        # 3. Traversal escape attempt -> blocked fail-closed
        try:
            tools.read_file(r"..\outside.txt")
        except ActionBlockedError as exc:
            typer.echo(f"[BLOCKED] fs.read traversal -> {exc}")

        # 4. Unapproved delete -> blocked
        try:
            tools.delete_file("readme.txt")
        except ActionBlockedError as exc:
            typer.echo(f"[BLOCKED] fs.delete -> {exc}")

        vr = verify_log(receipt_db)
        typer.echo(f"[VERIFY] ok={vr.ok} records={vr.total_records} head={vr.last_hash}")


@app.command()
def demo() -> None:
    """Run a self-contained local demo showing allow, block, and receipt verification."""
    policy = load_policy_yaml(_DEFAULT_STARTER_POLICY)
    with tempfile.TemporaryDirectory(prefix="actentra-demo-") as tmpdir:
        db_path = Path(tmpdir) / "receipts.db"
        store = ReceiptStore(db_path)
        boundary = Boundary(
            policy=policy,
            receipt_store=store,
            session_id="demo-session",
            agent_id="demo-agent",
        )

        # 1. Benign read inside workspace
        out = boundary.execute(
            tool="fs.read",
            verb="read",
            resource=r"path:C:\work\notes.txt",
            params={"encoding": "utf-8"},
            fn=lambda env, _dec: f"Read {env.action.resource}",
        )
        typer.echo(f"[ALLOW] {out}")

        # 2. Simulated traversal attack attempting to escape C:/work
        try:
            boundary.execute(
                tool="fs.read",
                verb="read",
                resource=r"path:C:\work\..\..\Windows\System32\drivers\etc\hosts",
                fn=lambda _env, _dec: "should never run",
            )
        except ActionBlockedError as exc:
            typer.echo(f"[BLOCKED] {exc}")

        # 3. Simulated prompt-injected outbound HTTP call
        try:
            boundary.execute(
                tool="http.post",
                verb="network",
                resource="https://evil.example/exfil",
                provenance=[ProvenanceItem(source="email:inbound", trust="untrusted")],
                fn=lambda _env, _dec: "should never run",
            )
        except ActionBlockedError as exc:
            typer.echo(f"[BLOCKED] {exc}")

        vr = verify_log(db_path)
        typer.echo(f"[VERIFY] ok={vr.ok} records={vr.total_records} head={vr.last_hash}")


@app.command("mcp-proxy")
def mcp_proxy_cmd(
    server_cmd: Annotated[
        list[str],
        typer.Argument(help="Downstream MCP server command and arguments (after --)."),
    ],
    policy_path: Annotated[
        Path, typer.Option("--policy", "-p", help="Path to YAML policy file.")
    ],
    db_path: Annotated[
        Path, typer.Option("--db", help="Path to SQLite receipt database.")
    ] = Path(".actentra/mcp-receipts.db"),
    session_id: Annotated[
        str, typer.Option("--session", help="Session ID for receipts and rate limits.")
    ] = "mcp-session",
) -> None:
    """Wrap an MCP stdio server and mediate all ``tools/call`` requests."""
    try:
        pack = load_policy_file(policy_path)
    except PolicyValidationError as exc:
        typer.echo(f"INVALID policy: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    store = ReceiptStore(db_path)
    boundary = Boundary(
        policy=pack,
        receipt_store=store,
        session_id=session_id,
        agent_id="mcp-client",
        framework="mcp",
    )
    rc = serve_stdio(boundary=boundary, server_cmd=server_cmd)
    raise typer.Exit(code=rc)


@app.command("serve")
def serve_cmd(
    policy_path: Annotated[
        Path, typer.Option("--policy", "-p", help="Path to YAML policy file.")
    ],
    db_path: Annotated[
        Path, typer.Option("--db", help="Path to SQLite receipt database.")
    ] = Path(".actentra/gateway-receipts.db"),
    host: Annotated[str, typer.Option("--host", "-h", help="Bind host.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port.")] = 8080,
    session_id: Annotated[
        str, typer.Option("--session", help="Session ID for crossings.")
    ] = "gateway-session",
) -> None:
    """Run the Actentra HTTP Gateway service and Operator Console."""
    try:
        pack = load_policy_file(policy_path)
    except PolicyValidationError as exc:
        typer.echo(f"INVALID policy: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    store = ReceiptStore(db_path)
    boundary = Boundary(
        policy=pack,
        receipt_store=store,
        session_id=session_id,
        agent_id="http-gateway",
        framework="http",
    )
    serve_http(boundary=boundary, host=host, port=port)


@checkpoint_app.command("keygen")
def checkpoint_keygen(
    out_dir: Annotated[
        Path, typer.Argument(help="Directory to write Ed25519 keypair.")
    ] = Path(".actentra/keys"),
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite existing key files.")
    ] = False,
) -> None:
    """Generate an Ed25519 keypair for signing receipt checkpoints."""
    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path = out_dir / "checkpoint.key.pem"
    pub_path = out_dir / "checkpoint.pub.pem"
    if (priv_path.exists() or pub_path.exists()) and not force:
        typer.echo(
            f"Key files already exist in {out_dir} (use --force to overwrite)", err=True
        )
        raise typer.Exit(code=1)
    priv_pem, pub_pem = generate_ed25519_keypair()
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    typer.echo(f"Generated Ed25519 keypair: private={priv_path} public={pub_path}")


@checkpoint_app.command("sign")
def checkpoint_sign_cmd(
    db_path: Annotated[Path, typer.Argument(help="Path to SQLite receipt database.")],
    key_path: Annotated[Path, typer.Option("--key", "-k", help="Ed25519 private key PEM.")],
    out_path: Annotated[
        Path, typer.Option("--out", "-o", help="Output checkpoint JSON file.")
    ] = Path("checkpoint.json"),
) -> None:
    """Sign a tamper-evident checkpoint at the current head of a receipt log."""
    try:
        priv_pem = key_path.read_bytes()
        cp = sign_checkpoint(db_path, priv_pem)
        write_checkpoint(cp, out_path)
    except (OSError, CheckpointError) as exc:
        typer.echo(f"CHECKPOINT SIGN FAILED: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Signed checkpoint seq={cp.seq} head={cp.head_hash} -> {out_path}")


@checkpoint_app.command("verify")
def checkpoint_verify_cmd(
    checkpoint_path: Annotated[Path, typer.Argument(help="Path to checkpoint JSON file.")],
    pubkey_path: Annotated[
        Path, typer.Option("--pubkey", "-p", help="Ed25519 public key PEM.")
    ],
    db_path: Annotated[
        Path | None, typer.Option("--db", help="Optional receipt DB to verify against.")
    ] = None,
) -> None:
    """Verify an Ed25519 signed checkpoint (and optionally its SQLite receipt DB)."""
    try:
        cp = load_checkpoint(checkpoint_path)
        pub_pem = pubkey_path.read_bytes()
    except (OSError, CheckpointError) as exc:
        typer.echo(f"CHECKPOINT VERIFY FAILED: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    ok, msg = verify_checkpoint(cp, pub_pem, db_path=db_path)
    if not ok:
        typer.echo(f"VERIFICATION FAILED: {msg}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"OK checkpoint seq={cp.seq} key_id={cp.key_id} head={cp.head_hash}")


if __name__ == "__main__":
    app()
