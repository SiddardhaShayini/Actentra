# Actentra Evaluation Corpora

Synthetic and curated JSONL test corpora used for regression, replay, and red-team verification:

- `incidents/`: Real-world agent failure cases (each mapped to Section 3 failure class + required control + source link).
- `redteam/`: Adversarial payloads (Windows path traversal, ADS, reserved device names, prompt-injected egress, privilege escalation).
- `benign/`: Representative safe tool calls used to measure false-positive rate (< 5% target in Phase 1).

Keep corpora compact and fast to replay on an 8 GB RAM / CPU-only laptop.
