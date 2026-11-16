"""Actentra gateway adapters (MCP stdio proxy and future local endpoints)."""

from actentra_gateway.demo import GatewayDemoResult, run_gateway_demonstration
from actentra_gateway.http_service import (
    ActentraHTTPHandler,
    ActentraHTTPServer,
    create_gateway_server,
    serve_http,
)
from actentra_gateway.mcp_proxy import MCPStdioProxy, MCPToolMapping, default_mcp_tool_mapper

__all__ = [
    "ActentraHTTPHandler",
    "ActentraHTTPServer",
    "GatewayDemoResult",
    "MCPStdioProxy",
    "MCPToolMapping",
    "create_gateway_server",
    "default_mcp_tool_mapper",
    "run_gateway_demonstration",
    "serve_http",
]
