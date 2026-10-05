"""The MCP half: a fastmcp proxy in front of any upstream MCP server, with the Gate applied to
every tools/list and every tools/call. One process serves one profile, so in an InteractiveAI
manifest attaching the gatehouse entry for a profile is the permission grant."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server import create_proxy
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from .policy import Gate, load


class GateMiddleware(Middleware):
    def __init__(self, gate: Gate, profile: str):
        if profile not in gate.profiles:
            raise ValueError(f"unknown profile {profile!r}; have {sorted(gate.profiles)}")
        self.gate, self.profile = gate, profile

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        return [t for t in await call_next(context) if self.gate.visible(self.profile, t.name)]

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        tool, args = context.message.name, dict(context.message.arguments or {})
        session = _session(context)
        started = time.monotonic()
        decision = self.gate.decide(self.profile, tool, args)
        replayed = False

        if decision.action != "allow":
            result = _data(decision.as_error())
        else:
            key = self.gate.replays.key(tool, args)
            result = self.gate.replays.get(key) if key else None
            replayed = result is not None
            if not replayed:
                result = self._mask(await call_next(context))
                if key and not result.is_error:
                    self.gate.replays.put(key, result)

        self._audit(session, tool, args, decision, replayed, started)
        return result

    def _mask(self, result: ToolResult) -> ToolResult:
        m = self.gate.mask
        content = [TextContent(type="text", text=m.text(c.text)) if isinstance(c, TextContent) else c
                   for c in result.content]
        structured = m(result.structured_content) if result.structured_content is not None else None
        return ToolResult(content=content, structured_content=structured, meta=result.meta,
                          is_error=result.is_error)

    def _audit(self, session, tool, args, decision, replayed, started):
        if not self.gate.audit_log:
            return
        line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "session": session,
                "profile": self.profile, "tool": tool, "args": self.gate.mask(args),
                "decision": "replayed" if replayed else decision.action, "rule": decision.rule,
                "ms": round((time.monotonic() - started) * 1000, 1)}
        with open(self.gate.audit_log, "a") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")


def _session(context: MiddlewareContext) -> str:
    try:
        return context.fastmcp_context.session_id
    except Exception:          # no session outside a live request (e.g. some test transports)
        return "-"


def _data(payload: dict) -> ToolResult:
    return ToolResult(content=[TextContent(type="text", text=json.dumps(payload))],
                      structured_content=payload)


def build(gate: Gate, profile: str, upstream=None, upstream_headers: dict | None = None):
    """A proxy server for one profile. `upstream` overrides the config (tests pass a FastMCP
    instance to run everything in memory)."""
    target = upstream if upstream is not None else gate.upstream
    if isinstance(target, str) and target.startswith("http"):
        # upstream credentials live in the gate, never in the agent manifest
        target = StreamableHttpTransport(target, headers=upstream_headers)
    elif isinstance(target, str):
        target = Path(target)
    auth = StaticTokenVerifier({gate.api_key: {"client_id": f"agent:{profile}", "scopes": []}}) \
        if gate.api_key else None
    proxy = create_proxy(target, name=f"gatehouse-{profile}", auth=auth)
    proxy.add_middleware(GateMiddleware(gate, profile))
    return proxy


def main(argv=None):
    p = argparse.ArgumentParser(prog="gatehouse", description="Guardrail proxy for MCP tools.")
    p.add_argument("config")
    p.add_argument("--profile", required=True)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8766)
    p.add_argument("--stdio", action="store_true", help="serve over stdio instead of streamable-http")
    a = p.parse_args(argv)
    gate = load(a.config)
    if not gate.api_key:
        print("gatehouse: no api_key set, accepting unauthenticated requests", file=sys.stderr)
    server = build(gate, a.profile)
    if a.stdio:
        server.run()
    else:
        server.run(transport="http", host=a.host, port=a.port)   # mounted at /mcp, the manifest default


if __name__ == "__main__":
    main()
