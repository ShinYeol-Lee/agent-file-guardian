#!/usr/bin/env python3
"""
MCP server: exposes gated file tools (read_file, write_file, list_dir,
delete_file) to any MCP-capable agent (Claude Desktop, etc.).

Instead of giving the agent raw filesystem access, you point it at this server.
Every call is run through the Guardian pipeline (policy → human approval →
audit) before any byte is touched.

Run:
    pip install "mcp[cli]"
    python -m guardian.server            # speaks MCP over stdio

Approval prompts are read from /dev/tty (NOT stdin), because stdin/stdout
carry the MCP protocol. If there is no terminal attached, the server fails
closed (denies the 'ask' case).
"""
from __future__ import annotations

import os
import sys

from .audit import render_request
from .engine import handle
from .policy import load_policy
from .types import FileRequest

POLICY_PATH = os.environ.get("GUARDIAN_POLICY", "policy.yaml")


def _tty_approver(req, decision, tri):  # noqa: ANN001
    print(render_request(req, decision, tri), file=sys.stderr)
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write("  Allow this action? [y/N] ")
            tty.flush()
            ans = tty.readline().strip().lower()
        return ans in ("y", "yes")
    except OSError:
        print("  [no tty attached -> denying, fail closed]", file=sys.stderr)
        return False


def _run(req: FileRequest, content: str = "") -> str:
    policy = load_policy(POLICY_PATH)
    res = handle(policy, req, content=content, approver=_tty_approver)
    if res.executed:
        return res.output or "(ok)"
    if res.error:
        return f"ERROR: {res.error}"
    if res.decision.action == "deny":
        return f"BLOCKED by policy rule '{res.decision.rule_name}'. Not permitted."
    return "DENIED by the user."


def build_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise SystemExit(
            'The MCP SDK is not installed. Run:  pip install "mcp[cli]"'
        ) from exc

    mcp = FastMCP("agent-file-guardian")

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read a text file, subject to the Guardian policy."""
        return _run(FileRequest("read", path))

    @mcp.tool()
    def list_dir(path: str) -> str:
        """List a directory, subject to the Guardian policy."""
        return _run(FileRequest("list", path))

    @mcp.tool()
    def write_file(path: str, content: str) -> str:
        """Write text to a file, subject to the Guardian policy."""
        return _run(
            FileRequest("write", path, size=len(content.encode()),
                        content_preview=content[:200]),
            content=content,
        )

    @mcp.tool()
    def delete_file(path: str) -> str:
        """Delete a file, subject to the Guardian policy."""
        return _run(FileRequest("delete", path))

    return mcp


if __name__ == "__main__":
    build_server().run()
