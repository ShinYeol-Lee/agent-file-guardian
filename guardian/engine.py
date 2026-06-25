"""
The pipeline that every file request flows through:

    triage (advisory)  →  policy (decides)  →  human approval (if 'ask')
                       →  execute (if allowed)  →  audit log (always)

Both the CLI demo and the MCP server call `handle()`, so the safety logic
lives in exactly one place.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Optional

from . import audit
from .policy import evaluate
from .triage import triage as run_triage
from .types import FileRequest, Result


def _do_read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _do_list(path: str) -> str:
    return "\n".join(sorted(os.listdir(path)))


def _do_write(path: str, content: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return f"wrote {len(content.encode())} bytes"


def _do_delete(path: str) -> str:
    os.remove(path)
    return "deleted"


def handle(
    policy: dict[str, Any],
    req: FileRequest,
    *,
    content: str = "",
    approver: Optional[Callable[[FileRequest, Any, Any], bool]] = None,
    execute: bool = True,
) -> Result:
    """Run one request through the full pipeline.

    `approver(req, decision, triage) -> bool` is called only when the policy
    verdict is 'ask'. If no approver is supplied, an 'ask' is treated as denied
    (fail-closed)."""
    tri = run_triage(req)
    decision = evaluate(policy, req)
    result = Result(request=req, decision=decision, triage=tri)

    if decision.action == "deny":
        result.approved = False
    elif decision.action == "ask":
        result.approved = bool(approver(req, decision, tri)) if approver else False
    else:  # allow
        result.approved = None  # no human needed

    allowed = decision.action == "allow" or result.approved is True

    if allowed and execute:
        try:
            if req.operation == "read":
                result.output = _do_read(req.path)        # type: ignore[attr-defined]
            elif req.operation == "list":
                result.output = _do_list(req.path)        # type: ignore[attr-defined]
            elif req.operation == "write":
                result.output = _do_write(req.path, content)  # type: ignore[attr-defined]
            elif req.operation == "delete":
                result.output = _do_delete(req.path)      # type: ignore[attr-defined]
            result.executed = True
        except Exception as exc:  # noqa: BLE001 - surface fs errors to the agent
            result.error = f"{type(exc).__name__}: {exc}"

    audit.log(result)
    return result
