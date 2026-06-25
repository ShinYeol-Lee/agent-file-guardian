"""Human approval prompt + append-only audit log."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from .types import FileRequest, PolicyDecision, Triage, Result

AUDIT_PATH = os.environ.get("GUARDIAN_AUDIT_LOG", "guardian-audit.log")

_RISK_MARK = {"low": "·", "medium": "!", "high": "!!!", "unknown": "?"}


def render_request(req: FileRequest, decision: PolicyDecision, tri: Triage) -> str:
    lines = [
        "",
        "  ┌─ AGENT FILE REQUEST " + "─" * 38,
        f"  │  what : {tri.summary}",
        f"  │  op   : {req.operation}    path: {req.path}",
        f"  │  risk : {tri.risk} {_RISK_MARK.get(tri.risk, '')}  (via {tri.source})",
        f"  │  rule : {decision.rule_name} → {decision.action.upper()}",
        "  └" + "─" * 58,
    ]
    return "\n".join(lines)


def request_approval(
    req: FileRequest,
    decision: PolicyDecision,
    tri: Triage,
    *,
    auto: bool | None = None,
) -> bool:
    """Return True if the human approves. `auto` (True/False) skips the prompt
    for non-interactive demos."""
    print(render_request(req, decision, tri), file=sys.stderr)
    if auto is not None:
        print(f"  [auto] approved={auto}", file=sys.stderr)
        return auto
    try:
        answer = input("  Allow this action? [y/N] ").strip().lower()
    except EOFError:
        answer = ""
    return answer in ("y", "yes")


def log(result: Result) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "operation": result.request.operation,
        "path": result.request.path,
        "size": result.request.size,
        "action": result.decision.action,
        "rule": result.decision.rule_name,
        "risk": result.triage.risk,
        "triage_source": result.triage.source,
        "summary": result.triage.summary,
        "approved": result.approved,
        "executed": result.executed,
        "error": result.error,
    }
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
