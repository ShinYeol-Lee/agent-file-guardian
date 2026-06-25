"""
Deterministic policy engine.

This is the ACTUAL security boundary. Rules are evaluated top to bottom;
the first rule whose path patterns (and optional operation filter) match wins.
If nothing matches, `default_action` applies.

Design choice: a probabilistic LLM must never be the thing that decides
allow/deny. That decision lives here, in plain, auditable code.
"""
from __future__ import annotations

import os
from typing import Any

import pathspec
import yaml

from .types import FileRequest, PolicyDecision, Action


def load_policy(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f) or {}
    policy.setdefault("default_action", "ask")
    policy.setdefault("rules", [])
    policy.setdefault("limits", {})
    return policy


def _normalize(p: str) -> str:
    """Expand ~ and return a clean posix-style string for matching.
    normpath() already drops a leading './' without eating dotfile dots."""
    p = os.path.expanduser(p)
    p = os.path.normpath(p)
    return p.replace(os.sep, "/")


def _matches(patterns: list[str], path: str) -> bool:
    norm = _normalize(path)
    for raw in patterns:
        pat = os.path.expanduser(raw) if raw.startswith("~") else raw
        pat = pat.replace(os.sep, "/")
        spec = pathspec.PathSpec.from_lines("gitwildmatch", [pat])
        if spec.match_file(norm):
            return True
    return False


def evaluate(policy: dict[str, Any], req: FileRequest) -> PolicyDecision:
    for rule in policy.get("rules", []):
        ops = rule.get("operations")
        if ops and req.operation not in ops:
            continue
        patterns = rule.get("match_paths", [])
        if patterns and not _matches(patterns, req.path):
            continue
        action: Action = rule.get("action", "ask")

        # A size limit can only make a decision *stricter*, never looser.
        max_bytes = policy.get("limits", {}).get("max_write_bytes")
        if (
            action == "allow"
            and req.operation == "write"
            and max_bytes is not None
            and req.size is not None
            and req.size > max_bytes
        ):
            return PolicyDecision(
                action="ask",
                rule_name=rule.get("name", "(unnamed)"),
                reason=f"Write of {req.size} bytes exceeds max_write_bytes "
                f"({max_bytes}); escalated from allow to ask.",
            )

        return PolicyDecision(
            action=action,
            rule_name=rule.get("name", "(unnamed)"),
            reason=f"Matched rule '{rule.get('name', '(unnamed)')}'.",
        )

    return PolicyDecision(
        action=policy["default_action"],
        rule_name="(default)",
        reason="No rule matched; applied default_action.",
    )
