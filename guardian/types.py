"""Shared data types for Agent File Guardian."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Literal

Operation = Literal["read", "write", "list", "delete"]
Action = Literal["allow", "ask", "deny"]


@dataclass
class FileRequest:
    """A file operation an agent wants to perform."""
    operation: Operation
    path: str
    size: Optional[int] = None          # bytes, for writes
    content_preview: Optional[str] = None  # first chars of a write, for triage


@dataclass
class PolicyDecision:
    """The deterministic verdict. THIS is the security boundary."""
    action: Action
    rule_name: str
    reason: str


@dataclass
class Triage:
    """Advisory, human-readable context. NOT part of the security boundary."""
    summary: str
    risk: Literal["low", "medium", "high", "unknown"]
    source: Literal["llm", "heuristic"]


@dataclass
class Result:
    request: FileRequest
    decision: PolicyDecision
    triage: Triage
    approved: Optional[bool] = None   # None = no human prompt was needed
    executed: bool = False
    output: Optional[str] = None      # file contents / listing / status
    error: Optional[str] = None
