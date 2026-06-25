"""
Advisory triage via a LOCAL LLM (Ollama). Optional by design.

The LLM's only job is to translate a raw file request into a plain-language
sentence and a rough risk label, so the human approval prompt is easy to read.

It NEVER decides allow/deny (that's policy.py). If Ollama is missing or the
local model is unreachable, we fall back to a simple keyword heuristic and the
system keeps working — the security boundary does not depend on the LLM.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .types import FileRequest, Triage

OLLAMA_URL = os.environ.get("GUARDIAN_OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("GUARDIAN_LLM_MODEL", "llama3.2")
TIMEOUT = float(os.environ.get("GUARDIAN_LLM_TIMEOUT", "8"))

_HIGH = (".env", "secret", ".key", ".pem", "id_rsa", ".ssh", "password", "credential", "wallet")
_MED = ("personal", "private", "diary", "tax", "medical", "bank")


def _heuristic(req: FileRequest) -> Triage:
    low = req.path.lower()
    if any(k in low for k in _HIGH):
        risk = "high"
    elif any(k in low for k in _MED):
        risk = "medium"
    else:
        risk = "low"
    if req.operation in ("write", "delete"):
        risk = "high" if risk != "low" else "medium"
    verb = {"read": "read", "write": "write to", "list": "list", "delete": "delete"}[req.operation]
    summary = f"The agent wants to {verb} '{req.path}'."
    return Triage(summary=summary, risk=risk, source="heuristic")


def _ask_ollama(req: FileRequest) -> Triage | None:
    prompt = (
        "You explain a file request from an AI agent to a human in ONE short sentence, "
        "then rate its risk as low, medium, or high. Respond ONLY as compact JSON "
        '{"summary": "...", "risk": "low|medium|high"} with no extra text.\n\n'
        f"operation: {req.operation}\npath: {req.path}\n"
        f"size_bytes: {req.size}\ncontent_preview: {req.content_preview or ''}\n"
    )
    payload = json.dumps(
        {"model": MODEL, "prompt": prompt, "stream": False, "format": "json"}
    ).encode()
    httpreq = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate", data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(httpreq, timeout=TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
        data = json.loads(body.get("response", "{}"))
        risk = str(data.get("risk", "unknown")).lower()
        if risk not in ("low", "medium", "high"):
            risk = "unknown"
        summary = str(data.get("summary") or _heuristic(req).summary)
        return Triage(summary=summary, risk=risk, source="llm")  # type: ignore[arg-type]
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError, TimeoutError):
        return None


def triage(req: FileRequest) -> Triage:
    """Try the local LLM; fall back to heuristic. Always returns something."""
    return _ask_ollama(req) or _heuristic(req)
