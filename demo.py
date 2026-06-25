#!/usr/bin/env python3
"""
Self-contained demo. No agent, no setup required.

    python demo.py            # interactive: you approve the 'ask' cases
    python demo.py --auto     # non-interactive: scripted approvals, for CI/readme

It builds a small sandbox of sample files, then sends a sequence of file
requests (as an AI agent would) through the Guardian pipeline so you can watch
allow / ask / deny play out, and see the audit log fill up.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile

from guardian import FileRequest, load_policy, handle
from guardian.audit import request_approval

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def banner(text: str) -> None:
    print(f"\n{DIM}{'=' * 64}{RESET}\n {text}\n{DIM}{'=' * 64}{RESET}")


def build_sandbox(root: str) -> None:
    os.makedirs(os.path.join(root, "workspace"), exist_ok=True)
    os.makedirs(os.path.join(root, "personal"), exist_ok=True)
    with open(os.path.join(root, "workspace", "notes.txt"), "w") as f:
        f.write("project notes: ship the thing\n")
    with open(os.path.join(root, "personal", "diary.txt"), "w") as f:
        f.write("dear diary...\n")
    with open(os.path.join(root, ".env"), "w") as f:
        f.write("API_KEY=super-secret-123\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--auto", action="store_true", help="non-interactive scripted approvals")
    args = ap.parse_args()

    policy = load_policy(os.path.join(os.path.dirname(__file__), "policy.yaml"))

    original_cwd = os.getcwd()
    # ignore_cleanup_errors keeps Windows happy if the temp dir is still busy.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as root:
        build_sandbox(root)
        os.chdir(root)  # so 'workspace/...' patterns match
        os.environ["GUARDIAN_AUDIT_LOG"] = os.path.join(root, "guardian-audit.log")

        # (request, scripted-answer-for-auto-mode)
        script = [
            (FileRequest("read", "workspace/notes.txt"), None),                       # allow
            (FileRequest("read", "personal/diary.txt"), False),                       # ask -> deny
            (FileRequest("write", "workspace/report.txt",
                         size=42, content_preview="quarterly numbers"), True),        # ask -> allow
            (FileRequest("read", ".env"), None),                                      # deny
        ]

        for i, (req, auto_answer) in enumerate(script, 1):
            banner(f"Request {i}/{len(script)}: agent wants to {req.operation} {req.path}")

            def approver(r, d, t):  # noqa: ANN001
                return request_approval(r, d, t, auto=auto_answer if args.auto else None)

            res = handle(
                policy, req,
                content="quarterly numbers go here\n" if req.operation == "write" else "",
                approver=approver,
            )

            verdict = res.decision.action
            color = {"allow": GREEN, "ask": YELLOW, "deny": RED}[verdict]
            if res.executed:
                print(f"  {GREEN}✓ EXECUTED{RESET} ({verdict}) — {res.output!r}"[:100])
            elif res.error:
                print(f"  {RED}✗ ERROR{RESET}: {res.error}")
            else:
                why = "blocked by policy" if verdict == "deny" else "human declined"
                print(f"  {color}✗ NOT EXECUTED{RESET} — {why}")

        banner("Audit log")
        with open(os.environ["GUARDIAN_AUDIT_LOG"]) as f:
            sys.stdout.write(f.read())

        # Leave the temp dir before it gets cleaned up — Windows refuses to
        # delete a directory that is still the process's working directory.
        os.chdir(original_cwd)

    print(
        f"\n{DIM}Note: this is a human-in-the-loop ergonomics layer, not a "
        f"cryptographic sandbox. See README.{RESET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
