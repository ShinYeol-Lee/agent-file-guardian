# Agent File Guardian

A small, honest gate between an AI agent and your files.

When you let an autonomous agent run on your machine, it inherits your machine's
trust boundary. Agent File Guardian sits in front of file operations and runs
each one through three steps before a single byte is touched:

1. **Triage** — a *local* LLM (via [Ollama](https://ollama.com)) translates the
   raw request into one plain sentence and a rough risk label, so you can
   actually read what the agent is about to do.
2. **Policy** — a deterministic rule file decides `allow` / `ask` / `deny`.
3. **Approval** — anything marked `ask` pauses for a human yes/no, and
   everything is written to an append-only audit log.

```
agent ──▶ [ triage: explain + risk ] ──▶ [ policy: allow|ask|deny ] ──▶ [ human if 'ask' ] ──▶ file
                  (local LLM,                 (plain code —                  (you)            + audit log
                   advisory only)         the real boundary)
```

## What this is — and what it is NOT

Please read this before trusting it with anything.

- This is a **human-in-the-loop ergonomics layer**, not a cryptographic
  sandbox. It makes "review every sensitive action" practical instead of
  exhausting.
- **The local LLM never decides `allow` or `deny`.** That would make a
  prompt-injectable, non-deterministic component your security boundary — a bad
  idea. The LLM only *explains*. The decision lives in `policy.yaml`, in plain
  auditable code. If Ollama isn't running, the gate still works; you just lose
  the nice summaries.
- It does **not** replace OS permissions, containers, or a real secrets vault.
  Run agents in a sandbox too. Treat this as defense-in-depth, not the whole
  defense.

If that framing is wrong or can be made stronger, that's exactly the kind of
issue/PR this repo is hoping for.

## Quick start (no agent needed)

```bash
pip install pyyaml pathspec
python demo.py            # interactive: you approve the 'ask' cases
python demo.py --auto     # scripted approvals, prints the whole trace
```

The demo builds a throwaway sandbox (a `workspace/` folder, a `personal/`
folder, and a fake `.env`) and sends four agent requests through the gate so you
can watch allow / ask / deny happen and see the audit log fill in.

## Real use: plug it into an agent over MCP

```bash
pip install "mcp[cli]"
python -m guardian.server        # speaks MCP over stdio
```

Point an MCP-capable agent at it instead of giving it raw filesystem tools.
Example Claude Desktop config:

```json
{
  "mcpServers": {
    "file-guardian": {
      "command": "python",
      "args": ["-m", "guardian.server"],
      "env": { "GUARDIAN_POLICY": "/absolute/path/to/policy.yaml" }
    }
  }
}
```

Approval prompts appear on your terminal (`/dev/tty`), since stdin/stdout carry
the MCP protocol. With no terminal attached, the server **fails closed** (denies
the `ask` case).

## Writing policy

`policy.yaml` is the whole security boundary. Rules are checked top to bottom;
the first match wins, so **put `deny` rules first**. Patterns are gitignore-style
globs.

```yaml
default_action: ask          # allow | ask | deny  — used when nothing matches

rules:
  - name: "Block secrets and keys"
    match_paths: ["**/.env", "**/*.key", "**/.ssh/**", "**/secrets/**"]
    action: deny

  - name: "Workspace reads are fine"
    match_paths: ["workspace/**"]
    operations: ["read", "list"]
    action: allow
```

`limits.max_write_bytes` can only make a verdict stricter (an oversized `allow`
write is escalated to `ask`) — never looser.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `GUARDIAN_POLICY` | `policy.yaml` | Path to the policy file |
| `GUARDIAN_AUDIT_LOG` | `guardian-audit.log` | Append-only JSONL log |
| `GUARDIAN_OLLAMA_URL` | `http://localhost:11434` | Local LLM endpoint |
| `GUARDIAN_LLM_MODEL` | `llama3.2` | Ollama model for triage |
| `GUARDIAN_LLM_TIMEOUT` | `8` | Seconds before falling back to heuristic |

## Ideas worth contributing

Honest about the gaps — these are open invitations, not finished claims:

- **Path-traversal hardening:** resolve `..`/symlinks and match policy on the
  real path before deciding.
- **Optional triage→escalation:** let a `high` LLM risk turn an `allow` into an
  `ask` (off by default, to keep the boundary deterministic).
- **Better approval channels:** desktop notification or phone push instead of a
  terminal prompt.
- **Per-session budgets:** "allow up to N writes / this much total" within one
  agent run.
- **More operations:** move/copy/chmod, and non-text files.

## License

MIT — see [LICENSE](LICENSE). Built as a proof of concept to make the idea
concrete. Fork it, break it, improve it.
