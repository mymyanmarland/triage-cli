# triage-cli — Spec v0.1

## Problem
When a server or site breaks, an AI agent cannot see inside the server.
Logs are huge and scattered, dashboards are made for human eyes, and the
human ends up copying fragments to the agent by hand.

## What it is
A read-only tool that turns a Linux server's scattered state into ONE
compact markdown report any AI agent can read in a single pass.

## Hard rules
1. **Read-only.** It never starts, stops, restarts, edits, or deletes anything.
2. **Secrets are redacted** before anything enters the report
   (passwords, tokens, API keys, Authorization headers, connection-string
   passwords, JWTs, cloud keys).
3. **Stdlib only.** Python 3, no pip installs, no API keys, no network calls.
4. **Graceful degradation.** A missing source (no systemd, no nginx log)
   is reported as `unavailable`, never as a crash.

## v0.1 scope
- `triage collect` — one markdown report with 5 sections:
  1. System — host, OS, uptime, load, CPU, memory, disk, top processes
  2. Services — systemd state + failed units (or `unavailable`)
  3. Ports — listening TCP ports (`ss`)
  4. Errors — journal errors + known log files, timestamps stripped,
     **deduplicated by signature with counts**, redacted
  5. Summary — one short paragraph an agent can act on
- `triage mcp` — minimal stdio MCP server exposing one tool,
  `triage_collect`, so Cursor / Claude Code / OpenClaw can call it.
- `SKILL.md` — agent instructions: when a site is down, run triage first.

## Out of scope for v0.1
- Fixing anything (report only)
- Fleet / multi-server mode
- Alerts, dashboards, hosted service

## Success criteria
- Runs on a plain Linux box and on the owner's VPS with zero installs.
- Report for a healthy machine is under ~150 lines.
- A planted fake secret in a log line never appears in the report.
- Unit tests for redaction and error dedupe pass.
