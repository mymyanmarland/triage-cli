# triage-cli — agent skill

## When to use
A website, app, bot, or service on a Linux server is down, slow, or
behaving strangely — and you need to know what is wrong before touching
anything.

## Rule
**Run triage FIRST, before reading raw logs or changing anything.**

```bash
python3 triage.py collect --hours 24 --out /tmp/triage-report.md
```

Then read the whole report (it is short by design). Work from it:

1. **Summary** — the one-paragraph picture.
2. **Services** — a failed service is usually the incident.
3. **Errors** — signatures are deduplicated: `×340` means one problem
   repeated 340 times, not 340 problems. Fix the highest count first.
4. **System / Ports** — rule out disk-full, memory, and port conflicts.

## Guarantees
- Read-only: running it never changes the machine.
- Secrets in logs are redacted before they reach the report.
- Missing sources show as `unavailable`, not as errors.

## MCP
`triage mcp` runs a stdio MCP server with one tool, `triage_collect`
(optional `hours`). Register it like any stdio MCP server:

```json
{ "command": "python3", "args": ["/path/to/triage.py", "mcp"] }
```
