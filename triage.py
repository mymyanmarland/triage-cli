#!/usr/bin/env python3
"""triage-cli — read-only server incident report for AI agents.

Turns a Linux server's scattered state (system, services, ports, logs)
into ONE compact, secret-redacted, error-deduplicated markdown report.

Stdlib only. No network. Never modifies anything on the machine.
"""
import argparse
import json
import os
import platform
import re
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime, timezone

VERSION = "0.1.0"
REDACTED = "[REDACTED]"

# ---------------------------------------------------------------- redaction
_SECRET_PATTERNS = [
    # key=value / key: value for sensitive keys
    (re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|"
                r"access[_-]?key|private[_-]?key|auth)\b(\s*[:=]\s*)(\S+)"),
     r"\1\2" + REDACTED),
    # Authorization: Bearer xxx / Basic xxx
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}"),
     r"\1 " + REDACTED),
    # scheme://user:pass@host  ->  scheme://user:[REDACTED]@host
    (re.compile(r"([a-z][a-z0-9+.\-]*://[^/\s:@]+:)([^@\s]+)(@)"),
     r"\1" + REDACTED + r"\3"),
    # well-known token shapes
    (re.compile(r"\b(ghp|gho|github_pat)_[A-Za-z0-9_]{10,}"), REDACTED),
    (re.compile(r"\bsk-[A-Za-z0-9\-_]{10,}"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{5,}"),
     REDACTED),  # JWT
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), REDACTED),  # Slack
]


def redact(text: str) -> str:
    """Remove secret-looking values from a line of text."""
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


# ---------------------------------------------------------------- helpers
def run(cmd, timeout=10):
    """Run a read-only command, return (ok, stdout). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False, ""


def read_file(path, limit=200_000):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return None


def tail_lines(path, n=500):
    data = read_file(path, limit=1_000_000)
    if data is None:
        return None
    return data.splitlines()[-n:]


# ---------------------------------------------------------------- sections
def section_system():
    lines = []
    lines.append(f"- Host: {platform.node() or 'unknown'}")
    osr = read_file("/etc/os-release") or ""
    m = re.search(r'^PRETTY_NAME="?(.*?)"?$', osr, re.M)
    lines.append(f"- OS: {m.group(1) if m else platform.platform()}")
    ok, up = run(["uptime", "-p"])
    if ok and up.strip():
        lines.append(f"- Uptime: {up.strip().replace('up ', '')}")
    try:
        load1, load5, load15 = os.getloadavg()
        lines.append(f"- Load (1/5/15 min): {load1:.2f} / {load5:.2f} / {load15:.2f} "
                     f"on {os.cpu_count()} CPU(s)")
    except OSError:
        pass
    mem = read_file("/proc/meminfo") or ""
    total = re.search(r"MemTotal:\s+(\d+)", mem)
    avail = re.search(r"MemAvailable:\s+(\d+)", mem)
    if total and avail:
        t, a = int(total.group(1)), int(avail.group(1))
        used_pct = 100 * (t - a) // max(t, 1)
        lines.append(f"- Memory: {used_pct}% used "
                     f"({(t - a) // 1024} MB of {t // 1024} MB)")
    ok, df = run(["df", "-P", "-x", "tmpfs", "-x", "devtmpfs"])
    disks = []
    if ok:
        lines.append("- Disks:")
        for row in df.splitlines()[1:]:
            parts = row.split()
            if len(parts) >= 6:
                pct = parts[4]
                disks.append((parts[5], pct))
                lines.append(f"  - {parts[5]}: {pct} used "
                             f"({parts[2]} of {parts[1]} KB)")
    ok, ps = run(["ps", "-eo", "comm,%mem", "--sort=-%mem"])
    if ok:
        top = [r.strip() for r in ps.splitlines()[1:6] if r.strip()]
        if top:
            lines.append("- Top processes by memory: " + ", ".join(top))
    return lines, disks


def section_services():
    lines = []
    ok, state = run(["systemctl", "is-system-running"])
    if not ok and not state.strip():
        return ["- systemd: unavailable (not running or not present)"], []
    lines.append(f"- systemd state: {state.strip().splitlines()[0] if state.strip() else 'unknown'}")
    ok, failed = run(["systemctl", "list-units", "--type=service",
                      "--state=failed", "--no-legend", "--no-pager"])
    failed_units = []
    if ok:
        for row in failed.splitlines():
            name = row.strip().split()[0] if row.strip() else ""
            if name:
                failed_units.append(name)
        if failed_units:
            lines.append(f"- Failed services ({len(failed_units)}):")
            for u in failed_units:
                lines.append(f"  - {u}")
        else:
            lines.append("- Failed services: none")
    ok, count = run(["systemctl", "list-units", "--type=service",
                     "--state=running", "--no-legend", "--no-pager"])
    if ok:
        n = len([r for r in count.splitlines() if r.strip()])
        lines.append(f"- Running services: {n}")
    return lines, failed_units


def section_ports():
    ok, out = run(["ss", "-tln"])
    if not ok:
        ok, out = run(["netstat", "-tln"])
    if not ok:
        return ["- Listening ports: unavailable (no ss/netstat)"], 0
    ports = []
    for row in out.splitlines()[1:]:
        parts = row.split()
        if len(parts) >= 4:
            local = parts[3]
            port = local.rsplit(":", 1)[-1]
            if port.isdigit():
                ports.append(int(port))
    ports = sorted(set(ports))
    return [f"- Listening TCP ports ({len(ports)}): "
            + (", ".join(str(p) for p in ports) if ports else "none")], len(ports)


# ---------------------------------------------------------------- errors
_TS = re.compile(
    r"^(\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?"
    r"(Z|[+-]\d{2}:?\d{2})?\]?\s+"
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)")
_ERROR_HINT = re.compile(r"(?i)error|fail|exception|traceback|critical|"
                         r"fatal|denied|refused|timeout|502|503|504|panic|crash")
LOG_FILES = [
    "/var/log/nginx/error.log",
    "/var/log/apache2/error.log",
    "/var/log/syslog",
    "/var/log/messages",
]


def signature(line: str) -> str:
    """Normalise an error line so repeats collapse into one signature."""
    s = _TS.sub("", line.strip())
    s = re.sub(r"0x[0-9a-fA-F]+", "0xN", s)
    s = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "IP", s)
    s = re.sub(r"\b\d+\b", "N", s)
    s = re.sub(r"\s+", " ", s)
    return s[:200]


def collect_errors(hours):
    """Return (groups, sources) where groups = OrderedDict sig -> dict."""
    groups = OrderedDict()
    sources = []

    def add(line, source):
        line = redact(line.strip())
        if not line or not _ERROR_HINT.search(line):
            return
        sig = signature(line)
        g = groups.get(sig)
        if g:
            g["count"] += 1
        else:
            groups[sig] = {"count": 1, "sample": line[:300], "source": source}

    ok, journal = run(["journalctl", "-p", "err", "--since",
                       f"{hours} hours ago", "--no-pager", "-n", "2000"],
                      timeout=20)
    if ok and journal.strip():
        sources.append(f"journal (last {hours}h, priority err+)")
        for line in journal.splitlines():
            if not line.startswith("--"):
                add(line, "journal")

    for path in LOG_FILES:
        lines = tail_lines(path, 500)
        if lines is not None:
            sources.append(path)
            for line in lines:
                add(line, path)

    # pm2 error logs if present
    pm2_dir = os.path.expanduser("~/.pm2/logs")
    if os.path.isdir(pm2_dir):
        for name in sorted(os.listdir(pm2_dir)):
            if "error" in name or "err" in name:
                lines = tail_lines(os.path.join(pm2_dir, name), 300)
                if lines:
                    sources.append(f"pm2:{name}")
                    for line in lines:
                        add(line, f"pm2:{name}")
    return groups, sources


def section_errors(hours):
    groups, sources = collect_errors(hours)
    lines = [f"- Sources checked: {', '.join(sources) if sources else 'none available'}"]
    if not groups:
        lines.append("- Errors found: none in the checked sources")
        return lines, groups
    ordered = sorted(groups.items(), key=lambda kv: -kv[1]["count"])
    lines.append(f"- Unique error signatures: {len(ordered)} "
                 f"(total {sum(g['count'] for _, g in ordered)} lines)")
    for sig, g in ordered[:20]:
        lines.append(f"  - ×{g['count']} [{g['source']}] {g['sample']}")
    if len(ordered) > 20:
        lines.append(f"  - … and {len(ordered) - 20} more signatures")
    return lines, groups


# ---------------------------------------------------------------- report
def build_report(hours=24):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sys_lines, disks = section_system()
    svc_lines, failed = section_services()
    port_lines, n_ports = section_ports()
    err_lines, groups = section_errors(hours)

    worst_disk = "n/a"
    if disks:
        worst_disk = max(disks, key=lambda d: int(d[1].strip('%')))[1]
    top_err = "none"
    if groups:
        sig, g = max(groups.items(), key=lambda kv: kv[1]["count"])
        top_err = f"×{g['count']} {sig[:90]}"
    summary = (
        f"{platform.node() or 'host'} at {now}: "
        f"{len(failed)} failed service(s), {n_ports} listening port(s), "
        f"fullest disk at {worst_disk}, "
        f"{len(groups)} unique error signature(s) in the last {hours}h. "
        f"Most frequent error: {top_err}."
    )

    out = [
        "# triage report",
        f"Generated: {now} · triage-cli v{VERSION} · read-only · secrets redacted",
        "",
        "## Summary",
        summary,
        "",
        "## 1. System",
        *sys_lines,
        "",
        "## 2. Services",
        *svc_lines,
        "",
        "## 3. Ports",
        *port_lines,
        "",
        f"## 4. Errors (last {hours}h, deduplicated)",
        *err_lines,
        "",
    ]
    return "\n".join(out)


# ---------------------------------------------------------------- MCP
def mcp_server():
    """Minimal stdio MCP server exposing one tool: triage_collect."""
    def send(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            continue
        method, rid = req.get("method"), req.get("id")
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "triage-cli", "version": VERSION}}})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
                "name": "triage_collect",
                "description": "Read-only server incident report "
                               "(system, services, ports, deduplicated errors).",
                "inputSchema": {"type": "object", "properties": {
                    "hours": {"type": "integer", "default": 24}}}}]}})
        elif method == "tools/call":
            hours = (req.get("params", {}).get("arguments") or {}).get("hours", 24)
            send({"jsonrpc": "2.0", "id": rid, "result": {"content": [
                {"type": "text", "text": build_report(int(hours))}]}})
        elif rid is not None:
            send({"jsonrpc": "2.0", "id": rid,
                  "error": {"code": -32601, "message": "method not found"}})


# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(prog="triage",
                                 description="Read-only server incident report for AI agents.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect", help="Generate a triage report")
    c.add_argument("--hours", type=int, default=24,
                   help="Error window in hours (default 24)")
    c.add_argument("--out", default=None,
                   help="Write report to this file instead of stdout")
    sub.add_parser("mcp", help="Run the stdio MCP server")
    args = ap.parse_args(argv)

    if args.cmd == "mcp":
        mcp_server()
        return 0
    report = build_report(args.hours)
    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
        print(f"wrote {args.out} ({len(report.splitlines())} lines)")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
