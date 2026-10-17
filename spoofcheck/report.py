"""Terminal and HTML output for a Report."""

from __future__ import annotations

import html

from .analyzer import Report

COLORS = {"HIGH": "31", "MEDIUM": "33", "LOW": "32",
          "high": "31", "medium": "33", "low": "36", "info": "90",
          "pass": "32", "fail": "31", "softfail": "33", "none": "90", "neutral": "90",
          "permerror": "31", "temperror": "33"}


def _c(text: str, key: str, color: bool) -> str:
    return f"\033[{COLORS.get(key, '0')}m{text}\033[0m" if color else text


def _dkim_summary(r: Report) -> str:
    return ", ".join(f"{d.result} ({d.domain or '-'})" for d in r.dkim)


def to_terminal(r: Report, color: bool = True) -> str:
    e = r.email
    bold = (lambda s: f"\033[1m{s}\033[0m") if color else (lambda s: s)
    lines = [
        bold(f"=== {r.source} ==="),
        f"Verdict: {_c(r.verdict + ' RISK', r.verdict, color)}   (score {r.score})"
        + ("   [offline: auth taken from headers]" if r.offline else ""),
        "",
        bold("Message"),
        f"  Subject      {e.subject}",
        f"  From         {e.from_name + ' ' if e.from_name else ''}<{e.from_addr}>",
        f"  Return-Path  {e.return_path or '-'}",
        f"  Reply-To     {', '.join(e.reply_to) or '-'}",
        f"  Sending IP   {e.sending_ip or '-'}  ({e.sending_ip_source})",
        "",
        bold(f"Route ({len(e.hops)} hops, oldest first)"),
    ]
    for i, h in enumerate(e.hops, 1):
        delay = f"+{h.delay_seconds:.0f}s" if h.delay_seconds is not None else ""
        when = h.timestamp.strftime("%Y-%m-%d %H:%M:%S %z") if h.timestamp else "no timestamp"
        lines.append(f"  {i}. {h.from_host or '?'} [{h.from_ip or '-'}] -> {h.by_host or '?'}  {when} {delay}")

    lines += ["", bold("Authentication")]
    lines.append(f"  SPF    {_c(r.spf.result.ljust(10), r.spf.result, color)} domain={r.spf.domain or '-'}  {r.spf.explanation}")
    for d in r.dkim:
        lines.append(f"  DKIM   {_c(d.result.ljust(10), d.result, color)} d={d.domain or '-'} s={d.selector or '-'}  {d.reason}")
    lines.append(f"  DMARC  {_c(r.dmarc.result.ljust(10), r.dmarc.result, color)} {r.dmarc.explanation}")
    if e.receiver_auth:
        recv = ", ".join(f"{k}={v}" for k, v in e.receiver_auth.items() if k in ("spf", "dkim", "dmarc"))
        lines.append(f"  Receiver ({e.receiver_auth.get('server', '?')}) recorded: {recv}")

    lines += ["", bold(f"Findings ({len(r.findings)})")]
    if not r.findings:
        lines.append("  None. Nothing suspicious detected.")
    for f in r.findings:
        lines.append(f"  [{_c(f.severity.upper(), f.severity, color)}] {f.title}")
        lines.append(f"      {f.detail}")
    return "\n".join(lines)


CSS = """
:root{--bg:#f7f8fa;--card:#fff;--text:#1d2330;--muted:#667085;--line:#e4e7ec;
--high:#c0392b;--medium:#b7791f;--low:#2b7a78;--info:#667085;--pass:#2f855a;--fail:#c0392b}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1e24;--text:#e6e8eb;--muted:#9aa4b2;--line:#2a3039}}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:900px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:28px 0 8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;overflow-x:auto}
.verdict{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:700;color:#fff}
.HIGH{background:var(--high)}.MEDIUM{background:var(--medium)}.LOW{background:var(--pass)}
table{border-collapse:collapse;width:100%}td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:13px}
.tag{font-weight:700;font-size:12px;text-transform:uppercase}
.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}
.pass{color:var(--pass)}.fail,.permerror{color:var(--fail)}.softfail,.temperror{color:var(--medium)}.none,.neutral{color:var(--muted)}
code{font-size:13px}
"""


def to_html(r: Report) -> str:
    e = r.email
    esc = html.escape
    hop_rows = "".join(
        f"<tr><td>{i}</td><td>{esc(h.from_host or '?')}</td><td><code>{esc(h.from_ip or '-')}</code></td>"
        f"<td>{esc(h.by_host or '?')}</td><td>{esc(h.timestamp.strftime('%Y-%m-%d %H:%M:%S %z') if h.timestamp else '-')}</td>"
        f"<td>{'+%ds' % h.delay_seconds if h.delay_seconds is not None else ''}</td></tr>"
        for i, h in enumerate(e.hops, 1))
    auth_rows = [f"<tr><td>SPF</td><td class='{r.spf.result}'><b>{r.spf.result}</b></td><td>{esc(r.spf.domain or '-')}</td>"
                 f"<td>{esc(r.spf.explanation)}</td></tr>"]
    auth_rows += [f"<tr><td>DKIM</td><td class='{d.result}'><b>{d.result}</b></td><td>{esc(d.domain or '-')}</td>"
                  f"<td>{esc(d.reason)}</td></tr>" for d in r.dkim]
    auth_rows.append(f"<tr><td>DMARC</td><td class='{r.dmarc.result}'><b>{r.dmarc.result}</b></td>"
                     f"<td>{esc(r.dmarc.domain or '-')}</td><td>{esc(r.dmarc.explanation)}</td></tr>")
    findings = "".join(
        f"<tr><td class='tag {f.severity}'>{f.severity}</td><td><b>{esc(f.title)}</b><br>{esc(f.detail)}</td></tr>"
        for f in r.findings) or "<tr><td colspan=2>Nothing suspicious detected.</td></tr>"
    fields = [("Subject", e.subject), ("From", f"{e.from_name} <{e.from_addr}>"), ("Return-Path", e.return_path or "-"),
              ("Reply-To", ", ".join(e.reply_to) or "-"), ("Sending IP", f"{e.sending_ip or '-'} ({e.sending_ip_source})")]
    msg_rows = "".join(f"<tr><th>{k}</th><td>{esc(v)}</td></tr>" for k, v in fields)

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Spoofing report</title><style>{CSS}</style></head>
<body><main>
<h1>Email spoofing report</h1><p style="color:var(--muted);margin:0 0 12px">{esc(r.source)}</p>
<span class="verdict {r.verdict}">{r.verdict} RISK</span> <span style="color:var(--muted)">score {r.score}</span>
<h2>Findings</h2><div class="card"><table>{findings}</table></div>
<h2>Message</h2><div class="card"><table>{msg_rows}</table></div>
<h2>Authentication</h2><div class="card"><table><tr><th>Check</th><th>Result</th><th>Domain</th><th>Detail</th></tr>{''.join(auth_rows)}</table></div>
<h2>Route (oldest first)</h2><div class="card"><table><tr><th>#</th><th>From</th><th>IP</th><th>By</th><th>Time</th><th>Delay</th></tr>{hop_rows}</table></div>
</main></body></html>"""
