#!/usr/bin/env python3
"""
cli.py — CyberTools API CLI

Usage:
  python cli.py recon    <domain>
  python cli.py scan     <url>
  python cli.py analyze  <url>
  python cli.py payloads <xss|sqli|lfi|ssrf>
  python cli.py workflow <domain|url>
  python cli.py last
  python cli.py ask      "<question>"

Env:
  CYBERTOOLS_URL  — API base URL (default: http://localhost:8000)
"""

import sys, json, os, urllib.request, urllib.parse, urllib.error

BASE_URL = os.environ.get("CYBERTOOLS_URL", "http://localhost:8000").rstrip("/")

# ── ANSI colors ────────────────────────────────────────────────────────────────
R  = "\033[0m"
B  = "\033[1m"
DIM= "\033[2m"
C  = "\033[96m"    # cyan
G  = "\033[92m"    # green
Y  = "\033[93m"    # yellow
RE = "\033[91m"    # red
LM = "\033[38;5;118m"  # lime

def _c(text, color): return f"{color}{text}{R}"

# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _get(path):
    try:
        req = urllib.request.Request(BASE_URL + path, headers={"User-Agent": "CyberTools-CLI/2.0"})
        with urllib.request.urlopen(req, timeout=60) as res:
            return json.loads(res.read())
    except urllib.error.HTTPError as e:
        try: return {"error": json.loads(e.read()).get("detail", str(e))}
        except: return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

def _post(path, body):
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(BASE_URL + path, data=data,
              headers={"User-Agent": "CyberTools-CLI/2.0", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as res:
            return json.loads(res.read())
    except urllib.error.HTTPError as e:
        try: return {"error": json.loads(e.read()).get("detail", str(e))}
        except: return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

# ── Display helpers ────────────────────────────────────────────────────────────

def _bar(label=""):
    w = 55
    line = "─" * w
    if label:
        pad = (w - len(label) - 2) // 2
        print(f"\n{_c('┌' + '─'*pad + f' {label} ' + '─'*pad + '┐', C)}")
    else:
        print(_c(line, DIM))

def _header(title):
    print(f"\n{_c('⚡', Y)} {_c('CyberTools', B)} {_c('›', DIM)} {_c(title, LM)}")
    _bar()

def _section(label):
    print(f"\n  {_c('▸ ' + label, Y)}")

def _row(k, v, color=G):
    print(f"  {_c(k + ':', DIM)} {_c(str(v), color)}")

def _bullet(text, color=C):
    print(f"  {_c('→', color)} {text}")

def _error(msg):
    print(f"\n  {_c('✗', RE)} {msg}\n")

def _print_summary(data):
    if data.get("smart_summary"):
        _section("Smart Summary")
        for line in data["smart_summary"]:
            _bullet(line)

def _print_next_steps(data):
    if data.get("next_steps"):
        _section("Next Steps")
        for i, step in enumerate(data["next_steps"], 1):
            print(f"  {_c(str(i) + '.', LM)} {step}")

def _print_error(data):
    if "error" in data:
        _error(data["error"])
        return True
    return False

# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_recon(domain):
    _header(f"Recon › {domain}")
    print(f"  {_c('Resolving IP and probing headers...', DIM)}")
    d = _get(f"/recon?domain={urllib.parse.quote(domain)}")
    if _print_error(d): return

    _section("Host Info")
    _row("domain",      d.get("domain"))
    _row("ip",          d.get("ip"))
    _row("protocol",    d.get("protocol", "").upper())
    _row("status",      d.get("status_code"))

    ssl = d.get("ssl", {})
    if ssl:
        _section("SSL")
        _row("valid",    ssl.get("valid"))
        _row("expires",  ssl.get("expires"))
        _row("days",     ssl.get("days_remaining"))
        _row("issuer",   ssl.get("issuer"))
        if ssl.get("warning"):
            _bullet(ssl["warning"], RE)

    if d.get("missing_security_headers"):
        _section("Missing Security Headers")
        for h in d["missing_security_headers"]:
            _bullet(h, RE)

    if d.get("tech_hints"):
        _section("Tech Stack")
        for t in d["tech_hints"]:
            _bullet(t, Y)

    _print_summary(d)
    _print_next_steps(d)
    print()

def cmd_analyze(url):
    _header(f"URL Analysis › {url}")
    print(f"  {_c('Following redirects...', DIM)}")
    d = _get(f"/analyze-url?url={urllib.parse.quote(url)}")
    if _print_error(d): return

    _section("Redirect Chain")
    for hop in d.get("redirect_chain", []):
        _row(hop["url"], hop["status"])
    _row("final url",    d.get("final_url"))
    _row("final status", d.get("final_status"))

    if d.get("misconfig_hints"):
        _section("Misconfigurations")
        for h in d["misconfig_hints"]:
            _bullet(h, RE)

    _print_summary(d)
    _print_next_steps(d)
    print()

def cmd_scan(url):
    _header(f"BB Scan › {url}")
    print(f"  {_c('Probing paths concurrently (3-5s)...', DIM)}")
    d = _get(f"/bb-scan?url={urllib.parse.quote(url)}")
    if _print_error(d): return

    found = d.get("interesting_paths", [])
    _section(f"Interesting Paths ({len(found)} found)")
    if found:
        for p in found:
            color = G if p["status"] == 200 else Y if str(p["status"]).startswith("3") else RE
            _row(p["path"], p["status"], color)
    else:
        _bullet("No interesting paths found.", DIM)

    _section("Bug Bounty Hints")
    for hint in d.get("bug_bounty_hints", [])[:6]:
        _bullet(hint, C)

    _print_summary(d)
    _print_next_steps(d)
    print()

def cmd_payloads(ptype):
    _header(f"Payloads › {ptype.upper()}")
    d = _get(f"/payloads?type={urllib.parse.quote(ptype)}")
    if _print_error(d): return

    _section(f"{d.get('description', '')}")
    for item in d.get("payloads", []):
        if isinstance(item, dict):
            label = _c(f"[{item.get('label', '')}]", DIM)
            print(f"  {_c(item['payload'], LM)}  {label}")
        else:
            print(f"  {_c(item, LM)}")

    _section("Usage Tips")
    for tip in d.get("usage_tips", []):
        _bullet(tip, Y)
    print()

def cmd_workflow(target):
    _header(f"Workflow › {target}")
    print(f"  {_c('Running recon + analyze + bb-scan concurrently...', DIM)}")
    d = _get(f"/workflow?target={urllib.parse.quote(target)}")
    if _print_error(d): return

    _row("elapsed", f"{d.get('elapsed_seconds')}s")

    recon = d.get("recon", {})
    if recon.get("ip"):
        _section("Recon")
        _row("ip",       recon.get("ip"))
        _row("status",   recon.get("status_code"))
        _row("protocol", recon.get("protocol", "").upper())

    found = d.get("bb_scan", {}).get("interesting_paths", [])
    _section(f"Interesting Paths ({len(found)})")
    for p in found[:8]:
        color = G if p["status"] == 200 else Y if str(p["status"]).startswith("3") else RE
        _row(p["path"], p["status"], color)

    _section("Combined Summary")
    for line in d.get("smart_summary", []):
        _bullet(line)

    _print_next_steps(d)
    print()

def cmd_last():
    _header("Last Scan")
    d = _get("/last-scan")
    if _print_error(d): return
    _row("target",    d.get("key"))
    _row("timestamp", d.get("timestamp"))
    _section("Summary")
    data = d.get("data", {})
    for line in data.get("smart_summary", [])[:8]:
        _bullet(line)
    print()

def cmd_ask(question):
    _header(f"Ask › {question}")
    d = _post("/chat-assist", {"question": question})
    if _print_error(d): return
    _section("Response")
    for line in d.get("response", []):
        _bullet(line, LM)
    if d.get("tip"):
        print(f"\n  {_c('tip:', DIM)} {d['tip']}")
    print()

# ── Entry ──────────────────────────────────────────────────────────────────────

USAGE = f"""
{_c('⚡ CyberTools CLI', B)}  {_c('v2.0', DIM)}

{_c('Usage:', Y)}
  python cli.py recon    <domain>              Domain recon (IP, SSL, headers)
  python cli.py analyze  <url>                 URL header/redirect analysis
  python cli.py scan     <url>                 Bug bounty path scan
  python cli.py payloads <xss|sqli|lfi|ssrf>  Get attack payloads
  python cli.py workflow <domain|url>          Full pipeline (recon+analyze+scan)
  python cli.py last                           Show last scan result
  python cli.py ask      "<question>"          Ask assistant about last scan

{_c('Env:', Y)}
  CYBERTOOLS_URL   API base URL  (default: http://localhost:8000)

{_c('Examples:', Y)}
  python cli.py recon example.com
  python cli.py workflow https://example.com
  python cli.py payloads sqli
  python cli.py ask "What should I test first?"
"""

def main():
    if len(sys.argv) < 2:
        print(USAGE); sys.exit(0)

    cmd = sys.argv[1].lower()
    arg = sys.argv[2] if len(sys.argv) > 2 else ""

    if   cmd == "recon":    cmd_recon(arg)
    elif cmd == "analyze":  cmd_analyze(arg)
    elif cmd == "scan":     cmd_scan(arg)
    elif cmd == "payloads": cmd_payloads(arg)
    elif cmd == "workflow": cmd_workflow(arg)
    elif cmd == "last":     cmd_last()
    elif cmd == "ask":      cmd_ask(arg)
    else:
        print(f"\n  {_c('Unknown command:', RE)} {cmd}")
        print(USAGE)
        sys.exit(1)

if __name__ == "__main__":
    main()