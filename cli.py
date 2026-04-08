import sys
import json
import os
import urllib.request
import urllib.parse
import urllib.error

BASE_URL = os.environ.get("CYBERTOOLS_URL", "http://localhost:8000").rstrip("/")


# ---------- Helpers ----------

def _get(path: str) -> dict:
    url = BASE_URL + path
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberTools-CLI/1.0"})
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        return {"error": body.get("detail", str(e))}
    except Exception as e:
        return {"error": str(e)}


def _print(data: dict):
    """Pretty print with color-coded smart_summary if present."""
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"

    # Print smart_summary first if present
    if "smart_summary" in data and data["smart_summary"]:
        print(f"\n{BOLD}── Smart Summary ──{RESET}")
        for line in data["smart_summary"]:
            print(f"  {CYAN}→{RESET} {line}")
        print()

    # Print rest of data
    for k, v in data.items():
        if k == "smart_summary":
            continue
        if k == "error":
            print(f"  {RED}✗ {k}:{RESET} {v}")
        elif isinstance(v, list):
            print(f"  {YELLOW}{k}:{RESET}")
            for item in v:
                if isinstance(item, dict):
                    print(f"    {DIM}{json.dumps(item)}{RESET}")
                else:
                    print(f"    {DIM}- {item}{RESET}")
        elif isinstance(v, dict):
            print(f"  {YELLOW}{k}:{RESET}")
            for dk, dv in v.items():
                print(f"    {DIM}{dk}: {dv}{RESET}")
        else:
            print(f"  {GREEN}{k}:{RESET} {v}")
    print()


def _header(title: str):
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    print(f"\n{BOLD}{CYAN}⚡ CyberTools — {title}{RESET}")
    print("─" * 50)


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_recon(domain: str):
    _header(f"Recon: {domain}")
    print("  Resolving IP, probing headers...")
    data = _get(f"/recon?domain={urllib.parse.quote(domain)}")
    _print(data)


def cmd_scan(url: str):
    _header(f"BB Scan: {url}")
    print("  Probing common paths (this may take ~15s)...")
    data = _get(f"/bb-scan?url={urllib.parse.quote(url)}")
    _print(data)


def cmd_analyze(url: str):
    _header(f"URL Analysis: {url}")
    print("  Following redirects and inspecting headers...")
    data = _get(f"/analyze-url?url={urllib.parse.quote(url)}")
    _print(data)


def cmd_payloads(ptype: str):
    _header(f"Payloads: {ptype.upper()}")
    data = _get(f"/payloads?type={urllib.parse.quote(ptype)}")
    _print(data)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    YELLOW = "\033[93m"
    RESET  = "\033[0m"

    if len(sys.argv) < 3:
        print(f"""
{YELLOW}CyberTools CLI{RESET}

Usage:
  python cli.py recon    <domain>         Recon a domain
  python cli.py scan     <url>            Bug bounty path scan
  python cli.py analyze  <url>            Analyze URL headers/redirects
  python cli.py payloads <xss|sqli|lfi|ssrf>  Get payloads

Environment:
  CYBERTOOLS_URL   API base URL (default: http://localhost:8000)

Examples:
  python cli.py recon example.com
  python cli.py scan https://example.com
  python cli.py payloads xss
        """)
        sys.exit(1)

    command = sys.argv[1].lower()
    arg     = sys.argv[2]

    if command == "recon":
        cmd_recon(arg)
    elif command == "scan":
        cmd_scan(arg)
    elif command == "analyze":
        cmd_analyze(arg)
    elif command == "payloads":
        cmd_payloads(arg)
    else:
        print(f"Unknown command: {command}. Use: recon | scan | analyze | payloads")
        sys.exit(1)


if __name__ == "__main__":
    main()