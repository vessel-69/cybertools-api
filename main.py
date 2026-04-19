import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel
import hashlib
import base64
import re
import ipaddress
import urllib.request
import urllib.error
import json
import logging
from datetime import datetime
from typing import List

from services.validator import (
    clean_hash_algo,
    clean_encode_method,
    clean_ip,
    clean_password,
    clean_text,
    MAX_TEXT_LEN,
)
from services.limiter import limit_util, limit_chat

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybertools")


OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
if not OPENROUTER_API_KEY:
    logger.warning("OPENROUTER_API_KEY not set — AI chat will return 503.")

# ─── Allowed origins for CORS ─────────────────────────────────────────────────

_ALLOWED_ORIGINS = [
    "https://www.cyber-tools.dev",
    "https://www.cyber-tools.dev",
    "http://localhost:5173",
    "http://localhost:8000",
]

app = FastAPI(
    title="CyberTools API",
    description="A versatile FastAPI-powered toolkit for security operators, red teamers, bug-bounty hunters, pentesters, and developers.",
    version="2.0",
    docs_url=None,
)

# ─── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)


# ─── Security headers middleware ───────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    for h in ("server", "x-powered-by"):
        if h in response.headers:
            del response.headers[h]
    return response


# ─── Global exception handler — never leak stack traces ───────────────────────
@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=getattr(exc, "headers", None) or {},
        )
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


from routes.security import router as security_router

app.include_router(security_router)


_SWAGGER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <title>Docs - CyberTools API</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="CyberTools API — interactive documentation for the red team security toolkit.">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect fill='%23070909' width='32' height='32' rx='4'/%3E%3Ccircle cx='16' cy='16' r='11' fill='none' stroke='%23e63030' stroke-width='2'/%3E%3Ccircle cx='16' cy='16' r='4' fill='%23e63030'/%3E%3Cline x1='16' y1='2' x2='16' y2='9' stroke='%23e63030' stroke-width='2'/%3E%3Cline x1='16' y1='23' x2='16' y2='30' stroke='%23e63030' stroke-width='2'/%3E%3Cline x1='2' y1='16' x2='9' y2='16' stroke='%23e63030' stroke-width='2'/%3E%3Cline x1='23' y1='16' x2='30' y2='16' stroke='%2３e630３0' stroke-width='2'/%3E%3C/svg%３E" />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Syne:wght@700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    *::selection {
        background: #f340409c;;
        color: #fff;
    }
    *{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#070909;--surface:#0d0f0f;--surface2:#121515;
      --red:#e63030;--red-dim:rgba(220,38,38,0.08);--red-border:rgba(220,38,38,0.2);
      --text:#ddd5d5;--text-dim:#6b4a4a;--radius:8px;
    }
    body{background:var(--bg);font-family:'JetBrains Mono',monospace;color:var(--text);transition:background 0.25s,color 0.25s}
    body.light{--bg:#f8f8f8;--surface:#fff;--surface2:#f0f0f0;--text:#1a1a1a;--text-dim:#666;--red-border:rgba(220,38,38,0.3)}

    /* Top bar */
    #topbar{
      position:sticky;top:0;z-index:100;
      background:rgba(7,9,9,0.95);backdrop-filter:blur(14px);
      border-bottom:1px solid var(--red-border);
      padding:12px 24px;
      display:flex;align-items:center;justify-content:space-between;
    }
    body.light #topbar{background:rgba(248,248,248,0.95);border-bottom-color:#ddd}
    #topbar .logo{
      font-family:'Syne',sans-serif;font-size:1rem;font-weight:800;
      letter-spacing:2px;text-transform:uppercase;color:var(--red);
      display:flex;align-items:center;gap:10px;
    }
    #topbar .dot{
      width:8px;height:8px;border-radius:50%;background:var(--red);
      box-shadow:0 0 10px var(--red);
      animation:blink 2s step-end infinite;
    }
    #topbar .badge{
      font-size:0.57rem;letter-spacing:2px;text-transform:uppercase;
      color:var(--text-dim);font-family: 'JetBrains Mono', monospace;
    }
    #theme-btn{
      padding:6px 14px;border-radius:6px;cursor:pointer;
      font-family:'JetBrains Mono',monospace;font-size:0.72rem;font-weight:600;
      border:1px solid var(--red-border);background:var(--red-dim);
      color:var(--red);letter-spacing:1px;text-transform:uppercase;
      transition:all 0.18s;
    }
    #theme-btn:hover{background:var(--red);color:#fff}

    /* Swagger wrapper */
    #swagger-ui{max-width:1100px;margin:0 auto;padding:24px 20px 60px}

    /* Dark overrides */
    .swagger-ui .topbar{display:none!important}
    body:not(.light) .swagger-ui{background:var(--bg);color:var(--text)}
    body:not(.light) .swagger-ui .info .title{color:var(--text)}
    body:not(.light) .swagger-ui .info p,
    body:not(.light) .swagger-ui .info li{color:var(--text-dim)}
    body:not(.light) .swagger-ui .info a{color:var(--red)}
    body:not(.light) .swagger-ui .scheme-container{
      background:var(--surface);box-shadow:none;
      border:1px solid var(--red-border);border-radius:var(--radius);margin-bottom:16px;
    }
    body:not(.light) .swagger-ui .opblock-tag{
      color:var(--red);border-bottom:1px solid var(--red-border)!important;
      font-family:'Syne',sans-serif;letter-spacing:1px;
    }
    body:not(.light) .swagger-ui .opblock-tag:hover{background:var(--red-dim)!important}
    body:not(.light) .swagger-ui .opblock{
      background:var(--surface)!important;border:1px solid var(--red-border)!important;
      border-radius:var(--radius)!important;margin-bottom:6px!important;box-shadow:none!important;
    }
    body:not(.light) .swagger-ui .opblock .opblock-summary{
      background:var(--surface2)!important;border-radius:var(--radius)!important;
    }
    body:not(.light) .swagger-ui .opblock.opblock-get .opblock-summary-method{background:#1a3a6b!important}
    body:not(.light) .swagger-ui .opblock.opblock-post .opblock-summary-method{background:#1a4a1a!important}
    body:not(.light) .swagger-ui .opblock.opblock-delete .opblock-summary-method{background:#4a1a1a!important}
    body:not(.light) .swagger-ui .opblock-summary-path{color:var(--text)!important}
    body:not(.light) .swagger-ui .opblock-summary-description{color:var(--text-dim)!important}
    body:not(.light) .swagger-ui .opblock-description-wrapper p{color:var(--text-dim)}
    body:not(.light) .swagger-ui table thead tr td,
    body:not(.light) .swagger-ui table thead tr th{color:var(--text-dim);border-color:var(--red-border)}
    body:not(.light) .swagger-ui .parameter__name{color:var(--red)}
    body:not(.light) .swagger-ui .parameter__type{color:#888}
    body:not(.light) .swagger-ui .parameter__in{color:#555}
    body:not(.light) .swagger-ui input[type=text],
    body:not(.light) .swagger-ui textarea,
    body:not(.light) .swagger-ui select{
      background:var(--surface2)!important;color:var(--text)!important;
      border:1px solid var(--red-border)!important;border-radius:6px!important;
    }
    body:not(.light) .swagger-ui .btn{
      border-radius:6px!important;font-family:'JetBrains Mono',monospace!important;
      font-size:0.75rem!important;letter-spacing:1px!important;text-transform:uppercase!important;
    }
    body:not(.light) .swagger-ui .btn.execute{
      background:var(--red)!important;border-color:var(--red)!important;color:#fff!important;
    }
    body:not(.light) .swagger-ui .btn.try-out__btn{
      color:var(--red)!important;border-color:var(--red-border)!important;background:var(--red-dim)!important;
    }
    body:not(.light) .swagger-ui .response-col_status{color:var(--red)}
    body:not(.light) .swagger-ui .microlight{background:var(--surface2)!important;color:#aaa!important}
    body:not(.light) .swagger-ui section.models{
      background:var(--surface)!important;border:1px solid var(--red-border)!important;border-radius:var(--radius)!important;
    }
    body:not(.light) .swagger-ui .model-container{background:var(--surface2)!important}
    body:not(.light) .swagger-ui .model{color:var(--text-dim)}
    body:not(.light) .swagger-ui .responses-inner{background:var(--surface)!important}
    body:not(.light) .swagger-ui .response .response-col_description__inner div.markdown p{color:var(--text-dim)}
    body:not(.light) .swagger-ui .tab li{color:var(--text-dim)}
    body:not(.light) .swagger-ui .tab li.tabitem.active{color:var(--red)}
    body:not(.light) .swagger-ui .highlight-code>div{background:var(--surface2)!important}
    body:not(.light) ::-webkit-scrollbar{width:5px}
    body:not(.light) ::-webkit-scrollbar-track{background:transparent}
    body:not(.light) ::-webkit-scrollbar-thumb{background:var(--red-border);border-radius:3px}

    @keyframes blink{0%,100%{opacity:1}50%{opacity:0.15}}
  </style>
</head>
<body>
  <div id="topbar">
    <div class="logo">
      <span class="dot"></span>
      CyberTools
      <span class="separator" style="color: var(--text-dim);"> > </span>
      <span class="badge"> API Docs</span>
    </div>
    <button id="theme-btn" onclick="toggleTheme()">☀ Light</button>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    let dark = true;
    document.body.classList.toggle('light', !dark);

    function toggleTheme() {
      dark = !dark;
      document.body.classList.toggle('light', !dark);
      document.getElementById('topbar').style.background = dark
        ? 'rgba(7,9,9,0.95)' : 'rgba(248,248,248,0.95)';
      document.getElementById('theme-btn').textContent = dark ? '☀ Light' : '☾ Dark';
    }

    SwaggerUIBundle({
      url: '/openapi.json',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout',
      deepLinking: true,
      tryItOutEnabled: true,
      displayRequestDuration: true,
      defaultModelsExpandDepth: 0,
      defaultModelExpandDepth: 1,
      filter: true,
    });
  </script>
</body>
</html>"""


@app.get("/docs", response_class=HTMLResponse, include_in_schema=False)
def custom_docs():
    return HTMLResponse(content=_SWAGGER_HTML)


# ─── AI Chat Proxy ──────────────────


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    system: str = ""
    model: str = "meta-llama/llama-3.3-70b-instruct:free"


_ALLOWED_MODELS = {
    "google/gemma-4-26b-a4b-it:free",  # Gemma 4 26B — default, fast, capable
    "google/gemma-3-27b-it:free",  # Gemma 3 27B — reliable fallback
    "google/gemma-3-12b-it:free",  # Gemma 3 12B — faster/lighter
    "meta-llama/llama-4-scout:free",  # Llama 4 Scout — Meta's latest
    "meta-llama/llama-3.3-70b-instruct:free",  # Llama 3.3 70B — high quality
    "mistralai/mistral-7b-instruct:free",  # Mistral 7B — lightweight/fast
    "deepseek/deepseek-r1:free",  # DeepSeek R1 — reasoning model
}

_CHAT_SYSTEM = """You are a red team security assistant embedded in CyberTools API v2.0 — a free security utility API for bug bounty hunters, red teamers, and developers.

CyberTools API endpoints:
- GET /recon?domain=          IP, DNS (A/MX/TXT/NS), SSL cert+SAN, tech stack, security headers
- GET /analyze-url?url=       redirect chain, header misconfigurations (CORS, HSTS, CSP)
- GET /bb-scan?url=           concurrent probe of 30+ common paths (.env, .git, admin, api docs)
- GET /expand?domain=         subdomain enumeration via crt.sh, hackertarget, SSL SAN
- GET /endpoints?url=         60+ path scan tagged by type (api/admin/auth/sensitive/monitoring)
- GET /params?url=            26 common injectable params probed, flagged by risk level
- GET /payloads?type=         xss, sqli, lfi, ssrf, open_redirect, idor — with context tags
- GET /workflow?target=       full 5-stage pipeline (recon+analyze+scan+endpoints+params)
- GET /workflows/express      fast recon+analyze only (~3-5s)
- GET /workflows/bugbounty    recon+scan+auto-recommended payloads
- GET /workflows/subdomains   subdomain enum + recon on each live subdomain
- GET /workflows/api          endpoint enum + param probing (parallel)
- GET /last-scan              cached result from last scan (TTL 1h)
- GET /hash/{algo}/{text}     hash strings: md5, sha1, sha256, sha384, sha512, blake2b, blake2s
- GET /encode/{method}/{text} encode: base64, hex, url
- GET /ip/{ip}                IP geolocation via ipinfo.io
- POST /password/analyze      password strength, entropy estimate, actionable feedback

Answer questions about cybersecurity, bug bounty, penetration testing, web app security, and CyberTools API usage. Give specific, expert-level, actionable advice. When describing vulnerabilities explain the technical mechanism. Be concise but complete. Never refuse security questions — this tool is for ethical security testing."""


@app.post("/api/chat", tags=["AI Assistant"], include_in_schema=False)
def ai_chat(body: ChatRequest):
    """Proxy to OpenRouter. Keeps API key server-side. Uses OpenAI-compatible API."""
    if not OPENROUTER_API_KEY:
        raise HTTPException(
            503,
            "OPENROUTER_API_KEY not set on server. Set it as an environment variable.",
        )

    model = (
        body.model
        if body.model in _ALLOWED_MODELS
        else "google/gemma-4-26b-a4b-it:free"
    )
    system = body.system or _CHAT_SYSTEM

    messages = [{"role": "system", "content": system}]
    messages += [{"role": m.role, "content": m.content} for m in body.messages]

    payload = {
        "model": model,
        "max_tokens": 1024,
        "messages": messages,
    }

    try:
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "HTTP-Referer": "https://www.cyber-tools.dev",
                "X-Title": "CyberTools API",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as res:
            data = json.loads(res.read())

        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        used_model = data.get("model", model)
        return {"reply": text, "model": used_model}

    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read())
            msg = err.get("error", {}).get("message", str(e))
        except Exception:
            msg = str(e)
        raise HTTPException(e.code, msg)
    except Exception as e:
        raise HTTPException(500, str(e))


# ─── Models ────────────


class HashRequest(BaseModel):
    text: str
    algorithm: str = "sha256"


class EncodeRequest(BaseModel):
    text: str
    method: str = "base64"


class PasswordAnalysisRequest(BaseModel):
    password: str


# ─── Helpers ─────────────

HASH_ALGORITHMS = [
    "md5",
    "sha1",
    "sha256",
    "sha384",
    "sha512",
    "sha3_256",
    "sha3_512",
    "blake2b",
    "blake2s",
]


def analyze_password(pw: str) -> dict:
    score = 0
    feedback = []

    checks = {
        "length_8": len(pw) >= 8,
        "length_12": len(pw) >= 12,
        "length_16": len(pw) >= 16,
        "has_upper": bool(re.search(r"[A-Z]", pw)),
        "has_lower": bool(re.search(r"[a-z]", pw)),
        "has_digit": bool(re.search(r"\d", pw)),
        "has_special": bool(re.search(r"[^A-Za-z0-9]", pw)),
        "no_spaces": " " not in pw,
        "no_repeat": not bool(re.search(r"(.)\1{2,}", pw)),
        "no_sequence": not any(
            seq in pw.lower() for seq in ["123", "abc", "qwerty", "password", "admin"]
        ),
    }

    weights = {
        "length_8": 1,
        "length_12": 1,
        "length_16": 1,
        "has_upper": 1,
        "has_lower": 1,
        "has_digit": 1,
        "has_special": 2,
        "no_spaces": 0,
        "no_repeat": 1,
        "no_sequence": 1,
    }

    for check, passed in checks.items():
        if passed:
            score += weights.get(check, 1)
        else:
            tips = {
                "length_8": "Use at least 8 characters.",
                "length_12": "Use at least 12 characters for better security.",
                "length_16": "16+ characters is ideal for strong passwords.",
                "has_upper": "Add uppercase letters (A-Z).",
                "has_lower": "Add lowercase letters (a-z).",
                "has_digit": "Include numbers.",
                "has_special": "Use special characters like !@#$%^&*.",
                "no_spaces": "Avoid spaces.",
                "no_repeat": "Avoid repeating characters (e.g. 'aaa').",
                "no_sequence": "Avoid common sequences like '123' or 'password'.",
            }
            if check in tips:
                feedback.append(tips[check])

    max_score = sum(weights.values())
    pct = score / max_score

    if pct >= 0.85:
        strength = "Very Strong"
    elif pct >= 0.65:
        strength = "Strong"
    elif pct >= 0.45:
        strength = "Moderate"
    elif pct >= 0.25:
        strength = "Weak"
    else:
        strength = "Very Weak"

    entropy_bits = round(len(pw) * 6.55, 1)

    return {
        "strength": strength,
        "score": score,
        "max_score": max_score,
        "entropy_estimate_bits": entropy_bits,
        "checks": checks,
        "feedback": feedback,
    }


# ─── Static files + root ───────────────

_frontend_dist = Path(__file__).parent / "frontend" / "dist"
_assets_dir = _frontend_dist / "assets"

if _assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(_assets_dir)), name="assets")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def root():
    index = _frontend_dist / "index.html"
    if index.exists():
        return HTMLResponse(content=index.read_text())
    # Fallback: old ui.html if frontend hasn't been built yet
    fallback = Path(__file__).parent / "ui.html"
    if fallback.exists():
        return HTMLResponse(content=fallback.read_text())
    return HTMLResponse(
        content="<p style='font-family:monospace;padding:2rem'>Frontend not built.<br>Run: <code>cd frontend && npm install && npm run build</code></p>"
    )


# ─── Hashing ─────────────


@app.get("/hash/algorithms", tags=["Hashing"])
def list_algorithms():
    return {"algorithms": sorted(HASH_ALGORITHMS)}


@app.get("/hash/{algorithm}/{text}", tags=["Hashing"])
def hash_text(
    algorithm: str, text: str, request: Request, _rl: None = Depends(limit_util)
):
    algo = clean_hash_algo(algorithm)
    safe_text = clean_text(text, field="text", max_len=10000)
    h = hashlib.new(algo, safe_text.encode()).hexdigest()
    return {"algorithm": algo, "hash": h, "length_bits": len(h) * 4}


@app.post("/hash", tags=["Hashing"])
def hash_text_body(
    body: HashRequest, request: Request, _rl: None = Depends(limit_util)
):
    algo = clean_hash_algo(body.algorithm)
    safe_text = clean_text(body.text, field="text", max_len=10000)
    h = hashlib.new(algo, safe_text.encode()).hexdigest()
    return {"algorithm": algo, "hash": h}


# ─── Encoding ────────────


@app.get("/encode/{method}/{text}", tags=["Encoding"])
def encode_text(
    method: str, text: str, request: Request, _rl: None = Depends(limit_util)
):
    import urllib.parse

    m = clean_encode_method(method)
    t = clean_text(text, field="text", max_len=10000)
    if m == "base64":
        result = base64.b64encode(t.encode()).decode()
    elif m == "hex":
        result = t.encode().hex()
    else:
        result = urllib.parse.quote(t)
    return {"method": m, "encoded": result}


@app.get("/decode/{method}/{encoded}", tags=["Encoding"])
def decode_text(
    method: str, encoded: str, request: Request, _rl: None = Depends(limit_util)
):
    import urllib.parse

    m = clean_encode_method(method)
    t = clean_text(encoded, field="encoded", max_len=10000)
    try:
        if m == "base64":
            result = base64.b64decode(t.encode()).decode()
        elif m == "hex":
            result = bytes.fromhex(t).decode()
        else:
            result = urllib.parse.unquote(t)
    except Exception:
        raise HTTPException(400, "Decoding failed — check input format.")
    return {"method": m, "decoded": result}


@app.post("/encode", tags=["Encoding"])
def encode_text_body(
    body: EncodeRequest, request: Request, _rl: None = Depends(limit_util)
):
    import urllib.parse

    m = clean_encode_method(body.method)
    t = clean_text(body.text, field="text", max_len=10000)
    if m == "base64":
        result = base64.b64encode(t.encode()).decode()
    elif m == "hex":
        result = t.encode().hex()
    else:
        result = urllib.parse.quote(t)
    return {"method": m, "encoded": result}


# ─── Network ───────────


@app.get("/ip/{ip}", tags=["Network"])
def ip_info(ip: str, request: Request, _rl: None = Depends(limit_util)):
    safe_ip = clean_ip(ip)
    try:
        if safe_ip == "me":
            with urllib.request.urlopen("https://ipinfo.io/json", timeout=5) as res:
                return json.loads(res.read())
        addr = ipaddress.ip_address(safe_ip)
        info: dict = {
            "ip": str(addr),
            "version": addr.version,
            "is_private": addr.is_private,
            "is_global": addr.is_global,
        }
        if not addr.is_private:
            try:
                with urllib.request.urlopen(
                    f"https://ipinfo.io/{safe_ip}/json", timeout=5
                ) as res:
                    geo = json.loads(res.read())
                info.update(
                    {
                        k: geo.get(k)
                        for k in ("org", "city", "region", "country", "timezone")
                    }
                )
            except Exception:
                info["geo"] = "unavailable"
        return info
    except Exception:
        raise HTTPException(400, "Invalid IP address.")


# ─── Utilities ────────────


@app.get("/time", tags=["Utilities"])
def current_time():
    now = datetime.utcnow()
    return {
        "utc": now.isoformat() + "Z",
        "unix_timestamp": int(now.timestamp()),
        "unix_timestamp_ms": int(now.timestamp() * 1000),
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
    }


# ─── Password ──────────


@app.post("/password/analyze", tags=["Password"])
def analyze_password_endpoint(
    body: PasswordAnalysisRequest, request: Request, _rl: None = Depends(limit_util)
):
    pw = clean_password(body.password)
    return analyze_password(pw)
