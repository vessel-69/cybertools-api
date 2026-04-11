import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel
import hashlib
import base64
import re
import ipaddress
import urllib.request
import json
from datetime import datetime

app = FastAPI(
    title="CyberTools API",
    description="A free utility API for common security and developer tasks.",
    version="1.0.0",
    docs_url=None,   # we serve custom /docs with dark mode toggle
)

from routes.security import router as security_router
app.include_router(security_router)


_SWAGGER_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>CyberTools API — Docs</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect fill='%23070909' width='32' height='32' rx='4'/%3E%3Ccircle cx='16' cy='16' r='11' fill='none' stroke='%23e63030' stroke-width='1.8'/%3E%3Ccircle cx='16' cy='16' r='4' fill='%23e63030'/%3E%3Cline x1='16' y1='2' x2='16' y2='9' stroke='%23e63030' stroke-width='1.8'/%3E%3Cline x1='16' y1='23' x2='16' y2='30' stroke='%23e63030' stroke-width='1.8'/%3E%3Cline x1='2' y1='16' x2='9' y2='16' stroke='%23e63030' stroke-width='1.8'/%3E%3Cline x1='23' y1='16' x2='30' y2='16' stroke='%23e63030' stroke-width='1.8'/%3E%3C/svg%3E" />
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    :root { --toggle-bg: #1a1a1a; }
    body { margin: 0; }
    #theme-btn {
      position: fixed; top: 14px; right: 16px; z-index: 9999;
      padding: 6px 14px; border-radius: 6px; cursor: pointer;
      font-family: monospace; font-size: 0.78rem; font-weight: 600;
      border: 1px solid #e63030; background: #0d0f0f;
      color: #e63030; letter-spacing: 1px; text-transform: uppercase;
      transition: all 0.2s;
    }
    #theme-btn:hover { background: #e63030; color: #fff; }
    body.dark .swagger-ui .topbar { background: #0d0f0f; border-bottom: 1px solid #2a0a0a; }
    body.dark .swagger-ui { background: #070909; color: #ddd5d5; }
    body.dark .swagger-ui .info .title, body.dark .swagger-ui .info p { color: #ddd5d5; }
    body.dark .swagger-ui .opblock-tag { color: #e63030; border-bottom-color: #2a0a0a; }
    body.dark .swagger-ui .opblock { background: #0d0f0f; border-color: #1e0808; }
    body.dark .swagger-ui .opblock .opblock-summary { background: #111515; }
    body.dark .swagger-ui .opblock-description-wrapper p,
    body.dark .swagger-ui .opblock-external-docs-wrapper p,
    body.dark .swagger-ui .opblock-title_normal p { color: #aaa; }
    body.dark .swagger-ui .responses-inner h4,
    body.dark .swagger-ui .responses-inner h5 { color: #ddd5d5; }
    body.dark .swagger-ui section.models { background: #0d0f0f; border-color: #1e0808; }
    body.dark .swagger-ui .model-container { background: #111515; }
    body.dark .swagger-ui input, body.dark .swagger-ui textarea,
    body.dark .swagger-ui select { background: #121515; color: #ddd5d5; border-color: #2a0a0a; }
    body.dark .swagger-ui .btn { color: #e63030; border-color: #e63030; }
    body.dark .swagger-ui .btn.execute { background: #e63030; color: #fff; }
    body.dark .swagger-ui table thead tr td, body.dark .swagger-ui table thead tr th { color: #aaa; border-color: #2a0a0a; }
    body.dark .swagger-ui .parameter__name { color: #e63030; }
    body.dark .swagger-ui .parameter__type { color: #aaa; }
    body.dark .swagger-ui .tab li { color: #aaa; }
    body.dark .swagger-ui .scheme-container { background: #0d0f0f; box-shadow: none; border-bottom: 1px solid #1e0808; }
    body.dark #swagger-ui { background: #070909; }
    body.dark .swagger-ui .wrapper { background: #070909; }
  </style>
</head>
<body class="dark">
  <button id="theme-btn" onclick="toggleTheme()">☀ Light</button>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    let dark = true;
    function toggleTheme() {
      dark = !dark;
      document.body.className = dark ? 'dark' : '';
      document.getElementById('theme-btn').textContent = dark ? '☀ Light' : '☾ Dark';
    }
    SwaggerUIBundle({
      url: '/openapi.json',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout',
      deepLinking: true,
    });
  </script>
</body>
</html>"""


@app.get("/docs", response_class=HTMLResponse, include_in_schema=False)
def custom_docs():
    return HTMLResponse(content=_SWAGGER_HTML)


# ─── Models ────────────────────────────────────────────────────────────────────

class HashRequest(BaseModel):
    text: str
    algorithm: str = "sha256"

class EncodeRequest(BaseModel):
    text: str
    method: str = "base64"

class PasswordAnalysisRequest(BaseModel):
    password: str


# ─── Helpers ───────────────────────────────────────────────────────────────────

HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"]

def analyze_password(pw: str) -> dict:
    score = 0
    feedback = []

    checks = {
        "length_8":     len(pw) >= 8,
        "length_12":    len(pw) >= 12,
        "length_16":    len(pw) >= 16,
        "has_upper":    bool(re.search(r"[A-Z]", pw)),
        "has_lower":    bool(re.search(r"[a-z]", pw)),
        "has_digit":    bool(re.search(r"\d", pw)),
        "has_special":  bool(re.search(r"[^A-Za-z0-9]", pw)),
        "no_spaces":    " " not in pw,
        "no_repeat":    not bool(re.search(r"(.)\1{2,}", pw)),
        "no_sequence":  not any(seq in pw.lower() for seq in ["123", "abc", "qwerty", "password", "admin"]),
    }

    weights = {
        "length_8": 1, "length_12": 1, "length_16": 1,
        "has_upper": 1, "has_lower": 1, "has_digit": 1, "has_special": 2,
        "no_spaces": 0, "no_repeat": 1, "no_sequence": 1,
    }

    for check, passed in checks.items():
        if passed:
            score += weights.get(check, 1)
        else:
            tips = {
                "length_8":    "Use at least 8 characters.",
                "length_12":   "Use at least 12 characters for better security.",
                "length_16":   "16+ characters is ideal for strong passwords.",
                "has_upper":   "Add uppercase letters (A-Z).",
                "has_lower":   "Add lowercase letters (a-z).",
                "has_digit":   "Include numbers.",
                "has_special": "Use special characters like !@#$%^&*.",
                "no_spaces":   "Avoid spaces.",
                "no_repeat":   "Avoid repeating characters (e.g. 'aaa').",
                "no_sequence": "Avoid common sequences like '123' or 'password'.",
            }
            if check in tips:
                feedback.append(tips[check])

    max_score = sum(weights.values())
    pct = score / max_score

    if pct >= 0.85:   strength = "Very Strong"
    elif pct >= 0.65: strength = "Strong"
    elif pct >= 0.45: strength = "Moderate"
    elif pct >= 0.25: strength = "Weak"
    else:             strength = "Very Weak"

    entropy_bits = round(len(pw) * 6.55, 1)

    return {
        "strength": strength,
        "score": score,
        "max_score": max_score,
        "entropy_estimate_bits": entropy_bits,
        "checks": checks,
        "feedback": feedback,
    }


# ─── Static files + root ───────────────────────────────────────────────────────

_frontend_dist = Path(__file__).parent / "frontend" / "dist"
_assets_dir    = _frontend_dist / "assets"

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
    return HTMLResponse(content="<p style='font-family:monospace;padding:2rem'>Frontend not built.<br>Run: <code>cd frontend && npm install && npm run build</code></p>")


# ─── Hashing ───────────────────────────────────────────────────────────────────

@app.get("/hash/algorithms", tags=["Hashing"])
def list_algorithms():
    return {"algorithms": HASH_ALGORITHMS}

@app.get("/hash/{algorithm}/{text}", tags=["Hashing"])
def hash_text(algorithm: str, text: str):
    algorithm = algorithm.lower()
    if algorithm not in HASH_ALGORITHMS:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm. Choose from: {HASH_ALGORITHMS}")
    h = hashlib.new(algorithm, text.encode()).hexdigest()
    return {"input": text, "algorithm": algorithm, "hash": h, "length_bits": len(h) * 4}

@app.post("/hash", tags=["Hashing"])
def hash_text_body(body: HashRequest):
    alg = body.algorithm.lower()
    if alg not in HASH_ALGORITHMS:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {alg}")
    h = hashlib.new(alg, body.text.encode()).hexdigest()
    return {"input_length": len(body.text), "algorithm": alg, "hash": h}


# ─── Encoding ──────────────────────────────────────────────────────────────────

@app.get("/encode/{method}/{text}", tags=["Encoding"])
def encode_text(method: str, text: str):
    method = method.lower()
    if method == "base64":
        result = base64.b64encode(text.encode()).decode()
    elif method == "hex":
        result = text.encode().hex()
    elif method == "url":
        import urllib.parse
        result = urllib.parse.quote(text)
    else:
        raise HTTPException(status_code=400, detail="Unsupported method. Use: base64, hex, url")
    return {"input": text, "method": method, "encoded": result}

@app.get("/decode/{method}/{encoded}", tags=["Encoding"])
def decode_text(method: str, encoded: str):
    method = method.lower()
    try:
        if method == "base64":
            result = base64.b64decode(encoded.encode()).decode()
        elif method == "hex":
            result = bytes.fromhex(encoded).decode()
        elif method == "url":
            import urllib.parse
            result = urllib.parse.unquote(encoded)
        else:
            raise HTTPException(status_code=400, detail="Unsupported method. Use: base64, hex, url")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decoding failed: {str(e)}")
    return {"encoded": encoded, "method": method, "decoded": result}

@app.post("/encode", tags=["Encoding"])
def encode_text_body(body: EncodeRequest):
    method = body.method.lower()
    text   = body.text
    if method == "base64":
        result = base64.b64encode(text.encode()).decode()
    elif method == "hex":
        result = text.encode().hex()
    elif method == "url":
        import urllib.parse
        result = urllib.parse.quote(text)
    else:
        raise HTTPException(status_code=400, detail="Unsupported method.")
    return {"method": method, "encoded": result}


# ─── Network ───────────────────────────────────────────────────────────────────

@app.get("/ip/{ip}", tags=["Network"])
def ip_info(ip: str):
    try:
        if ip == "me":
            with urllib.request.urlopen("https://ipinfo.io/json", timeout=5) as res:
                data = json.loads(res.read())
            return data
        addr = ipaddress.ip_address(ip)
        info = {
            "ip": str(addr), "version": addr.version,
            "is_private": addr.is_private, "is_loopback": addr.is_loopback,
            "is_multicast": addr.is_multicast, "is_global": addr.is_global,
            "is_reserved": addr.is_reserved,
        }
        if not addr.is_private:
            try:
                with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=5) as res:
                    geo = json.loads(res.read())
                info.update({
                    "org": geo.get("org"), "city": geo.get("city"),
                    "region": geo.get("region"), "country": geo.get("country"),
                    "timezone": geo.get("timezone"),
                })
            except Exception:
                info["geo"] = "unavailable"
        return info
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address.")


# ─── Utilities ─────────────────────────────────────────────────────────────────

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


# ─── Password ──────────────────────────────────────────────────────────────────

@app.post("/password/analyze", tags=["Password"])
def analyze_password_endpoint(body: PasswordAnalysisRequest):
    if not body.password:
        raise HTTPException(status_code=400, detail="Password cannot be empty.")
    return analyze_password(body.password)