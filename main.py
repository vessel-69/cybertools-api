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
    docs_url="/docs",
)

from routes.security import router as security_router

app.include_router(security_router)


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


# ─── Static files + root ───────────────────────────────────────────────────────

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


# ─── Hashing ───────────────────────────────────────────────────────────────────


@app.get("/hash/algorithms", tags=["Hashing"])
def list_algorithms():
    return {"algorithms": HASH_ALGORITHMS}


@app.get("/hash/{algorithm}/{text}", tags=["Hashing"])
def hash_text(algorithm: str, text: str):
    algorithm = algorithm.lower()
    if algorithm not in HASH_ALGORITHMS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported algorithm. Choose from: {HASH_ALGORITHMS}",
        )
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
        raise HTTPException(
            status_code=400, detail="Unsupported method. Use: base64, hex, url"
        )
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
            raise HTTPException(
                status_code=400, detail="Unsupported method. Use: base64, hex, url"
            )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decoding failed: {str(e)}")
    return {"encoded": encoded, "method": method, "decoded": result}


@app.post("/encode", tags=["Encoding"])
def encode_text_body(body: EncodeRequest):
    method = body.method.lower()
    text = body.text
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
            "ip": str(addr),
            "version": addr.version,
            "is_private": addr.is_private,
            "is_loopback": addr.is_loopback,
            "is_multicast": addr.is_multicast,
            "is_global": addr.is_global,
            "is_reserved": addr.is_reserved,
        }
        if not addr.is_private:
            try:
                with urllib.request.urlopen(
                    f"https://ipinfo.io/{ip}/json", timeout=5
                ) as res:
                    geo = json.loads(res.read())
                info.update(
                    {
                        "org": geo.get("org"),
                        "city": geo.get("city"),
                        "region": geo.get("region"),
                        "country": geo.get("country"),
                        "timezone": geo.get("timezone"),
                    }
                )
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
