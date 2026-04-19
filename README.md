<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗ ██████╗  ██████╗ ██╗     ███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ██║   ██║   ██║██║   ██║██║     ███████╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ██║   ██║   ██║██║   ██║██║     ╚════██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║   ██║   ╚██████╔╝╚██████╔╝███████╗███████║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
```

# CyberTools API v2.0

**Security Intelligence Platform for Bug Bounty Hunters, Red Teamers & Developers**

[![Python](https://img.shields.io/badge/Python-3.12-3776ab?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009485?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Available on PyPI](https://img.shields.io/badge/Available%20on-PyPI-blue?style=flat-square&logo=python)](https://pypi.org/project/cybertools-vessel)
[![Available on AUR](https://img.shields.io/badge/Available%20on-AUR-1C1E26?style=flat-square&logo=archlinux)](https://aur.archlinux.org/packages/cybertools-vessel)

</div>

---

## 🎯 What is CyberTools?

CyberTools is a **production-grade reconnaissance and security analysis API** that brings enterprise-level security automation to bug bounty hunters and independent security researchers. Think of it as your personal security operations center, accessible anywhere.

### Real-World Use Cases

```
Bug Bounty Hunter                Red Team Operator           Security Developer
     │                                  │                            │
     ├─ recon example.com              ├─ bb-scan + workflow        ├─ integrate /api/chat
     ├─ find subdomains (passive)      ├─ enumerate all endpoints   ├─ build custom tools
     ├─ analyze security headers       ├─ detect injectable params  ├─ automate testing
     ├─ get SSL cert info              ├─ recommend payloads        └─ real-time insights
     └─ ask AI for next steps          └─ concurrent full workflow
```

---

## ✨ Key Features

| Feature | Details |
|---------|---------|
| **17+ API Endpoints** | Recon, scanning, payload gen, utilities |
| **AI Chatbot** | Red team assistant powered by OpenRouter (Gemma 4, Llama 3.3, DeepSeek) |
| **Concurrent Scanning** | 12 parallel workers for fast probing |
| **SSRF Protection** | Blocks private IPs, cloud metadata, numeric IPs |
| **Rate Limiting** | Per-IP sliding window (30-120 req/min depending on endpoint) |
| **Input Validation** | Allowlist-based, no injection vectors |
| **Real-Time UI** | React frontend with floating AI chatbot, live updates |
| **Global CLI** | Available on PyPI (`pip install cybertools-vessel`) and AUR (`yay -S cybertools-vessel`) |
| **Designed for real-world usage** | HTTPS, security headers, error handling, logging |

---

## 🚀 Quick Start

###  Local Development

### 1. Backend (FastAPI)

```bash
cd cybertools-api
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 2. Frontend (React + TypeScript)

```bash
cd frontend
npm install
npm run build       # build once → FastAPI serves it at localhost:8000

# OR for hot-reload dev:
npm run dev         # → http://localhost:5173 (proxies API to :8000)
```

### 🖥 Use the Local CLI 

```bash
python cli.py recon    example.com
python cli.py analyze  https://example.com
python cli.py scan     https://example.com
python cli.py payloads xss
python cli.py workflow example.com
python cli.py last
python cli.py ask "What should I test first?"
```

### 🌐 Use the Global CLI (1 minute)

```bash
# Install from PyPI
pip install cybertools-vessel

# Or on Arch Linux
yay -S cybertools-vessel

# Use anywhere
cybtl                           # Interactive menu
cybtl recon example.com
cybtl workflow example.com --save report.json
```

---

## 📊 API Endpoints

### Security Operations (routes/security.py)

| Endpoint | Method | Purpose | Rate Limit |
|----------|--------|---------|-----------|
| `/recon` | GET | IP, DNS, SSL, headers, tech stack | 30/min |
| `/analyze-url` | GET | Redirect chain, misconfigs | 30/min |
| `/bb-scan` | GET | Concurrent path probe (30+ paths) | 30/min |
| `/expand` | GET | Subdomain enum via crt.sh + SAN | 30/min |
| `/endpoints` | GET | 60+ endpoint scan, tagged | 30/min |
| `/params` | GET | 26 injectable param probe | 30/min |
| `/workflow` | GET | Full 5-stage pipeline (concurrent) | 10/min |
| `/workflows/express` | GET | Recon + analyze only (~3-5s) | 10/min |
| `/workflows/bugbounty` | GET | Recon + scan + payloads | 10/min |
| `/workflows/subdomains` | GET | Subdomain enum + recon on each | 10/min |
| `/workflows/api` | GET | Endpoint enum + param probing | 10/min |
| `/payloads` | GET | xss/sqli/lfi/ssrf/idor/open_redirect | 60/min |
| `/last-scan` | GET | Cached result (TTL 1h) | 60/min |

### Utilities (main.py)

| Endpoint | Method | Purpose | Rate Limit |
|----------|--------|---------|-----------|
| `/api/chat` | POST | AI assistant (OpenRouter) | 20/min |
| `/hash/{algo}/{text}` | GET | md5, sha1-512, blake2b, blake2s | 120/min |
| `/encode/{method}/{text}` | GET | base64, hex, url encode | 120/min |
| `/decode/{method}/{text}` | GET | base64, hex, url decode | 120/min |
| `/ip/{ip}` | GET | Geolocation (ipinfo.io) | 120/min |
| `/password/analyze` | POST | Strength, entropy, feedback | 120/min |
| `/docs` | GET | Swagger API documentation | — |

---

## 🔒 Security Architecture

### API Key Protection

### Input Validation 
- SSRF blocker (private IPs, cloud metadata, numeric IPs)
- HTML/control character stripping
- Allowlist validation (payload types, hash algos, methods)
- Rate limiting per IP (sliding window)

### Network Security
- HTTPS with auto-renewing Certbot SSL
- CORS locked to cyber-tools.dev + localhost
- Security headers: HSTS, X-Frame-Options DENY, nosniff, CSP-ready
- No stack trace leaks (global error handler)

---

## 📦 Installation

### From PyPI
```bash
pip install cybertools-vessel
cybtl --help
```

### From AUR (Arch Linux)
```bash
yay -S cybertools-vessel
cybtl recon example.com
```

### From Source
```bash
git clone https://github.com/vessel-69/cybertools-api.git
cd cybertools-api
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

---

## 🎮 Usage Examples

### CLI (Global)
```bash
# Interactive menu
cybtl

# Direct commands
cybtl recon example.com
cybtl bb-scan https://example.com
cybtl workflow example.com --json
cybtl payloads xss
cybtl hash sha256 "hello world"
cybtl config  # show config
cybtl set api_url https://custom-server.com  # use self-hosted
```

### API (curl)
```bash
# Recon
curl https://www.cyber-tools.dev/recon?domain=example.com

# Chatbot
curl -X POST https://www.cyber-tools.dev/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{"role": "user", "content": "What is SSRF?"}],
    "model": "google/gemma-4-26b-a4b-it:free"
  }'

# Payloads
curl https://www.cyber-tools.dev/payloads?type=sqli
```

### Browser
```
https://www.cyber-tools.dev
├─ Interactive UI
├─ Floating AI chatbot (⌖ button)
├─ Real-time results
└─ Auto-generated Swagger docs at /docs
```

---

## 🏗️ Architecture

```
 Client (Web UI / CLI)
        │
        ▼
Backend API
        │
        ▼
External AI and data providers
       
```


---

## 📊 Performance

| Operation | Typical Time | Limits |
|-----------|--------------|--------|
| `/recon` | 500–800ms | DoH DNS, SSL cert fetch |
| `/expand` | 1–2s | crt.sh + hackertarget queries |
| `/bb-scan` | 2–5s | 12 concurrent workers |
| `/workflow` | 5–10s | Full 5-stage pipeline |
| `/api/chat` | 2–5s | Depends on OpenRouter queue |

Cached results available at `/last-scan` (TTL 1h).

---

## 🛡️ Security Features

- ✅ SSRF blocker (blocks 169.254.x, 100.64.x, 10.x, 192.168.x, 127.x)
- ✅ Input validation (allowlists, HTML strip, control char removal)
- ✅ Rate limiting (per-IP, sliding window)
- ✅ CORS locked (cyber-tools.dev + localhost only)
- ✅ Security headers (HSTS, nosniff, X-Frame-Options DENY)
- ✅ API key protection (server-side only, never frontend)
- ✅ Error handling (no stack trace leaks)
- ✅ HTTPS enforced (Certbot auto-renewal)

---

## 🎯 Why CyberTools?

1. **Unified Platform** — 17+ endpoints, one place to start reconnaissance
2. **Zero Cost** — Free OpenRouter models (Gemma, Llama, DeepSeek)
3. **Designed for real-world usage** — Rate limiting, input validation, security headers, logging
4. **Global Access** — PyPI + AUR packages, cloud-ready
5. **Red Team Focused** — Built by security professionals, for security professionals
6. **Concurrent Scanning** — 12 parallel workers, sub-5s workflow completion
7. **Real-Time UI** — React frontend with live updates and floating AI assistant

---

## 🤝 Contributing

- Found a bug?
- Have a feature idea?
- Have ideas or improvements?
- Open an issue on GitHub:
> https://github.com/vessel-69/cybertools-api/issues

---

## 📄 License

MIT License — See [LICENSE](./LICENSE)

---

## 🚀 Get Started

1. **Local Deployment**
2. **Locally:** `uvicorn main:app --reload --port 8000`
3. **Local CLI** `python cli.py`
4. **Global CLI:** `pip install cybertools-vessel && cybtl`

---

<div align="center">

**Made with ❤️ by vessel-69**

[🌐 Live API](https://www.cyber-tools.dev) · [📚 Docs](https://www.cyber-tools.dev/docs) · [🔧 GitHub](https://github.com/vessel-69/cybertools-api)

</div>