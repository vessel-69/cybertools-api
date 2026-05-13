<div align="center">

# CyberTools API v1.1.2

**Security intelligence tools for BB hunters, red teamers, devs, and people who enjoy staring at terminal output like it owes them money.**

[![Python](https://img.shields.io/badge/python-%3E%3D3.10-3776AB?style=flat-square&logo=python&logoColor=white)](https://pypi.org/project/CyberTools-vessel/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009485?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react)](https://react.dev)
[![License](https://img.shields.io/badge/license-MIT-e63030?style=flat-square)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-CyberTools--vessel-e63030?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/CyberTools-vessel/)
[![AUR](https://img.shields.io/badge/AUR-cybertools--vessel-1793D1?style=flat-square&logo=archlinux&logoColor=white)](https://aur.archlinux.org/packages/cybertools-vessel)

</div>

---

## What is CyberTools?

CyberTools is a reconnaissance and security analysis API built for bug bounty hunters, red team operators, and developers who want useful security automation without opening 47 tabs and slowly losing sanity.

It gives you a FastAPI backend, React frontend, AI assistant, recon tools, scanners, payload helpers, utilities, and a global CLI.

Basically:

```txt
You give it a target.
It gives you useful security info.
You pretend you totally expected all of it.
````

CyberTools is currently under active development, so expect upgrades, fixes, and the occasional "why did this work yesterday" moment.

---

## What can it do?

```
Bug Bounty Hunter                Red Team Operator           Security Developer
     │                                 │                            │
     ├─ recon example.com              ├─ bb-scan + workflow        ├─ integrate /api/chat
     ├─ find subdomains (passive)      ├─ enumerate all endpoints   ├─ build custom tools
     ├─ analyze security headers       ├─ detect injectable params  ├─ automate testing
     ├─ get SSL cert info              ├─ recommend payloads        └─ real-time insights
     └─ ask AI for next steps          └─ concurrent full workflow
```

---

## Key Features

| Feature             | Details                                             |
| ------------------- | --------------------------------------------------- |
| 17+ API endpoints   | Recon, scanning, payloads, utilities, workflows     |
| AI assistant        | Powered through OpenRouter models                   |
| Concurrent scanning | Fast probing with parallel workers                  |
| SSRF protection     | Blocks private IPs, metadata IPs, numeric IP tricks |
| Rate limiting       | Per-IP sliding window limits                        |
| Input validation    | Allowlist based validation for safer requests       |
| Real-time UI        | React frontend with live results and AI chat        |
| Global CLI          | Install with pipx, pip, or AUR                      |
| Security focused    | HTTPS, CORS, headers, error handling, logging       |

---

## Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/vessel-69/cybertools-api.git
cd cybertools-api
```

---

## Local Development

### Backend

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Backend should now be running at:

```txt
http://localhost:8000
```

Swagger docs:

```txt
http://localhost:8000/docs
```

---

### Frontend

```bash
cd frontend
npm install
npm run build
```

FastAPI can serve the built frontend from the backend.

For frontend hot reload:

```bash
npm run dev
```

Frontend dev server:

```txt
http://localhost:5173
```

---

## Local CLI Usage

```bash
python cli.py recon example.com
python cli.py analyze https://example.com
python cli.py scan https://example.com
python cli.py payloads xss
python cli.py workflow example.com
python cli.py last
python cli.py ask "What should I test first?"
```

Tiny terminal goblin is now active.

---

## Global CLI Installation

CyberTools also has a global CLI called `cybtl`.

### [Install with pipx (click this line for detailed pip/pix installation guide)](https://github.com/vessel-69/cybertools-vessel)

Recommended if you want a clean global install:

```bash
pipx install CyberTools-vessel
```

Then run:

```bash
cybtl
cybtl recon example.com
cybtl workflow example.com --save report.json
```

### Install with pip

```bash
pip install CyberTools-vessel
```

### Detailed pip and pipx installation guide

For full setup, update commands, reinstall commands, and CLI usage:

[CyberTools Vessel PyPI CLI Guide](https://github.com/vessel-69/cybertools-vessel)

---

### [Arch Linux Installation(click this line for detailed arch installation guide)](https://github.com/vessel-69/cybertools-vessel-aur)

If you are on Arch Linux or an Arch-based distro:

```bash
yay -S cybertools-vessel
```

Then run:

```bash
cybtl
cybtl recon example.com
```

### Detailed yay installation guide

For Arch Linux setup and AUR package details:

[CyberTools Vessel AUR Guide](https://github.com/vessel-69/cybertools-vessel-aur)

Arch users when the AUR build works first try:

```txt
rare W, screenshot it
```

---

## API Endpoints

### Security Operations

| Endpoint                | Method | Purpose                             | Rate Limit |
| ----------------------- | ------ | ----------------------------------- | ---------- |
| `/recon`                | GET    | IP, DNS, SSL, headers, tech stack   | 30/min     |
| `/analyze-url`          | GET    | Redirect chain and misconfig checks | 30/min     |
| `/bb-scan`              | GET    | Concurrent path probing             | 30/min     |
| `/expand`               | GET    | Subdomain enumeration               | 30/min     |
| `/endpoints`            | GET    | Endpoint discovery                  | 30/min     |
| `/params`               | GET    | Injectable parameter probing        | 30/min     |
| `/workflow`             | GET    | Full multi-stage workflow           | 10/min     |
| `/workflows/express`    | GET    | Fast recon and analysis             | 10/min     |
| `/workflows/bugbounty`  | GET    | Recon, scan, and payload flow       | 10/min     |
| `/workflows/subdomains` | GET    | Subdomain enum and recon            | 10/min     |
| `/workflows/api`        | GET    | API endpoint and param checks       | 10/min     |
| `/payloads`             | GET    | Payload generation                  | 60/min     |
| `/last-scan`            | GET    | Cached last result                  | 60/min     |

---

### Utilities

| Endpoint                  | Method | Purpose                             | Rate Limit     |
| ------------------------- | ------ | ----------------------------------- | -------------- |
| `/api/chat`               | POST   | AI security assistant               | 20/min         |
| `/hash/{algo}/{text}`     | GET    | Hash text with supported algorithms | 120/min        |
| `/encode/{method}/{text}` | GET    | Encode text                         | 120/min        |
| `/decode/{method}/{text}` | GET    | Decode text                         | 120/min        |
| `/ip/{ip}`                | GET    | IP geolocation lookup               | 120/min        |
| `/password/analyze`       | POST   | Password strength analysis          | 120/min        |
| `/docs`                   | GET    | Swagger API docs                    | No fixed limit |

---

## Usage Examples

### CLI

```bash
cybtl
cybtl recon example.com
cybtl bb-scan https://example.com
cybtl workflow example.com --json
cybtl payloads xss
cybtl hash sha256 "hello world"
cybtl config
cybtl set api_url https://custom-server.com
```

---

### API with curl

```bash
curl https://www.cyber-tools.dev/recon?domain=example.com
```

```bash
curl -X POST https://www.cyber-tools.dev/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {
        "role": "user",
        "content": "What is SSRF?"
      }
    ],
    "model": "google/gemma-4-26b-a4b-it:free"
  }'
```

```bash
curl https://www.cyber-tools.dev/payloads?type=sqli
```

---

## Browser

```txt
https://www.cyber-tools.dev
```

You get:

```txt
Interactive UI
Floating AI chatbot
Real-time results
Swagger docs at /docs
```

No PhD required. Just click stuff responsibly.

---

## Security Architecture

CyberTools is not just "send request and pray."

It includes:

* SSRF protection
* Private IP blocking
* Cloud metadata IP blocking
* Numeric IP blocking
* Input validation
* HTML and control character stripping
* Per-IP rate limiting
* CORS restrictions
* Security headers
* Server-side API key handling
* Global error handling
* No stack trace leaking
* HTTPS support

---

## Security Features

| Area        | Protection                                |
| ----------- | ----------------------------------------- |
| SSRF        | Blocks internal and dangerous IP ranges   |
| Inputs      | Allowlist validation and cleanup          |
| Rate limits | Sliding window per IP                     |
| CORS        | Locked to trusted origins                 |
| Headers     | HSTS, nosniff, X-Frame-Options            |
| API keys    | Kept server side only                     |
| Errors      | Clean responses without leaking internals |
| HTTPS       | Production-ready SSL setup                |

---

## Architecture

```txt
Web UI / CLI
     |
     v
FastAPI Backend
     |
     v
Security Tools, AI Providers, External Data Sources
```

Simple enough to understand, useful enough to actually ship.

---

## Performance

| Operation | Typical Time | Limits |
|-----------|--------------|--------|
| `/recon` | 500–800ms | DoH DNS, SSL cert fetch |
| `/expand` | 1–2s | crt.sh + hackertarget queries |
| `/bb-scan` | 2–5s | 12 concurrent workers |
| `/workflow` | 5–10s | Full 5-stage pipeline |
| `/api/chat` | 2–5s | Depends on OpenRouter queue |

Cached results available at `/last-scan` (TTL 1h).

---

## Why CyberTools?

Because recon should not feel like assembling IKEA furniture during a power cut.

CyberTools gives you:

1. One place for common recon and security checks
2. CLI access from anywhere
3. Web UI for easier usage
4. AI assistant for security questions
5. PyPI and AUR installation options
6. Safer backend design
7. Real-world focused workflows

It is built for people who want practical output, not a dashboard that looks expensive but says nothing.

---

## Install Summary

### Local

```bash
git clone https://github.com/vessel-69/cybertools-api.git
cd cybertools-api
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### pipx

```bash
pipx install CyberTools-vessel
cybtl
```

Guide:

[PyPI CLI Guide](https://github.com/vessel-69/cybertools-vessel)

### Arch Linux

```bash
yay -S cybertools-vessel
cybtl
```

Guide:

[AUR Installation Guide](https://github.com/vessel-69/cybertools-vessel-aur)

---

## Contributing

Found a bug?

Have an idea?

Something exploded and you have logs?

Open an issue:

```txt
https://github.com/vessel-69/cybertools-api/issues
```

Pull requests are welcome too. Just do not submit cursed code that works only on your laptop at 3 AM.

---

## License

MIT License — See [LICENSE](./LICENSE)

---

## Get Started

1. **Local Deployment**
2. **Locally:** `uvicorn main:app --reload --port 8000`
3. **Local CLI** `python cli.py`
4. **Global CLI:** `pipx install CyberTools-vessel && cybtl`

---

<div align="center">

**Made with <3 by vessel-69**

[🌐 Live API](https://www.cyber-tools.dev) · [📚 Docs](https://www.cyber-tools.dev/docs) · [🔧 GitHub](https://github.com/vessel-69/cybertools-api)

</div>