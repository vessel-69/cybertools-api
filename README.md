# CyberTools API

A versatile, high-performance security and developer utility API built with **FastAPI** and a **React + TypeScript** frontend.

**Live URL:** https://cybertools-api.fly.dev  
**Interactive Docs:** https://cybertools-api.fly.dev/docs

---

## 🗂 Project Structure

```
cybertools-api/
├── routes/
│   ├── __init__.py
│   └── security.py          # recon, analyze-url, bb-scan, payloads, workflow, chat
├── services/
│   ├── __init__.py
│   └── recon.py             # all logic — pure functions
├── frontend/
│   ├── package.json
│   ├── tsconfig.json
│   ├── tsconfig.node.json
│   ├── vite.config.ts       # proxies API routes to FastAPI in dev
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx           # root component, all state
│       ├── index.css         # lime/dark terminal aesthetic
│       ├── types/index.ts    # TypeScript types for all API responses
│       ├── api/client.ts     # typed fetch wrappers
│       └── components/
│           ├── Navbar.tsx
│           ├── LeftPanel.tsx
│           ├── ResultPanel.tsx
│           ├── ui/primitives.tsx   # KVRow, Section, HintItem, etc.
│           └── results/index.tsx   # ReconSection, BBScanSection, etc.
├── cli.py                   # CLI tool (python cli.py recon example.com)
├── main.py                  # FastAPI entry point
├── Dockerfile               # multi-stage: Node builds frontend, Python serves
├── fly.toml                 # Fly.io deployment config
├── requirements.txt
└── ui.html                  # fallback if frontend not built
```

---

## 🚀 Local Development

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

---

## 🛠 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/recon?domain=` | IP, SSL, headers, tech stack |
| GET | `/analyze-url?url=` | Redirect chain, misconfigurations |
| GET | `/bb-scan?url=` | Bug bounty path scan (concurrent) |
| GET | `/payloads?type=` | xss, sqli, lfi, ssrf payloads |
| GET | `/workflow?target=` | Full pipeline (recon+analyze+scan) |
| GET | `/last-scan` | Cached result from last scan |
| POST | `/chat-assist` | Rule-based assistant |
| GET | `/hash/{algo}/{text}` | Hash a string |
| GET | `/encode/{method}/{text}` | base64, hex, url encode |
| GET | `/decode/{method}/{text}` | Decode |
| POST | `/password/analyze` | Password strength analysis |
| GET | `/ip/{ip}` | IP geolocation info |
| GET | `/time` | UTC time in multiple formats |

---

## 🖥 CLI

```bash
python cli.py recon    example.com
python cli.py analyze  https://example.com
python cli.py scan     https://example.com
python cli.py payloads xss
python cli.py workflow example.com
python cli.py last
python cli.py ask "What should I test first?"
```

---

## 📦 Deployment (Fly.io)

```bash
fly auth signup
fly launch
fly deploy
```

---

## 📜 License

MIT License
