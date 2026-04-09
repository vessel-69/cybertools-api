# 🛠️ CyberTools API

**A versatile, lean security toolkit for the modern Red Teamer.**

[](https://github.com/vessel-69/cybertools-api)
[](https://fly.io)
[](https://fly.io/docs/reference/regions/)


CyberTools API is a high-performance security backend built with **FastAPI**, designed to handle the heavy lifting of hashing, encoding, and password analysis. Whether you're auditing credentials or automating encoding workflows, this API provides the precision and speed required for tactical operations.

-----

## ⚡ Core Features

  - **🔐 Cryptographic Hashing:** Support for MD5, SHA-1, SHA-256, and SHA-512.
  - **🛡️ Password Analysis:** Comprehensive entropy checks and complexity scoring.
  - **🔄 Encoding/Decoding:** Multi-layer support including Base64 and URL encoding.
  - **🐳 Dockerized Architecture:** Optimized for lightweight deployment and scaling.
  - **🎨 Minimalist UI:** Includes `ui.html` featuring a custom low-key aesthetic.


-----

## 🚀 Quick Start

### 1\. Prerequisites

  - Python 3.12+
  - Docker (optional for containerized runs)

### 2\. Local Installation

```bash
# Clone the repository
git clone https://github.com/vessel-69/cybertools-api.git
cd cybertools-api

# Install dependencies
pip install -r requirements.txt

# Run the API
uvicorn main:app --reload
```

### 3\. Docker Deployment

```bash
docker build -t cybertools-api .
docker run -p 8080:8080 cybertools-api
```

-----

## 🌍 Infrastructure

  - **Hosting:** [Fly.io](https://fly.io)
  - **CI/CD:** Automated via GitHub Actions (configured for `vessel-69`)

-----

## 📁 Repository Structure

```text
.
├── app/
│   ├── main.py          # FastAPI Core logic
│   ├── hashing.py       # Cryptographic functions
│   └── encoding.py      # Data transformation logic
├── static/
│   └── ui.html          # Custom UI dashboard
├── .gitignore           # Recursively ignores __pycache__
├── Dockerfile           # Fly.io deployment config
└── README.md            # You are here
```

-----

## 🛡️ Operational Security (OPSEC)

This project is built for security research and ethical testing.

  - **No Logs Policy:** Designed to be stateless.
  - **Clean Repo:** All sensitive history and cached files are purged.

-----

## 👨‍💻 Maintainer

**Vessel** *GitHub: [@vessel-69](https://www.google.com/search?q=https://github.com/vessel-69)*

-----

*© 2026 CyberTools API | Versatility in every bit.*