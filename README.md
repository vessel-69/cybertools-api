-----

# ⚡ CyberTools API

[](https://fastapi.tiangolo.com/)
[](https://www.python.org/)
[](https://fly.io)

A versatile, high-performance toolkit for common security and developer tasks. Built with **FastAPI** and deployed globally for free.

> **Live URL:** `https://cybertools-api.fly.dev` 
> **Interactive Docs:** `https://cybertools-api.fly.dev/docs`

---

--

## 🛠 Features & How to Use

### 1\. Hashing Engine

Securely hash strings using multiple industry-standard algorithms.

- **Supported:** `md5`, `sha1`, `sha256`, `sha512`, `blake2b`, and more.
- **How to use:** \* **GET:** `/hash/{algorithm}/{text}`
  - **POST:** Send a JSON body to `/hash` with `{"text": "your_string", "algorithm": "sha256"}`.

### 2\. Encoding & Decoding

Convert data between different formats for web and binary tasks.

- **Methods:** `base64`, `hex`, `url`.
- **How to use:** \* **Encode:** `GET /encode/base64/hello` → returns `aGVsbG8=`.
  - **Decode:** `GET /decode/base64/aGVsbG8=` → returns `hello`.

### 3\. Smart Password Analysis

Don't just check length—analyze the actual security of a password.

- **Features:** Entropy estimation, character variety checks, and actionable feedback.
- **How to use:**
  - **POST:** `/password/analyze` with `{"password": "your_password"}`.
  - **Response:** Returns a strength label (e.g., "Strong") and a list of tips to improve it.

### 4\. Network Intelligence

Quickly identify IP properties and geolocation data.

- **How to use:**
  - **Check any IP:** `GET /ip/8.8.8.8`.
  - **Check yourself:** `GET /ip/me` to see your current public IP and origin.

---

## 🚀 Quick Start (Local Development)

To run this API on your own Ubuntu machine:

1.  **Clone and Enter:**

    ```bash
    git clone https://github.com/vessel-69/cybertools-api.git
    cd cybertools-api
    ```

2.  **Setup Virtual Environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install & Run:**

    ```bash
    pip install -r requirements.txt
    uvicorn main:app --reload
    ```

    View the API at `http://127.0.0.1:8000/docs`.

---

## 📦 Deployment

[cite_start]This project is optimized for **Docker** and **Fly.io**[cite: 3].

- **Region:** Deployed in `sin` (Singapore) for optimal performance in the Asia-Pacific region.
- **Memory:** Runs on a lightweight `shared-cpu-1x` with `256mb` RAM.

---

## 📜 License

This project is licensed under the **MIT License**.

---
