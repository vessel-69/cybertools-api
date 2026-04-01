# CyberTools API

A free, public utility API for common security and developer tasks — hashing, encoding, password analysis, and more.

Built with [FastAPI](https://fastapi.tiangolo.com/) for the [RaspAPI](https://raspapi.hackclub.com/) Hack Club YSWS.

## Live URL

> https://cybertools-api.fly.dev

Interactive docs: 

> https://cybertools-api.fly.dev/docs

---

## Endpoints

### Hashing

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/hash/algorithms` | List all supported algorithms |
| GET | `/hash/{algorithm}/{text}` | Hash a string |
| POST | `/hash` | Hash text via request body |

**Supported algorithms:** `md5`, `sha1`, `sha256`, `sha384`, `sha512`, `sha3_256`, `sha3_512`, `blake2b`, `blake2s`

**Example:**
```
GET /hash/sha256/hello
→ { "input": "hello", "algorithm": "sha256", "hash": "2cf24db...", "length_bits": 256 }
```

---

### Encoding / Decoding

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/encode/{method}/{text}` | Encode a string |
| GET | `/decode/{method}/{encoded}` | Decode a string |
| POST | `/encode` | Encode via request body |

**Supported methods:** `base64`, `hex`, `url`

**Example:**
```
GET /encode/base64/hello
→ { "encoded": "aGVsbG8=" }
```

---

### Network

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ip/{ip}` | Get info about an IP address |
| GET | `/ip/me` | Get info about your own IP |

---

### Utilities

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/time` | Current UTC time in multiple formats |

---

### Password Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/password/analyze` | Analyze password strength |

**Example request body:**
```json
{ "password": "MyS3cur3P@ss!" }
```

**Example response:**
```json
{
  "strength": "Strong",
  "score": 8,
  "max_score": 10,
  "entropy_estimate_bits": 85.1,
  "checks": { ... },
  "feedback": ["Use at least 16 characters for ideal security."]
}
```

> ⚠️ Never send a password you actually use. This endpoint is for testing only.

---

## Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run dev server
uvicorn main:app --reload --port 8000
```

Then open: `http://localhost:8000/docs`

---

## Hosting

Recommended options:
- **[Fly.io](https://fly.io)** — Free tier, easiest deployment
- **Cloudflare Tunnel** — Self-hosted on your machine/Pi, free

See the [RaspAPI hosting guides](https://raspapi.hackclub.com/guides) for step-by-step instructions.

---

## License

MIT
