# ── Stage 1: Build React frontend ─────────────────────────────────────────────
FROM node:20-slim AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python API ────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY ui.html .
COPY services/ ./services/
COPY routes/ ./routes/

COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
