"""
routes/security.py — all security endpoints.
Logic lives in services/recon.py.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from services.recon import (
    recon_domain, analyze_url, bb_scan, get_payloads,
    run_workflow, chat_assist, get_last_scan
)

router = APIRouter(tags=["Security"])


class ChatRequest(BaseModel):
    question: str
    scan_result: Optional[dict] = None


@router.get("/recon")
def recon(domain: str = Query(..., description="Domain to recon, e.g. example.com")):
    """Recon a domain: IP, headers, SSL info, tech detection, smart_summary, next_steps."""
    if not domain:
        raise HTTPException(400, "domain is required.")
    result = recon_domain(domain)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@router.get("/analyze-url")
def analyze(url: str = Query(..., description="URL to analyze, e.g. https://example.com")):
    """Follow redirects, detect header misconfigurations, return smart_summary."""
    if not url:
        raise HTTPException(400, "url is required.")
    return analyze_url(url)


@router.get("/bb-scan")
def bounty_scan(url: str = Query(..., description="Target URL for bug bounty recon")):
    """
    Probe 30+ common paths concurrently. Returns interesting findings,
    bug bounty hints, and next_steps. ~3-5x faster than sequential.
    """
    if not url:
        raise HTTPException(400, "url is required.")
    return bb_scan(url)


@router.get("/payloads")
def payloads(type: str = Query(..., description="xss | sqli | lfi | ssrf")):
    """Categorized, labeled attack payloads for security testing."""
    result = get_payloads(type)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@router.get("/workflow")
def workflow(target: str = Query(..., description="Domain or URL to run full pipeline on")):
    """
    Full pipeline: recon + analyze-url + bb-scan, run concurrently.
    Returns combined results, deduplicated next_steps, and merged smart_summary.
    """
    if not target:
        raise HTTPException(400, "target is required.")
    return run_workflow(target)


@router.get("/last-scan")
def last_scan():
    """Returns the result of the most recent scan stored in memory."""
    data = get_last_scan()
    if not data:
        raise HTTPException(404, "No scan results in memory yet. Run /recon, /bb-scan, or /workflow first.")
    return data


@router.post("/chat-assist")
def chat(body: ChatRequest):
    """
    Rule-based assistant. Ask questions about your last scan result.
    Examples: 'What should I test?', 'What headers are missing?', 'Is this vulnerable?'
    Optionally pass scan_result in body to override last-scan context.
    """
    if not body.question.strip():
        raise HTTPException(400, "question cannot be empty.")
    return chat_assist(body.question, body.scan_result)