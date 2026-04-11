"""
routes/security.py — all security endpoints.
Logic lives in services/recon.py.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from services.recon import (
    recon_domain, analyze_url, bb_scan, get_payloads,
    run_workflow, chat_assist, get_last_scan,
    expand_target, find_endpoints, find_params,
    run_workflow_express, run_workflow_bugbounty,
    run_workflow_subdomains, run_workflow_api,
    get_cache_status, clear_cache,
)

router = APIRouter(tags=["Security"])


class ChatRequest(BaseModel):
    question: str
    scan_result: Optional[dict] = None


# ── Core endpoints ────────────────────────────────────────────────────────────

@router.get("/recon")
def recon(domain: str = Query(..., description="Domain to recon, e.g. example.com")):
    """IP, DNS (A/MX/TXT/NS via DoH), SSL cert+SAN, headers, tech, smart_summary. Cached 10min."""
    if not domain:
        raise HTTPException(400, "domain is required.")
    result = recon_domain(domain)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@router.get("/analyze-url")
def analyze(url: str = Query(..., description="URL to analyze, e.g. https://example.com")):
    """Follow redirects, detect header misconfigs. Cached 5min."""
    if not url:
        raise HTTPException(400, "url is required.")
    return analyze_url(url)


@router.get("/bb-scan")
def bounty_scan(url: str = Query(..., description="Target URL for bug bounty recon")):
    """Probe 30+ paths concurrently (max_workers=12). Cached 5min."""
    if not url:
        raise HTTPException(400, "url is required.")
    return bb_scan(url)


@router.get("/payloads")
def payloads(
    type: str = Query(..., description="xss | sqli | lfi | ssrf | open_redirect | idor"),
    context: Optional[str] = Query(None, description="Filter by injection context"),
):
    """Categorized payloads with labels and context tags."""
    result = get_payloads(type, context)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@router.get("/expand")
def expand(domain: str = Query(..., description="Domain to enumerate subdomains for")):
    """Passive subdomain enumeration: crt.sh + hackertarget + SSL SAN. Cached 10min."""
    if not domain:
        raise HTTPException(400, "domain is required.")
    return expand_target(domain)


@router.get("/endpoints")
def endpoints(url: str = Query(..., description="Target URL to enumerate endpoints")):
    """Probe 60+ common paths. Tags each: api|admin|auth|sensitive|monitoring. Cached 5min."""
    if not url:
        raise HTTPException(400, "url is required.")
    return find_endpoints(url)


@router.get("/params")
def params(url: str = Query(..., description="Target URL to probe for injectable parameters")):
    """Probe 26 common params. Flags those producing different responses. Cached 5min."""
    if not url:
        raise HTTPException(400, "url is required.")
    return find_params(url)


@router.get("/workflow")
def workflow(target: str = Query(..., description="Domain or URL for full pipeline")):
    """
    Full 5-stage concurrent pipeline:
    Stage 1+2: recon + analyze-url (parallel)
    Stage 3+4+5: bb-scan + endpoints + params (parallel)
    Cached 5min.
    """
    if not target:
        raise HTTPException(400, "target is required.")
    return run_workflow(target)


@router.get("/last-scan")
def last_scan():
    """Returns most recent scan result from memory (TTL 1h)."""
    data = get_last_scan()
    if not data:
        raise HTTPException(404, "No scan results yet. Run /recon, /bb-scan, or /workflow first.")
    return data


@router.post("/chat-assist")
def chat(body: ChatRequest):
    """Rule-based assistant. Reads last-scan cache automatically."""
    if not body.question.strip():
        raise HTTPException(400, "question cannot be empty.")
    return chat_assist(body.question, body.scan_result)


# ── Workflow variants ─────────────────────────────────────────────────────────

@router.get("/workflows/express", tags=["Workflows"])
def workflow_express(target: str = Query(..., description="Domain or URL")):
    """
    Express workflow: recon + analyze-url only.
    Fast (~3-5s). Good for a quick first look.
    """
    if not target:
        raise HTTPException(400, "target is required.")
    return run_workflow_express(target)


@router.get("/workflows/full", tags=["Workflows"])
def workflow_full(target: str = Query(..., description="Domain or URL")):
    """Alias for /workflow — full 5-stage pipeline."""
    if not target:
        raise HTTPException(400, "target is required.")
    return run_workflow(target)


@router.get("/workflows/bugbounty", tags=["Workflows"])
def workflow_bugbounty(target: str = Query(..., description="Domain or URL")):
    """
    Bug bounty workflow: recon + bb-scan + auto-recommended payloads.
    Analyzes tech stack and found paths to recommend relevant payload types.
    """
    if not target:
        raise HTTPException(400, "target is required.")
    return run_workflow_bugbounty(target)


@router.get("/workflows/subdomains", tags=["Workflows"])
def workflow_subdomains(domain: str = Query(..., description="Domain to enumerate")):
    """
    Subdomain workflow: expand_target + recon on top 5 live subdomains.
    Returns expansion results + per-subdomain recon data.
    """
    if not domain:
        raise HTTPException(400, "domain is required.")
    return run_workflow_subdomains(domain)


@router.get("/workflows/api", tags=["Workflows"])
def workflow_api(url: str = Query(..., description="Target URL for API-focused scan")):
    """
    API scan workflow: endpoint enumeration + param probing (parallel).
    Tags endpoints by type, flags injectable parameters by risk level.
    """
    if not url:
        raise HTTPException(400, "url is required.")
    return run_workflow_api(url)


@router.post("/workflows/batch", tags=["Workflows"])
def workflow_batch(body: dict):
    """
    Batch workflow: run express workflow on multiple targets.
    Body: {"targets": ["example.com", "test.com"], "mode": "express"}
    Runs sequentially to avoid overloading. Max 5 targets.
    """
    targets = body.get("targets", [])
    if not targets:
        raise HTTPException(400, "targets list is required.")
    if len(targets) > 5:
        raise HTTPException(400, "Maximum 5 targets per batch.")

    results = {}
    for target in targets:
        try:
            results[target] = run_workflow_express(str(target))
        except Exception as e:
            results[target] = {"error": str(e)}

    return {
        "batch_size": len(targets),
        "results": results,
    }


@router.get("/workflows/cache/status", tags=["Workflows"])
def cache_status():
    """Returns current TTL cache stats: total, active, expired entries and active keys."""
    return get_cache_status()


@router.delete("/workflows/cache", tags=["Workflows"])
def cache_clear():
    """Clears all TTL cache entries. Forces fresh data on next request."""
    return clear_cache()