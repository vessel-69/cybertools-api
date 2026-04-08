from fastapi import APIRouter, HTTPException, Query
from services.recon import recon_domain, analyze_url, bb_scan, get_payloads

router = APIRouter(tags=["Security"])


@router.get("/recon")
def recon(domain: str = Query(..., description="Domain to recon, e.g. example.com")):
    """
    Recon a domain: resolves IP, probes HTTP headers, detects tech stack,
    identifies missing security headers, and returns a smart_summary.
    """
    if not domain:
        raise HTTPException(status_code=400, detail="domain is required.")
    return recon_domain(domain)


@router.get("/analyze-url")
def analyze(url: str = Query(..., description="Full URL to analyze, e.g. https://example.com")):
    """
    Analyze a URL: follows redirects, checks headers for misconfigurations,
    and returns security findings with a smart_summary.
    """
    if not url:
        raise HTTPException(status_code=400, detail="url is required.")
    return analyze_url(url)


@router.get("/bb-scan")
def bounty_scan(url: str = Query(..., description="Target URL for bug bounty recon")):
    """
    Bug bounty recon: probes common sensitive paths (/admin, /.env, /api, etc.),
    returns non-404 findings and actionable bug bounty hints.
    """
    if not url:
        raise HTTPException(status_code=400, detail="url is required.")
    return bb_scan(url)


@router.get("/payloads")
def payloads(type: str = Query(..., description="Payload type: xss | sqli | lfi | ssrf")):
    """
    Returns categorized attack payloads for security testing.
    Types: xss, sqli, lfi, ssrf
    """
    result = get_payloads(type)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result