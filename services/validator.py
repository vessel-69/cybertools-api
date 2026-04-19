import re
import ipaddress
from fastapi import HTTPException

MAX_TEXT_LEN   = 500
MAX_DOMAIN_LEN = 253
MAX_URL_LEN    = 2048

_BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "metadata.google.internal", "169.254.169.254",
    "100.100.100.200", "100.64.0.1",
}

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_VALID_PAYLOAD_TYPES  = {"xss", "sqli", "lfi", "ssrf", "open_redirect", "idor"}
_VALID_HASH_ALGOS     = {"md5","sha1","sha256","sha384","sha512","sha3_256","sha3_512","blake2b","blake2s"}
_VALID_ENCODE_METHODS = {"base64", "hex", "url"}

_LABEL_RE      = re.compile(r"^(?!-)[a-zA-Z0-9\-]{1,63}(?<!-)$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HTML_RE       = re.compile(r"<[^>]{0,200}>")


def _reject(field: str, reason: str):
    raise HTTPException(422, f"Invalid {field}: {reason}")


def _is_private_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def _check_ssrf(host: str, field: str):
    h = host.lower().strip()
    if h in _BLOCKED_HOSTS:
        _reject(field, "target not allowed")
    if _is_private_ip(h):
        _reject(field, "private/reserved addresses not allowed")
    if re.match(r"^[0-9]+$", h) or re.match(r"^0x[0-9a-f]+$", h, re.IGNORECASE):
        _reject(field, "encoded IP addresses not allowed")


def clean_domain(raw: str, field: str = "domain") -> str:
    if not raw or not raw.strip():
        _reject(field, "cannot be empty")
    d = re.sub(r"^https?://", "", raw.strip(), flags=re.IGNORECASE)
    d = d.split("/")[0].split("?")[0].split("#")[0].lower()
    if len(d) > MAX_DOMAIN_LEN:
        _reject(field, f"exceeds {MAX_DOMAIN_LEN} characters")
    if _CONTROL_CHARS.search(d):
        _reject(field, "contains invalid characters")
    if ".." in d or "/" in d or "\\" in d:
        _reject(field, "contains invalid characters")
    host = d.split(":")[0]
    _check_ssrf(host, field)
    labels = host.split(".")
    if len(labels) < 2:
        _reject(field, "must be a valid domain e.g. example.com")
    for label in labels:
        if not label:
            _reject(field, "empty label (double dot)")
        if not _LABEL_RE.match(label):
            _reject(field, "invalid label format")
    return d


def clean_url(raw: str, field: str = "url") -> str:
    if not raw or not raw.strip():
        _reject(field, "cannot be empty")
    u = raw.strip()
    if len(u) > MAX_URL_LEN:
        _reject(field, f"exceeds {MAX_URL_LEN} characters")
    if _CONTROL_CHARS.search(u):
        _reject(field, "contains invalid characters")
    if not re.match(r"^https?://", u, re.IGNORECASE):
        if "://" in u:
            _reject(field, "only http and https schemes allowed")
        u = "https://" + u
    try:
        host = u.split("://", 1)[1].split("/")[0].split("?")[0].split(":")[0].lower()
    except Exception:
        _reject(field, "malformed URL")
    if not host:
        _reject(field, "missing host")
    _check_ssrf(host, field)
    return u


def clean_text(raw: str, field: str = "text", max_len: int = MAX_TEXT_LEN) -> str:
    if not raw:
        _reject(field, "cannot be empty")
    t = _CONTROL_CHARS.sub("", str(raw))
    t = _HTML_RE.sub("", t).strip()
    if not t:
        _reject(field, "empty after sanitisation")
    if len(t) > max_len:
        _reject(field, f"exceeds {max_len} characters")
    return t


def clean_payload_type(raw: str, field: str = "type") -> str:
    p = raw.strip().lower() if raw else ""
    if p not in _VALID_PAYLOAD_TYPES:
        _reject(field, f"must be one of {sorted(_VALID_PAYLOAD_TYPES)}")
    return p


def clean_hash_algo(raw: str, field: str = "algorithm") -> str:
    a = raw.strip().lower() if raw else ""
    if a not in _VALID_HASH_ALGOS:
        _reject(field, f"must be one of {sorted(_VALID_HASH_ALGOS)}")
    return a


def clean_encode_method(raw: str, field: str = "method") -> str:
    m = raw.strip().lower() if raw else ""
    if m not in _VALID_ENCODE_METHODS:
        _reject(field, f"must be one of {sorted(_VALID_ENCODE_METHODS)}")
    return m


def clean_ip(raw: str, field: str = "ip") -> str:
    r = raw.strip().lower() if raw else ""
    if not r:
        _reject(field, "cannot be empty")
    if r == "me":
        return "me"
    try:
        ipaddress.ip_address(r)
    except ValueError:
        _reject(field, "not a valid IP address")
    if _is_private_ip(r):
        _reject(field, "private/reserved addresses not allowed")
    return r


def clean_password(raw: str, field: str = "password") -> str:
    if not raw:
        _reject(field, "cannot be empty")
    p = _CONTROL_CHARS.sub("", str(raw))
    if len(p) > 1000:
        _reject(field, "exceeds 1000 characters")
    return p