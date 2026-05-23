# this file contains service-probe and TLS formatting helpers


import re
from datetime import datetime
from typing import Dict, List, Optional

from .builders import _clean_text
from .constants import (
    HTTP_TITLE_MAX,
    SSH_PROBE_PORTS,
    TLS_WEB_PORTS,
    WEB_PORTS,
    WEB_SVC_HINTS,
)


def should_try_http_probe(port: int, guessed_svc: str, guess_source: str) -> bool:
    low = guessed_svc.lower()
    if port in WEB_PORTS or port in TLS_WEB_PORTS:
        return True
    if port in SSH_PROBE_PORTS or low == "ssh":
        return False
    if any(hint in low for hint in WEB_SVC_HINTS):
        return True
    if port >= 1024 and guess_source != "builtin":
        return True
    return False


def has_http_probe_signal(res) -> bool:
    if res.err is not None:
        return False
    raw = (res.raw or "").lstrip().lower()
    info = (res.info or "").lower()
    return (
        raw.startswith("http/")
        or "http/" in info
        or "title:" in info
        or "server:" in info
        or "cf-ray" in info
        or "redirect" in info
    )


def extract_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return _clean_text(match.group(1), HTTP_TITLE_MAX)


def _flatten_cert_name(parts) -> Dict[str, str]:
    flat: Dict[str, str] = {}
    for item in parts or ():
        for key, value in item:
            flat[key] = value
    return flat


def _fmt_cert_date(raw: str) -> str:
    if not raw:
        return ""
    normalized = re.sub(r"\s+", " ", raw.strip())
    try:
        return datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z").strftime(
            "%Y-%m-%d"
        )
    except ValueError:
        return normalized


def tls_cert_bits(cert: Optional[Dict[str, object]]) -> List[str]:
    if not cert:
        return []

    bits: List[str] = []
    subject = _flatten_cert_name(cert.get("subject"))
    common_name = subject.get("commonName", "")
    if common_name:
        bits.append(f"TLS CN: {_clean_text(common_name, 80)}")

    san = cert.get("subjectAltName") or []
    dns_names = [value for kind, value in san if kind.lower() == "dns"]
    if dns_names:
        first = _clean_text(dns_names[0], 80)
        if len(dns_names) > 1:
            bits.append(f"TLS SAN: {first} (+{len(dns_names) - 1})")
        elif first != common_name:
            bits.append(f"TLS SAN: {first}")

    expires = _fmt_cert_date(str(cert.get("notAfter", "")).strip())
    if expires:
        bits.append(f"TLS Expires: {expires}")
    return bits

