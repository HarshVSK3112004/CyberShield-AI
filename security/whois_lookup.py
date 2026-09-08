"""
WHOIS domain lookup — registrar, creation date, expiration date, domain age.
"""
from datetime import datetime
 
import whois  # python-whois package
 
from utils.helper import extract_domain, get_logger
 
logger = get_logger(__name__)
 
 
def _first(value):
    """python-whois sometimes returns a list for date fields; normalize to one value."""
    if isinstance(value, list):
        return value[0] if value else None
    return value
 
 
def _to_naive(dt):
    """Strip timezone info if present, so date math never mixes naive/aware
    datetimes. Some registrars return timezone-aware creation/expiry dates,
    others don't — this normalizes either case to naive UTC-ish datetime."""
    if isinstance(dt, datetime) and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt
 
 
def get_whois(url: str) -> dict:
    domain = extract_domain(url)
    domain = domain.split(":")[0]
 
    result = {
        "domain": domain,
        "registrar": None,
        "created_on": None,
        "expires_on": None,
        "domain_age_days": None,
        "error": None,
    }
 
    if not domain:
        result["error"] = "Could not determine domain from URL."
        return result
 
    try:
        w = whois.whois(domain)
        created = _to_naive(_first(w.creation_date))
        expires = _to_naive(_first(w.expiration_date))
 
        result["registrar"] = w.registrar
        if isinstance(created, datetime):
            result["created_on"] = created.strftime("%Y-%m-%d")
            result["domain_age_days"] = (datetime.utcnow() - created).days
        if isinstance(expires, datetime):
            result["expires_on"] = expires.strftime("%Y-%m-%d")
 
        if not w.registrar and not created:
            result["error"] = "No WHOIS record found (domain may be new, private, or invalid)."
 
    except Exception as e:  # noqa: BLE001
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)
        result["error"] = str(e)
 
    return result
 
