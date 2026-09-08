"""
Shared helper utilities used across the CyberShield-AI app.
"""
import re
import logging
from urllib.parse import urlparse

import validators
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def get_logger(name: str) -> logging.Logger:
    """Return a module-level logger."""
    return logging.getLogger(name)


def is_valid_url(url: str) -> bool:
    """Check whether the given string is a syntactically valid URL."""
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    # Allow bare domains like "example.com" by adding a scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return bool(validators.url(url))


def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme (http/https) prefixed."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def extract_domain(url: str) -> str:
    """Extract just the domain (netloc) from a URL."""
    url = normalize_url(url)
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def is_valid_email(email: str) -> bool:
    """Check whether the given string is a syntactically valid email address."""
    if not email or not isinstance(email, str):
        return False
    return bool(validators.email(email.strip()))


# ---------------- Password hashing (Argon2id) ---------------- #
#
# Argon2id is the OWASP-recommended password hashing algorithm: it is
# deliberately slow (memory-hard), and PasswordHasher() generates a unique
# random salt per call automatically — unlike a bare SHA-256 hash, which is
# fast to compute (bad for passwords) and, if a static salt is reused across
# every user, means one leaked salt weakens every account at once.

_ph = PasswordHasher()  # sensible defaults: time_cost=3, memory_cost=64MB, parallelism=4


def hash_password(password: str) -> str:
    """Hash a password with Argon2id. Returns an encoded hash string that
    already embeds the algorithm parameters and a random salt — nothing
    else needs to be stored alongside it."""
    return _ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored Argon2id hash.
    Returns False (rather than raising) on a wrong password, a corrupted
    hash, or a hash produced by a different/older scheme."""
    try:
        return _ph.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def risk_label(score: float) -> str:
    """Convert a 0-1 phishing probability into a human-readable risk label."""
    if score >= 0.75:
        return "🔴 High Risk"
    elif score >= 0.45:
        return "🟠 Medium Risk"
    else:
        return "🟢 Low Risk"