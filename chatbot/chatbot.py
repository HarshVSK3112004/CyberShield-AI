"""
FAQ chatbot for cybersecurity/phishing questions.

By default this uses lightweight rule-based keyword matching against
intents.json (no external calls, no API key required). If a Gemini API key
is configured, it upgrades to real AI-generated answers instead, and falls
back to the rule-based matcher automatically if the Gemini call fails or no
key is set — mirroring the same optional-integration pattern used by
security/virustotal.py.

To enable Gemini:
  1. Get a free API key from https://aistudio.google.com/apikey
     (Google now issues "auth" keys starting with AQ. rather than the older
     AIza... format — either works with this code, since auth is sent via
     the x-goog-api-key header, not a query parameter.)
  2. Add to your .env file:  GEMINI_API_KEY=your_key_here
  (optional) GEMINI_MODEL=gemini-3.6-flash   # defaults to this if unset
  (Google retired gemini-2.5-flash for the free/dev tier on Oct 16, 2026 —
  if a 404 ever comes back mentioning a newer model, update the default
  above and/or set GEMINI_MODEL in .env to override without a code change.)
"""
import json
import os
import random
import re
from typing import Optional

import requests
from dotenv import load_dotenv

from utils.helper import get_logger

load_dotenv()
logger = get_logger(__name__)

_INTENTS_PATH = os.path.join(os.path.dirname(__file__), "intents.json")

with open(_INTENTS_PATH, "r", encoding="utf-8") as f:
    _INTENTS_DATA = json.load(f)["intents"]

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
GEMINI_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)

SYSTEM_PROMPT = (
    "You are the built-in cybersecurity assistant inside CyberShield-AI, a "
    "phishing-detection web app. Answer any question related to "
    "cybersecurity, at a conceptual/educational level — including but not "
    "limited to: attack types and their patterns (phishing, malware, "
    "ransomware, spyware, viruses, worms, DDoS, SQL injection, XSS, "
    "man-in-the-middle, social engineering, zero-days); well-known security "
    "tools and what they're used for (Nmap, Wireshark, Metasploit, Burp "
    "Suite, Nessus, John the Ripper, Kali Linux); frameworks and standards "
    "(OWASP Top 10, MITRE ATT&CK, NIST, CVE/CWE); network and infra security "
    "(firewalls, VPNs, IDS/IPS, encryption, SSL/TLS); identity and access "
    "(passwords, 2FA/MFA, authentication); incident response and threat "
    "actors; WHOIS/domain reputation; and cybersecurity career/certification "
    "guidance. Explain how attacks and tools work conceptually so the user "
    "understands and can defend against them — do not provide step-by-step "
    "exploit code, working malware, or specific attack instructions against "
    "a real, named target. Keep answers concise (2-5 sentences unless the "
    "user asks for more detail), practical, and beginner-friendly. If a "
    "question is clearly unrelated to cybersecurity or online safety (e.g. "
    "cooking, sports, general trivia), politely redirect the user back to "
    "those topics instead of answering it."
)


# ---------------- Rule-based matcher (default / fallback) ---------------- #

# Common filler words that shouldn't count toward a topic match on their own
# (e.g. "what is ransomware" shouldn't match the "what is phishing" pattern
# just because both share "what"/"is").
_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "do", "does",
    "for", "how", "i", "if", "in", "is", "it", "of", "on", "or", "should",
    "site", "that", "the", "this", "to", "was", "what", "when", "where",
    "why", "will", "with", "you", "your",
}


def _tokenize(text: str, drop_stopwords: bool = False) -> set:
    tokens = set(re.findall(r"[a-z0-9']+", text.lower()))
    if drop_stopwords:
        tokens -= _STOPWORDS
    return tokens


def _rule_based_response(user_input: str) -> str:
    """Keyword-overlap matcher against intents.json. No network calls.

    Matching is done on meaningful (non-stopword) tokens only, so a query
    like "what is ransomware" doesn't falsely match a "what is phishing"
    pattern just because they share filler words like "what"/"is".
    """
    user_tokens = _tokenize(user_input, drop_stopwords=True)
    best_score = 0
    best_intent = None

    for intent in _INTENTS_DATA:
        if intent["tag"] == "fallback":
            continue
        for pattern in intent["patterns"]:
            pattern_tokens = _tokenize(pattern, drop_stopwords=True)
            if not pattern_tokens:
                continue
            overlap = len(user_tokens & pattern_tokens)
            score = overlap / len(pattern_tokens)
            if score > best_score:
                best_score = score
                best_intent = intent

    if best_intent and best_score >= 0.5:
        return random.choice(best_intent["responses"])

    fallback = next((i for i in _INTENTS_DATA if i["tag"] == "fallback"), None)
    return fallback["responses"][0] if fallback else "I'm not sure how to answer that."


# ---------------- Gemini-backed responder (optional) ---------------- #

_last_gemini_error: Optional[str] = None  # for temporary CHATBOT_DEBUG diagnostics


def _gemini_response(user_input: str, timeout: float = 15.0) -> Optional[str]:
    """Call the Gemini API. Returns None on any failure so the caller can
    fall back to the rule-based matcher instead of erroring out."""
    global _last_gemini_error

    if not GEMINI_API_KEY:
        _last_gemini_error = "GEMINI_API_KEY is not set in this environment"
        return None

    payload = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_input}]}],
        "generationConfig": {
            # Gemini 3.x "thinking" tokens count against maxOutputTokens even
            # though they're never shown, so this needs real headroom above
            # what the visible answer alone would need, or replies truncate
            # mid-sentence. "minimal" thinking keeps latency/cost down for a
            # straightforward FAQ bot that doesn't need deep reasoning.
            "maxOutputTokens": 1024,
            "thinkingConfig": {"thinkingLevel": "minimal"},
        },
    }

    try:
        resp = requests.post(
            GEMINI_URL,
            headers={
                "x-goog-api-key": GEMINI_API_KEY,
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        candidates = data.get("candidates", [])
        if not candidates:
            logger.warning("Gemini returned no candidates for input: %r", user_input)
            _last_gemini_error = f"200 OK but no candidates: {data}"
            return None

        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts).strip()
        if not text:
            _last_gemini_error = f"200 OK but empty text, parts={parts}"
        return text or None

    except requests.exceptions.RequestException as e:
        logger.warning("Gemini API call failed, falling back to rule-based: %s", e)
        body = getattr(getattr(e, "response", None), "text", "")
        _last_gemini_error = f"{e} | body={body[:300]}"
        return None
    except (KeyError, IndexError, ValueError) as e:
        logger.warning("Unexpected Gemini response shape, falling back: %s", e)
        _last_gemini_error = f"Unexpected response shape: {e}"
        return None


# ---------------- Public entry point ---------------- #

def get_response(user_input: str) -> str:
    """Return a chatbot reply for the given user input.

    Uses Gemini if GEMINI_API_KEY is configured and the call succeeds;
    otherwise (or on any failure) falls back to the rule-based matcher.
    """
    if not user_input or not user_input.strip():
        return "Please type a question about phishing or online safety."

    if GEMINI_API_KEY:
        ai_reply = _gemini_response(user_input)
        if ai_reply:
            return ai_reply
        # fell through: key configured but call failed -> use rule-based

    fallback_text = _rule_based_response(user_input)

    # TEMPORARY diagnostic: set CHATBOT_DEBUG=1 as a secret/env var to see
    # exactly why Gemini isn't being used, right inside the chat reply.
    # Remove the CHATBOT_DEBUG secret once this is confirmed working.
    if os.getenv("CHATBOT_DEBUG"):
        key_status = "SET" if GEMINI_API_KEY else "NOT SET"
        fallback_text += f"\n\n[DEBUG] GEMINI_API_KEY: {key_status} | last_error: {_last_gemini_error}"

    return fallback_text
