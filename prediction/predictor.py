"""
Loads the trained model + vectorizer and exposes a simple predict() function.
Falls back to the heuristic score (feature_extractor) if the model files are
missing, so the app never hard-crashes if training hasn't been run yet.
"""
import os
import joblib
import tldextract

from prediction.feature_extractor import extract_features, heuristic_risk_score
from prediction.trusted_domains import is_trusted_domain
from utils.helper import get_logger, normalize_url

logger = get_logger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "models", "vectorizer.pkl")

# Offline-only mode: never fetch the public suffix list over the network
# (avoids a slow/failing first request on a fresh deploy). tldextract
# ships a bundled snapshot that's used automatically as the fallback.
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

_model = None
_vectorizer = None
_load_attempted = False


def _load_artifacts():
    global _model, _vectorizer, _load_attempted
    _load_attempted = True
    try:
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
        logger.info("Loaded phishing model + vectorizer.")
    except FileNotFoundError:
        logger.warning(
            "Model/vectorizer not found at %s / %s. Run models/train_model.py "
            "or rely on heuristic-only scoring.",
            MODEL_PATH, VECTORIZER_PATH,
        )
        _model, _vectorizer = None, None


def predict(url: str) -> dict:
    """Return a dict with the verdict, probability, and supporting heuristics."""
    if not _load_attempted:
        _load_artifacts()

    url = normalize_url(url)
    features = extract_features(url)

    if _model is not None and _vectorizer is not None:
        # The model was trained on bare URLs without a scheme prefix
        # (the source dataset's URLs never include http(s)://), so the
        # scheme is stripped here to match that distribution — feeding a
        # scheme-prefixed string at inference time is out-of-distribution
        # for the model and produces unreliable predictions.
        vectorizer_input = normalize_url(url).split("://", 1)[-1]
        X = _vectorizer.transform([vectorizer_input])
        proba = _model.predict_proba(X)[0]
        # class 1 = phishing (see train_model.py label_bin encoding)
        phishing_proba = float(proba[1]) if len(proba) > 1 else float(proba[0])
        source = "ml_model"
    else:
        phishing_proba = heuristic_risk_score(features)
        source = "heuristic_fallback"

    verdict = "Phishing" if phishing_proba >= 0.5 else "Legitimate"

    # Trusted-domain allowlist override: a pure character-based model can
    # mistake a well-known brand name for a phishing indicator, since that
    # same substring also appears in real spoofed domains in the training
    # data (e.g. "paypal.com.resolvesecure.us"). If the URL's *actual*
    # registered domain matches a known-trusted entry, force the verdict
    # to Legitimate — the raw ML probability is still reported below for
    # transparency, it's just not the final word for these domains.
    extracted = _tld_extractor(url)
    registered_domain = extracted.top_domain_under_public_suffix
    allowlist_override = is_trusted_domain(registered_domain)
    if allowlist_override:
        verdict = "Legitimate"

    return {
        "url": url,
        "verdict": verdict,
        "probability": round(phishing_proba, 4),
        "source": source,
        "allowlist_override": allowlist_override,
        "features": features,
    }
