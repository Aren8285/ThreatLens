"""Local NLP triage via a pre-trained Hugging Face phishing-text classifier.

Model: aamoshdahal/email-phishing-distilbert-finetuned (DistilBERT, 67M params)
Label map (per the model card; config omits id2label):
    LABEL_0 = legitimate, LABEL_1 = phishing

Runs on CPU in a worker thread so we never block the FastAPI event loop.
Falls back to a lightweight keyword-heuristic scorer if transformers/torch are
unavailable or the model fails to load.
"""
from __future__ import annotations

import asyncio
import logging
import threading

logger = logging.getLogger("ml_triage")

try:
    from config import HF_MODEL_ID as _CFG_MODEL_ID, HF_MODEL_REVISION as _CFG_REV
except ImportError:
    _CFG_MODEL_ID = None
    _CFG_REV = "main"

MODEL_ID = _CFG_MODEL_ID or "aamoshdahal/email-phishing-distilbert-finetuned"
REVISION = _CFG_REV

# LABEL_0 -> legitimate, LABEL_1 -> phishing (per model card)
_LABEL_MAP = {"LABEL_0": "legitimate", "LABEL_1": "phishing"}
# Map each label to the probability weight we want (p_phishing)
_label_to_phishing = {"LABEL_0": 0.0, "LABEL_1": 1.0}

_classifier = None            # transformers pipeline, loaded lazily
_model_failed = False
_lock = threading.Lock()

# Fallback heuristic keyword weights (urgency, threats, money, authority ...)
_KEYWORDS = {
    "urgent": 3, "immediately": 3, "suspended": 3, "account locked": 4,
    "verify your account": 4, "confirm your identity": 4, "click here": 3,
    "act now": 3, "limited time": 2, "unusual activity": 4,
    "unauthorized": 3, "password": 2, "bank": 1, "wire transfer": 4,
    "gift card": 4, "bitcoin": 4, "crypto": 3, "payment failed": 4,
    "invoice attached": 4, "refund": 3, "winner": 3, "lottery": 4,
    "prince": 4, "inheritance": 4, "ssn": 4, "social security": 4,
    "irs": 3, "arrest warrant": 5, "refund pending": 4,
    "security alert": 4, "reset your password": 4,
    "your account has been": 4, "dear customer": 2, "dear user": 3,
    "final notice": 4, "24 hours": 2, "48 hours": 2, "click the link": 3,
    "login here": 4, "secure portal": 3, "marketing": 0,
}


def _load_pipeline():
    global _classifier, _model_failed
    if _classifier is not None or _model_failed:
        return _classifier
    with _lock:
        if _classifier is not None or _model_failed:
            return _classifier
        try:
            from transformers import pipeline

            _classifier = pipeline(
                "text-classification",
                model=MODEL_ID,
                revision=REVISION,
                device=-1,                     # CPU
                top_k=None,                    # get both labels' scores
                truncation=True,
                max_length=512,
            )
            logger.info("Loaded HF phishing classifier: %s", MODEL_ID)
        except Exception as exc:  # pragma: no cover - depends on pip install
            logger.warning("HF model load failed (%s) — using heuristic fallback", exc)
            _model_failed = True
    return _classifier


def predict_sync(text: str) -> dict:
    """Classify text. Returns {model, label, phishing_probability, confidence, engine}."""
    text = (text or "").strip()
    if not text:
        return {"model": "none", "label": "unknown", "phishing_probability": None,
                "confidence": None, "engine": "empty-input"}

    # Truncate to reasonable model input length (chars), model handles tokens.
    clean = " ".join(text.split())[:4000]

    pipe = _load_pipeline()
    if pipe is not None:
        try:
            results = pipe(clean)
            # transformers 4.50 with top_k=None returns [[{label,score},...]]
            # (list-wrapped dict / list-of-lists variants all collapsed here)
            while isinstance(results, list) and results and isinstance(results[0], list):
                results = results[0]
            if isinstance(results, dict):
                results = [results]
            p_phishing = 0.0
            for r in results:
                phish = _label_to_phishing.get(r["label"])
                if phish is not None and phish > 0:
                    p_phishing = float(r["score"])
                elif phish is not None and phish == 0:
                    p_phishing = 1.0 - float(r["score"])
            label = "phishing" if p_phishing >= 0.5 else "legitimate"
            return {
                "model": MODEL_ID,
                "label": label,
                "phishing_probability": round(p_phishing, 4),
                "confidence": round(max(p_phishing, 1.0 - p_phishing) * 100, 1),
                "engine": "transformers-distilbert",
            }
        except Exception as exc:
            logger.warning("transformers inference failed (%s) — falling back", exc)

    # Heuristic keyword fallback — weighted keyword sum, squashed to 0..1.
    low = clean.lower()
    raw = sum(w for kw, w in _KEYWORDS.items() if kw in low)
    # normalize: log-ish squashing — 0 -> 0, ~10+ matches -> ~0.99
    import math
    p = 1.0 - math.exp(-raw / 6.0)
    label = "phishing" if p >= 0.5 else "legitimate"
    return {
        "model": "keyword-heuristic-fallback",
        "label": label,
        "phishing_probability": round(p, 4),
        "confidence": round(max(p, 1 - p) * 100, 1),
        "engine": "heuristic-fallback",
    }


async def predict(text: str) -> dict:
    """Async wrapper — runs CPU-bound predict_sync in a thread executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, predict_sync, text)
