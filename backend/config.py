"""Application configuration — everything overridable via backend/.env."""
from __future__ import annotations
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")


def _get(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


# ------------------------------------------------------------------ API keys
GEMINI_API_KEY: str = _get("GEMINI_API_KEY") or _get("GOOGLE_API_KEY")
OPENAI_API_KEY: str = _get("OPENAI_API_KEY")
VIRUSTOTAL_API_KEY: str = _get("VIRUSTOTAL_API_KEY")
APIVOID_API_KEY: str = _get("APIVOID_API_KEY")

# ------------------------------------------------------------------- LLM
# Default model ids; override in .env if you want a different tier.
GEMINI_TEXT_MODEL: str = _get("GEMINI_TEXT_MODEL", "gemini-3.1-flash-lite")
GEMINI_VISION_MODEL: str = _get("GEMINI_VISION_MODEL", "gemini-3.1-flash-lite")
OPENAI_TEXT_MODEL: str = _get("OPENAI_TEXT_MODEL", "gpt-4o-mini")
OPENAI_VISION_MODEL: str = _get("OPENAI_VISION_MODEL", "gpt-4o-mini")
LLM_TEMPERATURE: float = float(_get("LLM_TEMPERATURE", "0.2"))

# ---------------------------------------------------------- local ML triage
HF_MODEL_ID: str = _get("HF_MODEL_ID", "aamoshdahal/email-phishing-distilbert-finetuned")
HF_MODEL_REVISION: str = _get("HF_MODEL_REVISION", "main")
HF_OFFLINE: bool = _get("HF_OFFLINE", "0") == "1"

# ------------------------------------------------------------- OSINT tuning
# VirusTotal public tier allows ~4 lookups/minute and ~500/day.
VT_RATE_PER_MINUTE: int = int(_get("VT_RATE_PER_MINUTE", "4"))
OSINT_MAX_LOOKUPS_PER_REQUEST: int = int(_get("OSINT_MAX_LOOKUPS_PER_REQUEST", "3"))
OSINT_TIMEOUT_SECONDS: float = float(_get("OSINT_TIMEOUT_SECONDS", "20"))


def llm_provider_available() -> str | None:
    """None if no LLM configured; else the provider name in priority order."""
    if GEMINI_API_KEY:
        return "gemini"
    if OPENAI_API_KEY:
        return "openai"
    return None


def api_status() -> dict:
    """Which external services are configured — surfaced to the UI."""
    return {
        "llm_provider": llm_provider_available(),
        "gemini": bool(GEMINI_API_KEY),
        "openai": bool(OPENAI_API_KEY),
        "virustotal": bool(VIRUSTOTAL_API_KEY),
        "apivoid": bool(APIVOID_API_KEY),
    }
