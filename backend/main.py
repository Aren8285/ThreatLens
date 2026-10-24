"""FastAPI backend — Threat Intelligence & Phishing Analysis Dashboard.

Unified pipeline for both text and screenshot input:

    text ──┐
           ├─> [IOC extraction + defang] ──> (ML triage ‖ OSINT enrich) ──> [GenAI synthesis] ──> JSON report
    image ─┴─> [Vision LLM OCR / pytesseract fallback]

Run:
    backend/venv/bin/uvicorn main:app --reload --port 8000
"""
from __future__ import annotations

import asyncio
import base64
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import config
from services import llm, ml_triage, osint, synthesizer
from services.ioc_extractor import extract_iocs

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)-12s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("pipeshark")

app = FastAPI(
    title="ThreatLens — Phishing & Threat Intelligence API",
    version="1.0.0",
    description="Analyzes suspicious messages/screenshots: IOC extraction, "
                "OSINT enrichment, ML triage, GenAI synthesis.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    """One of `text` or `image_base64` must be present (image wins if both)."""
    text: Optional[str] = Field(None,
        description="Raw suspicious message text (email body, SMS, chat, etc.)")
    image_base64: Optional[str] = Field(None,
        description="Screenshot as base64 or data-URI. OCR is run automatically.")
    include_raw_text: bool = Field(True, description="Echo source text + OCR in response")


class AnalyzeResponse(BaseModel):
    # Final LLM report — matches the UI contract exactly
    verdict: str
    confidence_score: int
    psychological_analysis: dict
    osint_findings: str
    remediation_steps: list[str]
    attack_flowchart: str
    # Supporting pipeline evidence
    ml_triage: Optional[dict] = None
    osint_records: list[dict] = []
    iocs: list[dict] = []
    ocr_text: Optional[str] = None
    source_text: Optional[str] = None
    source_type: str = "text"
    llm_used: bool = False
    degraded: bool = False
    degradation_reason: Optional[str] = None
    api_status: dict = {}


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------
async def _ocr_from_image(image_b64: str) -> tuple[str, str]:
    """Vision LLM first (Gemini/OpenAI), pytesseract as secondary fallback."""
    uri = image_b64 if image_b64.startswith("data:") else f"data:image/png;base64,{image_b64}"
    # Rough size check (~8MB of base64)
    if len(uri) > 11_000_000:
        raise HTTPException(413, "Image too large (max ~8MB base64)")
    provider = config.llm_provider_available()
    if provider:
        logger.info("OCR via vision LLM provider=%s", provider)
        try:
            txt = await llm.vision_extract_text(uri)
            return txt.strip(), f"vision-llm/{provider}"
        except llm.LLMUnavailable as exc:
            logger.warning("Vision LLM OCR failed: %s", exc)
    # pytesseract fallback
    try:
        import pytesseract  # type: ignore
        from PIL import Image  # type: ignore
        from io import BytesIO
        img = Image.open(BytesIO(base64.b64decode(uri.split(",", 1)[-1])))
        txt = pytesseract.image_to_string(img)
        return txt.strip(), "pytesseract"
    except Exception as exc:
        raise HTTPException(
            422,
            f"No OCR engine available: {exc}. Configure GEMINI_API_KEY or "
            "OPENAI_API_KEY for vision OCR, or install pytesseract + tesseract binary.",
        )


async def run_pipeline(req: AnalyzeRequest) -> AnalyzeResponse:
    api_status = config.api_status()

    # ---- Stage 1: input handling -----------------------------------------
    source_type = "image"
    ocr_text = None
    text = (req.text or "").strip()

    if req.image_base64:
        ocr_text, engine = await _ocr_from_image(req.image_base64)
        text = text or ocr_text
        source_type = "image+text" if req.text and req.text.strip() else "image"
        logger.info("OCR done via %s (%d chars)", engine, len(ocr_text))
    if not text:
        raise HTTPException(400, "Provide either `text` or `image_base64`")

    # ---- Stage 2: IOC extraction + defang --------------------------------
    ioc_objs = extract_iocs(text)
    ioc_dicts = [i.as_dict() for i in ioc_objs]
    for d in ioc_dicts:
        d["notes"] = [n for n in d["notes"] if n]  # normalise
    logger.info("Extracted %d IOCs: %s", len(ioc_dicts),
                [(d['ioc_type'], d['defanged'][:50]) for d in ioc_dicts])

    # ---- Stage 3 + 4 concurrent: ML triage ‖ OSINT enrichment -------------
    ml_task = asyncio.create_task(ml_triage.predict(text))
    osint_task = asyncio.create_task(osint.enrich_iocs(ioc_dicts))
    ml, osint_records = await asyncio.gather(ml_task, osint_task, return_exceptions=True)
    if isinstance(ml, Exception):
        logger.warning("ML triage error: %s — continuing with None", ml)
        ml = {"model": "error", "label": "unknown", "phishing_probability": None,
              "confidence": None, "engine": "error"}
    if isinstance(osint_records, Exception):
        logger.warning("OSINT error: %s — continuing without enrichment", osint_records)
        osint_records = [{**d, "lookups": [], "overall": "lookup_failed"} for d in ioc_dicts]

    osint_sum = osint.osint_summary_for_llm(osint_records) if osint_records else \
        "NO OSINT data available (no IOC lookups succeeded or no keys configured)."

    # ---- Stage 5: GenAI synthesis ----------------------------------------
    report = await synthesizer.synthesize(text, ml, osint_records, osint_sum)

    resp = AnalyzeResponse(
        verdict=report["verdict"],
        confidence_score=report["confidence_score"],
        psychological_analysis=report["psychological_analysis"],
        osint_findings=report["osint_findings"],
        remediation_steps=report["remediation_steps"],
        attack_flowchart=report["attack_flowchart"],
        ml_triage=ml,
        osint_records=osint_records,
        iocs=ioc_dicts,
        ocr_text=ocr_text,
        source_text=text if req.include_raw_text else None,
        source_type=source_type,
        llm_used=report.get("llm_used", False),
        degraded=report.get("degraded", False),
        degradation_reason=report.get("degradation_reason"),
        api_status=api_status,
    )
    return resp


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "app": "ThreatLens",
        "api_status": config.api_status(),
        "capabilities": {
            "llm_synthesis": llm.PROVIDER is not None,
            "vision_ocr": llm.PROVIDER == "gemini" or llm.PROVIDER == "openai",
            "local_ml_model": not ml_triage._model_failed,
            "osint": bool(config.VIRUSTOTAL_API_KEY or config.APIVOID_API_KEY),
        },
    }


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    """Full analysis pipeline: OCR → IOC extract+defang → ML triage ‖ OSINT → LLM synthesis."""
    try:
        return await run_pipeline(req)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Analyze pipeline crashed")
        raise HTTPException(500, f"Analysis pipeline error: {exc}")


@app.post("/api/ocr")
async def ocr_only(req: AnalyzeRequest):
    """Extract text from a screenshot and IOC-defang it, without the full pipeline."""
    if not req.image_base64:
        raise HTTPException(400, "image_base64 required")
    txt, engine = await _ocr_from_image(req.image_base64)
    ioc_objs = extract_iocs(txt)
    return {
        "engine": engine,
        "ocr_text": txt,
        "iocs": [i.as_dict() for i in ioc_objs],
    }


# If the frontend was built (npm run build → dist/), serve it statically.
_FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIST), html=True),
              name="frontend")
    logger.info("Serving frontend build from %s", _FRONTEND_DIST)


# Standard-color CLI entry
def _main():  # pragma: no cover
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)


if __name__ == "__main__":  # pragma: no cover
    _main()

