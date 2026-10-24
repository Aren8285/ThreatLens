"""LLM provider abstraction — Google Gemini first, OpenAI fallback.

Both text generation (GenAI synthesis) and vision/OCR go through here.
Provider is auto-detected from configured keys; every function is fully async
so the FastAPI pipeline can fan out LLM + OSINT + ML calls under one event loop.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re

import httpx

import config

logger = logging.getLogger("llm")

_TIMEOUT = httpx.Timeout(90.0, connect=15.0)


class LLMUnavailable(Exception):
    """Raised when no LLM provider is configured or reachable."""


PROVIDER = config.llm_provider_available()  # 'gemini' | 'openai' | None


async def generate(prompt: str, system: str = "", temperature: float | None = None) -> str:
    """Generate text via the configured providers (Gemini first, OpenAI fallback).

    Each configured provider is tried in priority order; the first success wins.
    Raises LLMUnavailable only when every configured provider fails (or none
    configured).
    """
    temp = config.LLM_TEMPERATURE if temperature is None else temperature
    errors: list[str] = []
    for provider in _available_providers():
        try:
            if provider == "gemini":
                return await _gemini_generate(prompt, system, temp)
            return await _openai_generate(prompt, system, temp)
        except LLMUnavailable as exc:
            logger.warning("LLM provider %s failed: %s — trying next", provider, exc)
            errors.append(f"{provider}: {exc}")
    if errors:
        raise LLMUnavailable(" | ".join(errors))
    raise LLMUnavailable("No LLM provider key configured (GEMINI_API_KEY or OPENAI_API_KEY)")


async def vision_extract_text(image_data_uri: str, hint: str = "") -> str:
    """Extract visible text from an image (OCR via vision LLM)."""
    prompt = (
        "You are an OCR engine for a cybersecurity triage application. Extract ALL "
        "text visible in this screenshot as plain text, preserving the order in "
        "which it appears, including sender/subject lines, URLs, phone numbers, "
        "crypto wallet addresses and any UI chrome text. Output ONLY the extracted "
        "text, no commentary, no markdown formatting.\n"
        + (f"Additional hint: {hint}" if hint else "")
    )
    errors: list[str] = []
    for provider in _available_providers():
        try:
            if provider == "gemini":
                return await _gemini_vision(image_data_uri, prompt)
            return await _openai_vision(image_data_uri, prompt)
        except LLMUnavailable as exc:
            logger.warning("Vision provider %s failed: %s — trying next", provider, exc)
            errors.append(f"{provider}: {exc}")
    if errors:
        raise LLMUnavailable(" | ".join(errors))
    raise LLMUnavailable("No LLM provider key configured — vision OCR unavailable")


def _available_providers() -> list[str]:
    """Provider priority chain, filtered by which keys are present."""
    out: list[str] = []
    if config.GEMINI_API_KEY:
        out.append("gemini")
    if config.OPENAI_API_KEY:
        out.append("openai")
    return out


# --------------------------------------------------------------------------
# Google Gemini
# --------------------------------------------------------------------------
async def _gemini_generate(prompt: str, system: str, temperature: float) -> str:
    model = config.GEMINI_TEXT_MODEL
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={config.GEMINI_API_KEY}"
    )
    body: dict = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temperature, "maxOutputTokens": 4096},
    }
    if system:
        body["system_instruction"] = {"parts": [{"text": system}]}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        r = await client.post(url, json=body)
        if r.status_code != 200:
            detail = r.text[:400]
            raise LLMUnavailable(f"Gemini API error {r.status_code}: {detail}")
        data = r.json()
        parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts)
        if not text.strip():
            raise LLMUnavailable(f"Gemini returned empty content: {json.dumps(data)[:400]}")
        return text


async def _gemini_vision(image_data_uri: str, prompt: str) -> str:
    model = config.GEMINI_VISION_MODEL
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={config.GEMINI_API_KEY}"
    )
    header, b64 = _split_data_uri(image_data_uri)
    mime = header or "image/png"
    body = {
        "contents": [{
            "role": "user",
            "parts": [
                {"text": prompt},
                {"inline_data": {"mimeType": mime, "data": b64}},
            ],
        }],
        "generationConfig": {"temperature": 0.0, "maxOutputTokens": 2048},
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        r = await client.post(url, json=body)
        if r.status_code != 200:
            raise LLMUnavailable(f"Gemini Vision error {r.status_code}: {r.text[:400]}")
        data = r.json()
        parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts)


# --------------------------------------------------------------------------
# OpenAI
# --------------------------------------------------------------------------
async def _openai_generate(prompt: str, system: str, temperature: float) -> str:
    url = "https://api.openai.com/v1/chat/completions"
    messages = ([{"role": "system", "content": system}] if system else []) + [
        {"role": "user", "content": prompt}
    ]
    body = {
        "model": config.OPENAI_TEXT_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": 4096,
        "response_format": {"type": "json_object"},
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        r = await client.post(url, headers=_oai_headers(), json=body)
        if r.status_code != 200:
            raise LLMUnavailable(f"OpenAI API error {r.status_code}: {r.text[:400]}")
        return r.json()["choices"][0]["message"]["content"]


async def _openai_vision(image_data_uri: str, prompt: str) -> str:
    url = "https://api.openai.com/v1/chat/completions"
    body = {
        "model": config.OPENAI_VISION_MODEL,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": image_data_uri}},
            ],
        }],
        "max_tokens": 2048,
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        r = await client.post(url, headers=_oai_headers(), json=body)
        if r.status_code != 200:
            raise LLMUnavailable(f"OpenAI Vision error {r.status_code}: {r.text[:400]}")
        return r.json()["choices"][0]["message"]["content"]


def _oai_headers() -> dict:
    return {"Authorization": f"Bearer {config.OPENAI_API_KEY}"}


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------
def _split_data_uri(uri: str) -> tuple[str | None, str]:
    """Returns (mime, base64 payload). Accepts raw base64 too."""
    m = re.match(r"^data:([^;]+);base64,(.*)$", uri, re.S)
    if m:
        return m.group(1), m.group(2)
    # If not a data URI, assume it's already base64 — sniff type from header
    try:
        head = base64.b64decode(uri[:32]).lower()
        for sig, mime in ((b"\x89png", "image/png"), (b"\xff\xd8", "image/jpeg"),
                          (b"gif", "image/gif"), (b"RIFF", "image/webp"),
                          (b"BM", "image/bmp")):
            if head.startswith(sig):
                return mime, uri
    except Exception:
        pass
    return "image/png", uri  # best guess (Gemini infers fine)


def extract_json(text: str) -> dict | None:
    """Pull the first JSON object out of an LLM response, tolerating fences."""
    if not text:
        return None
    # Direct parse attempt
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Strip markdown fences
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass
    # First balanced {...} block
    depth = 0
    start = text.find("{")
    if start == -1:
        return None
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    break
    return None
