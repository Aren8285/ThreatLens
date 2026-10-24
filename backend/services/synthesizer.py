"""GenAI synthesis — the final pipeline stage.

Feeds raw text + ML triage score + OSINT findings into the configured LLM with
a strict system prompt requiring a specific JSON schema output. Validates and
repairs the LLM's JSON; when no LLM is configured, generates a degraded
(but structurally valid) rule-based report so the UI still renders.
"""
from __future__ import annotations

import logging
import re

from . import llm

logger = logging.getLogger("synth")

SYSTEM_PROMPT = """You are a senior cyber-threat analyst producing reports for a \
Security Operations Center triage dashboard. You are given:
1. The raw suspicious message text (possibly extracted via OCR from a screenshot).
2. The output of a local NLP phishing classifier (a mathematical phishing probability).
3. OSINT enrichment results from threat-intelligence APIs (VirusTotal / APIVoid) \
for the extracted IOCs (URLs, domains, IPs, crypto wallet addresses).
4. Regex/parser notes about the IOCs (e.g. brand keywords in the URL path).

Your job: synthesise ALL of this evidence into a single final verdict report.
Weigh the evidence yourself — the ML score and OSINT data are strong signals but \
not absolute truth; use your contextual judgment. Be brutally honest: if there \
is insufficient evidence, lower the confidence score instead of guessing.

STRICT OUTPUT RULES:
- Output ONLY one JSON object. No markdown, no code fences, no commentary.
- Every field listed in the schema is mandatory.
- "attack_flowchart" MUST be a single valid Mermaid.js flowchart definition, \
starting with the exact line "flowchart TD" and containing no markdown fences.
- Never include live URLs. Use the defanged forms exactly as provided to you.
- Do not invent OSINT data that was not provided. If OSINT returned nothing, \
say so in osint_findings.

JSON SCHEMA:
{
  "verdict": "High Risk Threat" | "Suspicious" | "Safe / False Positive",
  "confidence_score": <integer 0-100, your aggregated confidence in the verdict>,
  "psychological_analysis": {
    "summary": "<1-3 sentence overview of the social-engineering intent>",
    "tactics": [
      {"name": "<e.g. Urgency, Authority Spoofing, Fear, Greed, Curiosity>",
       "evidence": "<quote or paraphrase from the message>",
       "severity": "critical" | "high" | "medium" | "low" | "none"}
    ]
  },
  "osint_findings": "<multi-line plain-text summary of what the threat intel \
APIs found for each IOC, including engine counts, and any IOCs that could not \
be checked and why>",
  "remediation_steps": ["<actionable step 1>", "<step 2>", ...],
  "attack_flowchart": "<Mermaid flowchart string>"
}

FLOWCHART REQUIREMENTS:
- If the verdict is a threat ("High Risk Threat" or "Suspicious"): map the \
attack along the Cyber Kill Chain: Delivery -> Execution -> Exploitation -> \
Installation -> Blast Radius / Impact. Label each stage with a concrete detail \
from THIS message (e.g. delivery vector "email from IT support", execution \
"victim clicks credential-harvesting page", blast radius "email account takeover, \
lateral phishing, financial fraud"). Include mitigations as terminal nodes where \
natural (e.g. "Report to SOC", "Password reset").
- If the verdict is "Safe / False Positive": map the benign verification flow \
that proves safety (e.g. "Message reviewed" -> "Sender domain verified" -> \
"VirusTotal reports 0/90 malicious" -> "ML classifier: legitimate" -> "No action \
needed :normal arrow to 'Legitimate communication'").
- Use ASCII-only node ids (A, B, C1...), quotes around labels containing spaces \
or special chars, no parentheses inside unquoted labels, keep it under 25 lines."""

MAX_LLM_ATTEMPTS = 2

_VALID_VERDICTS = {"High Risk Threat", "Suspicious", "Safe / False Positive"}


def build_user_prompt(text: str, ml: dict, osint_records: list[dict],
                      osint_sum: str, ioc_notes: str) -> str:
    ml_block = (
        "ML TRIAGE:\n"
        f"  model: {ml.get('model')}\n"
        f"  label: {ml.get('label')}\n"
        f"  phishing_probability: {ml.get('phishing_probability')}\n"
        f"  classifier_confidence: {ml.get('confidence')}\n"
    ) if ml.get("phishing_probability") is not None else "ML TRIAGE: unavailable"

    osint_block = f"OSINT ENRICHMENT:\n{osint_sum}"

    iocs_block = ioc_notes or "No IOCs extracted."

    payload = (
        "MESSAGE TEXT (verbatim):\n"
        f"\"\"\"\n{text[:6000]}\n\"\"\"\n\n"
        f"{ml_block}\n\n"
        f"{osint_block}\n\n"
        f"EXTRACTED IOCs (defanged):\n{iocs_block}\n\n"
        "Produce the final JSON report now."
    )
    return payload


def _flatten_ioc_notes(osint_records: list[dict]) -> str:
    lines = []
    for rec in osint_records:
        notes = "; ".join(rec.get("notes", []))
        look = " | ".join(
            f"{l.get('provider')}: {l.get('verdict') or ('present' if l.get('present') else 'no-record')}"
            for l in rec.get("lookups", [])
        ) or "no lookups"
        lines.append(
            f"- [{rec['ioc_type']}] {rec.get('defanged')} — notes: {notes or '—'}; lookups: {look}"
        )
    return "\n".join(lines) if lines else ""


def _validate_mermaid(s: str) -> str | None:
    if not s:
        return None
    s = s.strip()
    s = re.sub(r"^```(?:mermaid)?\s*", "", s, flags=re.M)
    s = re.sub(r"\s*```$", "", s, flags=re.M).strip()
    if not re.match(r"^(flowchart|graph)", s):
        return None
    return s


async def synthesize(text: str, ml: dict, osint_records: list[dict],
                     osint_sum: str) -> dict:
    """Returns the final report dict matching the UI contract."""
    prompt = build_user_prompt(
        text, ml, osint_records, osint_sum, _flatten_ioc_notes(osint_records)
    )

    llm_error = None
    try:
        raw = await llm.generate(prompt, system=SYSTEM_PROMPT)
        report = llm.extract_json(raw)
        if report:
            report = _sanitise_report(report)
            if report is not None:
                report["llm_used"] = True
                report["degraded"] = False
                return report
            llm_error = "LLM returned fields that failed schema validation"
        else:
            llm_error = "LLM returned unparseable JSON"
        # One retry with corrective nudge
        retry = await llm.generate(
            prompt + "\n\nREMINDER: output ONLY the JSON object per the schema. "
            "attack_flowchart must start with 'flowchart TD'.",
            system=SYSTEM_PROMPT,
        )
        report = llm.extract_json(retry)
        if report:
            report = _sanitise_report(report)
            if report is not None:
                report["llm_used"] = True
                report["degraded"] = False
                return report
    except llm.LLMUnavailable as exc:
        llm_error = str(exc)
    except Exception as exc:  # network errors etc.
        logger.exception("Synthesis failed")
        llm_error = f"LLM call failed: {exc}"

    report = _rule_based_report(text, ml, osint_records, osint_sum, llm_error)
    report["degraded"] = True
    report["degradation_reason"] = llm_error or "LLM output failed validation"
    report["llm_used"] = False
    return report


def _sanitise_report(r: dict) -> dict | None:
    if not isinstance(r, dict):
        return None
    verdict = str(r.get("verdict", "")).strip()
    # Normalise common LLM variants
    for best in _VALID_VERDICTS:
        if verdict.lower() == best.lower():
            verdict = best
    if verdict not in _VALID_VERDICTS:
        low = verdict.lower()
        if "high" in low or "threat" in low or "phish" in low:
            verdict = "High Risk Threat"
        elif "susp" in low:
            verdict = "Suspicious"
        elif any(k in low for k in ("safe", "legitimate", "false")):
            verdict = "Safe / False Positive"
        else:
            return None
    try:
        conf = int(float(r.get("confidence_score", 0)))
    except (TypeError, ValueError):
        return None
    conf = max(0, min(100, conf))

    psych = r.get("psychological_analysis") or {}
    tactics = psych.get("tactics") or []
    if isinstance(tactics, str):
        tactics = [tactics]
    clean_tactics = []
    for t in tactics:
        if isinstance(t, str):
            clean_tactics.append({"name": t, "evidence": "", "severity": "medium"})
        elif isinstance(t, dict) and t.get("name"):
            clean_tactics.append({
                "name": str(t["name"])[:120],
                "evidence": str(t.get("evidence", ""))[:400],
                "severity": str(t.get("severity", "medium"))[:20],
            })

    remediation = r.get("remediation_steps") or []
    if isinstance(remediation, str):
        remediation = [remediation]
    remediation = [str(x)[:400] for x in remediation if str(x).strip()][:12]

    flow = _validate_mermaid(str(r.get("attack_flowchart", "")))

    return {
        "verdict": verdict,
        "confidence_score": conf,
        "psychological_analysis": {
            "summary": str(psych.get("summary", ""))[:1500],
            "tactics": clean_tactics,
        },
        "osint_findings": str(r.get("osint_findings", ""))[:4000],
        "remediation_steps": remediation,
        # The ONLY Mermaid output path we keep. If invalid, we fall back to the
        # structurally-correct chart for that verdict.
        "attack_flowchart": flow or
        ("flowchart TD\n" + _fallback_flow_of("threat" if verdict != "Safe / False Positive" else "safe")),
    }


def _fallback_flow_of(kind: str) -> str:
    if kind == "threat":
        return (
            "A[Message delivered] --> B[Victim interaction]\n"
            "B --> C[Potential credential/finance impact]\n"
            "C --> D[Blast radius limited — indicator data saved]\n"
            "D --> E[Recommend: block IOCs, report]"
        )
    return (
        "A[Message reviewed] --> B[IOCs checked — clean]\n"
        "B --> C[Classifiers found no phishing signals]\n"
        "C --> D[Benign communication confirmed]"
    )


def _rule_based_report(text: str, ml: dict, osint_records: list[dict],
                       osint_sum: str, llm_error: str | None) -> dict:
    """Degraded mode — still valid UI contract, no LLM involved."""
    p = ml.get("phishing_probability")
    p = 0.0 if p is None else float(p)
    p_ct = round(p * 100)

    bail_flags = sum(1 for rec in osint_records if rec.get("overall") == "malicious")
    clean_flags = sum(1 for rec in osint_records if rec.get("overall") == "clean")
    susp_flags = sum(1 for rec in osint_records if rec.get("overall") in ("suspicious", "mixed"))

    sig = p * 0.5 + (0.35 if bail_flags else 0) + (0.15 * susp_flags) - (0.25 if clean_flags else 0)
    sig = max(0.02, min(0.98, sig))

    if bail_flags or susp_flags or p >= 0.75:
        verdict = "High Risk Threat" if (bail_flags or p >= 0.75) else "Suspicious"
    elif p < 0.25 and not bail_flags:
        verdict = "Safe / False Positive"
    else:
        verdict = "Suspicious"
    if verdict == "High Risk Threat":
        conf = max(int(35 + p_ct * 0.6 + 40 * min(bail_flags, 1)), 55)
    elif verdict == "Suspicious":
        conf = 42 + int(sig * 30)
    else:
        conf = 78 + (14 if clean_flags else 0)
    conf = min(conf, 96)

    tactics = []
    low = text.lower()
    _t_kits = {
        "Urgency": ("urgent", "immediately", "24 hours", "suspend", "act now"),
        "Authority Spoofing": ("bank", "irs", "support@", "admin", "official"),
        "Fear": ("suspended", "unauthorized", "compromised", "warrant", "locked"),
        "Greed": ("refund", "prize", "winner", "inheritance", "crypto", "bitcoin"),
        "Credential Hook": ("verify", "login", "password", "confirm identity"),
    }
    for name, kws in _t_kits.items():
        hit = next((k for k in kws if k in low), None)
        if hit:
            tactics.append({"name": name, "evidence": f"Keyword pattern: '{hit}'",
                            "severity": "high" if verdict != "Safe / False Positive" else "low"})
    if not tactics:
        tactics.append({"name": "No classic social-engineering patterns detected",
                        "evidence": "", "severity": "none"})

    threat = verdict != "Safe / False Positive"
    osint_txt = osint_sum if osint_sum != "NO OSINT data available (no IOC lookups succeeded or no keys configured)." \
        else "No OSINT lookups were performed (no provider keys configured or rate-limited)."
    if llm_error:
        osint_txt = f"[LLM synthesis unavailable — rule-based degraded report: {llm_error}]\n" + osint_txt

    remed = (
        ["Block the reported IOCs at your mail gateway and DNS resolver.",
         "If clicked: reset credentials and review MFA/2FA audit logs.",
         "Report the phishing message to your SOC / IT security team."]
        if threat else
        ["No remediation needed — message filtered as false positive.",
         "Retain the artifact for audit trail.",
         "Re-check if future messages arrive from the same sender."]
    )

    if threat:
        flow = ("flowchart TD\n"
                "A[Malicious message delivered] --> B[User opens / reading]\n"
                "B --> C{Does user interact?}\n"
                "C -- Yes --> D[Phishing link / wallet lure activated]\n"
                "D --> E[Execution: credentials captured or funds requested]\n"
                "E --> F[Exploitation & install in victim environment]\n"
                "F --> G[BLAST RADIUS: account takeover, financial theft]\n"
                "C -- No --> H[Containment: report + block IOCs]\n"
                "H --> I[Incident closed — no impact]\n"
                "D --> G")
    else:
        flow = ("flowchart TD\n"
                "A[Message received] --> B[Content parsed & IOCs checked]\n"
                "B --> C[ML classifier: legitimate]\n"
                "C --> D[OSINT reputation: clean]\n"
                "D --> E[Benign verification flow completed]\n"
                "E --> F[No action needed — false positive]")

    return {
        "verdict": verdict,
        "confidence_score": conf,
        "psychological_analysis": {"summary":
            "Rule-based degraded analysis (LLM unavailable). Patterns observed in the raw text.",
            "tactics": tactics},
        "osint_findings": osint_txt,
        "remediation_steps": remed,
        "attack_flowchart": flow,
        "degraded": True,
        "degradation_reason": llm_error or "LLM provider not configured",
        "llm_used": False,
    }
