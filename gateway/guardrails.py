"""
Guardrails layer: input validation (prompt-injection / jailbreak detection,
topic scoping) and output filtering (PII leakage, basic toxicity).

Design note: instead of a hard binary "block / allow" classifier, injection
detection here uses a small set of weighted heuristic signals combined into
a fuzzy risk score in [0, 1] (see `score_injection_risk`). This mirrors
Mamdani-style fuzzy aggregation (union of triggered rules, each with a
membership weight) rather than a crisp threshold on a single signal -- it
tends to generalize better to novel injection phrasing than a single regex
match/no-match gate, and gives you a tunable "flag for review" band instead
of only allow/deny.
"""
import re
from dataclasses import dataclass, field
from typing import Optional

from config import settings

# ---------------------------------------------------------------------------
# Signal patterns. Each is (compiled_regex, weight). Weights are heuristic
# and should be tuned against your own red-team results (see redteam/).
# ---------------------------------------------------------------------------
INJECTION_SIGNALS: list[tuple[re.Pattern, float]] = [
    (re.compile(r"\bignore (all|any|the)? ?(previous|prior|above) instructions\b", re.I), 0.9),
    (re.compile(r"\byou are now\b|\bact as\b|\bpretend (you are|to be)\b", re.I), 0.4),
    (re.compile(r"\bdisregard (your|the) (system|previous) prompt\b", re.I), 0.9),
    (re.compile(r"\breveal (your|the) (system prompt|instructions|guidelines)\b", re.I), 0.7),
    (re.compile(r"\bdeveloper mode\b|\bdan mode\b|\bjailbreak\b", re.I), 0.8),
    (re.compile(r"\bno (restrictions|limits|filters)\b", re.I), 0.5),
    (re.compile(r"\bthis is (a test|hypothetical|fictional)\b.*\b(ignore|bypass)\b", re.I), 0.6),
    (re.compile(r"\bbase64|rot13|hex decode\b", re.I), 0.3),
    (re.compile(r"<\s*system\s*>|\[system\]|###\s*system", re.I), 0.6),
    (re.compile(r"\brespond only with\b.*\bnothing else\b", re.I), 0.2),
]

PII_SIGNALS: dict[str, re.Pattern] = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "phone": re.compile(r"\b(\+?\d{1,3}[-.\s]?)?\d{10}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "ssn_like": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "aadhaar_like": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

# Minimal keyword-based toxicity gate. Swap for a real classifier
# (e.g. `detoxify`) for production use -- this is intentionally lightweight
# so the project runs with zero extra heavy deps.
TOXIC_KEYWORDS = {"kill yourself", "hate you", "slur_placeholder"}


@dataclass
class GuardrailResult:
    allowed: bool
    risk_score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    redacted_text: Optional[str] = None


def score_injection_risk(text: str) -> tuple[float, list[str]]:
    """Fuzzy aggregation of triggered injection signals.

    Uses a noisy-OR style combination: risk = 1 - prod(1 - w_i) over
    triggered signals, so multiple weak signals can still add up to a high
    score, but no single moderate signal auto-blocks on its own.
    """
    triggered = []
    complement_product = 1.0
    for pattern, weight in INJECTION_SIGNALS:
        if pattern.search(text):
            triggered.append(pattern.pattern)
            complement_product *= (1 - weight)
    risk = 1 - complement_product
    return round(risk, 3), triggered


def check_input(text: str) -> GuardrailResult:
    risk, triggered = score_injection_risk(text)

    if risk >= settings.INJECTION_BLOCK_THRESHOLD:
        return GuardrailResult(
            allowed=False,
            risk_score=risk,
            reasons=[f"prompt_injection_blocked ({len(triggered)} signal(s))"] + triggered,
        )

    reasons = []
    if risk >= settings.INJECTION_FLAG_THRESHOLD:
        reasons.append(f"prompt_injection_flagged ({len(triggered)} signal(s))")
        reasons.extend(triggered)

    if settings.ALLOWED_TOPICS:
        text_lower = text.lower()
        if not any(topic.strip().lower() in text_lower for topic in settings.ALLOWED_TOPICS):
            reasons.append("off_topic_flagged")

    return GuardrailResult(allowed=True, risk_score=risk, reasons=reasons)


def check_output(text: str) -> GuardrailResult:
    reasons = []
    redacted = text

    for label, pattern in PII_SIGNALS.items():
        if pattern.search(text):
            reasons.append(f"pii_detected:{label}")
            redacted = pattern.sub(f"[REDACTED_{label.upper()}]", redacted)

    lowered = text.lower()
    for kw in TOXIC_KEYWORDS:
        if kw in lowered:
            reasons.append(f"toxicity_flagged:{kw}")

    # Output is never hard-blocked here -- PII is redacted and returned,
    # toxicity is flagged for the audit log. Tune to your risk appetite.
    return GuardrailResult(
        allowed=True,
        risk_score=0.0,
        reasons=reasons,
        redacted_text=redacted if redacted != text else None,
    )
