"""
LLM Gateway: an OpenAI-compatible /v1/chat/completions endpoint that sits
in front of an open-source LLM (served from Colab or via HF Inference API)
and applies guardrails, rate limiting, auth, and audit logging.

Run locally:
    uvicorn main:app --reload --port 8000

Run in Docker / HF Spaces: see Dockerfile.
"""
import time
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from config import settings
from guardrails import check_input, check_output
from security import audit_log, create_token, rate_limit_dependency, verify_token

app = FastAPI(title="LLM Gateway", version="0.1.0")


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "gateway-default"
    messages: list[ChatMessage]
    max_tokens: int = 512
    temperature: float = 0.7


class TokenRequest(BaseModel):
    subject: str


@app.get("/health")
def health():
    return {"status": "ok", "backend": settings.MODEL_BACKEND}


@app.post("/auth/token")
def issue_token(req: TokenRequest):
    """Dev-only helper to mint a JWT for testing. Replace with real auth
    (OAuth, API keys, etc.) before using this anywhere near production."""
    return {"access_token": create_token(req.subject), "token_type": "bearer"}


async def call_backend(messages: list[dict], max_tokens: int, temperature: float) -> str:
    """Dispatch to whichever backend is configured."""
    if settings.MODEL_BACKEND == "colab":
        if not settings.COLAB_ENDPOINT:
            raise HTTPException(500, "COLAB_ENDPOINT not configured")
        url = settings.COLAB_ENDPOINT.rstrip("/") + "/v1/chat/completions"
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(url, json={
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            })
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    elif settings.MODEL_BACKEND == "hf_inference":
        if not settings.HF_TOKEN:
            raise HTTPException(500, "HF_TOKEN not configured")
        url = f"https://router.huggingface.co/v1/chat/completions"
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {settings.HF_TOKEN}"},
                json={
                    "model": settings.HF_MODEL_ID,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    raise HTTPException(500, f"Unknown MODEL_BACKEND: {settings.MODEL_BACKEND}")


@app.post("/v1/chat/completions")
async def chat_completions(
    req: ChatCompletionRequest,
    _rate_limit=Depends(rate_limit_dependency),
    subject: Optional[str] = Depends(verify_token),
):
    start = time.time()
    user_text = " ".join(m.content for m in req.messages if m.role == "user")

    # --- Input guardrails ---
    input_result = check_input(user_text)
    if not input_result.allowed:
        audit_log.write({
            "event": "input_blocked",
            "subject": subject,
            "risk_score": input_result.risk_score,
            "reasons": input_result.reasons,
            "prompt_preview": user_text[:200],
        })
        raise HTTPException(status_code=400, detail={
            "error": "blocked_by_guardrails",
            "reasons": input_result.reasons,
        })

    # --- Call model backend ---
    try:
        completion = await call_backend(
            [m.model_dump() for m in req.messages], req.max_tokens, req.temperature
        )
    except httpx.HTTPError as exc:
        audit_log.write({"event": "backend_error", "subject": subject, "error": str(exc)})
        raise HTTPException(status_code=502, detail=f"Backend error: {exc}")

    # --- Output guardrails ---
    output_result = check_output(completion)
    final_text = output_result.redacted_text or completion

    latency_ms = round((time.time() - start) * 1000, 1)

    audit_log.write({
        "event": "completion_served",
        "subject": subject,
        "input_risk_score": input_result.risk_score,
        "input_flags": input_result.reasons,
        "output_flags": output_result.reasons,
        "latency_ms": latency_ms,
        "prompt_preview": user_text[:200],
    })

    return {
        "id": f"gw-{int(start * 1000)}",
        "object": "chat.completion",
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": final_text},
            "finish_reason": "stop",
        }],
        "gateway_metadata": {
            "input_risk_score": input_result.risk_score,
            "input_flags": input_result.reasons,
            "output_flags": output_result.reasons,
            "latency_ms": latency_ms,
        },
    }


@app.get("/audit/verify")
def verify_audit_log():
    """Confirms the audit log hash chain hasn't been tampered with."""
    valid, broken_line = audit_log.verify_chain()
    return {"valid": valid, "broken_at_line": broken_line}
