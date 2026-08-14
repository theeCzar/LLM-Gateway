"""
Central configuration for the LLM Gateway.
All values are read from environment variables (see .env.example).
"""
import os
from dataclasses import dataclass, field


def _bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes")


@dataclass
class Settings:
    # --- Model backend ---
    # Default and recommended: "hf_inference" -- calls Hugging Face's hosted
    # Inference Providers API, so no model weights are ever downloaded or
    # run on your own machine. "colab" remains available as an optional
    # self-hosted backend if you want it later (see colab/ directory).
    MODEL_BACKEND: str = os.getenv("MODEL_BACKEND", "hf_inference")

    # Required when MODEL_BACKEND == "hf_inference"
    HF_TOKEN: str = os.getenv("HF_TOKEN", "")
    HF_MODEL_ID: str = os.getenv("HF_MODEL_ID", "Qwen/Qwen2.5-7B-Instruct")

    # Optional, only used if MODEL_BACKEND == "colab"
    COLAB_ENDPOINT: str = os.getenv("COLAB_ENDPOINT", "")

    # --- Auth ---
    JWT_SECRET: str = os.getenv("JWT_SECRET", "change-me-in-production")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))
    # If true, requests without a valid JWT are rejected. Turn off for local testing.
    REQUIRE_AUTH: bool = _bool("REQUIRE_AUTH", "false")

    # --- Rate limiting (token bucket) ---
    RATE_LIMIT_CAPACITY: int = int(os.getenv("RATE_LIMIT_CAPACITY", "20"))
    RATE_LIMIT_REFILL_PER_SEC: float = float(os.getenv("RATE_LIMIT_REFILL_PER_SEC", "0.5"))

    # --- Guardrails ---
    # Fuzzy risk threshold above which a request is blocked outright (0-1).
    INJECTION_BLOCK_THRESHOLD: float = float(os.getenv("INJECTION_BLOCK_THRESHOLD", "0.7"))
    # Threshold above which a request is allowed but flagged for review.
    INJECTION_FLAG_THRESHOLD: float = float(os.getenv("INJECTION_FLAG_THRESHOLD", "0.4"))
    ALLOWED_TOPICS: list = field(default_factory=lambda: os.getenv(
        "ALLOWED_TOPICS", ""
    ).split(",") if os.getenv("ALLOWED_TOPICS") else [])

    # --- Audit log ---
    AUDIT_LOG_PATH: str = os.getenv("AUDIT_LOG_PATH", "audit_log.jsonl")


settings = Settings()
