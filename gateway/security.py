"""
Security primitives: token-bucket rate limiting, JWT auth, and a
hash-chained (tamper-evident) audit log.
"""
import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Optional

import jwt
from fastapi import Header, HTTPException, Request

from config import settings

# ---------------------------------------------------------------------------
# Token bucket rate limiter (per client key, in-memory).
# Same pattern as a token-bucket API limiter: capacity + steady refill rate.
# ---------------------------------------------------------------------------
class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self.tokens: dict[str, float] = {}
        self.last_refill: dict[str, float] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self._lock:
            now = time.monotonic()
            tokens = self.tokens.get(key, self.capacity)
            last = self.last_refill.get(key, now)

            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
            allowed = tokens >= 1
            if allowed:
                tokens -= 1

            self.tokens[key] = tokens
            self.last_refill[key] = now
            return allowed


bucket = TokenBucket(settings.RATE_LIMIT_CAPACITY, settings.RATE_LIMIT_REFILL_PER_SEC)


def rate_limit_dependency(request: Request):
    client_key = request.client.host if request.client else "unknown"
    if not bucket.allow(client_key):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


# ---------------------------------------------------------------------------
# JWT auth
# ---------------------------------------------------------------------------
def create_token(subject: str) -> str:
    payload = {
        "sub": subject,
        "iat": int(time.time()),
        "exp": int(time.time()) + settings.JWT_EXPIRY_MINUTES * 60,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_token(authorization: Optional[str] = Header(None)) -> Optional[str]:
    if not settings.REQUIRE_AUTH:
        return "anonymous"
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload["sub"]
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")


# ---------------------------------------------------------------------------
# Tamper-evident audit log: each line is a JSON record that includes the
# hash of the previous line, so any retroactive edit breaks the chain.
# ---------------------------------------------------------------------------
class AuditLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self._lock = threading.Lock()
        if not self.path.exists():
            self.path.touch()

    def _last_hash(self) -> str:
        if self.path.stat().st_size == 0:
            return "0" * 64
        with open(self.path, "rb") as f:
            f.seek(-1, 2)
            # find last newline-delimited record
            data = self.path.read_text().strip().splitlines()
            if not data:
                return "0" * 64
            last_record = json.loads(data[-1])
            return last_record["record_hash"]

    def write(self, event: dict) -> dict:
        with self._lock:
            prev_hash = self._last_hash()
            event = dict(event)
            event["prev_hash"] = prev_hash
            event["timestamp"] = time.time()
            record_str = json.dumps(event, sort_keys=True)
            record_hash = hashlib.sha256((prev_hash + record_str).encode()).hexdigest()
            event["record_hash"] = record_hash
            with open(self.path, "a") as f:
                f.write(json.dumps(event) + "\n")
            return event

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Returns (is_valid, first_broken_line_number_or_None)."""
        prev_hash = "0" * 64
        lines = self.path.read_text().strip().splitlines()
        for i, line in enumerate(lines):
            record = json.loads(line)
            claimed_hash = record.pop("record_hash")
            record["prev_hash"]  # noqa: B018 (accessed for clarity)
            expected = hashlib.sha256(
                (prev_hash + json.dumps(record, sort_keys=True)).encode()
            ).hexdigest()
            if expected != claimed_hash:
                return False, i
            prev_hash = claimed_hash
        return True, None


audit_log = AuditLog(settings.AUDIT_LOG_PATH)
