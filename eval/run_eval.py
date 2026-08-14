"""
Eval harness: runs test_cases.json against a running gateway instance and
reports accuracy / hallucination / safety-block metrics. Designed to be run
in CI (GitHub Actions) after every guardrail or prompt-template change, so
regressions get caught before merge -- not just code bugs, but quality and
safety regressions in the model-facing layer.

Usage:
    python run_eval.py --gateway-url http://localhost:8000 [--fail-under 0.8]
"""
import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).parent


def load_cases():
    with open(HERE / "test_cases.json") as f:
        return json.load(f)


def run_case(client: httpx.Client, gateway_url: str, case: dict) -> dict:
    start = time.time()
    resp = client.post(
        f"{gateway_url}/v1/chat/completions",
        json={"messages": [{"role": "user", "content": case["prompt"]}]},
        timeout=60,
    )
    latency_ms = round((time.time() - start) * 1000, 1)

    blocked = resp.status_code == 400
    result = {
        "id": case["id"],
        "category": case["category"],
        "latency_ms": latency_ms,
        "blocked": blocked,
        "expected_block": case["should_block"],
        "block_correct": blocked == case["should_block"],
    }

    if not blocked and resp.status_code == 200:
        content = resp.json()["choices"][0]["message"]["content"]
        result["response_preview"] = content[:200]
        expected = case.get("expected_contains", [])
        result["content_match"] = (
            any(e.lower() in content.lower() for e in expected) if expected else True
        )
    else:
        result["content_match"] = None
        result["response_preview"] = f"HTTP {resp.status_code}"

    result["pass"] = result["block_correct"] and (result["content_match"] is not False)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway-url", default="http://localhost:8000")
    parser.add_argument("--fail-under", type=float, default=0.8,
                         help="Exit non-zero if pass rate falls below this (for CI gating)")
    parser.add_argument("--db", default=str(HERE / "eval_results.db"))
    args = parser.parse_args()

    cases = load_cases()
    results = []
    with httpx.Client() as client:
        for case in cases:
            try:
                results.append(run_case(client, args.gateway_url, case))
            except httpx.HTTPError as exc:
                results.append({"id": case["id"], "category": case["category"], "pass": False,
                                 "error": str(exc)})

    passed = sum(1 for r in results if r.get("pass"))
    total = len(results)
    pass_rate = passed / total if total else 0

    # persist run to sqlite for trend tracking across CI runs
    conn = sqlite3.connect(args.db)
    conn.execute("""CREATE TABLE IF NOT EXISTS eval_runs (
        run_ts REAL, case_id TEXT, category TEXT, pass INTEGER, latency_ms REAL, detail TEXT
    )""")
    run_ts = time.time()
    for r in results:
        conn.execute(
            "INSERT INTO eval_runs VALUES (?, ?, ?, ?, ?, ?)",
            (run_ts, r["id"], r["category"], int(bool(r.get("pass"))),
             r.get("latency_ms"), json.dumps(r)),
        )
    conn.commit()
    conn.close()

    print(f"\n=== Eval report: {passed}/{total} passed ({pass_rate:.1%}) ===")
    by_category: dict[str, list] = {}
    for r in results:
        by_category.setdefault(r["category"], []).append(r)
    for cat, rs in by_category.items():
        cat_pass = sum(1 for r in rs if r.get("pass"))
        print(f"  {cat:15s} {cat_pass}/{len(rs)}")
        for r in rs:
            if not r.get("pass"):
                print(f"    FAIL {r['id']}: {r.get('response_preview', r.get('error'))}")

    if pass_rate < args.fail_under:
        print(f"\nPass rate {pass_rate:.1%} below threshold {args.fail_under:.1%} -- failing CI.")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
