"""
Runs the injection-prompt red-team suite against a live gateway and reports
the guardrail catch rate, broken down by attack category, plus a false-
positive rate on the benign_control category (prompts that should NOT be
blocked). This is the number you put in your resume bullet -- e.g.
"92% catch rate across 10 attack patterns, 0% false-positive rate on
benign traffic."

Usage:
    python run_redteam.py --gateway-url http://localhost:8000
"""
import argparse
import json
from pathlib import Path

import httpx

HERE = Path(__file__).parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway-url", default="http://localhost:8000")
    args = parser.parse_args()

    with open(HERE / "injection_prompts.json") as f:
        prompts = json.load(f)

    results = []
    with httpx.Client(timeout=60) as client:
        for p in prompts:
            resp = client.post(
                f"{args.gateway_url}/v1/chat/completions",
                json={"messages": [{"role": "user", "content": p["prompt"]}]},
            )
            blocked = resp.status_code == 400
            risk_score = None
            if blocked:
                risk_score = None  # detail body has reasons, not score, by design
            elif resp.status_code == 200:
                risk_score = resp.json().get("gateway_metadata", {}).get("input_risk_score")
            results.append({**p, "blocked": blocked, "input_risk_score": risk_score})

    attack = [r for r in results if r["category"] != "benign_control"]
    benign = [r for r in results if r["category"] == "benign_control"]

    caught = sum(1 for r in attack if r["blocked"])
    catch_rate = caught / len(attack) if attack else 0

    false_positives = sum(1 for r in benign if r["blocked"])
    fp_rate = false_positives / len(benign) if benign else 0

    print(f"\n=== Red-team report ===")
    print(f"Attack catch rate:    {caught}/{len(attack)} ({catch_rate:.1%})")
    print(f"Benign false-positive rate: {false_positives}/{len(benign)} ({fp_rate:.1%})\n")

    by_cat: dict[str, list] = {}
    for r in attack:
        by_cat.setdefault(r["category"], []).append(r)
    for cat, rs in by_cat.items():
        c = sum(1 for r in rs if r["blocked"])
        print(f"  {cat:22s} {c}/{len(rs)} caught")
        for r in rs:
            if not r["blocked"]:
                print(f"    MISSED: {r['id']} -> {r['prompt'][:70]}")

    for r in benign:
        if r["blocked"]:
            print(f"  FALSE POSITIVE on benign: {r['id']} -> {r['prompt'][:70]}")

    with open(HERE / "redteam_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results written to redteam_results.json")


if __name__ == "__main__":
    main()
