"""Ghost Data Still Exists - deletion audit agent.

Usage (from the repository root):
    python code/main.py                     # audit dataset/deletion_requests.csv -> output.csv
    python code/main.py --samples           # audit the public samples -> code/evaluation/sample_predictions.csv
    python code/main.py --no-llm            # rule-only intent classification
    python code/main.py --requests F --out O
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from audit import P, World, build_context, finalize_case, link_default_account, link_slot  # noqa: E402
from ingest import ingest  # noqa: E402
from intent import Usage, classify_all  # noqa: E402

ROOT = os.path.dirname(HERE)
DATASET = os.path.join(ROOT, "dataset")


def read_requests(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def case_sort_key(cid: str) -> tuple:
    try:
        return (0, int(cid.split("_")[1]))
    except (IndexError, ValueError):
        return (1, cid)


def run(requests_path: str, out_path: str, use_llm: bool, context_paths: list[str]) -> dict:
    t0 = time.time()
    obs, manifest = ingest(DATASET, os.path.join(HERE, "image_extractions.json"))
    world = World(DATASET, obs, manifest)
    targets = read_requests(requests_path)
    # every known request shares one activity stream: audit them together so a
    # resource linked to one request is not handed to another
    everyone = list({r["case_id"]: r for p in context_paths + [requests_path] for r in read_requests(p)}.values())
    usage = Usage()
    authorised = classify_all(everyone, usage, use_llm=use_llm)

    # phase 1: identity + evidence linking for every authorised request
    contexts = {}
    results: dict[str, tuple[str, list]] = {}
    for case in everyone:
        if authorised[case["case_id"]]:
            contexts[case["case_id"]] = build_context(world, case)
        else:
            results[case["case_id"]] = ("NOT_APPLICABLE", [])
    # phase 2: activity-stream fallback, one deletion-worker burst at a time
    taken = {rid for c in contexts.values() for rid in c.resources}
    bursts: dict[str, list] = {}
    for c in contexts.values():
        bursts.setdefault(c.case["reported_at"], []).append(c)
    for ra in sorted(bursts, key=P):
        group = sorted(bursts[ra], key=lambda c: case_sort_key(c.case["case_id"]))
        link_slot(world, group, taken)
        taken |= {rid for c in group for rid in c.resources}
    claimed: dict[str, set] = {}
    for c in contexts.values():
        for rid in c.resources:
            claimed.setdefault(rid, set()).add(c.uid)
    for c in contexts.values():
        link_default_account(world, c, claimed)
    # phase 3: state reconstruction, policy, steps
    for cid, ctx in contexts.items():
        results[cid] = finalize_case(world, ctx)

    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for case in sorted(targets, key=lambda r: case_sort_key(r["case_id"])):
            status, steps = results[case["case_id"]]
            w.writerow([case["case_id"], status, json.dumps(steps, ensure_ascii=False, separators=(",", ":"))])
    return {"cases": len(targets), "seconds": round(time.time() - t0, 2), "observations": len(obs),
            "usage": usage.__dict__}


def write_usage_report(stats: dict, llm_enabled: bool) -> None:
    """Regenerate evaluation/usage_report.md from the run that produced output.csv."""
    from intent import MODEL, PRICES
    u = stats["usage"]
    n = stats["cases"]
    rows, tot_cost = [], 0.0
    for model, m in sorted(u["by_model"].items()):
        pin, pout = PRICES.get(model, (0.0, 0.0))
        cost = m["input_tokens"] / 1e6 * pin + m["output_tokens"] / 1e6 * pout
        tot_cost += cost
        rows.append(f"| Anthropic | `{model}` | {m['calls']} | {m['input_tokens']:,} | {m['output_tokens']:,} | "
                    f"{m['input_tokens'] + m['output_tokens']:,} | ${cost:.4f} |")
    if not rows:
        rows.append(f"| Anthropic | `{MODEL}` (intent fallback, not invoked) | 0 | 0 | 0 | 0 | $0.0000 |")
    total_tokens = u["input_tokens"] + u["output_tokens"]
    path = os.path.join(HERE, "evaluation", "usage_report.md")
    with open(os.path.join(HERE, "evaluation", "usage_static.md"), encoding="utf-8") as fh:
        static = fh.read()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"""# Token usage and cost - final full-dataset run

Generated automatically by `python code/main.py` at the end of the run that wrote `output.csv`
({n} requests, {stats['observations']:,} evidence observations, {stats['seconds']} s wall clock,
LLM intent pass {'enabled' if llm_enabled else 'disabled (--no-llm)'}).

## Runtime model usage (this run)

| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Est. cost |
|---|---|---:|---:|---:|---:|---:|
{chr(10).join(rows)}
| **Overall** | | **{u['calls']}** | **{u['input_tokens']:,}** | **{u['output_tokens']:,}** | **{total_tokens:,}** | **${tot_cost:.4f}** |

- Average tokens per request: **{total_tokens / n:.1f}**
- Estimated cost per request: **${tot_cost / n:.6f}**
- Prices used (USD / 1M tokens, input/output): {', '.join(f'`{k}` {v[0]:.2f}/{v[1]:.2f}' for k, v in PRICES.items())}

{static}""")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", action="store_true")
    ap.add_argument("--requests")
    ap.add_argument("--out")
    ap.add_argument("--no-llm", action="store_true")
    a = ap.parse_args()
    main_req = os.path.join(DATASET, "deletion_requests.csv")
    sample_req = os.path.join(DATASET, "sample_deletion_requests.csv")
    if a.samples:
        req, out, ctx = sample_req, os.path.join(HERE, "evaluation", "sample_predictions.csv"), [main_req]
    else:
        req = a.requests or main_req
        out = a.out or os.path.join(ROOT, "output.csv")
        # samples share the activity stream with the evaluation set; custom
        # cases are perturbations of samples, so they run against the evaluation set only
        ctx = [main_req] if a.requests and os.path.abspath(req) != os.path.abspath(main_req) else             [p for p in (main_req, sample_req) if os.path.abspath(p) != os.path.abspath(req)]
    stats = run(req, out, not a.no_llm, ctx)
    print(json.dumps(stats, indent=2))
    if os.path.abspath(req) == os.path.abspath(main_req):
        write_usage_report(stats, not a.no_llm)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
