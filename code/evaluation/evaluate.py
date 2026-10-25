"""Score a predictions CSV against a gold CSV (same format as output.csv).

Metrics
  status_accuracy   : deletion_status exact match per case
  sequence_accuracy : steps_json array identical (order-sensitive) per case
  step P/R/F1       : steps matched as (phase, system_id, resource_id, operation, state, evidence_id)
  field accuracy    : for steps aligned by position, share of fields that match
  resource P/R      : (system_id, resource_id) sets discovered per case

Usage: python code/evaluation/evaluate.py GOLD.csv PRED.csv [--show]
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter

FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load(path: str) -> dict[str, tuple[str, list[dict]]]:
    with open(path, encoding="utf-8") as fh:
        return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(fh)}


def key(s: dict, with_ev: bool = True) -> tuple:
    return tuple(s.get(f, "") for f in (FIELDS if with_ev else FIELDS[:-1]))


def score(gold: dict, pred: dict) -> dict:
    n = len(gold)
    status_ok = seq_ok = 0
    tp = fp = fn = 0
    tp_ne = fp_ne = fn_ne = 0
    field_hits = field_total = 0
    res_tp = res_fp = res_fn = 0
    per_case = {}
    for cid, (gs, gsteps) in gold.items():
        ps, psteps = pred.get(cid, ("", []))
        status_ok += gs == ps
        clean_p = [{k: v for k, v in s.items() if k != "step_no"} for s in psteps]
        clean_g = [{k: v for k, v in s.items() if k != "step_no"} for s in gsteps]
        seq = clean_p == clean_g and [s.get("step_no") for s in psteps] == list(range(1, len(psteps) + 1))
        seq_ok += seq
        gc, pc = Counter(key(s) for s in gsteps), Counter(key(s) for s in psteps)
        inter = sum((gc & pc).values())
        tp += inter
        fp += sum(pc.values()) - inter
        fn += sum(gc.values()) - inter
        gc2, pc2 = Counter(key(s, False) for s in gsteps), Counter(key(s, False) for s in psteps)
        inter2 = sum((gc2 & pc2).values())
        tp_ne += inter2
        fp_ne += sum(pc2.values()) - inter2
        fn_ne += sum(gc2.values()) - inter2
        for i in range(max(len(gsteps), len(psteps))):
            g = gsteps[i] if i < len(gsteps) else {}
            p = psteps[i] if i < len(psteps) else {}
            for f in FIELDS:
                field_total += 1
                field_hits += bool(g) and bool(p) and g.get(f) == p.get(f)
        gr = {(s["system_id"], s["resource_id"]) for s in gsteps}
        pr = {(s["system_id"], s["resource_id"]) for s in psteps}
        res_tp += len(gr & pr)
        res_fp += len(pr - gr)
        res_fn += len(gr - pr)
        per_case[cid] = dict(status_ok=gs == ps, seq_ok=seq, gold_status=gs, pred_status=ps,
                             missing=sorted(gc - pc), extra=sorted(pc - gc))

    def prf(t, f_p, f_n):
        p = t / (t + f_p) if t + f_p else 1.0
        r = t / (t + f_n) if t + f_n else 1.0
        return p, r, (2 * p * r / (p + r) if p + r else 0.0)

    return dict(
        cases=n,
        status_accuracy=status_ok / n,
        sequence_accuracy=seq_ok / n,
        step_prf=prf(tp, fp, fn),
        step_prf_ignoring_evidence=prf(tp_ne, fp_ne, fn_ne),
        field_accuracy=field_hits / field_total if field_total else 1.0,
        resource_prf=prf(res_tp, res_fp, res_fn),
        per_case=per_case,
    )


def main() -> None:
    gold, pred = load(sys.argv[1]), load(sys.argv[2])
    gold = {k: v for k, v in gold.items() if k in pred} if "--subset" in sys.argv else gold
    s = score(gold, pred)
    print(f"cases                 {s['cases']}")
    print(f"status accuracy       {s['status_accuracy']:.3f}")
    print(f"sequence accuracy     {s['sequence_accuracy']:.3f}")
    print("step P/R/F1           %.3f / %.3f / %.3f" % s["step_prf"])
    print("step P/R/F1 (no ev)   %.3f / %.3f / %.3f" % s["step_prf_ignoring_evidence"])
    print(f"field accuracy        {s['field_accuracy']:.3f}")
    print("resource P/R/F1       %.3f / %.3f / %.3f" % s["resource_prf"])
    if "--show" in sys.argv:
        for cid, c in s["per_case"].items():
            if not c["seq_ok"]:
                print(f"\n{cid} gold={c['gold_status']} pred={c['pred_status']}")
                for m in c["missing"]:
                    print("   - missing", m)
                for m in c["extra"]:
                    print("   + extra  ", m)


if __name__ == "__main__":
    main()
