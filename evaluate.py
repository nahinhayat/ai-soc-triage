"""Evaluate triage results against hand-labeled ground truth.

Usage:
    python evaluate.py results.json [labels.csv]

Defaults to data/labels.csv (the small sample). For the generated benchmark:
    python main.py data/large_auth.log --llm --json results.json
    python evaluate.py results.json data/large_labels.csv

Scoring is deliberately SOC-shaped:
  - recall counts ALL labeled attacks in the denominator, so punting an
    attack to needs_investigation still costs recall
  - explicitly clearing an attack (predicting false_positive) is reported
    separately as a DANGEROUS MISS — the worst possible outcome
"""
import csv
import json
import sys
from collections import Counter


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    results_path = sys.argv[1]
    labels_path = sys.argv[2] if len(sys.argv) > 2 else "data/labels.csv"

    with open(results_path) as f:
        results = {r["src_ip"]: r["verdict"] for r in json.load(f)}
    with open(labels_path) as f:
        labels = {row["src_ip"]: row["verdict"] for row in csv.DictReader(f)}

    truth_tp = {ip for ip, v in labels.items() if v == "true_positive"}
    truth_fp = {ip for ip, v in labels.items() if v == "false_positive"}
    flagged = {ip for ip, v in results.items() if v == "true_positive"}
    cleared = {ip for ip, v in results.items() if v == "false_positive"}
    punted = {ip for ip, v in results.items() if v == "needs_investigation"}

    tp = flagged & truth_tp            # attack correctly flagged
    fp = flagged & truth_fp            # benign wrongly flagged (analyst time wasted)
    dangerous = cleared & truth_tp     # attack explicitly cleared (worst case)
    benign_ok = cleared & truth_fp
    punted_attacks = punted & truth_tp
    punted_benign = punted & truth_fp

    precision = len(tp) / len(flagged) if flagged else 0.0
    recall = len(tp) / len(truth_tp) if truth_tp else 0.0

    mismatches = [(ip, labels[ip], results.get(ip, "missing"))
                  for ip in labels if results.get(ip) != labels[ip]]

    print(f"Alerts: {len(labels)} labeled ({len(truth_tp)} attacks, {len(truth_fp)} benign)")
    print(f"Verdicts: {dict(Counter(results.values()))}\n")
    print(f"Precision (flagged attacks that were real): {precision:.0%}")
    print(f"Recall    (real attacks that were flagged): {recall:.0%}")
    print(f"Benign correctly cleared: {len(benign_ok)}/{len(truth_fp)}")
    print(f"False alarms raised:      {len(fp)}")
    print(f"Punted to investigation:  {len(punted_attacks)} attacks, {len(punted_benign)} benign")

    if dangerous:
        print(f"\nDANGEROUS MISSES — attacks explicitly cleared as benign ({len(dangerous)}):")
        for ip in sorted(dangerous):
            print(f"  {ip}")
    else:
        print("\nNo dangerous misses (no attack was explicitly cleared as benign).")

    if mismatches:
        print(f"\nAll disagreements with ground truth ({len(mismatches)}):")
        print(f"  {'source IP':<18} {'truth':<16} predicted")
        for ip, truth, pred in sorted(mismatches):
            print(f"  {ip:<18} {truth:<16} {pred}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
