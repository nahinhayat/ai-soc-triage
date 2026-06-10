"""Evaluate triage results against hand-labeled ground truth.

Usage:
    python main.py --llm --json results.json
    python evaluate.py results.json
"""
import csv
import json
import sys
from collections import Counter


def load_labels(path: str = "data/labels.csv") -> dict:
    with open(path) as f:
        return {row["src_ip"]: row["verdict"] for row in csv.DictReader(f)}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 1

    with open(sys.argv[1]) as f:
        results = {r["src_ip"]: r["verdict"] for r in json.load(f)}
    labels = load_labels()

    # needs_investigation counts as neither correct nor incorrect for
    # accuracy, but is tracked so we can see how often the engine punts.
    tp = fp = fn = correct_fp = punted = 0
    rows = []
    for ip, truth in labels.items():
        pred = results.get(ip, "missing")
        if pred == "needs_investigation":
            punted += 1
        elif truth == "true_positive" and pred == "true_positive":
            tp += 1
        elif truth == "true_positive":
            fn += 1
        elif truth == "false_positive" and pred == "false_positive":
            correct_fp += 1
        elif truth == "false_positive" and pred == "true_positive":
            fp += 1
        rows.append((ip, truth, pred, "OK" if pred == truth else "MISS"))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    print(f"{'source IP':<18} {'truth':<16} {'predicted':<20} result")
    print("-" * 64)
    for row in rows:
        print(f"{row[0]:<18} {row[1]:<16} {row[2]:<20} {row[3]}")
    print("-" * 64)
    print(f"Attack detection — precision: {precision:.0%}  recall: {recall:.0%}")
    print(f"Benign correctly cleared: {correct_fp}  |  punted to investigation: {punted}")
    print(f"Verdict distribution: {dict(Counter(results.values()))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
