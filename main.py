"""AI-powered SOC alert triage pipeline.

Usage:
    python main.py                          # heuristic engine (no API key needed)
    python main.py --llm                    # Claude-powered triage
    python main.py --llm --json out.json    # also save machine-readable results
"""
import argparse
import json
import os
import sys

from src.parser import group_events, parse_log
from src.enrich import enrich_alert
from src.report import print_report, rank
from src.triage import heuristic_triage, llm_triage


def main() -> int:
    ap = argparse.ArgumentParser(description="Triage auth logs into a ranked alert queue.")
    ap.add_argument("logfile", nargs="?", default="data/sample_auth.log",
                    help="Path to an sshd auth log (default: bundled sample)")
    ap.add_argument("--source", choices=["file", "splunk"], default="file",
                    help="Event source: local sshd log file, or Splunk (Windows/AD "
                         "events 4624/4625 via the REST API; needs SPLUNK_* env vars)")
    ap.add_argument("--earliest", default="-24h@h",
                    help="Splunk search window start (default: last 24h)")
    ap.add_argument("--llm", action="store_true",
                    help="Use Claude for triage (requires ANTHROPIC_API_KEY)")
    ap.add_argument("--model", default="claude-opus-4-8",
                    help="Claude model to use with --llm")
    ap.add_argument("--workers", type=int, default=4,
                    help="Parallel triage calls with --llm (default 4)")
    ap.add_argument("--json", metavar="PATH",
                    help="Write ranked results to a JSON file")
    args = ap.parse_args()

    if args.source == "splunk":
        import requests
        from src.splunk_source import fetch_ad_events
        try:
            events = fetch_ad_events(earliest=args.earliest)
        except RuntimeError as e:
            print(f"Splunk config error: {e}", file=sys.stderr)
            return 1
        except requests.RequestException as e:
            print(f"Splunk connection failed: {e}", file=sys.stderr)
            return 1
        alerts = group_events(events)
        log_source = "splunk_windows_ad"
        if not alerts:
            print("Splunk search returned no 4624/4625 events in the window.",
                  file=sys.stderr)
            return 1
    else:
        alerts = parse_log(args.logfile)
        log_source = "sshd_file"
        if not alerts:
            print(f"No SSH auth events found in {args.logfile}", file=sys.stderr)
            return 1

    enriched = []
    for a in alerts:
        summary = a.summary_dict()
        summary["log_source"] = log_source
        enriched.append(enrich_alert(summary))

    if args.llm:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ANTHROPIC_API_KEY is not set. Run without --llm for the "
                  "heuristic engine, or export your key first.", file=sys.stderr)
            return 1
        results = llm_triage(enriched, model=args.model, max_workers=args.workers)
        engine = f"Claude ({args.model})"
    else:
        results = heuristic_triage(enriched)
        engine = "heuristic baseline"

    print_report(results, engine)

    if args.json:
        with open(args.json, "w") as f:
            json.dump([r.model_dump() for r in rank(results)], f, indent=2)
        print(f"\nResults written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
