"""Streamlit dashboard for the AI SOC triage pipeline.

Run with:
    streamlit run dashboard.py
"""
import csv
import json
import os
import tempfile

import pandas as pd
import streamlit as st

from src.enrich import enrich_alert
from src.parser import parse_log
from src.triage import Severity, Verdict, llm_triage

def _load_dotenv(path=".env"):
    """Tiny .env loader so the dashboard picks up keys without exports."""
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()

# (log file, ground-truth labels, optional precomputed triage results)
DATASETS = {
    "Sample SSH log (7 alerts)":
        ("data/sample_auth.log", "data/labels.csv", None),
    "Benchmark (523 alerts, 5 hosts)":
        ("data/large_auth.log", "data/large_labels.csv", "data/benchmark_results_sonnet.json"),
}

SEVERITY_RANK = {s: i for i, s in enumerate(
    [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.informational])}
SEVERITY_BADGE = {
    Severity.critical: ":red-background[CRITICAL]",
    Severity.high: ":red[HIGH]",
    Severity.medium: ":orange[MEDIUM]",
    Severity.low: ":blue[LOW]",
    Severity.informational: ":gray[INFO]",
}
VERDICT_LABEL = {
    Verdict.true_positive: "true positive",
    Verdict.false_positive: "false positive",
    Verdict.needs_investigation: "needs investigation",
}

st.set_page_config(page_title="AI SOC Triage", page_icon="🛡️", layout="wide")


@st.cache_data(show_spinner=False)
def parse_and_enrich(log_text: str):
    """Parse and enrich without any LLM calls. Cached."""
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(log_text)
        path = f.name
    try:
        alerts = parse_log(path)
    finally:
        os.unlink(path)

    enriched = [enrich_alert(a.summary_dict()) for a in alerts]
    raw_events = {a.src_ip: [e.raw for e in a.events] for a in alerts}
    return enriched, raw_events


@st.cache_data(show_spinner=False)
def triage_with_claude(log_text: str, model: str):
    """Claude triage. Cached so engine/model reruns are free."""
    enriched, _ = parse_and_enrich(log_text)
    return [r.model_dump() for r in llm_triage(enriched, model=model)]


def load_labels(path) -> dict:
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        return {row["src_ip"]: row["verdict"] for row in csv.DictReader(f)}


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.title("🛡️ AI SOC Triage")
    st.caption("SSH auth logs → enriched, AI-triaged, ranked alert queue")

    preselect = 1 if st.query_params.get("dataset") == "benchmark" else 0
    dataset_choice = st.radio("Dataset", list(DATASETS.keys()), index=preselect)
    uploaded = st.file_uploader("...or upload an sshd auth log", type=["log", "txt"])

    model = st.selectbox("Model", ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"])
    if not os.environ.get("ANTHROPIC_API_KEY"):
        key = st.text_input("Anthropic API key", type="password",
                            help="Stored only in this session's environment")
        if key:
            os.environ["ANTHROPIC_API_KEY"] = key
    if not os.environ.get("ANTHROPIC_API_KEY"):
        st.warning("Set an Anthropic API key to triage alerts.")
        st.stop()

if uploaded is not None:
    log_text = uploaded.getvalue().decode("utf-8", errors="replace")
    labels_path = results_path = None
else:
    log_path, labels_path, results_path = DATASETS[dataset_choice]
    with open(log_path) as f:
        log_text = f.read()

# ---------------------------------------------------------------- pipeline
enriched, raw_events = parse_and_enrich(log_text)
n_lines = len(log_text.splitlines())

if results_path and os.path.exists(results_path):
    with open(results_path) as f:
        results = json.load(f)
    engine_label = "claude-sonnet-4-6 · precomputed benchmark run"
else:
    if n_lines > 600 and not st.session_state.get("large_run_ok"):
        st.info(f"This dataset has {n_lines:,} log lines — likely several hundred "
                f"alerts. Claude triage costs roughly $0.02 per alert and takes a "
                f"few minutes (results are cached afterwards).")
        if st.button("Triage with Claude"):
            st.session_state["large_run_ok"] = True
            st.rerun()
        st.stop()
    with st.spinner("Claude is triaging alerts..."):
        results = triage_with_claude(log_text, model)
    engine_label = model

if not results:
    st.error("No SSH auth events found in this log.")
    st.stop()

results.sort(key=lambda r: (SEVERITY_RANK[Severity(r["severity"])], -r["confidence"]))
enriched_by_ip = {a["src_ip"]: a for a in enriched}

attacks = [r for r in results if r["verdict"] == "true_positive"]
benign = [r for r in results if r["verdict"] == "false_positive"]
critical = [r for r in results if r["severity"] == "critical"]

# ---------------------------------------------------------------- header
hosts = sorted({h for a in enriched for h in a.get("hosts_targeted", [])})
firsts = [a["first_seen"] for a in enriched if a.get("first_seen")]
lasts = [a["last_seen"] for a in enriched if a.get("last_seen")]

st.title("🛡️ SOC alert triage")
st.markdown(
    f"**{n_lines:,} log events** from **{len(hosts)} host{'s' if len(hosts) != 1 else ''}** "
    f"correlated into **{len(results)} alerts** — triaged by Claude and ranked worst-first."
)
if firsts and lasts:
    st.caption(f"Activity window: {min(firsts)} → {max(lasts)}  ·  model: {engine_label}")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Alerts in queue", len(results))
c2.metric("Confirmed attacks", len(attacks))
c3.metric("Cleared as benign", len(benign))
c4.metric("Critical — act now", len(critical))

# ---------------------------------------------------------------- activity chart
st.subheader("Most active sources")
chart_df = pd.DataFrame(
    [{"source IP": a["src_ip"],
      "failed logins": a["failed_logins"],
      "successful logins": a["successful_logins"],
      "probes (no auth)": a.get("connection_probes_no_auth", 0)} for a in enriched]
)
chart_df["total"] = chart_df.drop(columns="source IP").sum(axis=1)
top = chart_df.nlargest(15, "total")
if len(chart_df) > 15:
    st.caption(f"Top 15 of {len(chart_df)} sources by event volume")
st.bar_chart(
    top.set_index("source IP")[["failed logins", "successful logins", "probes (no auth)"]],
    color=["#e24b4a", "#1d9e75", "#ba7517"],
    horizontal=True,
    height=max(240, 28 * len(top)),
)

# ---------------------------------------------------------------- queue
st.subheader("Analyst queue — highest risk first")
MAX_SHOWN = 30
if len(results) > MAX_SHOWN:
    st.caption(f"Showing the top {MAX_SHOWN} of {len(results)} alerts — "
               f"export the full queue with `python main.py --llm --json`")
for i, r in enumerate(results[:MAX_SHOWN], 1):
    sev = Severity(r["severity"])
    verdict = VERDICT_LABEL[Verdict(r["verdict"])]
    if r["mitre_technique_name"] not in ("N/A", ""):
        attack = f"{r['mitre_technique_name']} ({r['mitre_technique_id']})"
    elif r["verdict"] == "false_positive":
        attack = "benign activity"
    else:
        attack = "unclear pattern"
    header = (f"**#{i}**  ·  `{r['src_ip']}`  ·  {SEVERITY_BADGE[sev]}  ·  "
              f"**{attack}**  ·  {verdict}  ·  {r['confidence']}%")
    with st.expander(header, expanded=(i == 1)):
        left, right = st.columns([3, 2])
        with left:
            st.markdown(f"**Analyst summary** — {r['summary']}")
            st.markdown("**Recommended actions**")
            for n, action in enumerate(r["recommended_actions"], 1):
                st.markdown(f"{n}. {action}")
        with right:
            ctx = enriched_by_ip[r["src_ip"]]["enrichment"]
            intel = ctx["threat_intel"]
            st.markdown("**Enrichment**")
            st.markdown(f"- Geolocation: {ctx['geolocation']}")
            st.markdown(f"- Reputation: {intel.get('reputation', 'no records')}")
            if intel.get("tags"):
                st.markdown(f"- Intel tags: {', '.join(intel['tags'])}")
            st.markdown(f"- ATT&CK: `{r['mitre_technique_id']}` {r['mitre_technique_name']}")
        st.markdown("**Raw events**")
        st.code("\n".join(raw_events[r["src_ip"]]), language="text")

# ---------------------------------------------------------------- evaluation
labels = load_labels(labels_path)
if labels:
    st.subheader("Evaluation against ground truth")
    rows = []
    for ip, truth in labels.items():
        pred = next((r["verdict"] for r in results if r["src_ip"] == ip), "missing")
        rows.append({"source IP": ip, "ground truth": truth, "predicted": pred,
                     "result": "✅" if pred == truth else "❌"})
    eval_df = pd.DataFrame(rows)
    correct = (eval_df["ground truth"] == eval_df["predicted"]).sum()
    st.markdown(f"**{correct}/{len(eval_df)}** verdicts match the hand-labeled ground truth.")
    st.dataframe(eval_df, width="stretch", hide_index=True)
