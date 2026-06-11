"""Streamlit dashboard for the AI SOC triage pipeline.

Run with:
    streamlit run dashboard.py
"""
import calendar
import csv
import hashlib
import json
import math
import os
import re
import tempfile

import altair as alt
import pandas as pd
import pydeck as pdk
import streamlit as st

from src.case_store import STATUS_ICON, STATUSES, get_cases, update_case
from src.enrich import enrich_alert
from src.parser import parse_log
from src.triage import Severity, Verdict, generate_incident_report, llm_triage

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
VERDICT_ALL = list(VERDICT_LABEL.values())
SEV_ORDER = ["critical", "high", "medium", "low", "informational"]
SEV_COLORS = ["#e24b4a", "#f0716f", "#ef9f27", "#378add", "#888780"]

# Coordinates for the cities that appear in enrichment geolocation strings
# (format: "CC — City (ASN/provider)").
CITY_COORDS = {
    "Moscow": (55.76, 37.62), "St. Petersburg": (59.93, 30.36),
    "Hangzhou": (30.27, 120.16), "Shenzhen": (22.54, 114.06),
    "Amsterdam": (52.37, 4.90), "São Paulo": (-23.55, -46.63),
    "Hanoi": (21.03, 105.85), "Tehran": (35.69, 51.39),
    "Mumbai": (19.08, 72.88), "Seoul": (37.57, 126.98),
    "Warsaw": (52.23, 21.01), "Istanbul": (41.01, 28.98),
    "Stockholm": (59.33, 18.07), "Panama City": (8.98, -79.52),
    "Chicago": (41.88, -87.63), "Dallas": (32.78, -96.80),
    "Toronto": (43.65, -79.38), "Iowa": (41.88, -93.10),
    "Ashburn": (39.04, -77.49), "Frankfurt": (50.11, 8.68),
}


# Tactic mapping for the techniques the triage engines emit; parent
# technique is used as a fallback for sub-techniques.
TACTIC_MAP = {
    "T1595": "Reconnaissance",
    "T1078": "Initial Access",
    "T1110": "Credential Access",
    "T1021": "Lateral Movement",
    "T1046": "Discovery",
}
TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Credential Access",
                "Discovery", "Lateral Movement", "Other"]
MONTHS = {m: i for i, m in enumerate(calendar.month_abbr) if m}
TS_RE = re.compile(r"^(\w{3})\s+(\d+)\s(\d\d):(\d\d):\d\d")


def timeline_df(raw_events, results):
    """One row per log event with its hour and the parent alert's severity."""
    sev_by_ip = {r["src_ip"]: r["severity"] for r in results}
    rows = []
    for ip, lines in raw_events.items():
        sev = sev_by_ip.get(ip, "informational")
        for line in lines:
            m = TS_RE.match(line)
            if not m:
                continue
            mon, day, hour, _ = m.groups()
            rows.append({"hour": pd.Timestamp(2026, MONTHS.get(mon, 6),
                                              int(day), int(hour)),
                         "severity": sev})
    return pd.DataFrame(rows)


def attack_matrix_df(results):
    """Confirmed attacks grouped into a MITRE ATT&CK tactic/technique grid.

    Grouped by technique ID only — the LLM may phrase the technique *name*
    slightly differently across alerts, and grouping on the name would
    produce near-duplicate rows.
    """
    counts, names = {}, {}
    for r in results:
        tid = r["mitre_technique_id"]
        if r["verdict"] != "true_positive" or tid in ("N/A", ""):
            continue
        counts[tid] = counts.get(tid, 0) + 1
        name_votes = names.setdefault(tid, {})
        name_votes[r["mitre_technique_name"]] = name_votes.get(r["mitre_technique_name"], 0) + 1
    rows = []
    for tid, count in counts.items():
        name = max(names[tid], key=names[tid].get)
        tactic = TACTIC_MAP.get(tid, TACTIC_MAP.get(tid.split(".")[0], "Other"))
        rows.append({"tactic": tactic, "technique": f"{tid} — {name}", "alerts": count})
    return pd.DataFrame(rows)


def entity_tables(enriched, results):
    """Top targeted accounts and hosts across confirmed attacks."""
    verdict_by_ip = {r["src_ip"]: r["verdict"] for r in results}
    accounts, hosts = {}, {}
    for a in enriched:
        if verdict_by_ip.get(a["src_ip"]) != "true_positive":
            continue
        for user in a["usernames_targeted"]:
            accounts[user] = accounts.get(user, 0) + 1
        for host in a.get("hosts_targeted", []):
            hosts[host] = hosts.get(host, 0) + 1
    acc_df = (pd.DataFrame([{"account": u, "attacking sources": n}
                            for u, n in accounts.items()])
              .sort_values("attacking sources", ascending=False).head(10))
    host_df = (pd.DataFrame([{"host": h, "attack alerts": n}
                             for h, n in hosts.items()])
               .sort_values("attack alerts", ascending=False).head(10))
    return acc_df, host_df


def ioc_df(results, enriched_by_ip):
    """Exportable indicators of compromise: external attacking IPs."""
    rows = []
    for r in results:
        if r["verdict"] != "true_positive":
            continue
        ctx = enriched_by_ip[r["src_ip"]]
        if ctx["enrichment"]["internal_source"]:
            continue
        intel = ctx["enrichment"]["threat_intel"]
        rows.append({
            "indicator": r["src_ip"], "type": "ipv4",
            "severity": r["severity"], "technique": r["mitre_technique_id"],
            "reputation": intel.get("reputation", "no records"),
            "tags": ";".join(intel.get("tags") or []),
            "first_seen": ctx.get("first_seen", ""),
            "last_seen": ctx.get("last_seen", ""),
        })
    return pd.DataFrame(rows)


def attack_origin_df(results, enriched_by_ip):
    """Aggregate confirmed attacks per city for the bubble map."""
    cities = {}
    for r in results:
        if r["verdict"] != "true_positive":
            continue
        geo = enriched_by_ip[r["src_ip"]]["enrichment"]["geolocation"]
        if "—" not in geo:
            continue
        city = geo.split("—", 1)[1].split("(")[0].strip()
        if city in CITY_COORDS:
            cities[city] = cities.get(city, 0) + 1
    rows = []
    for city, count in cities.items():
        lat, lon = CITY_COORDS[city]
        rows.append({"city": city, "lat": lat, "lon": lon, "attacks": count,
                     "radius": 90_000 + 130_000 * math.sqrt(count)})
    return pd.DataFrame(rows)

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

punted = [r for r in results if r["verdict"] == "needs_investigation"]
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Alerts in queue", len(results))
c2.metric("Confirmed attacks", len(attacks))
c3.metric("Needs review", len(punted))
c4.metric("Cleared as benign", len(benign))
c5.metric("Critical — act now", len(critical))

# ---------------------------------------------------------------- overview charts
left, right = st.columns(2)
with left:
    st.subheader("Queue by severity")
    sev_counts = (pd.DataFrame({"severity": [r["severity"] for r in results]})
                  .value_counts().reset_index(name="alerts"))
    sev_chart = alt.Chart(sev_counts).mark_bar().encode(
        x=alt.X("alerts:Q", title=None),
        y=alt.Y("severity:N", sort=SEV_ORDER, title=None),
        color=alt.Color("severity:N",
                        scale=alt.Scale(domain=SEV_ORDER, range=SEV_COLORS),
                        legend=None),
        tooltip=["severity", "alerts"],
    ).properties(height=200)
    st.altair_chart(sev_chart, use_container_width=True)
with right:
    st.subheader("Attack techniques")
    techniques = [r["mitre_technique_name"] for r in results
                  if r["verdict"] == "true_positive"
                  and r["mitre_technique_name"] not in ("N/A", "")]
    if techniques:
        tech_counts = (pd.DataFrame({"technique": techniques})
                       .value_counts().reset_index(name="alerts").head(8))
        tech_chart = alt.Chart(tech_counts).mark_bar(color="#d85a30").encode(
            x=alt.X("alerts:Q", title=None),
            y=alt.Y("technique:N", sort="-x", title=None),
            tooltip=["technique", "alerts"],
        ).properties(height=200)
        st.altair_chart(tech_chart, use_container_width=True)
    else:
        st.caption("No confirmed attacks in this dataset.")

# Per-source activity is only readable on small datasets; at benchmark
# scale the top sources are uniformly noisy brute-forcers.
if len(enriched) <= 20:
    st.subheader("Most active sources")
    chart_df = pd.DataFrame(
        [{"source IP": a["src_ip"],
          "failed logins": a["failed_logins"],
          "successful logins": a["successful_logins"],
          "probes (no auth)": a.get("connection_probes_no_auth", 0)} for a in enriched]
    )
    chart_df["total"] = chart_df.drop(columns="source IP").sum(axis=1)
    top = chart_df.nlargest(15, "total")
    st.bar_chart(
        top.set_index("source IP")[["failed logins", "successful logins", "probes (no auth)"]],
        color=["#e24b4a", "#1d9e75", "#ba7517"],
        horizontal=True,
        height=max(240, 28 * len(top)),
    )

# ---------------------------------------------------------------- attack map
geo_df = attack_origin_df(results, enriched_by_ip)
if not geo_df.empty:
    st.subheader("Attack origins")
    st.caption("Confirmed attacks by source geolocation — bubble size = attack count")
    st.pydeck_chart(pdk.Deck(
        map_style=None,
        initial_view_state=pdk.ViewState(latitude=28, longitude=20, zoom=1.1),
        layers=[pdk.Layer(
            "ScatterplotLayer",
            data=geo_df,
            get_position="[lon, lat]",
            get_radius="radius",
            get_fill_color=[226, 75, 74, 170],
            get_line_color=[80, 19, 19],
            line_width_min_pixels=1,
            stroked=True,
            pickable=True,
        )],
        tooltip={"text": "{city}: {attacks} attack alert(s)"},
    ), height=420)

# ---------------------------------------------------------------- queue + eval
st.divider()
truth_labels = load_labels(labels_path)
dataset_key = hashlib.sha1(log_text.encode()).hexdigest()[:12]
cases = get_cases(dataset_key)


def _persist(field, widget_key, ip):
    update_case(dataset_key, ip, **{field: st.session_state[widget_key]})


tab_names = ["Analyst queue", "Threat analysis"]
if truth_labels:
    tab_names.append("Evaluation vs ground truth")
tabs = st.tabs(tab_names)

with tabs[0]:
    fcol, scol = st.columns([5, 2], vertical_alignment="bottom")
    with fcol:
        sev_sel = st.pills("Severity", SEV_ORDER, selection_mode="multi",
                           default=SEV_ORDER, key="f_sev")
        verdict_sel = st.pills("Verdict", VERDICT_ALL, selection_mode="multi",
                               default=VERDICT_ALL, key="f_verdict")
    with scol:
        ip_query = st.text_input("Find source IP", placeholder="e.g. 10.0.")

    # Empty pill selection = no filter on that dimension (show all)
    active_sev = sev_sel or SEV_ORDER
    active_verdict = verdict_sel or VERDICT_ALL
    filtered = [r for r in results
                if r["severity"] in active_sev
                and VERDICT_LABEL[Verdict(r["verdict"])] in active_verdict
                and (not ip_query or ip_query in r["src_ip"])]
    st.caption(f"{len(filtered)} of {len(results)} alerts match · ranked highest risk first")
    show_case_forms = len(filtered) <= 150
    if not show_case_forms:
        st.caption("ℹ️ Case management forms appear when 150 or fewer alerts "
                   "are shown — narrow the filters to work cases.")

    with st.container(height=620):
        for i, r in enumerate(filtered, 1):
            sev = Severity(r["severity"])
            case = cases.get(r["src_ip"], {})
            status = case.get("status", "New")
            if r["mitre_technique_name"] not in ("N/A", ""):
                attack = f"{r['mitre_technique_name']} ({r['mitre_technique_id']})"
            elif r["verdict"] == "false_positive":
                attack = "benign activity"
            else:
                attack = "unclear pattern"
            header = (f"{SEVERITY_BADGE[sev]} · `{r['src_ip']}` · **{attack}** · "
                      f"{r['confidence']}%")
            if status != "New":
                header += f" · {STATUS_ICON[status]} {status.lower()}"
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
                    st.markdown("**Assessment**")
                    st.markdown(f"- Verdict: {VERDICT_LABEL[Verdict(r['verdict'])]} "
                                f"({r['confidence']}% confidence)")
                    st.markdown(f"- ATT&CK: `{r['mitre_technique_id']}` {r['mitre_technique_name']}")
                    st.markdown("**Enrichment**")
                    st.markdown(f"- Geolocation: {ctx['geolocation']}")
                    st.markdown(f"- Reputation: {intel.get('reputation', 'no records')}")
                    if intel.get("tags"):
                        st.markdown(f"- Intel tags: {', '.join(intel['tags'])}")
                st.markdown("**Raw events**")
                st.code("\n".join(raw_events[r["src_ip"]]), language="text")
                if show_case_forms:
                    ip = r["src_ip"]
                    st.markdown("**Case management**")
                    cc1, cc2, cc3 = st.columns([1.4, 1.4, 2])
                    cc1.selectbox("Status", STATUSES,
                                  index=STATUSES.index(status),
                                  key=f"cs_{dataset_key}_{ip}",
                                  on_change=_persist,
                                  args=("status", f"cs_{dataset_key}_{ip}", ip))
                    cc2.text_input("Assignee", value=case.get("assignee", ""),
                                   key=f"ca_{dataset_key}_{ip}",
                                   on_change=_persist,
                                   args=("assignee", f"ca_{dataset_key}_{ip}", ip))
                    cc3.segmented_control("AI verdict feedback",
                                          ["👍 agree", "👎 disagree"],
                                          default=case.get("feedback"),
                                          key=f"cf_{dataset_key}_{ip}",
                                          on_change=_persist,
                                          args=("feedback", f"cf_{dataset_key}_{ip}", ip))
                    st.text_area("Investigation notes", value=case.get("notes", ""),
                                 key=f"cn_{dataset_key}_{ip}", height=70,
                                 on_change=_persist,
                                 args=("notes", f"cn_{dataset_key}_{ip}", ip))

# ---------------------------------------------------------------- threat analysis
with tabs[1]:
    st.markdown("##### Attack timeline")
    tl_df = timeline_df(raw_events, results)
    if not tl_df.empty:
        tl_chart = alt.Chart(tl_df).mark_bar().encode(
            x=alt.X("hour:T", title=None),
            y=alt.Y("count()", title="events"),
            color=alt.Color("severity:N",
                            scale=alt.Scale(domain=SEV_ORDER, range=SEV_COLORS),
                            legend=alt.Legend(orient="top", title=None)),
            tooltip=[alt.Tooltip("hour:T"), "severity", alt.Tooltip("count()", title="events")],
        ).properties(height=220)
        st.altair_chart(tl_chart, use_container_width=True)

    st.markdown("##### MITRE ATT&CK coverage")
    mx_df = attack_matrix_df(results)
    if not mx_df.empty:
        base = alt.Chart(mx_df).encode(
            x=alt.X("tactic:N", sort=TACTIC_ORDER, title=None,
                    axis=alt.Axis(labelAngle=0, orient="top")),
            y=alt.Y("technique:N", title=None),
        )
        heat = base.mark_rect().encode(
            color=alt.Color("alerts:Q", scale=alt.Scale(scheme="reds"), legend=None))
        text = base.mark_text(fontWeight="bold").encode(
            text="alerts:Q",
            color=alt.condition("datum.alerts > 60", alt.value("white"), alt.value("#501313")))
        st.altair_chart((heat + text).properties(height=60 + 38 * mx_df["technique"].nunique()),
                        use_container_width=True)
    else:
        st.caption("No confirmed attacks to map.")

    e1, e2 = st.columns(2)
    acc_df, host_df = entity_tables(enriched, results)
    with e1:
        st.markdown("##### Most targeted accounts")
        st.dataframe(acc_df, width="stretch", hide_index=True)
    with e2:
        st.markdown("##### Most targeted hosts")
        st.dataframe(host_df, width="stretch", hide_index=True)

    st.markdown("##### Indicators of compromise")
    iocs = ioc_df(results, enriched_by_ip)
    if iocs.empty:
        st.caption("No external attack indicators.")
    else:
        st.caption(f"{len(iocs)} external attacking IPs")
        d1, d2, _ = st.columns([1.5, 1.5, 3])
        d1.download_button("Download IOCs (CSV)", iocs.to_csv(index=False),
                           "iocs.csv", "text/csv")
        d2.download_button("Download blocklist (TXT)",
                           "\n".join(iocs["indicator"]), "blocklist.txt", "text/plain")

    fb = [(ip, c) for ip, c in cases.items() if c.get("feedback")]
    if fb:
        st.markdown("##### Analyst feedback on AI verdicts")
        agree = sum(1 for _, c in fb if "agree" in c["feedback"] and "dis" not in c["feedback"])
        st.caption(f"{agree} agree · {len(fb) - agree} disagree — exportable as new "
                   f"labeled training data")
        verdict_by_ip = {r["src_ip"]: r["verdict"] for r in results}
        fb_df = pd.DataFrame([{
            "src_ip": ip, "ai_verdict": verdict_by_ip.get(ip, ""),
            "analyst_feedback": c["feedback"], "notes": c.get("notes", ""),
        } for ip, c in fb])
        st.download_button("Download feedback (CSV)", fb_df.to_csv(index=False),
                           "analyst_feedback.csv", "text/csv")

    st.markdown("##### Incident report")
    attack_ips = [r["src_ip"] for r in results if r["verdict"] == "true_positive"]
    if not attack_ips:
        st.caption("No confirmed attacks to report on.")
    elif not os.environ.get("ANTHROPIC_API_KEY"):
        st.caption("Set an API key to generate incident reports.")
    else:
        rc1, rc2 = st.columns([2, 1], vertical_alignment="bottom")
        report_ip = rc1.selectbox("Alert", attack_ips, key="report_ip")
        if rc2.button("Generate with Claude"):
            r = next(x for x in results if x["src_ip"] == report_ip)
            with st.spinner("Claude is writing the incident report..."):
                report_md = generate_incident_report(
                    enriched_by_ip[report_ip], r, raw_events[report_ip], model=model)
            st.session_state["last_report"] = (report_ip, report_md)
        if st.session_state.get("last_report", (None,))[0] == report_ip:
            report_md = st.session_state["last_report"][1]
            with st.container(height=420):
                st.markdown(report_md)
            st.download_button("Download report (Markdown)", report_md,
                               f"incident_{report_ip.replace('.', '_')}.md",
                               "text/markdown")

if truth_labels:
    with tabs[2]:
        rows = []
        for ip, truth in truth_labels.items():
            pred = next((r["verdict"] for r in results if r["src_ip"] == ip), "missing")
            rows.append({"source IP": ip, "ground truth": truth, "predicted": pred,
                         "result": "✅" if pred == truth else "❌"})
        eval_df = pd.DataFrame(rows)
        correct = (eval_df["ground truth"] == eval_df["predicted"]).sum()
        st.markdown(f"**{correct}/{len(eval_df)}** verdicts match the hand-labeled ground truth.")
        st.dataframe(eval_df, width="stretch", hide_index=True)
