# AI SOC Triage — LLM-Assisted SSH Alert Triage Pipeline

An AI-powered Security Operations Center (SOC) assistant that ingests raw SSH
authentication logs, enriches them with threat intelligence context, and uses
**Claude** to triage each alert the way a Tier 2 analyst would — producing a
ranked queue with verdicts, MITRE ATT&CK mappings, plain-English summaries,
and prioritized response actions.

Built to address the #1 pain point in security operations: **alert fatigue**.
Analysts drown in raw events; this pipeline turns them into a short, ranked
list of what actually matters.

## Pipeline

```
raw auth.log ──> parse & correlate ──> enrich ──> triage ──> ranked report
                 (group events per     (GeoIP,    (Claude or  (severity-sorted
                  source IP)           threat     heuristic    queue + actions)
                                       intel)     baseline)
```

1. **Parse** — regex-based parser turns `sshd` syslog lines into structured
   events, correlated into one alert per source IP (failed/successful logins,
   usernames targeted, success-after-failure detection).
2. **Enrich** — each alert gets geolocation and threat-intel reputation
   context (offline static table for the demo; designed to swap in AbuseIPDB /
   VirusTotal / MaxMind with no other changes).
3. **Triage** — Claude receives the enriched alert and returns a **schema-validated
   structured verdict** (Pydantic + the Anthropic structured-outputs API):
   verdict, severity, confidence, MITRE ATT&CK technique, analyst summary,
   and ordered response actions. A rule-based heuristic engine serves as an
   offline fallback and evaluation baseline.
4. **Report** — results are ranked by severity and confidence into an analyst
   queue rendered in the terminal.

## Quick start

```bash
pip install -r requirements.txt

# No API key needed — heuristic baseline on the bundled sample log
python main.py

# Claude-powered triage
export ANTHROPIC_API_KEY=sk-ant-...
python main.py --llm

# Interactive dashboard (upload your own logs, switch engines, view evals)
streamlit run dashboard.py
```

## Splunk + Active Directory integration

Instead of flat files, the pipeline can pull live **Windows / Active Directory
authentication events** (EventCode 4625 failed logon, 4624 successful logon)
from a Splunk instance via the REST API:

```bash
export SPLUNK_HOST=mystack.splunkcloud.com   # or your server IP
export SPLUNK_TOKEN=eyJr...                  # Settings > Tokens in Splunk Web
export SPLUNK_INDEX=wineventlog

python main.py --source splunk --earliest -24h@h --llm
```

Splunk events are normalized into the same internal event model as SSH logs,
so enrichment, triage, and reporting are identical. AD-specific semantics are
handled in triage: internal sources are not assumed benign — many failures
from one internal host across multiple accounts is flagged as possible
lateral movement / internal password spraying (T1110.003).

See `.env.example` for all connection options (basic auth, self-signed
certs, custom index). The Splunk-to-pipeline mapping is covered by an offline
fixture (`data/sample_splunk_export.jsonl`) so it can be tested without a
live instance.

## Evaluation

The repo includes hand-labeled ground truth (`data/labels.csv`) for every
source IP in the sample log, and an evaluation harness that measures triage
precision and recall — because an AI security tool you haven't measured is a
liability, not an asset.

```bash
python main.py --llm --json results.json
python evaluate.py results.json
```

## What the sample log contains

The bundled `data/sample_auth.log` simulates one day on an internet-facing
web server, including:

| Pattern | Source | Ground truth |
|---|---|---|
| Multi-username brute force (15 attempts) | `203.0.113.45` | attack (blocked) |
| **Success after repeated failures** | `198.51.100.23` | account compromise |
| Root brute force from a Tor exit node | `185.220.101.7` | attack (blocked) |
| Credential spraying on service accounts | `91.240.118.172` | attack (blocked) |
| Routine admin publickey logins | `10.0.0.5` | benign |
| User typo then successful login | `10.0.0.12` | benign |

## Design notes

- **Structured outputs, not free text.** Triage verdicts come back as a
  validated Pydantic model via `client.messages.parse()` — no brittle JSON
  parsing of model prose, and malformed responses fail loudly.
- **Prompt caching.** The system prompt is cached (`cache_control: ephemeral`)
  so triaging N alerts only pays for the analyst instructions once.
- **The LLM never decides alone.** Threat-intel reputation is provided as
  *context to weigh*, and the heuristic baseline exists so LLM verdicts can be
  benchmarked, not blindly trusted.

## Roadmap

- [ ] Live enrichment: AbuseIPDB + MaxMind GeoLite2
- [x] Splunk ingestion (`--source splunk` pulls Windows/AD events 4624/4625 via the REST API)
- [ ] Agentic enrichment: let Claude call lookup tools itself via tool use
- [ ] Windows Event Log (4625/4624) support
- [x] Streamlit dashboard (`streamlit run dashboard.py`)

## Disclaimer

All log data is synthetic, generated for demonstration. IP addresses are from
documentation/example ranges or well-known public scanner ranges; no real
systems were involved.
