"""Triage enriched alerts.

Two engines:
  - llm_triage: Claude with structured outputs (the showcase path)
  - heuristic_triage: rule-based fallback so the pipeline runs offline
"""
import json
from enum import Enum
from typing import List

from pydantic import BaseModel, Field

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst triaging \
authentication alerts. Alerts come from SSH logs (log_source: sshd_file) or Windows / \
Active Directory Security events 4624/4625 pulled from Splunk (log_source: \
splunk_windows_ad). For each alert you receive a JSON summary of activity from one \
source IP, including enrichment (geolocation, threat intelligence reputation).

Assess the alert the way an experienced Tier 2 analyst would:
- Internal IPs with one or two failed logins followed by success are usually typos, not attacks.
- For Windows/AD alerts, internal sources are NOT automatically benign: many failed \
logons from one internal host against multiple accounts suggests lateral movement or \
internal password spraying (T1110.003). Weigh volume and account diversity, not just \
network location.
- Many failed logins across many usernames (especially 'invalid user' attempts) indicate \
brute-force or credential-spraying activity. Map to MITRE ATT&CK T1110.
- A successful login AFTER repeated failures from an external IP is the most dangerous \
pattern: likely account compromise. Treat as critical and recommend containment.
- Pure connection probes with no authentication attempts (connection_probes_no_auth: \
banner grabbing, port scanning) are reconnaissance — a true positive, but rate it low \
or informational severity and map to T1595 Active Scanning.
- max_auth_exceeded_events means sshd cut the attacker off mid-burst; preauth_disconnects \
alongside failures are typical of automated brute-force tooling. Both strengthen a \
brute-force assessment.
- Failed publickey attempts across accounts suggest SSH key scanning/spraying rather \
than password guessing.
- One source IP hitting multiple hosts (hosts_targeted) suggests scanning or spraying \
across the estate, not a user mistake.
- Use the threat intelligence reputation to adjust confidence, not to decide alone.

Be precise and avoid alarmism: a blocked brute force with zero successes is lower \
severity than any successful suspicious login. Write the summary in plain English for \
a junior analyst, and make recommended actions specific and ordered by priority."""


class Verdict(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    needs_investigation = "needs_investigation"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class TriageResult(BaseModel):
    src_ip: str
    verdict: Verdict
    severity: Severity
    confidence: int = Field(description="0-100 confidence in the verdict")
    mitre_technique_id: str = Field(description="Most relevant MITRE ATT&CK technique ID, e.g. T1110.001, or 'N/A'")
    mitre_technique_name: str
    summary: str = Field(description="2-3 sentence plain-English explanation for an analyst")
    recommended_actions: List[str] = Field(description="Ordered, specific next steps")


def llm_triage(enriched_alerts: List[dict], model: str = "claude-opus-4-8",
               max_workers: int = 4) -> List[TriageResult]:
    import anthropic
    from concurrent.futures import ThreadPoolExecutor

    # Generous retry budget: on lower API tiers, large batches hit per-minute
    # token limits and must wait out the window (the SDK honors retry-after).
    client = anthropic.Anthropic(max_retries=10)

    def triage_one(alert: dict) -> TriageResult:
        response = client.messages.parse(
            model=model,
            max_tokens=1024,
            system=[{
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{
                "role": "user",
                "content": "Triage this SSH alert:\n" + json.dumps(alert, indent=2),
            }],
            output_format=TriageResult,
        )
        return response.parsed_output

    # The client is thread-safe; parallelism is bounded to stay under rate
    # limits. executor.map preserves input order.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(triage_one, enriched_alerts))


def heuristic_triage(enriched_alerts: List[dict]) -> List[TriageResult]:
    """Rule-based triage for offline runs. Intentionally simpler than the LLM —
    it exists to keep the pipeline demoable without an API key and as a
    baseline to evaluate the LLM against."""
    results = []
    for a in enriched_alerts:
        internal = a["enrichment"]["internal_source"]
        reputation = a["enrichment"]["threat_intel"].get("reputation", "no records")
        failed, accepted = a["failed_logins"], a["successful_logins"]
        probes = a.get("connection_probes_no_auth", 0)
        max_auth = a.get("max_auth_exceeded_events", 0)

        if probes >= 2 and failed == 0 and accepted == 0:
            verdict, severity, conf = Verdict.true_positive, Severity.low, 75
            summary = (f"{a['src_ip']} made {probes} connection probes (no banner / "
                       f"no auth attempt) against {len(a.get('hosts_targeted', []))} "
                       f"host(s) — scanner reconnaissance, no login attempted.")
            actions = ["No containment needed; confirm perimeter exposure is intended",
                       "Add the IP to scanner watchlists",
                       "Verify SSH is not exposed wider than necessary"]
            tech, tech_name = "T1595", "Active Scanning"
        elif a["success_after_failures"] and not internal:
            verdict, severity, conf = Verdict.true_positive, Severity.critical, 90
            summary = (f"External IP {a['src_ip']} failed {failed} logins and then "
                       f"successfully authenticated — likely account compromise.")
            actions = ["Disable the affected account", "Isolate the host",
                       "Block the source IP", "Review session activity after login"]
            tech, tech_name = "T1110.001", "Brute Force: Password Guessing"
        elif internal and failed >= 4 and len(a["usernames_targeted"]) >= 3:
            verdict, severity, conf = Verdict.true_positive, Severity.high, 75
            summary = (f"Internal host {a['src_ip']} failed logins against "
                       f"{len(a['usernames_targeted'])} different accounts — possible "
                       f"lateral movement or internal password spraying.")
            actions = ["Identify the user/process on the source host",
                       "Check the source host for signs of compromise",
                       "Review which accounts were targeted for privilege level"]
            tech, tech_name = "T1110.003", "Brute Force: Password Spraying"
        elif (failed >= 4 or (failed >= 2 and len(a["usernames_targeted"]) >= 3)) and not internal:
            verdict, severity = Verdict.true_positive, Severity.high
            conf = 85 if reputation == "malicious" else 70
            if max_auth:
                conf = min(95, conf + 5)
            summary = (f"External IP {a['src_ip']} made {failed} failed logins across "
                       f"{len(a['usernames_targeted'])} usernames with no success — "
                       f"brute-force attempt, currently blocked.")
            actions = ["Block the source IP at the firewall",
                       "Confirm no successful logins from this IP elsewhere",
                       "Verify password auth is disabled where possible"]
            tech, tech_name = "T1110", "Brute Force"
        elif internal and failed <= 2 and accepted >= 1:
            verdict, severity, conf = Verdict.false_positive, Severity.informational, 80
            if failed:
                summary = (f"Internal user on {a['src_ip']} mistyped a password "
                           f"{failed} time(s) before logging in — routine behavior.")
            else:
                summary = (f"Internal source {a['src_ip']} logged in normally "
                           f"({accepted} successful login(s), no failures).")
            actions = ["No action required"]
            tech, tech_name = "N/A", "N/A"
        else:
            verdict, severity, conf = Verdict.needs_investigation, Severity.medium, 50
            summary = (f"Activity from {a['src_ip']} ({failed} failed / {accepted} "
                       f"successful logins) does not match a clear pattern.")
            actions = ["Review full session history for this IP",
                       "Check if the account owner recognizes the activity"]
            tech, tech_name = "N/A", "N/A"

        results.append(TriageResult(
            src_ip=a["src_ip"], verdict=verdict, severity=severity, confidence=conf,
            mitre_technique_id=tech, mitre_technique_name=tech_name,
            summary=summary, recommended_actions=actions,
        ))
    return results
