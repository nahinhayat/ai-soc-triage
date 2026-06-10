"""Pull Windows / Active Directory authentication events from Splunk.

Queries the Splunk REST API for Windows Security events:
    4625 — failed logon      -> Event(action="failed")
    4624 — successful logon  -> Event(action="accepted")

and normalizes them into the same Event objects the SSH file parser
produces, so the rest of the pipeline (enrich -> triage -> report) is
unchanged.

Configuration (environment variables):
    SPLUNK_HOST        e.g. mystack.splunkcloud.com or 192.168.1.50
    SPLUNK_PORT        management port, default 8089
    SPLUNK_TOKEN       authentication token (preferred), or
    SPLUNK_USERNAME / SPLUNK_PASSWORD for basic auth
    SPLUNK_INDEX       index holding Windows events, default wineventlog
    SPLUNK_VERIFY_SSL  "false" to allow self-signed certs (default true)
"""
import json
import os
from typing import Iterator, List, Optional

import requests

from .parser import Event

# Logon types 3 (network) and 10 (RDP) are the remote-auth events that
# matter for this pipeline; 4625 is kept unfiltered so local lockout
# storms still surface. STATUS_NO_SUCH_USER marks the AD equivalent of
# sshd's "invalid user".
NO_SUCH_USER = {"0xc0000064", "0xC0000064"}

SPL_QUERY = """search index={index} source="*Security*" (EventCode=4625 OR (EventCode=4624 AND Logon_Type IN (3, 10)))
| eval src=coalesce(src_ip, Source_Network_Address)
| eval account=coalesce(user, mvindex(Account_Name, -1))
| where isnotnull(src) AND src!="-" AND NOT match(account, "\\$$")
| table _time host EventCode account src Logon_Type Sub_Status
"""


def _config():
    host = os.environ.get("SPLUNK_HOST")
    if not host:
        raise RuntimeError("SPLUNK_HOST is not set — see .env.example")
    port = os.environ.get("SPLUNK_PORT", "8089")
    verify = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() != "false"

    headers, auth = {}, None
    token = os.environ.get("SPLUNK_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif os.environ.get("SPLUNK_USERNAME"):
        auth = (os.environ["SPLUNK_USERNAME"], os.environ.get("SPLUNK_PASSWORD", ""))
    else:
        raise RuntimeError("Set SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD")
    return f"https://{host}:{port}", headers, auth, verify


def event_from_result(result: dict) -> Optional[Event]:
    """Map one Splunk search result row to a normalized Event."""
    src = result.get("src", "")
    account = result.get("account", "")
    code = result.get("EventCode", "")
    if not src or not account or code not in ("4624", "4625"):
        return None
    return Event(
        timestamp=result.get("_time", ""),
        host=result.get("host", "unknown"),
        action="accepted" if code == "4624" else "failed",
        user=account,
        src_ip=src,
        invalid_user=result.get("Sub_Status", "") in NO_SUCH_USER,
        method=f"windows_logon_type_{result.get('Logon_Type', '?')}",
        raw=(f"{result.get('_time', '')} {result.get('host', '')} "
             f"EventCode={code} account={account} src={src} "
             f"logon_type={result.get('Logon_Type', '?')}"),
    )


def _iter_export_results(lines: Iterator[bytes]) -> Iterator[dict]:
    """The export endpoint streams one JSON object per line."""
    for line in lines:
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if "result" in obj:
            yield obj["result"]


def fetch_ad_events(earliest: str = "-24h@h", latest: str = "now") -> List[Event]:
    """Run the AD auth search against Splunk and return normalized events."""
    base_url, headers, auth, verify = _config()
    index = os.environ.get("SPLUNK_INDEX", "wineventlog")

    response = requests.post(
        f"{base_url}/services/search/v2/jobs/export",
        headers=headers,
        auth=auth,
        verify=verify,
        data={
            "search": SPL_QUERY.format(index=index),
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
        },
        stream=True,
        timeout=120,
    )
    response.raise_for_status()

    events = [e for e in
              (event_from_result(r) for r in _iter_export_results(response.iter_lines()))
              if e is not None]
    # Alert correlation assumes chronological order for success-after-failure
    events.sort(key=lambda e: e.timestamp)
    return events
