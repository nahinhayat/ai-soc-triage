"""Parse Linux sshd auth logs into per-source-IP alerts.

Supported event types (actions):
  failed             Failed password|publickey for [invalid user] NAME from IP
  accepted           Accepted password|publickey for NAME from IP
  max_auth           error: maximum authentication attempts exceeded for NAME from IP
  preauth_disconnect Connection closed/reset/disconnect before authentication
  probe              Did not receive identification string / invalid banner
                     (port scanners and banner grabbers that never attempt auth)
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional

LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed (?P<method>password|publickey) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
MAX_AUTH_RE = re.compile(
    r"maximum authentication attempts exceeded for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
CLOSED_USER_RE = re.compile(
    r"(?:Connection closed by|Disconnected from) (?:authenticating|invalid) user (?P<user>\S+) (?P<ip>\S+) port \d+ \[preauth\]"
)
PREAUTH_RE = re.compile(
    r"(?:Received disconnect from|Connection reset by) (?P<ip>\S+) port \d+.*\[preauth\]"
)
PROBE_RE = re.compile(
    r"Did not receive identification string from (?P<ip>\S+)"
    r"|Connection from (?P<ip2>\S+) port \d+: invalid format"
)


@dataclass
class Event:
    timestamp: str
    host: str
    action: str  # "failed" | "accepted" | "max_auth" | "preauth_disconnect" | "probe"
    user: str    # "" for events with no associated username
    src_ip: str
    invalid_user: bool = False
    method: Optional[str] = None
    raw: str = ""


@dataclass
class Alert:
    src_ip: str
    host: str
    events: List[Event] = field(default_factory=list)

    @property
    def failed_count(self) -> int:
        return sum(1 for e in self.events if e.action == "failed")

    @property
    def accepted_count(self) -> int:
        return sum(1 for e in self.events if e.action == "accepted")

    @property
    def usernames(self) -> List[str]:
        seen = []
        for e in self.events:
            if e.user and e.user not in seen:
                seen.append(e.user)
        return seen

    @property
    def invalid_user_count(self) -> int:
        return sum(1 for e in self.events if e.invalid_user)

    @property
    def probe_count(self) -> int:
        return sum(1 for e in self.events if e.action == "probe")

    @property
    def preauth_disconnects(self) -> int:
        return sum(1 for e in self.events if e.action == "preauth_disconnect")

    @property
    def max_auth_exceeded(self) -> int:
        return sum(1 for e in self.events if e.action == "max_auth")

    @property
    def hosts_targeted(self) -> List[str]:
        seen = []
        for e in self.events:
            if e.host not in seen:
                seen.append(e.host)
        return seen

    @property
    def first_seen(self) -> str:
        return self.events[0].timestamp if self.events else ""

    @property
    def last_seen(self) -> str:
        return self.events[-1].timestamp if self.events else ""

    @property
    def success_after_failures(self) -> bool:
        """True if a failed attempt is later followed by an accepted login."""
        saw_failure = False
        for e in self.events:
            if e.action == "failed":
                saw_failure = True
            elif e.action == "accepted" and saw_failure:
                return True
        return False

    def summary_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "hosts_targeted": self.hosts_targeted,
            "failed_logins": self.failed_count,
            "successful_logins": self.accepted_count,
            "invalid_user_attempts": self.invalid_user_count,
            "max_auth_exceeded_events": self.max_auth_exceeded,
            "preauth_disconnects": self.preauth_disconnects,
            "connection_probes_no_auth": self.probe_count,
            "usernames_targeted": self.usernames,
            "success_after_failures": self.success_after_failures,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


def parse_line(line: str) -> Optional[Event]:
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    ts, host, msg = m.group("ts"), m.group("host"), m.group("msg")

    fm = FAILED_RE.search(msg)
    if fm:
        return Event(ts, host, "failed", fm.group("user"), fm.group("ip"),
                     invalid_user=bool(fm.group("invalid")),
                     method=fm.group("method"), raw=line.strip())
    am = ACCEPTED_RE.search(msg)
    if am:
        return Event(ts, host, "accepted", am.group("user"), am.group("ip"),
                     method=am.group("method"), raw=line.strip())
    mm = MAX_AUTH_RE.search(msg)
    if mm:
        return Event(ts, host, "max_auth", mm.group("user"), mm.group("ip"),
                     invalid_user=bool(mm.group("invalid")), raw=line.strip())
    cm = CLOSED_USER_RE.search(msg)
    if cm:
        return Event(ts, host, "preauth_disconnect", cm.group("user"),
                     cm.group("ip"), raw=line.strip())
    pm = PREAUTH_RE.search(msg)
    if pm:
        return Event(ts, host, "preauth_disconnect", "", pm.group("ip"),
                     raw=line.strip())
    bm = PROBE_RE.search(msg)
    if bm:
        return Event(ts, host, "probe", "", bm.group("ip") or bm.group("ip2"),
                     raw=line.strip())
    return None


def group_events(events: List[Event]) -> List[Alert]:
    """Correlate a stream of events into one alert per source IP.

    Source-agnostic: works for events parsed from sshd files, Splunk
    searches, or any other feed that yields Event objects.
    """
    alerts = {}
    for event in events:
        if event.src_ip not in alerts:
            alerts[event.src_ip] = Alert(src_ip=event.src_ip, host=event.host)
        alerts[event.src_ip].events.append(event)
    return list(alerts.values())


def parse_log(path: str) -> List[Alert]:
    """Parse an sshd log file and group events into one alert per source IP."""
    with open(path) as f:
        events = [e for e in (parse_line(line) for line in f) if e is not None]
    return group_events(events)
