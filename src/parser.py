"""Parse Linux sshd auth logs into per-source-IP alerts.

Supports the common syslog formats:
  Failed password for [invalid user] NAME from IP port PORT ssh2
  Accepted password|publickey for NAME from IP port PORT ssh2
  Invalid user NAME from IP port PORT
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional

LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)


@dataclass
class Event:
    timestamp: str
    host: str
    action: str  # "failed" | "accepted"
    user: str
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
            if e.user not in seen:
                seen.append(e.user)
        return seen

    @property
    def invalid_user_count(self) -> int:
        return sum(1 for e in self.events if e.invalid_user)

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
            "host": self.host,
            "failed_logins": self.failed_count,
            "successful_logins": self.accepted_count,
            "invalid_user_attempts": self.invalid_user_count,
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
                     invalid_user=bool(fm.group("invalid")), raw=line.strip())
    am = ACCEPTED_RE.search(msg)
    if am:
        return Event(ts, host, "accepted", am.group("user"), am.group("ip"),
                     method=am.group("method"), raw=line.strip())
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
