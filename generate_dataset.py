"""Generate a labeled benchmark dataset of synthetic SSH auth activity.

Random by default — every run produces a different dataset (different IPs,
hosts, scenario counts, volumes, and timing). The seed is printed so any
run can be reproduced exactly with --seed.

Event realism: beyond failed/accepted passwords, scenarios emit the noise
real sshd logs contain — pre-auth disconnects, "maximum authentication
attempts exceeded" bursts, failed publickey attempts (key scanning), and
pure connection probes from scanners that never attempt authentication.

Scenario families (counts randomized per run):
  Benign (false_positive):
    B1 internal users: typos then successful logins
    B2 internal service accounts: successful key-based logins only
    B3 HARD misconfigured internal cron: one account failing repeatedly
    B4 HARD employee home IP: 1-2 failures then success (looks like compromise)
    B5 HARD CI/automation from cloud IP: successful logins only, external
  Attacks (true_positive):
    A1 classic external brute force (with max-auth + preauth noise)
    A2 account compromise: failures then a successful login
    A3 HARD slow-and-low: 3 failures against root spread over hours
    A4 HARD distributed spray: one /24, 2 failures per IP, same account
    A5 HARD stolen credentials: clean login from known-bad infrastructure
    A6 internal lateral movement: spraying accounts from inside
    R1 scanner reconnaissance: connection probes only, no auth attempts
    R2 SSH key scanning: failed publickey attempts across hosts

Outputs: data/large_auth.log, data/large_labels.csv, data/intel.json

Usage:  python generate_dataset.py [--seed N]
"""
import argparse
import csv
import json
import random
from datetime import datetime, timedelta

HOSTS = ["web-01", "web-02", "bastion-01", "app-03", "db-01"]
BASE = datetime(2026, 6, 6, 0, 0, 0)
SPAN_HOURS = 72

FIRST_NAMES = ["j", "m", "s", "d", "a", "r", "b", "f", "l", "t", "g", "p", "e", "n", "k", "c"]
LAST_NAMES = ["chen", "patel", "lee", "kim", "nguyen", "taylor", "wilson", "hassan",
              "zhang", "okafor", "miller", "singh", "castro", "ali", "brown", "garcia",
              "ivanov", "dubois", "novak", "santos"]
SPRAY_USERS = ["admin", "root", "test", "guest", "oracle", "postgres", "mysql", "jenkins",
               "ftpuser", "ubnt", "pi", "git", "www-data", "nagios", "user", "support",
               "administrator", "deploy", "es", "hadoop"]
SVC_NAMES = ["backup", "deployer", "metrics", "patching", "inventory", "sync", "etl",
             "monitor", "archiver", "indexer"]
BAD_GEOS = ["RU — Moscow (AS49505 SELECTEL)", "CN — Hangzhou (AS37963 Alibaba)",
            "NL — Amsterdam (AS202425 hosting)", "BR — São Paulo (AS28573)",
            "VN — Hanoi (AS45899 VNPT)", "IR — Tehran (AS58224)",
            "IN — Mumbai (AS55836 Reliance)", "KR — Seoul (AS4766 KT)",
            "PL — Warsaw (AS204957 hosting)", "TR — Istanbul (AS34984)"]
NEUTRAL_GEOS = ["US — Chicago (AS7922 Comcast residential)",
                "US — Dallas (AS7018 AT&T residential)",
                "CA — Toronto (AS812 Rogers residential)",
                "US — Iowa (AS396982 Google Cloud)",
                "US — Ashburn (AS14618 Amazon AWS)",
                "DE — Frankfurt (AS24940 Hetzner)"]
SCANNER_TAG_SETS = [["ssh-bruteforce", "mass-scanner"], ["botnet-node", "ssh-bruteforce"],
                    ["mass-scanner"], ["ssh-bruteforce", "compromised-host"],
                    ["scanner", "shodan-like"]]


class Generator:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.lines = []    # (datetime, line)
        self.labels = []   # (ip, verdict, notes)
        self.intel = {}    # ip -> enrichment entry
        self._used_ips = set()
        self._used_users = set()

    # ------------------------------------------------------------ identities
    def internal_ip(self):
        while True:
            ip = f"10.{self.rng.randint(0, 4)}.{self.rng.randint(0, 5)}.{self.rng.randint(2, 254)}"
            if ip not in self._used_ips:
                self._used_ips.add(ip)
                return ip

    def external_ip(self, subnet=None):
        while True:
            if subnet:
                ip = f"{subnet}.{self.rng.randint(2, 254)}"
            else:
                first = self.rng.choice([23, 31, 37, 45, 62, 77, 80, 89, 91, 103, 109,
                                         121, 134, 141, 146, 152, 163, 171, 178, 185,
                                         193, 194, 202, 209, 212, 217, 221])
                ip = f"{first}.{self.rng.randint(1, 254)}.{self.rng.randint(0, 254)}.{self.rng.randint(2, 254)}"
            if ip not in self._used_ips:
                self._used_ips.add(ip)
                return ip

    def person(self):
        while True:
            user = self.rng.choice(FIRST_NAMES) + self.rng.choice(LAST_NAMES)
            if user not in self._used_users:
                self._used_users.add(user)
                return user

    def add_intel(self, ip, reputation, tags=None, geo=None, reports=None):
        self.intel[ip] = {
            "geo": geo or self.rng.choice(BAD_GEOS if reputation != "no records" else NEUTRAL_GEOS),
            "reputation": reputation,
            "tags": tags or [],
            "reports_90d": reports if reports is not None else
            (self.rng.randint(40, 2000) if reputation == "malicious"
             else self.rng.randint(5, 80) if reputation == "suspicious" else 0),
        }

    # ------------------------------------------------------------ emitters
    def ts(self, dt):
        return f"Jun {dt.day:2d} {dt:%H:%M:%S}"

    def emit(self, dt, host, msg):
        self.lines.append((dt, f"{self.ts(dt)} {host} sshd[{self.rng.randint(1000, 99999)}]: {msg}"))

    def port(self):
        return self.rng.randint(1024, 65000)

    def failed(self, dt, host, user, ip, invalid=False, method="password"):
        prefix = "invalid user " if invalid else ""
        self.emit(dt, host, f"Failed {method} for {prefix}{user} from {ip} port {self.port()} ssh2")

    def accepted(self, dt, host, user, ip, method="password"):
        suffix = ""
        if method == "publickey":
            suffix = ": RSA SHA256:" + "".join(self.rng.choices("abcdefABCDEF0123456789", k=10))
        self.emit(dt, host, f"Accepted {method} for {user} from {ip} port {self.port()} ssh2{suffix}")

    def max_auth(self, dt, host, user, ip, invalid=False):
        prefix = "invalid user " if invalid else ""
        self.emit(dt, host, f"error: maximum authentication attempts exceeded for {prefix}{user} "
                            f"from {ip} port {self.port()} ssh2 [preauth]")

    def preauth_disconnect(self, dt, host, ip, user=None):
        if user and self.rng.random() < 0.5:
            kind = self.rng.choice(["Connection closed by", "Disconnected from"])
            who = self.rng.choice(["authenticating", "invalid"])
            self.emit(dt, host, f"{kind} {who} user {user} {ip} port {self.port()} [preauth]")
        else:
            kind = self.rng.choice([
                f"Received disconnect from {ip} port {self.port()}:11: Bye Bye [preauth]",
                f"Connection reset by {ip} port {self.port()} [preauth]",
            ])
            self.emit(dt, host, kind)

    def probe(self, dt, host, ip):
        if self.rng.random() < 0.6:
            self.emit(dt, host, f"Did not receive identification string from {ip} port {self.port()}")
        else:
            self.emit(dt, host, f"banner exchange: Connection from {ip} port {self.port()}: invalid format")

    # ------------------------------------------------------------ timing
    def window(self):
        return BASE + timedelta(minutes=self.rng.randint(0, SPAN_HOURS * 60))

    def steps(self, dt, lo=3, hi=40):
        while True:
            dt += timedelta(seconds=self.rng.randint(lo, hi))
            yield dt

    def host(self):
        return self.rng.choice(HOSTS)

    # ------------------------------------------------------------ benign
    def b1_internal_typos(self):
        ip, user, host = self.internal_ip(), self.person(), self.host()
        t = self.steps(self.window())
        for _ in range(self.rng.choice([0, 0, 1, 1, 2])):
            self.failed(next(t), host, user, ip)
        if self.rng.random() < 0.2:
            self.preauth_disconnect(next(t), host, ip, user)  # closed laptop lid, retried
        for _ in range(self.rng.randint(1, 4)):
            self.accepted(next(t), host, user, ip,
                          method=self.rng.choice(["password", "publickey"]))
        self.labels.append((ip, "false_positive", f"internal user {user}, typos then normal login"))

    def b2_internal_service(self):
        ip, host = self.internal_ip(), self.host()
        user = f"svc-{self.rng.choice(SVC_NAMES)}{self.rng.randint(1, 9)}"
        t = self.steps(self.window(), 600, 4000)
        for _ in range(self.rng.randint(3, 7)):
            self.accepted(next(t), host, user, ip, method="publickey")
        self.labels.append((ip, "false_positive", f"internal service account {user}, scheduled jobs"))

    def b3_misconfigured_cron(self):
        ip, host = self.internal_ip(), self.host()
        user = f"svc-{self.rng.choice(SVC_NAMES)}{self.rng.randint(1, 9)}"
        t = self.steps(self.window(), 1500, 2300)
        for _ in range(self.rng.randint(7, 14)):
            self.failed(next(t), host, user, ip)
        self.labels.append((ip, "false_positive",
                            f"HARD: internal cron with stale credentials for {user}"))

    def b4_employee_home(self):
        ip, user, host = self.external_ip(), self.person(), self.host()
        t = self.steps(self.window())
        for _ in range(self.rng.randint(1, 2)):
            self.failed(next(t), host, user, ip)
        self.accepted(next(t), host, user, ip)
        self.add_intel(ip, "no records", geo=self.rng.choice(NEUTRAL_GEOS[:3]))
        self.labels.append((ip, "false_positive",
                            f"HARD: employee {user} from home IP, typo then success"))

    def b5_cloud_ci(self):
        ip, host = self.external_ip(), self.host()
        t = self.steps(self.window(), 1200, 3600)
        for _ in range(self.rng.randint(3, 6)):
            self.accepted(next(t), host, "deploy", ip, method="publickey")
        self.add_intel(ip, "no records", geo=self.rng.choice(NEUTRAL_GEOS[3:]))
        self.labels.append((ip, "false_positive",
                            "HARD: CI pipeline from cloud IP, key-based, no failures"))

    # ------------------------------------------------------------ attacks
    def a1_brute_force(self):
        ip, host = self.external_ip(), self.host()
        t = self.steps(self.window(), 2, 15)
        users = self.rng.sample(SPRAY_USERS, self.rng.randint(4, 10))
        attempts = self.rng.randint(8, 35)
        for i in range(attempts):
            u = self.rng.choice(users)
            self.failed(next(t), host, u, ip, invalid=(u not in ("root", "admin")))
            if (i + 1) % 6 == 0:
                self.max_auth(next(t), host, u, ip, invalid=(u not in ("root", "admin")))
                self.preauth_disconnect(next(t), host, ip, u)
        self.add_intel(ip, self.rng.choice(["malicious", "suspicious"]),
                       tags=self.rng.choice(SCANNER_TAG_SETS))
        self.labels.append((ip, "true_positive", "classic multi-username brute force, blocked"))

    def a2_compromise(self):
        ip, host = self.external_ip(), self.host()
        user = self.rng.choice(["deploy", "backup", "webadmin", "devops"])
        t = self.steps(self.window(), 5, 25)
        for i in range(self.rng.randint(4, 10)):
            self.failed(next(t), host, user, ip)
            if i == 5:
                self.max_auth(next(t), host, user, ip)
        self.accepted(next(t), host, user, ip)
        self.add_intel(ip, self.rng.choice(["suspicious", "no records"]),
                       tags=self.rng.choice([["recent-bruteforce-reports"], []]),
                       geo=self.rng.choice(BAD_GEOS))
        self.labels.append((ip, "true_positive", f"account compromise: {user} success after failures"))

    def a3_slow_and_low(self):
        ip, host = self.external_ip(), self.host()
        t = self.steps(self.window(), 7000, 14000)
        for _ in range(3):
            self.failed(next(t), host, "root", ip)
        self.add_intel(ip, "malicious", tags=["ssh-bruteforce", "slow-scanner"])
        self.labels.append((ip, "true_positive",
                            "HARD: slow-and-low — 3 root failures over hours, known-bad IP"))

    def a4_distributed_spray(self, n_nodes):
        subnet = (f"{self.rng.choice([91, 103, 141, 171, 185, 193])}."
                  f"{self.rng.randint(1, 254)}.{self.rng.randint(0, 254)}")
        target = self.rng.choice(["administrator", "root", "admin"])
        host = self.host()
        for _ in range(n_nodes):
            ip = self.external_ip(subnet=subnet)
            t = self.steps(self.window(), 30, 300)
            for _ in range(2):
                self.failed(next(t), host, target, ip, invalid=(target == "administrator"))
            if self.rng.random() < 0.5:
                self.preauth_disconnect(next(t), host, ip, target)
            self.add_intel(ip, "malicious", tags=["botnet-node", "ssh-bruteforce"])
            self.labels.append((ip, "true_positive",
                                f"HARD: distributed spray node ({subnet}.0/24) vs '{target}'"))

    def a5_stolen_credentials(self):
        ip, host = self.external_ip(), self.host()
        user = self.person()
        t = self.steps(self.window(), 600, 2500)
        for _ in range(self.rng.randint(1, 2)):
            self.accepted(next(t), host, user, ip)
        self.add_intel(ip, "malicious", tags=["infostealer-infra", "anonymizing-vpn"],
                       geo="PA — Panama City (AS213412 VPN egress)")
        self.labels.append((ip, "true_positive",
                            f"HARD: stolen credentials — clean login as {user}, zero failures"))

    def a6_lateral_movement(self):
        ip, host = self.internal_ip(), self.host()
        t = self.steps(self.window(), 20, 150)
        for _ in range(self.rng.randint(4, 7)):
            self.failed(next(t), host, self.person(), ip)
        self.labels.append((ip, "true_positive",
                            "internal lateral movement: spraying accounts from one host"))

    def r1_scanner_recon(self):
        ip = self.external_ip()
        t = self.steps(self.window(), 5, 600)
        for _ in range(self.rng.randint(2, 7)):
            self.probe(next(t), self.host(), ip)
        rep = self.rng.choice(["malicious", "suspicious", "no records"])
        self.add_intel(ip, rep, tags=self.rng.choice(SCANNER_TAG_SETS) if rep != "no records" else [])
        self.labels.append((ip, "true_positive",
                            "scanner recon: connection probes only, no auth attempted"))

    def r2_key_scanning(self):
        ip = self.external_ip()
        t = self.steps(self.window(), 10, 90)
        for _ in range(self.rng.randint(3, 8)):
            self.failed(next(t), self.host(), self.rng.choice(["root", "git", "deploy"]),
                        ip, method="publickey")
            if self.rng.random() < 0.4:
                self.preauth_disconnect(next(t), self.host(), ip)
        self.add_intel(ip, self.rng.choice(["malicious", "suspicious"]),
                       tags=["ssh-key-scanning"])
        self.labels.append((ip, "true_positive",
                            "SSH key scanning: failed publickey attempts across hosts"))

    # ------------------------------------------------------------ build
    def build(self):
        plan = [
            (self.b1_internal_typos, self.rng.randint(10, 16)),
            (self.b2_internal_service, self.rng.randint(3, 6)),
            (self.b3_misconfigured_cron, self.rng.randint(2, 4)),
            (self.b4_employee_home, self.rng.randint(2, 4)),
            (self.b5_cloud_ci, self.rng.randint(1, 3)),
            (self.a1_brute_force, self.rng.randint(6, 10)),
            (self.a2_compromise, self.rng.randint(2, 4)),
            (self.a3_slow_and_low, self.rng.randint(2, 4)),
            (self.a5_stolen_credentials, self.rng.randint(1, 3)),
            (self.a6_lateral_movement, self.rng.randint(1, 3)),
            (self.r1_scanner_recon, self.rng.randint(3, 6)),
            (self.r2_key_scanning, self.rng.randint(2, 4)),
        ]
        for scenario, count in plan:
            for _ in range(count):
                scenario()
        self.a4_distributed_spray(self.rng.randint(3, 5))

    def write(self):
        self.lines.sort(key=lambda x: x[0])
        with open("data/large_auth.log", "w") as f:
            f.write("\n".join(line for _, line in self.lines) + "\n")
        with open("data/large_labels.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["src_ip", "verdict", "notes"])
            w.writerows(self.labels)
        with open("data/intel.json", "w") as f:
            json.dump(self.intel, f, indent=2, sort_keys=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=None,
                    help="Seed for reproducibility (default: random each run)")
    args = ap.parse_args()

    seed = args.seed if args.seed is not None else random.SystemRandom().randint(0, 2**31)
    gen = Generator(seed)
    gen.build()
    gen.write()

    n_tp = sum(1 for _, v, _ in gen.labels if v == "true_positive")
    n_fp = len(gen.labels) - n_tp
    n_hard = sum(1 for _, _, note in gen.labels if note.startswith("HARD"))
    print(f"seed {seed}: {len(gen.lines)} log lines, {len(gen.labels)} alerts "
          f"({n_tp} attacks, {n_fp} benign, {n_hard} hard cases)")
    print(f"reproduce with: python generate_dataset.py --seed {seed}")


if __name__ == "__main__":
    main()
