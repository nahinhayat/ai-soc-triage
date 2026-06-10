"""Generate a larger labeled benchmark dataset of synthetic SSH auth activity.

Produces ~50 alerts (one per source IP) spanning easy and deliberately hard
cases, so the heuristic baseline and the LLM engine can actually disagree:

  Benign (labeled false_positive):
    B1  internal users: typos then successful logins
    B2  internal service accounts: successful logins only
    B3  HARD misconfigured internal cron: one account failing repeatedly
    B4  HARD employee home IP: 1-2 failures then success (looks like compromise)
    B5  HARD CI/automation from cloud IP: successful logins only, external

  Attacks (labeled true_positive):
    A1  classic external brute force: many failures, many usernames
    A2  account compromise: failures then a successful login
    A3  HARD slow-and-low: 3 failures against root spread over hours
    A4  HARD distributed spray: 4 IPs in one /24, 2 failures each, same account
    A5  HARD stolen credentials: successful login only, from known-bad IP
    A6  internal lateral movement: spraying across accounts from inside

Outputs: data/large_auth.log, data/large_labels.csv, data/intel.json
Deterministic (seeded) so results are reproducible.

Usage:  python generate_dataset.py
"""
import csv
import json
import random
from datetime import datetime, timedelta

random.seed(1337)

HOST = "web-01"
BASE = datetime(2026, 6, 8, 0, 0, 0)

lines = []   # (datetime, raw line)
labels = []  # (src_ip, verdict, notes)
intel = {}   # ip -> {geo, reputation, tags, reports_90d}

INTERNAL_USERS = ["jchen", "mpatel", "slee", "dkim", "anguyen", "rtaylor",
                  "bwilson", "fhassan", "lzhang", "tokafor", "gmiller", "psingh",
                  "ecastro", "nali"]
SPRAY_USERS = ["admin", "root", "test", "guest", "oracle", "postgres", "mysql",
               "jenkins", "ftpuser", "ubnt", "pi", "git", "www-data", "nagios"]
BAD_GEOS = ["RU — Moscow (AS49505 SELECTEL)", "CN — Hangzhou (AS37963 Alibaba)",
            "NL — Amsterdam (AS202425 hosting)", "BR — São Paulo (AS28573)",
            "VN — Hanoi (AS45899 VNPT)", "IR — Tehran (AS58224)"]


def ts(dt):
    return f"Jun {dt.day:2d} {dt:%H:%M:%S}"


def emit(dt, msg):
    lines.append((dt, f"{ts(dt)} {HOST} sshd[{random.randint(1000, 99999)}]: {msg}"))


def failed(dt, user, ip, invalid=False):
    prefix = "invalid user " if invalid else ""
    emit(dt, f"Failed password for {prefix}{user} from {ip} port {random.randint(30000, 60000)} ssh2")


def accepted(dt, user, ip, method="password"):
    suffix = ": RSA SHA256:" + "".join(random.choices("abcdefABCDEF0123456789", k=8)) \
        if method == "publickey" else ""
    emit(dt, f"Accepted {method} for {user} from {ip} port {random.randint(30000, 60000)} ssh2{suffix}")


def window(hours=20):
    return BASE + timedelta(minutes=random.randint(0, hours * 60))


def steps(dt, lo=3, hi=40):
    while True:
        dt += timedelta(seconds=random.randint(lo, hi))
        yield dt


# ---------------------------------------------------------------- benign
def b1_internal_typos(n=14):
    for i in range(n):
        ip = f"10.0.0.{10 + i}"
        user = INTERNAL_USERS[i]
        t = steps(window())
        for _ in range(random.choice([0, 0, 1, 1, 2])):
            failed(next(t), user, ip)
        for _ in range(random.randint(1, 4)):
            accepted(next(t), user, ip, method=random.choice(["password", "publickey"]))
        labels.append((ip, "false_positive", f"internal user {user}, typos then normal login"))


def b2_internal_services(n=5):
    for i in range(n):
        ip = f"10.0.1.{20 + i}"
        user = f"svc-{random.choice(['backup', 'deployer', 'metrics', 'patching', 'inventory'])}{i}"
        t = steps(window(), 600, 4000)
        for _ in range(random.randint(3, 6)):
            accepted(next(t), user, ip, method="publickey")
        labels.append((ip, "false_positive", f"internal service account {user}, scheduled jobs"))


def b3_misconfigured_cron(n=3):
    for i in range(n):
        ip = f"10.0.2.{30 + i}"
        user = f"svc-sync{i}"
        t = steps(window(8), 1500, 2200)
        for _ in range(random.randint(7, 12)):
            failed(next(t), user, ip)
        labels.append((ip, "false_positive",
                       f"HARD: internal cron with stale credentials for {user}, fails every ~30min"))


def b4_employee_home(n=3):
    for i in range(n):
        ip = f"73.158.22.{40 + i}"
        user = INTERNAL_USERS[-(i + 1)]
        t = steps(window())
        for _ in range(random.randint(1, 2)):
            failed(next(t), user, ip)
        accepted(next(t), user, ip)
        intel[ip] = {"geo": "US — Chicago (AS7922 Comcast residential)",
                     "reputation": "no records", "tags": [], "reports_90d": 0}
        labels.append((ip, "false_positive",
                       f"HARD: employee {user} from home IP, typo then success — looks like compromise"))


def b5_cloud_ci(n=2):
    for i in range(n):
        ip = f"34.74.10.{50 + i}"
        t = steps(window(), 1200, 3600)
        for _ in range(random.randint(3, 5)):
            accepted(next(t), "deploy", ip, method="publickey")
        intel[ip] = {"geo": "US — Iowa (AS396982 Google Cloud)",
                     "reputation": "no records", "tags": [], "reports_90d": 0}
        labels.append((ip, "false_positive",
                       "HARD: CI pipeline deploying from cloud IP, key-based, no failures"))


# ---------------------------------------------------------------- attacks
def a1_brute_force(n=9):
    for i in range(n):
        ip = f"{random.choice(['45.155.205', '194.26.29', '141.98.10', '92.255.85'])}.{60 + i}"
        t = steps(window(), 2, 15)
        users = random.sample(SPRAY_USERS, random.randint(4, 9))
        for _ in range(random.randint(8, 30)):
            u = random.choice(users)
            failed(next(t), u, ip, invalid=(u not in ("root", "admin")))
        rep = random.choice(["malicious", "suspicious"])
        intel[ip] = {"geo": random.choice(BAD_GEOS), "reputation": rep,
                     "tags": ["ssh-bruteforce", "mass-scanner"],
                     "reports_90d": random.randint(40, 2000)}
        labels.append((ip, "true_positive", "classic multi-username brute force, blocked"))


def a2_compromise(n=3):
    for i in range(n):
        ip = f"185.196.8.{70 + i}"
        user = random.choice(["deploy", "backup", "webadmin"])
        t = steps(window(), 5, 20)
        for _ in range(random.randint(4, 9)):
            failed(next(t), user, ip)
        accepted(next(t), user, ip)
        intel[ip] = {"geo": random.choice(BAD_GEOS),
                     "reputation": random.choice(["suspicious", "no records"]),
                     "tags": ["recent-bruteforce-reports"] if i % 2 else [],
                     "reports_90d": random.randint(0, 60)}
        labels.append((ip, "true_positive", f"account compromise: {user} success after failures"))


def a3_slow_and_low(n=3):
    for i in range(n):
        ip = f"80.94.95.{80 + i}"
        t = steps(window(6), 7000, 11000)
        for _ in range(3):
            failed(next(t), "root", ip)
        intel[ip] = {"geo": random.choice(BAD_GEOS), "reputation": "malicious",
                     "tags": ["ssh-bruteforce", "slow-scanner"],
                     "reports_90d": random.randint(400, 1500)}
        labels.append((ip, "true_positive",
                       "HARD: slow-and-low — only 3 root failures spread over hours, known-bad IP"))


def a4_distributed_spray(n=4):
    for i in range(n):
        ip = f"171.25.193.{10 + i}"
        t = steps(window(2), 30, 300)
        for _ in range(2):
            failed(next(t), "administrator", ip, invalid=True)
        intel[ip] = {"geo": "SE — Stockholm (AS198093 relay hosting)",
                     "reputation": "malicious", "tags": ["botnet-node", "ssh-bruteforce"],
                     "reports_90d": random.randint(100, 900)}
        labels.append((ip, "true_positive",
                       "HARD: distributed spray — 2 attempts/IP across a botnet /24, same account"))


def a5_stolen_credentials(n=2):
    for i in range(n):
        ip = f"146.70.85.{90 + i}"
        user = random.choice(["mpatel", "rtaylor"])
        t = steps(window(), 600, 2000)
        for _ in range(random.randint(1, 2)):
            accepted(next(t), user, ip)
        intel[ip] = {"geo": "PA — Panama City (AS213412 VPN egress)",
                     "reputation": "malicious",
                     "tags": ["infostealer-infra", "anonymizing-vpn"],
                     "reports_90d": random.randint(150, 700)}
        labels.append((ip, "true_positive",
                       f"HARD: stolen credentials — clean login as {user} from infostealer infra, zero failures"))


def a6_lateral_movement(n=2):
    for i in range(n):
        ip = f"10.0.3.{100 + i}"
        t = steps(window(3), 20, 120)
        for u in random.sample(INTERNAL_USERS, 5):
            failed(next(t), u, ip)
        labels.append((ip, "true_positive",
                       "internal lateral movement: spraying several accounts from one host"))


def main():
    b1_internal_typos(); b2_internal_services(); b3_misconfigured_cron()
    b4_employee_home(); b5_cloud_ci()
    a1_brute_force(); a2_compromise(); a3_slow_and_low()
    a4_distributed_spray(); a5_stolen_credentials(); a6_lateral_movement()

    lines.sort(key=lambda x: x[0])
    with open("data/large_auth.log", "w") as f:
        f.write("\n".join(line for _, line in lines) + "\n")

    with open("data/large_labels.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src_ip", "verdict", "notes"])
        w.writerows(labels)

    with open("data/intel.json", "w") as f:
        json.dump(intel, f, indent=2, sort_keys=True)

    n_tp = sum(1 for _, v, _ in labels if v == "true_positive")
    n_fp = len(labels) - n_tp
    n_hard = sum(1 for _, _, note in labels if note.startswith("HARD"))
    print(f"{len(lines)} log lines, {len(labels)} alerts "
          f"({n_tp} attacks, {n_fp} benign, {n_hard} hard cases)")


if __name__ == "__main__":
    main()
