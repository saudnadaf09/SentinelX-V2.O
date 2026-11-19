"""Synthetic, safe demo telemetry (RFC 5737 documentation IPs, fictional hosts/users).

Builds one scenario touching every shipped detection rule. Timestamps are relative
to ``base`` so a replay always looks recent.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

WIN = "LAB-WIN-01"
LNX = "LAB-LNX-01"
ATTACKER_LNX = "203.0.113.50"
ATTACKER_WIN = "198.51.100.77"
SCANNER = "192.0.2.99"
C2 = "198.51.100.20"


def build_scenario(base: datetime | None = None, prefix: str = "demo") -> dict[str, list[dict]]:
    """Return {hostname: [envelope, ...]} - envelopes follow the ingestion API schema."""
    base = (base or datetime.now(timezone.utc)) - timedelta(minutes=12)
    n = [0]

    def ev(host: str, offset: float, source: str, raw: dict) -> dict:
        n[0] += 1
        ts = (base + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
        return {"event_id": f"{prefix}-{n[0]:04d}", "timestamp": ts, "source_type": source,
                "host": {"name": host}, "raw": raw}

    lnx, win = [], []
    # Linux: SSH brute force, then success for the same account/source, then privilege changes
    for i in range(7):
        lnx.append(ev(LNX, i * 8, "linux_auth", {"program": "sshd", "message":
                      f"Failed password for invalid user admin from {ATTACKER_LNX} port {40100 + i} ssh2"}))
    lnx.append(ev(LNX, 70, "linux_auth", {"program": "sshd", "message":
                  f"Accepted password for admin from {ATTACKER_LNX} port 40111 ssh2"}))
    lnx.append(ev(LNX, 95, "linux_auth", {"program": "sudo", "message":
                  "admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/sbin/useradd svc_backup"}))
    lnx.append(ev(LNX, 96, "linux_auth", {"program": "useradd", "message":
                  "new user: name=svc_backup, UID=1002, GID=1002, home=/home/svc_backup, shell=/bin/bash"}))
    lnx.append(ev(LNX, 99, "linux_auth", {"program": "usermod", "message": "add 'svc_backup' to group 'sudo'"}))

    # Windows: logon failures, success, then post-compromise behaviour as the same user
    for i in range(6):
        win.append(ev(WIN, 20 + i * 5, "windows_security", {"EventID": 4625, "TargetUserName": "labuser",
                      "TargetDomainName": "LAB", "IpAddress": ATTACKER_WIN, "LogonType": "10"}))
    win.append(ev(WIN, 60, "windows_security", {"EventID": 4624, "TargetUserName": "labuser",
                  "TargetDomainName": "LAB", "IpAddress": ATTACKER_WIN, "LogonType": "10"}))
    ps_enc = "JABwAD0AIgBzAGUAbgB0AGkAbgBlAGwAeAAtAHQAZQBzAHQAIgA="  # harmless: $p="sentinelx-test"
    win.append(ev(WIN, 120, "sysmon", {"EventID": 1, "User": "LAB\\labuser", "ProcessId": 4120,
                  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  "CommandLine": f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {ps_enc}",
                  "ParentImage": "C:\\Windows\\explorer.exe", "ProcessGuid": "{demo-guid-0001}"}))
    # Benign lab automation using the same flags: demonstrates a rule exclusion
    win.append(ev(WIN, 125, "sysmon", {"EventID": 1, "User": "LAB\\svc-lab", "ProcessId": 4200,
                  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  "CommandLine": f"powershell.exe -EncodedCommand {ps_enc}",
                  "ParentImage": "C:\\Lab\\lab-automation.exe"}))
    win.append(ev(WIN, 140, "sysmon", {"EventID": 1, "User": "LAB\\labuser", "ProcessId": 4300,
                  "Image": "C:\\Windows\\System32\\wscript.exe",
                  "CommandLine": "wscript.exe C:\\Users\\labuser\\AppData\\Local\\Temp\\update.js",
                  "ParentImage": "C:\\Windows\\explorer.exe"}))
    win.append(ev(WIN, 150, "sysmon", {"EventID": 1, "User": "LAB\\labuser", "ProcessId": 4400,
                  "Image": "C:\\Users\\labuser\\AppData\\Local\\Temp\\svc_update.exe",
                  "CommandLine": "svc_update.exe /quiet", "ParentImage": "C:\\Windows\\System32\\wscript.exe"}))
    win.append(ev(WIN, 165, "sysmon", {"EventID": 3, "User": "LAB\\labuser", "ProcessId": 4120, "Protocol": "tcp",
                  "Initiated": "true", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  "SourceIp": "192.0.2.10", "SourcePort": 50122, "DestinationIp": C2, "DestinationPort": 4444}))
    win.append(ev(WIN, 180, "sysmon", {"EventID": 1, "User": "LAB\\labuser", "ProcessId": 4500,
                  "Image": "C:\\Windows\\System32\\sc.exe", "CommandLine": "sc.exe stop WinDefend",
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe"}))
    win.append(ev(WIN, 190, "sysmon", {"EventID": 1, "User": "LAB\\labuser", "ProcessId": 4510,
                  "Image": "C:\\Windows\\System32\\schtasks.exe",
                  "CommandLine": "schtasks.exe /create /tn Updater /tr C:\\Users\\labuser\\AppData\\Local\\Temp\\svc_update.exe /sc onlogon",
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe"}))
    win.append(ev(WIN, 200, "windows_security", {"EventID": 4720, "SubjectUserName": "labuser",
                  "TargetUserName": "svc_backup$"}))
    win.append(ev(WIN, 205, "windows_security", {"EventID": 4732, "SubjectUserName": "labuser",
                  "TargetUserName": "Administrators", "MemberName": "svc_backup$"}))
    # Network scan seen by Suricata on the Windows lab segment
    for i in range(20):
        win.append(ev(WIN, 230 + i * 0.5, "suricata", {"event_type": "flow", "src_ip": SCANNER, "src_port": 50000 + i,
                      "dest_ip": "192.0.2.10", "dest_port": 20 + i, "proto": "TCP"}))
    return {WIN: win, LNX: lnx}


def write_jsonl(path: str, scenario: dict[str, list[dict]]) -> int:
    count = 0
    with open(path, "w", encoding="utf-8") as fh:
        for host, events in scenario.items():
            for e in events:
                fh.write(json.dumps({"asset": host, "envelope": e}) + "\n")
                count += 1
    return count
