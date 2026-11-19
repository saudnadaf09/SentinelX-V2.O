"""Embedded subset of MITRE ATT&CK Enterprise used by SentinelX rules.

This is a curated subset, not the full matrix. Verify names/tactics against the
current ATT&CK release before publishing mappings: https://attack.mitre.org/
"""
from __future__ import annotations

DATASET_LABEL = "ATT&CK Enterprise (curated subset; verify against the current release)"

TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

# technique_id -> (name, [tactics])
TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Brute Force: Password Guessing", ["Credential Access"]),
    "T1078": ("Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1136": ("Create Account", ["Persistence"]),
    "T1136.001": ("Create Account: Local Account", ["Persistence"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1059": ("Command and Scripting Interpreter", ["Execution"]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["Execution"]),
    "T1027": ("Obfuscated Files or Information", ["Defense Evasion"]),
    "T1204": ("User Execution", ["Execution"]),
    "T1036": ("Masquerading", ["Defense Evasion"]),
    "T1562": ("Impair Defenses", ["Defense Evasion"]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ["Defense Evasion"]),
    "T1053": ("Scheduled Task/Job", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1543": ("Create or Modify System Process", ["Persistence", "Privilege Escalation"]),
    "T1543.003": ("Create or Modify System Process: Windows Service", ["Persistence", "Privilege Escalation"]),
    "T1571": ("Non-Standard Port", ["Command and Control"]),
    "T1071": ("Application Layer Protocol", ["Command and Control"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1046": ("Network Service Discovery", ["Discovery"]),
    "T1021": ("Remote Services", ["Lateral Movement"]),
    "T1021.004": ("Remote Services: SSH", ["Lateral Movement"]),
    "T1548": ("Abuse Elevation Control Mechanism", ["Privilege Escalation", "Defense Evasion"]),
}


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def resolve(refs: list[dict]) -> list[dict]:
    """Enrich [{technique_id}] with name/tactics/url. Unknown IDs are flagged, not dropped."""
    out = []
    for r in refs:
        tid = r["technique_id"]
        if tid in TECHNIQUES:
            name, tactics = TECHNIQUES[tid]
            out.append({"technique_id": tid, "name": name, "tactics": tactics, "url": technique_url(tid)})
        else:
            out.append({"technique_id": tid, "name": "Unlisted technique", "tactics": [],
                        "url": technique_url(tid)})
    return out
