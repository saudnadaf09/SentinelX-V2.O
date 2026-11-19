# SentinelX endpoint agent (Windows and Linux)

Single file, Python 3.9+, **standard library only** (`agent/sentinelx_agent.py`). It reads security logs locally and
sends them to SentinelX over HTTP(S). Use **HTTPS** for anything beyond localhost (the agent warns otherwise).

## What it collects (and nothing else)
| OS | Sources | Events |
|---|---|---|
| Windows | `wevtutil` read-only queries | Security: 4624, 4625 (logons), 4720 (account created), 4728/4732 (group changes), 1102 (log cleared) · System: 7045 (service installed), 104 (log cleared) · Sysmon (if installed): 1 process creation, 3 network, 11 file create |
| Linux | `/var/log/auth.log` or `/var/log/secure`, else `journalctl` | Only lines from `sshd`, `sudo`, `useradd`, `usermod`, `gpasswd`. Every other log line stays on the host. |

It never reads user files, browser data, passwords, keys or documents. First run starts at the **end** of existing logs (no historical backfill).
Missing permissions and unavailable sources are **reported to the server** per source (`permission_denied`, `unavailable`, `error`) and shown on the Endpoints page.

## 1. Register the endpoint in SentinelX
Endpoints, then **Register endpoint** (choose Windows/Linux, LIVE or TEST), then **API keys**, **Create key**.
Copy the shown `agent.json` (the key is displayed once). Revoking the key or deregistering the endpoint stops it immediately.

## 2. Windows
Requirements: Python 3.9+ on the endpoint, run as Administrator/SYSTEM to read the Security log.
```powershell
# elevated PowerShell, in the folder containing sentinelx_agent.py, install-windows.ps1 and your agent.json
.\install-windows.ps1 -ConfigPath .\agent.json
Get-ScheduledTask SentinelXAgent | Get-ScheduledTaskInfo
```
Test one cycle by hand first: `python sentinelx_agent.py --config agent.json --once`
Sysmon (optional, recommended): install Sysmon with a config of your choice; without it the Sysmon source shows `unavailable`.

## 3. Linux
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sentinelx-agent
sudo mkdir -p /opt/sentinelx-agent /etc/sentinelx-agent /var/lib/sentinelx-agent
sudo cp sentinelx_agent.py /opt/sentinelx-agent/ && sudo cp agent.json /etc/sentinelx-agent/
sudo chown -R sentinelx-agent /var/lib/sentinelx-agent && sudo chmod 600 /etc/sentinelx-agent/agent.json
sudo chown sentinelx-agent /etc/sentinelx-agent/agent.json
# state_dir must be writable: add  "state_dir": "/var/lib/sentinelx-agent"  to agent.json
sudo cp sentinelx-agent.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now sentinelx-agent
journalctl -u sentinelx-agent -f
```
The service user is in groups `adm` and `systemd-journal` so it can read logs without root.

## Operations
| Task | Command |
|---|---|
| One test cycle | `python sentinelx_agent.py --config agent.json --once` |
| Rotate credential | `python sentinelx_agent.py --config agent.json --rotate-key` (new key written to the config, old key revoked) |
| Deregister | `python sentinelx_agent.py --config agent.json --deregister` (key revoked, endpoint removed from monitoring; events kept) |
| Update | replace `sentinelx_agent.py`, restart the task/service |

## Reliability
Events are written to an on-disk spool before sending and removed only after the server answers; outages cause retries with
backoff and nothing is lost (spool capped at 50 MB, oldest dropped with an error log). Delivery is idempotent
(stable event ids + `Idempotency-Key`), so retries never create duplicate alerts. A 401/403 (revoked/expired key, deregistered
endpoint) stops the agent with an error. Heartbeats report agent version, OS, IP, per-source health, spooled events and last error;
the Endpoints page turns **offline** when no heartbeat/event arrives for an hour (stale after 5 minutes).

## Troubleshooting
| Symptom | Meaning / fix |
|---|---|
| Endpoint stays `never_seen` | No heartbeat arrived: check `server_url`, firewall, key not revoked, run `--once` and read the output. |
| Source `permission_denied` | Windows: run as Administrator/SYSTEM. Linux: user must be in group `adm`. |
| Source `unavailable` | Channel/log does not exist (Sysmon not installed; no auth.log on this distro and no journalctl). |
| HTTP warning in log | You are using plain HTTP; put SentinelX behind HTTPS. |
| Windows Task does nothing | Python path for SYSTEM: re-run the installer; test with `schtasks /run /tn SentinelXAgent`. |

**Verification status:** the parsers, Linux log collector, spool/retry/idempotency and revoked-key handling are covered by executed tests
(against a local fake server and temp files). **Real Windows Event Log collection (`wevtutil`) and Linux journald collection have not been run
on real machines by the author**: validate with `--once` on your endpoint.

## Syslog / network devices
Set `SYSLOG_UDP_PORT=5514` (and `SYSLOG_BIND=0.0.0.0` to receive from other machines) in `backend/.env`, register a **Network device** endpoint with its
sender IP, and point the device at `<server-ip>:5514/udp`. Datagrams from unregistered IPs are dropped and counted as rejected. The device is shown
connected only after its first valid message. RFC 3164/5424 syslog, key=value firewall lines (`action=deny src=... dst=... dpt=...`) and sshd/sudo lines are parsed.
DNS-specific parsing is **not** implemented (DNS server logs arrive as generic syslog messages).
