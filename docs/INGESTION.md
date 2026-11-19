# Sending telemetry

Create an endpoint (Endpoints page), then **API keys > Create key** and copy the key (shown once).

```bash
curl -sS -X POST http://localhost:8080/api/v1/ingest/events/batch \
  -H "X-API-Key: sxk_xxxxxxxx_..." -H "Content-Type: application/json" -H "Idempotency-Key: batch-0001" \
  -d '{"events":[{"event_id":"ssh-1","timestamp":"2026-11-14T12:00:00Z","source_type":"linux_auth",
       "host":{"name":"LAB-LNX-01"},
       "raw":{"program":"sshd","message":"Failed password for invalid user admin from 203.0.113.50 port 4242 ssh2"}}]}'
```
Response: `{"request_id","accepted","rejected","duplicate_batch","errors":[{"index","reason"}]}`.
Limits: 500 events and 1 MB per request; 600 requests/min per key. Reusing an `Idempotency-Key` within 1 h returns `duplicate_batch: true`.

## source_type and `raw`
| source_type | `raw` fields used |
|---|---|
| `sysmon` | `EventID` (1 process, 3 network, 11 file), `Image`, `CommandLine`, `ParentImage`, `User`, `ProcessId`, `ProcessGuid`, `Hashes`, `SourceIp/Port`, `DestinationIp/Port`, `Protocol`, `Initiated`, `TargetFilename` |
| `windows_security` | `EventID` 4624/4625 (`TargetUserName`, `TargetDomainName`, `IpAddress`, `LogonType`), 4720, 4728/4732 (`SubjectUserName`, `TargetUserName`, `MemberName`) |
| `linux_auth` | `message` (sshd failed/accepted/invalid user, useradd, usermod/gpasswd group add, sudo), `program` |
| `suricata` | EVE JSON `event_type` `alert` or `flow` with `src_ip`, `dest_ip`, `dest_port`, `proto`, `alert.signature` |

`event_id` should be unique per source event; reposting the same id is ignored (no duplicate alerts).
Timestamps must be ISO 8601; more than 24 h in the future is rejected.

## Collectors
No collector binaries are bundled. Use Fluent Bit / Winlogbeat style shippers (or a small script) that wrap each
log record in the envelope above and POST batches over HTTPS (put a TLS-terminating proxy in front for anything
beyond localhost). Only monitor systems you are authorized to monitor. Collector configs are on the roadmap.

## Replay
`python -m app.cli export-sample --out my.jsonl` / `python -m app.cli replay-sample [--file my.jsonl]`.
