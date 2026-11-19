Synthetic telemetry only (RFC 5737 documentation IPs, fictional hosts/users). Safe to share publicly.
- `sample_events.jsonl`: 47 events, one JSON object per line: `{"asset": "<hostname>", "envelope": {...ingest event...}}`
- Replay: `python -m app.cli replay-sample --file sample-data/sample_events.jsonl` (timestamps are fixed to 2026-11-14,
  so they will fall outside default "last 24 hours" views; omit `--file` to generate fresh, recent timestamps).
