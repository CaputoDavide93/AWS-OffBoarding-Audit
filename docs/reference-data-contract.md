# Data contract reference

The collector emits a flat list of dicts. This is the interface between the
collection stage and the reporting stage — every field here is either
produced by the collector or added by `enrich()` in the report builder.

## Collector output (per event)

```python
{
  "event_id":     "b76d...",
  "time_utc":      "2026-08-14T09:21:33+00:00",  # ISO 8601, UTC, required
  "account_id":    "111122223333",
  "account_name":  "prod-platform",
  "region":        "eu-west-1",
  "event_source":  "ec2.amazonaws.com",
  "event_name":    "ModifySnapshotAttribute",     # required
  "matched_on":    "leaver@example.com",
  "match_mode":    "exact",                       # exact or explicit loose fallback
  "principal_arn": "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_.../leaver@example.com",
  "principal_id":  "ARO...:leaver@example.com",
  "source_ip":     "82.14.9.201",
  "user_agent":    "aws-cli/2.15.0",              # truncated to 120 chars
  "error_code":    "",                            # "" or e.g. "AccessDenied"
  "resources":     "snap-0a1b2c3d",               # "; "-joined, ≤400 chars
  "resources_json": "[{...}]",
  "request_params": "{...}",                      # compact JSON, default ≤32768 chars
  "request_params_truncated": false,
  "request_params_original_length": 312,
  "event_scope": "management"                     # or "data" from Lake
}
```

`request_params` is the most valuable field for detection and stays bounded
because policy documents can be large. The default cap is 32 KiB; the
collector records whether truncation occurred. Truncation happens in
`sweep_region`, not in the reporter — by the time a report script sees the
field, the limit has already been applied.

The event JSON stays backward compatible across versions. Collection
completeness lives in the sidecar `<out>.manifest.json` — never infer full
coverage from an empty event list without reading the manifest, since a
denied account or region also produces zero events.

## Fields added by `enrich()`

After the report builder's `enrich()` runs, each row additionally carries:

| Field | Type | Meaning |
| --- | --- | --- |
| `_ts` | `datetime` (UTC, tz-aware) | Parsed timestamp |
| `_local` | `datetime` | Same instant in the configured display timezone |
| `severity` | str | Display severity, after timing escalation — see [severity model](explanation-architecture.md#severity-two-tracks-not-one) |
| `base_severity` | str | Intrinsic severity, before timing escalation — drives all sorting and filtering |
| `category` | str | e.g. `Persistence`, `Privilege escalation` |
| `description`, `why`, `verify` | str | Catalogue explanation text |
| `curated` | bool | Whether this came from the curated catalogue vs. a prefix-based guess |
| `tactics` | list[str] | MITRE tactic names, from TrailDiscover |
| `used_in_wild` | bool | Whether TrailDiscover has recorded this event name in a real incident |
| `incidents` | list[{description, link}] | Up to 3 incident references |
| `content_findings` | list[{severity, title, detail}] | Parameter-level detector output |
| `flags` | list[str] | e.g. `"After last working day"`, `"Weekend"`, `"Failed: AccessDenied"` |
| `principal_key` | str | Best available stable principal identifier |
| `target_type`, `target_id`, `target_key` | str | Normalized target, used for filters and sequence correlation |
| `current_state` | str | `active` \| `present` \| `removed` \| `unknown` — set when a `--state` file is supplied |
| `baseline_status` | str | `above` \| `within` \| `insufficient` — set when a `--baseline` file is supplied |

## Related

- [Explanation: severity model and design invariants](explanation-architecture.md)
- [CLI reference](reference-cli.md)
