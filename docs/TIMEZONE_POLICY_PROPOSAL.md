# Reporting timezone review and proposal

Reviewed 2026-10-14 (Asia/Calcutta). The owner approved this policy and it is now
implemented. See [implementation and regression evidence](AUTH_TIMEZONE_IMPLEMENTATION.md).
The inconsistency and review probes below describe the pre-change application.
No retained acceptance database was accessed during implementation.

## Concrete inconsistency

threatService.js computes today's boundary with host-local setHours(0,0,0,0).
Its $hour and $dateToString expressions omit timezone and consequently use UTC.
The same omission affects attack-vector, AI prediction and honeypot date groups.
StatusBar.jsx formats the browser's local time and appends IST without setting
timeZone. The hour label comparison fixed in native acceptance now renders the
API correctly, but it does not resolve this underlying timezone disagreement.

An isolated probe of the actual analytics function froze the instant at
2026-10-13T20:00:00Z (2026-10-14 01:30 IST), capturing queries without MongoDB:

| Backend process timezone | Current start-of-today filter | Current hour bucket |
| --- | --- | --- |
| UTC | 2026-10-13T00:00:00Z | 20 |
| Asia/Kolkata | 2026-10-13T18:30:00Z | 20 |

The same instant should belong to October 14, hour 01 for IST reporting. A
browser running in UTC would currently show 20:00 with an IST suffix; explicit
Asia/Kolkata formatting shows 01:30 regardless of process/browser timezone.

[MongoDB $hour](https://www.mongodb.com/docs/manual/reference/operator/aggregation/hour/)
and [$dateToString](https://www.mongodb.com/docs/manual/reference/operator/aggregation/datetostring/)
document UTC as the default and allow an explicit named timezone.

## Recommended policy: UTC storage, explicit IST reporting

- Store timestamps as UTC instants (BSON Date / ISO 8601 with Z or offset).
  Preserve existing timestamps. Never shift stored values to represent display
  timezone, and never interpret offset-free input using the server's local zone.
- Use Asia/Kolkata as the explicit reporting timezone for this deployment, matching
  the intended IST dashboard. Use one shared configuration/helper contract across
  backend analytics and frontend formatting; do not infer it from the host OS.
- Define Today as [IST midnight, next IST midnight), converted into UTC for MongoDB
  range queries. On October 14 this is [October 13 18:30Z, October 14 18:30Z).
  Use both inclusive start and exclusive end so future-dated records are excluded.
- Group hour/day/week results with timezone: 'Asia/Kolkata' in MongoDB expressions.
  Keep HH:00 chart labels, but label the chart Today (IST), rather than suggesting
  a rolling 24-hour window. A rolling window is a separate explicitly named view.
- Define a seven-calendar-day chart as the current IST day plus six preceding
  IST days, using the same UTC bounds and grouping zone. Existing code's rolling
  weekAgo plus calendar groups is a different contract; this change needs approval.
- Return timezone, UTC rangeStart/rangeEnd and window meaning with analytics.
  Use the same date keys in weekly/attack-vector/honeypot/AI charts and counters.
- Format status clock, tooltips and threat-log timestamps with explicit timeZone:
  'Asia/Kolkata'. Show IST or the named timezone. Locale 'en-IN' alone does not
  select India as the timezone. Avoid appending IST to an unqualified local clock.

An alternative consistent policy is UTC reporting everywhere, including the clock,
day filters, labels and tooltips. It would require changing the existing IST UI
intent. Mixed host-local filters and UTC groups are not a consistent policy.

## Small implementation sequence

1. Add one tested reporting-time helper/configuration contract and an analytics
   response field. Validate allowed named timezone(s); invalid configuration must
   fail clearly. The first scope can be fixed Asia/Kolkata, avoiding an unnecessary
   arbitrary-timezone settings UI or new date dependency.
2. Apply the same UTC day/range bounds and explicit zone to threat hourly/daily,
   vector, AI prediction, honeypot and websocket daily counters. Do not alter
   stored timestamps, model thresholds or threat classifications.
3. Wire frontend formatting/labels to that reporting metadata and preserve the
   existing hourly field names. Test loading/error states as well as nonzero data.

This proposal changes reporting boundaries and counts near midnight. Approve
the named zone and Today/seven-day window semantics before applying it. No
timezone runtime change was made during the original review; the approved
implementation is documented separately.

## Regression cases for the approved policy

- 18:29:59.999Z versus 18:30:00Z at the IST date boundary; start included and next
  midnight excluded. Include month/year and leap-day boundaries.
- 00:00Z versus 00:30Z map to 05:30/06:00 IST: test the half-hour offset rather
  than adding five hours to UTC hour numbers.
- Run helpers/analytics tests with UTC and Asia/Kolkata host settings; output
  ranges, day keys and buckets must match. Browser clocks must match across zones.
- Today KPI, hourly total and daily groups agree over the same records. BLOCKED
  counts remain based on persisted containment status, not just model decisions.
- Seven-day buckets agree across threat/vector/AI/honeypot views. A future timestamp
  is excluded from today's range; empty real data remains an honest empty state.
- Actual MongoDB aggregation requires a separately approved new fixture database.
  The original review probes only captured pipelines in memory; the subsequent
  implementation has been exercised against the approved isolated test database.

Evidence: .test-runtime/security-review-20261014.json. No production-readiness
or live Cowrie claim is made.
