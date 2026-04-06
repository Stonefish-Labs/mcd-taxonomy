# TIME — Temporal Operations

**Applies to:** Source and binary.

## Description

Operations involving time retrieval, comparison, delays, or time-conditioned execution. Time-based logic is the foundation of logic bombs and time bombs: code that activates only after a specific date, during specific hours, or after a delay designed to outlast analysis windows.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `TIME.GET` | Time Retrieval | Getting the current time, date, or timestamp. Benign in isolation, significant when the result feeds a conditional that gates other behavior. |
| `TIME.CMP` | Time Comparison | Comparing the current time against a specific date, timestamp, or time range. The conditional logic that enables "activate after January 1" or "only run between 2am and 4am." |
| `TIME.DELAY` | Execution Delay | Sleep, wait, or delay operations that pause execution for significant durations. Used to outlast sandbox analysis windows (most automated analysis runs for under 5 minutes). |
| `TIME.SCHED` | Scheduled Execution | Setting timers, alarms, or scheduling callbacks for future execution within the current process lifetime. Distinguished from `PRST.SCHED` in that this is in-process timing, not OS-level task scheduling. |

## Severity Baseline

`TIME.CMP` against a hardcoded date (`ARTF.TIMESTAMP`) is high. `TIME.DELAY` with long durations is medium (sandbox evasion signal).

## Escalation Factors

The following conditions increase the suspicion level of any `TIME` finding:

- **Hardcoded activation date or date range.** `TIME.CMP` against an `ARTF.TIMESTAMP` literal is the canonical logic bomb pattern. The specificity of a hardcoded future date with no legitimate configuration context is the strongest escalation signal in this POI.
- **Delay duration calibrated to sandbox analysis windows.** `TIME.DELAY` values in the 3-10 minute range align with known sandbox execution windows (most automated analysis runs under 5 minutes). Constants like `sleep(360)` rather than derived values are more suspicious.
- **Time check precedes sensitive or irreversible operations.** When `TIME.CMP` or `TIME.GET` gates a payload (file write, network call, credential access, process spawn), the temporal check functions as an activation condition. Proximity to `EXEC.*`, `NETW.*`, or `PRST.*` is a strong escalation signal.
- **Time logic is obfuscated or decomposed.** Date components assembled at runtime (year, month, day as separate variables), epoch arithmetic obscuring the target date, or multi-step comparisons reconstructing a threshold are `OBFS` co-indicators.
- **Multiple independent time checks converging on the same window.** A single `TIME.CMP` can be coincidental. Two or more checks independently constraining execution to the same narrow date range indicate deliberate activation logic.
- **Time check absent from documentation, changelog, or issue history.** Temporal logic with no corresponding documented requirement is an artifact of concealment. Introduction in a single commit with no review discussion is an additional signal.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **Time used for logging, metrics, or telemetry only.** `TIME.GET` feeding a log timestamp, a latency calculation, or metrics emission is ambient and expected. The absence of any downstream conditional removes suspicion.
- **Delay is user-configurable or bounded by documented timeout policy.** `TIME.DELAY` values read from config or environment variables, particularly with conventional names (`retry_interval`, `poll_delay`, `backoff_ms`) and enforced bounds, are consistent with legitimate retry logic. *(Caveat: do not de-escalate if the default value falls in the 3-10 minute range with no operational justification.)*
- **Scheduled execution is a documented product feature.** `TIME.SCHED` in application code with corresponding user documentation and configuration UI is expected. *(Caveat: scheduling infrastructure can be legitimate while the scheduled payload is not.)*
- **Comparison target is a deprecation date or trial cutoff with corresponding UX.** Software disabling features after a hardcoded date is common in trial products. Escalate only if post-expiry behavior is disproportionate (data destruction, exfiltration) relative to normal enforcement (feature lock, purchase prompt).

> **Important caveat:** `TIME.GET` alone is almost never suspicious. It is the usage of the retrieved time value that determines severity. Always trace the data flow from the time retrieval to its consumer before closing a `TIME` finding.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `TIME.CMP` + `ARTF.TIMESTAMP` | Logic bomb — hardcoded activation date gates payload execution | High |
| `TIME.DELAY` + `EXEC.*` | Sandbox evasion — delay outlasts analysis window before executing payload | Medium-high |
| `TIME.CMP` + `NETW.*` | Beacon activation — network callback gated on date/time | High |
| `TIME.SCHED` + `PRST.*` | In-process persistence — timer re-registers or re-executes payload on interval | Medium |
| `TIME.CMP` + `OBFS.*` | Concealed activation logic — date arithmetic or decomposed comparison obscures target window | High |
| `TIME.DELAY` + `TIME.CMP` | Layered evasion — delay to outlast sandbox followed by date check to constrain activation | High |
| `TIME.GET` + `NETW.*` | Timestamped exfiltration — time retrieval as nonce or beacon interval in outbound data | Medium |

## Disambiguation

### TIME.SCHED vs. PRST.SCHED

This is the highest-priority disambiguation in the TIME family.

**`TIME.SCHED`** covers in-process timers — scheduling implemented entirely within the running process using language or framework primitives: `setTimeout`/`setInterval` (JavaScript), `threading.Timer` (Python), `ScheduledExecutorService` (Java), `time.AfterFunc` (Go). The scheduled execution lives and dies with the process. It does not survive process termination, reboot, or service restart.

**`PRST.SCHED`** covers OS-level scheduling mechanisms that persist independently of the originating process: cron entries, Windows Task Scheduler tasks, launchd plists, systemd timers. The key difference is that `PRST.SCHED` survives the process that created it.

**Heuristic:** if the scheduled action requires the original process to be running to execute, it is `TIME.SCHED`. If it can execute after the original process exits, it is `PRST.SCHED`. Both may co-occur — a payload that uses `TIME.CMP` to decide when to install a cron job warrants both tags.

### TIME.GET vs. TIME.CMP

`TIME.GET` is retrieval of current time with no subsequent conditional branching. It becomes `TIME.CMP` the moment the retrieved value is tested against a threshold, reference date, or range. Many findings are initially identified as `TIME.GET` during triage and promoted to `TIME.CMP` after data flow analysis. Do not finalize a `TIME.GET`-only finding without tracing all downstream uses of the returned value.

### TIME.DELAY as Obfuscated TIME.CMP

A long `TIME.DELAY` is sometimes used in place of an explicit `TIME.CMP` when the author wants to avoid a detectable date literal. The delay is calibrated to expire at the target activation window relative to a known deployment date. This is harder to detect statically because there is no comparison target. Treat `TIME.DELAY` with anomalously large values (hours to days) as functionally equivalent to `TIME.CMP` in severity assessment.

## Investigation Questions

When a `TIME` finding is detected, answer these questions to drive the investigation:

### For TIME.CMP specifically:
1. **What is the activation condition?** What is the exact threshold — a specific date, a relative offset, a window? Is the target value hardcoded (`ARTF.TIMESTAMP`) or derived? If derived, from where?
2. **What executes after the time check passes?** Trace the positive branch. The time check itself is not the finding — the action it enables is. Characterize the payload before assigning final severity.

### For TIME.DELAY specifically:
3. **Is the delay duration consistent with a legitimate operational requirement?** Is there a documented reason for this sleep duration (rate limiting, retry backoff, polling interval)? Does it fall in the 3-10 minute range with no explanation?

### For any TIME subtype:
4. **When was this code introduced and by whom?** Review commit history. A single commit introducing temporal gating with no associated issue, review, or explanation is a significant contextual signal.
5. **Does the time logic appear in a dependency rather than first-party code?** Time-based activation in a transitive dependency is higher risk because it is less likely to have been reviewed.
6. **Is the time check reachable from a normal execution path?** Dead code containing time logic may indicate removed functionality or a staging artifact. Confirm reachability before escalating — but do not dismiss, as unreachable time-gated payloads have appeared in code staged for later activation.
7. **Are multiple independent time constraints present?** Two or more constraints narrowing execution to the same window indicate deliberate activation design.
8. **Does the time logic survive process termination?** Determine whether scheduled execution is in-process (`TIME.SCHED`) or registered with an OS facility (`PRST.SCHED`).
