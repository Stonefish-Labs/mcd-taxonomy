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
