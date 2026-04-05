# BP-TIMEBOMB — Logic Bomb / Time Bomb

## Description

Code that remains dormant until a specific condition is met — a date passes, a counter reaches a threshold, an environment variable appears, or a network signal is received — then activates a payload. The danger is that the code passes all analysis and testing during the dormant period.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `TIME.CMP` or `EVSN.ENVCHECK` | The trigger condition |
| **Required** | *Any payload POI* | The behavior that activates when the condition is met |
| Supporting | `ARTF.TIMESTAMP` | A hardcoded activation date |
| Supporting | `TIME.DELAY` | A delay before activation |
| Supporting | `OBFS.*` | Concealing the trigger logic or payload |
| Supporting | `EVSN.TIMING` | Ensuring the bomb doesn't trigger during analysis |

## Real-World Analogue

The `colors`/`faker` sabotage had a date-based activation. Nation-state malware frequently uses time-based triggers to coordinate activation across compromised systems.

## Investigation Guidance

- **Verify:** What is the trigger condition? What activates when the condition is met? Has the condition already been met (is the bomb already active)?
- **Escalates:** Trigger is a specific future date. Payload involves destructive operations, exfiltration, or backdoor activation. Trigger logic is obfuscated.
- **De-escalates:** Time comparison is for cache expiration, rate limiting, or feature flags. Conditional logic gates a documented feature.
