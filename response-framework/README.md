# Response Framework

When the taxonomy produces a finding — a POI, a behavioral pattern match, or a combination escalated by contextual signals — the next question is: **what do you do about it?**

This framework defines six response tiers, from closing a benign finding to engaging law enforcement on a confirmed compromise. Every finding should map to exactly one tier based on the investigation outcome. Tiers are not permanent — a finding can escalate or de-escalate as new evidence emerges or monitored code changes.

## Response Tiers

| Tier | Name | Summary |
|---|---|---|
| 0 | [Informational — Close](tier-0-informational.md) | Investigated, confirmed benign. Document and close. |
| 1 | [Document and Monitor](tier-1-document-and-monitor.md) | Noted signal, not actionable now. Watch for code changes that would escalate. |
| 2 | [Engineering Referral](tier-2-engineering-referral.md) | Security flaw or dead code, not malicious. Route to engineering for remediation. |
| 3 | [Passive Monitoring](tier-3-passive-monitoring.md) | Add logging and instrumentation. Track execution and code changes. |
| 4 | [Active Monitoring and Alerting](tier-4-active-monitoring.md) | Real-time detection and alerting. Prepare containment. |
| 5 | [Immediate Response](tier-5-immediate-response.md) | Confirmed or high-confidence malicious. Contain, escalate, and respond. |

## Tier Selection

Tier selection is driven by two factors:

1. **Current state** — What does the evidence say right now? Is this benign, ambiguous, suspicious, or confirmed malicious?
2. **Proximity to harm** — How close is this code to being weaponized? A function that reads credentials but doesn't transmit them is one code change away from a credential theft pattern. That proximity matters even if the current state is technically benign.

The confidence and severity levels from the [Investigation Framework](../investigation/) feed directly into tier selection:

| Severity | Confidence | Typical Starting Tier |
|---|---|---|
| Informational | Any | Tier 0 |
| Low | Low | Tier 0 or 1 |
| Low | Medium–High | Tier 1 |
| Medium | Low | Tier 1 |
| Medium | Medium | Tier 1–3 (depends on proximity to harm) |
| Medium | High | Tier 3 |
| High | Low–Medium | Tier 3–4 |
| High | High | Tier 4–5 |
| Critical | Any | Tier 4–5 |

These are starting points, not rules. Practitioner judgment determines the final tier.

## Monitoring for Change

A core principle of this framework: **findings are not static.** Code changes. Dependencies update. Behaviors that are benign today can become malicious with a single commit.

Tiers 1 and 3 both include monitoring for change, but at different levels:

- **Tier 1** monitors at the **code level** — watching for diffs, new dependencies, function signature changes, or new code paths near the finding. This is static surveillance. The question is: "did someone change this in a way that escalates the finding?"
- **Tier 3** monitors at both the **code level and runtime level** — instrumentation to detect whether the code path executes in production, combined with code-level change detection. The question is: "is this executing, and is the code around it changing in ways that remove whatever blocker currently prevents harm?"

A finding that is one code change away from being weaponized should never be Tier 0. Even if the current state is technically benign, proximity to harm demands at minimum Tier 1 with explicit change monitoring.
