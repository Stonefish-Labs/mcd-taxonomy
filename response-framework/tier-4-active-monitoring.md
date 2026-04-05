# Tier 4 — Active Monitoring and Alerting

## When to Use

The finding is high-confidence suspicious or the code has been observed exhibiting behaviors that are consistent with a malicious pattern. The investigation has not yet confirmed malicious intent definitively, but the evidence is strong enough that execution of the flagged behavior should trigger an immediate alert and be prepared for containment.

This is also the appropriate tier when passive monitoring (Tier 3) has revealed concerning runtime behavior — the instrumentation showed something unexpected, and the finding has escalated.

## Actions

1. **Deploy real-time detection and alerting.** Move beyond passive logging to active alerting:
   - Alert on execution of the flagged code path.
   - Alert on network connections to flagged destinations.
   - Alert on file access to flagged sensitive paths.
   - Alert on any behavior that completes a behavioral pattern match that was previously partial.
2. **Prepare containment actions.** Define and stage — but do not yet execute — containment measures:
   - Network isolation of affected systems.
   - Blocking or quarantining the package or dependency.
   - Revoking credentials that may be compromised.
   - Rolling back to a known-good version.
3. **Continue code-level monitoring** with heightened scrutiny. Any code change to the flagged area should trigger immediate review, not wait for the next cycle.
4. **Brief relevant stakeholders.** Security leadership, the team that owns the affected code, and anyone who needs to be ready to act should be aware that a finding is at Tier 4 and containment may be imminent.
5. **Define the trigger for Tier 5.** Be explicit: "If this alert fires, we execute containment plan X." The transition from Tier 4 to Tier 5 should not require a meeting — it should be a predefined action.

## Examples

- `BP-CREDTHEFT` pattern with all required POIs present (`CRED.CLOUD` + `NETW.HTTP`), confirmed by passive monitoring showing the code path is executing, but the destination appears to be a legitimate analytics service. Active monitoring to alert if the destination changes or the request payload includes credential material.
- `BP-BACKDOOR` Variant A — partial pattern match with `NETW.LISTEN` + `EXEC.SHELL` in a package that was recently updated by a new maintainer. The listener has not been observed accepting connections, but the capability exists.
- A package where passive monitoring detected intermittent outbound connections to an IP that does not appear in the source code — suggesting dynamic resolution or a configuration change since the last static scan.
- Escalation from Tier 3 where instrumentation revealed a `TIME.CMP` condition will be met within days and the gated code path includes `NETW.HTTP` + `FSYS.READ`.

## Escalation Triggers

- An active alert fires — the flagged behavior has executed in a way consistent with the suspected malicious pattern.
- New evidence confirms malicious intent (e.g., the network destination is confirmed as attacker infrastructure, the exfiltrated data is confirmed as credentials).
- The code changes in a way that removes any remaining doubt.

Escalation moves immediately to Tier 5 (Immediate Response).

## De-escalation Triggers

- Extended active monitoring with no alerts firing. The behavior is not executing as the pattern predicted.
- New evidence explains the behavior as benign (e.g., the new maintainer is confirmed legitimate, the network destination is confirmed as an authorized service).
- The flagged code is removed or refactored.

De-escalation moves the finding to Tier 3 (Passive Monitoring) or Tier 1 (Document and Monitor).
