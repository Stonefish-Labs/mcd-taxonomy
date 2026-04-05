# Tier 2 — Engineering Referral

## When to Use

The finding is not malicious, but it is a legitimate security concern that should be fixed through normal engineering channels. This is the off-ramp for findings that are security bugs, dangerous patterns, dead code, or poor hygiene — not intentional malice.

MCD analysis surfaces things that traditional security scanning often misses, particularly in code that was written without malicious intent but creates real risk. Hardcoded credentials left by a developer, unused network functionality that widens the attack surface, overly broad file permissions, deprecated crypto implementations — these are engineering problems, not threat actor problems.

## Actions

1. **Document the finding as a security issue**, not an MCD finding. Translate the POI/behavioral pattern language into terms that make sense for an engineering team: "hardcoded AWS key in config module" rather than "ARTF.CREDENTIAL detected."
2. **Route to the appropriate engineering or security team** through existing vulnerability management workflows (security bug tracker, JIRA, etc.).
3. **Track remediation** through normal engineering processes. The MCD program does not own remediation — engineering does.
4. **Close the MCD finding** once the engineering referral is created. The issue now lives in the engineering backlog.

## Examples

- `ARTF.CREDENTIAL` — A hardcoded API key left in source. Not malicious, but needs to be rotated and moved to a secrets manager.
- `CRPT.CERT` — Certificate validation disabled in a production HTTP client. Likely a development shortcut that was never removed. Creates MITM risk.
- `LOAD.DESER` — Unsafe deserialization of user input using pickle. Not intentionally malicious, but a well-known RCE vector that needs to be fixed.
- Dead code containing `NETW.LISTEN` — An unused debug endpoint that binds to a port. Not actively malicious, but it widens the attack surface and should be removed.
- `OBFS.ENCODE` — Base64-encoded connection strings in config files. Likely an attempt at "security through obscurity" rather than actual malice. Should be replaced with proper secrets management.

## Relationship to MCD

This tier exists because MCD analysis is broader than malware detection. The same techniques that find intentional backdoors also find accidental ones. The same patterns that detect credential theft also detect credential mismanagement. The response is different — engineering fix vs. incident response — but the detection is the same.

Not everything MCD finds is malicious. Having a clear path to route non-malicious findings to the right team prevents the MCD program from becoming a bottleneck and ensures legitimate issues get fixed.
