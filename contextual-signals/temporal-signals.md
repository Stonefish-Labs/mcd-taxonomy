# Temporal Signals

| Signal | Description | Effect |
|---|---|---|
| **Abandonment followed by activity** | A long-dormant package suddenly receives updates | May indicate account compromise |
| **Coordinated publication** | Multiple related packages published in a short time window by the same or related accounts | May indicate a coordinated campaign |
| **Pre-event timing** | Package published or updated shortly before a known compromise or incident | Temporal correlation may indicate the package was part of the attack |
| **Pre-staged clean version** | A clean version of a package published shortly before a malicious version of the same package, apparently to build registry history and bypass "new package" detection heuristics. The Axios attacker published `plain-crypto-js@4.2.0` (clean decoy) 18 hours before the malicious `@4.2.1`, specifically to avoid automated "brand-new package" alarms. | Elevates suspicion of the subsequent version; indicates attacker awareness of and deliberate evasion of registry-level scanning |
