# Malicious Code Detection Taxonomy

A structured, language-agnostic framework for detecting malicious behaviors in source code and compiled binaries. Every category applies equally to Python, JavaScript, Java, C, Go, Rust, shell scripts, compiled binaries, and any other artifact that can express computation.

## Architecture

The taxonomy operates on two primary layers and one supporting layer:

- **[Points of Investigation (POIs)](pois/)** — Atomic, independently detectable indicators that something warrants closer inspection. These are evidence, not verdicts.
- **[Behavioral Patterns](behavioral-patterns/)** — Named compositions of POIs that, taken together, suggest a specific malicious intent. These are hypotheses built from evidence.
- **[Contextual Signals](contextual-signals/)** — Ecosystem and metadata observations that modify confidence in findings from the first two layers. These are not detectable within the code itself.

## Core Principle

No single POI is proof of malice. A hardcoded URL is not malicious. A base64 decode is not malicious. But a hardcoded URL combined with base64-encoded shell commands executed at install time in a package that appeared yesterday — that demands investigation.

**The power of this taxonomy is in composition.**

## Quick Reference

### POI Categories (16)

| ID | Name | ID | Name |
|---|---|---|---|
| [ARTF](pois/ARTF/) | Hardcoded Artifacts | [PRST](pois/PRST/) | Persistence |
| [NETW](pois/NETW/) | Network Communication | [PRIV](pois/PRIV/) | Privilege Escalation |
| [FSYS](pois/FSYS/) | Filesystem Operations | [RECN](pois/RECN/) | System Reconnaissance |
| [EXEC](pois/EXEC/) | Code Execution | [TIME](pois/TIME/) | Temporal Operations |
| [LOAD](pois/LOAD/) | Dynamic Code Loading | [PKGM](pois/PKGM/) | Package & Build Manipulation |
| [OBFS](pois/OBFS/) | Obfuscation | [CRPT](pois/CRPT/) | Cryptographic Operations |
| [EVSN](pois/EVSN/) | Evasion & Anti-Analysis | [AITM](pois/AITM/) | AI-Targeted Manipulation |
| [CRED](pois/CRED/) | Credential & Secret Access | [RSRC](pois/RSRC/) | Resource Manipulation |

### Behavioral Patterns (14)

| ID | Name | ID | Name |
|---|---|---|---|
| [BP-SUPPLY](behavioral-patterns/BP-SUPPLY.md) | Supply Chain Payload | [BP-MINER](behavioral-patterns/BP-MINER.md) | Resource Hijacking |
| [BP-CREDTHEFT](behavioral-patterns/BP-CREDTHEFT.md) | Credential Theft | [BP-ROOTKIT](behavioral-patterns/BP-ROOTKIT.md) | Rootkit / Self-Modification |
| [BP-BACKDOOR](behavioral-patterns/BP-BACKDOOR.md) | Backdoor | [BP-WORM](behavioral-patterns/BP-WORM.md) | Worm / Propagation |
| [BP-DROPPER](behavioral-patterns/BP-DROPPER.md) | Dropper / Downloader | [BP-TROJAN](behavioral-patterns/BP-TROJAN.md) | Trojan / Disguised Payload |
| [BP-EXFIL](behavioral-patterns/BP-EXFIL.md) | Data Exfiltration | [BP-AGENTMANIP](behavioral-patterns/BP-AGENTMANIP.md) | Agent Manipulation |
| [BP-RANSOM](behavioral-patterns/BP-RANSOM.md) | Ransomware | [BP-TYPOSQUAT](behavioral-patterns/BP-TYPOSQUAT.md) | Typosquat / Dep. Confusion |
| [BP-TIMEBOMB](behavioral-patterns/BP-TIMEBOMB.md) | Logic Bomb / Time Bomb | [BP-LATERAL](behavioral-patterns/BP-LATERAL.md) | Lateral Movement |

## On Binary Analysis

This taxonomy treats compiled binaries as first-class targets. Decompiled output, disassembly, import tables, string dumps, and behavioral traces are all valid surfaces for POI detection. Where a POI manifests differently in source versus binary form, the description calls this out. Source-to-binary drift — where a compiled artifact contains behaviors not present in the published source — is itself a high-value signal addressed in [Contextual Signals](contextual-signals/).

## Investigation and Response

Every finding should be accompanied by structured investigation guidance. The [Investigation Framework](investigation/) defines how to move from detection to determination: is this malicious, benign, or inconclusive?

Once a determination is made, the [Response Framework](response-framework/) defines what to do about it — six tiers from closing a benign finding to activating incident response:

| Tier | Name | Summary |
|---|---|---|
| 0 | [Informational — Close](response-framework/tier-0-informational.md) | Confirmed benign. Document and close. |
| 1 | [Document and Monitor](response-framework/tier-1-document-and-monitor.md) | Ambiguous signal. Watch for code changes that escalate. |
| 2 | [Engineering Referral](response-framework/tier-2-engineering-referral.md) | Security flaw, not malicious. Route to engineering. |
| 3 | [Passive Monitoring](response-framework/tier-3-passive-monitoring.md) | Instrument and observe. Track execution and code changes. |
| 4 | [Active Monitoring](response-framework/tier-4-active-monitoring.md) | Real-time alerting. Containment staged and ready. |
| 5 | [Immediate Response](response-framework/tier-5-immediate-response.md) | Confirmed malicious. Contain, escalate, respond. |

## Contributing

This taxonomy is a living document. Contributions are welcome:

- **Open an issue** to propose new POI subtypes, behavioral patterns, or contextual signals.
- **Submit examples** of real-world malicious code mapped to the taxonomy. Each POI category has an `examples/` directory for this purpose.
- **Challenge the model** — if a category is too broad, too narrow, or missing a real-world attack pattern, say so.

The goal is a community-validated reference that detection tooling, security teams, and researchers can build against.

## Version History

Current version: **2.2**

| Version | Changes |
|---|---|
| **2.2** | Incorporated lessons from the Axios npm supply chain compromise (March 2026). Added `EVSN.MASQ`, `PKGM.PHANTOM`, expanded `EVSN.FORENSIC` and `EXEC.PROC`, added contextual signals for provenance attestation downgrade and pre-staged clean versions. |
| **2.1** | Incorporated lessons from the TeamPCP/LiteLLM supply chain campaign (March 2026). Added `RECN.PROCMEM`, `NETW.DECENTRAL`, `EVSN.FORENSIC`, `OBFS.FILELESS`, `BP-LATERAL`, and execution context signals. |
| **2.0** | Initial public release. 16 POI categories, 14 behavioral patterns, contextual signals, and investigation guidance framework. |

## License

This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). You are free to share and adapt this material for any purpose, with attribution.
