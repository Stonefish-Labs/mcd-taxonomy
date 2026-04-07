# EVSN — Evasion and Anti-Analysis

**Applies to:** Source and binary.

## Description

Techniques that detect, resist, or circumvent analysis environments, debugging tools, security monitoring, or human review. If obfuscation is about hiding *what* code does, evasion is about controlling *when and where* it does it. Code that checks whether it is being debugged, whether it is running in a VM or sandbox, or whether the environment looks like a CI pipeline before activating its payload is exhibiting evasion behavior.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `EVSN.DEBUG` | Debugger Detection | Checking for attached debuggers, breakpoints, or debug flags. Includes `IsDebuggerPresent`, ptrace self-attach, timing checks that detect single-stepping, and debug register inspection. |
| `EVSN.SANDBOX` | Sandbox / VM Detection | Detecting virtual machines, containers, or sandboxed environments via hardware fingerprinting, known VM artifacts (VMware tools, VBox guest additions), MAC address prefixes, or resource profiles (low RAM/CPU = sandbox). |
| `EVSN.ENVCHECK` | Environment Fingerprinting | Checking for specific environment characteristics before activating: presence of CI variables (`CI=true`, `GITHUB_ACTIONS`), specific usernames, specific hostnames, geographic indicators, or installed software profiles. Payload activates only when the environment matches a target profile. |
| `EVSN.TIMING` | Timing-Based Evasion | Using execution timing to detect analysis (debuggers slow execution) or to delay malicious behavior past typical sandbox analysis windows (sleep for 10 minutes, then activate). |
| `EVSN.LOG` | Logging / Monitoring Evasion | Disabling, redirecting, or suppressing logging and monitoring systems. Clearing event logs, disabling audit trails, unhooking security APIs, or suppressing error output. |
| `EVSN.TAMPER` | Anti-Tamper / Integrity Checks | Code that verifies its own integrity and refuses to run if modified. While legitimate in some contexts (DRM, licensing), in malware this prevents analysis via patching or instrumentation. |
| `EVSN.FORENSIC` | Anti-Forensic Techniques | Deliberate manipulation of forensic artifacts to impede investigation. Includes: timestomping (setting file creation/modification times to false values — the LiteLLM npm track set timestamps to October 26, 1985 as an anti-forensic measure), log deletion or truncation, evidence file wiping, overwriting slack space, manipulating shell history files, clearing recent-file lists, modifying audit trails, and **evidence replacement/substitution** — swapping malicious artifacts with pre-staged clean decoys so that post-incident inspection shows a convincing forgery rather than an absence. The Axios compromise used this technique: after execution, `setup.js` deleted itself and the malicious `package.json`, then renamed a pre-staged clean stub (`package.md`) into `package.json` — leaving a completely clean-looking manifest in place of the malicious one. Evidence *replacement* is meaningfully harder to detect than evidence *deletion*: deletion leaves an absence, replacement leaves a convincing forgery. Distinguished from `EVSN.LOG` (which suppresses *ongoing* monitoring) in that `EVSN.FORENSIC` targets *historical* evidence that would be used in post-incident analysis. |
| `EVSN.MASQ` | Masquerading | Renaming, copying, or disguising files, binaries, processes, or network traffic to impersonate legitimate system components. This targets both automated detection (tools that allowlist known system paths or process names) and human reviewers (analysts who skim process lists or file trees and dismiss familiar-looking names). Includes: **binary masquerading** — copying a legitimate executable to a new name or path to disguise what is actually running (the Axios compromise copied `powershell.exe` to `%PROGRAMDATA%\wt.exe` to masquerade as Windows Terminal), **filesystem masquerading** — placing payloads in paths that mimic OS conventions (the same attack named its macOS binary `com.apple.act.mond` under `/Library/Caches/`, mimicking Apple's reverse-DNS daemon naming convention), and **traffic masquerading** — crafting network requests to blend into expected traffic patterns (the Axios C&C POST body used the prefix `packages.npm.org/` to look like legitimate npm registry traffic in log review). Distinguished from `OBFS.RENAME` (which addresses source code identifier obfuscation) in that `EVSN.MASQ` operates on *runtime artifacts* — the files, processes, and traffic that defenders observe during and after execution. |
| `EVSN.SECDISABLE` | Security Control Disabling | Disabling, weakening, or reconfiguring host security mechanisms to create favorable conditions for subsequent attack stages. Includes: **firewall manipulation** — creating permissive inbound rules (especially with unrestricted source addresses and no program binding), disabling host firewalls entirely, or adding broad protocol exceptions; **exploit mitigation disabling** — turning off ASLR, DEP, Control Flow Guard, stack canaries, or other exploit mitigations at runtime or through build/configuration changes; **security tool exclusion injection** — adding paths, processes, hashes, or file types to AV/EDR exclusion lists so that payloads in those locations are not scanned; **security policy weakening** — modifying AppLocker rules to permit unsigned execution, setting SELinux or AppArmor to permissive mode, disabling macOS Gatekeeper or System Integrity Protection verification, weakening Windows Defender SmartScreen; **security status falsification** — suppressing or spoofing security center dashboard reporting to prevent administrators from noticing degraded protection. Distinguished from `EVSN.LOG` (which targets audit trails and monitoring *output*) in that `EVSN.SECDISABLE` targets *active defensive controls* — the mechanisms that would prevent or detect an attack in progress, not the records that would reveal it afterward. Distinguished from `CRPT.CERT` (which specifically targets PKI trust chain manipulation) in that `EVSN.SECDISABLE` covers host-level security enforcement broadly across firewall, endpoint protection, OS policy, and exploit mitigation surfaces. |

## Severity Baseline

`EVSN.SANDBOX` and `EVSN.ENVCHECK` are high in library/dependency context. `EVSN.DEBUG` is high outside of development tooling. `EVSN.FORENSIC` is high in all contexts — legitimate code has no reason to falsify timestamps or destroy forensic artifacts. `EVSN.MASQ` is high — legitimate packages do not rename system binaries or disguise their artifacts as OS components. `EVSN.SECDISABLE` is high in all contexts — legitimate libraries do not disable firewalls, inject AV exclusions, or weaken exploit mitigations. In a dependency context, any security control manipulation is critical.

## Escalation Factors

The following conditions increase the suspicion level of any `EVSN` finding:

- **Evasion gates a payload delivery or exfiltration action.** Any evasion behavior that precedes `EXEC.*`, `NETW.*` (exfiltration), or `PRST.*` raises severity to critical. Evasion alone is suspicious; evasion that controls when a destructive or theft-oriented payload fires confirms adversarial intent.
- **`EVSN.ENVCHECK` targets specific hosts, usernames, or domain membership.** Checks for named usernames, hostnames, or Active Directory domains indicate a targeted attack rather than opportunistic malware. The payload activates only on matching hosts, which also means it will not fire in generic sandbox analysis — by design.
- **`EVSN.FORENSIC` replaces evidence rather than deleting it.** Overwriting artifacts with plausible clean content (the Axios compromise replaced its malicious `package.json` with a pre-staged clean stub and deleted `setup.js` after execution) is harder to detect than deletion because file-presence checks pass. Evidence replacement is a higher-confidence indicator than evidence deletion.
- **Timestamp manipulation targets a specific past date.** Setting timestamps to a precise historical value (the LiteLLM npm track set timestamps to October 26, 1985) suggests automation and coordination, not accidental artifact corruption. Arbitrary-but-specific dates are more suspicious than zeroed or missing timestamps.
- **`EVSN.MASQ` uses legitimate OS binary names or paths.** Copying a real system binary to a writable location and renaming malicious code after it (the Axios compromise copied `powershell.exe` to `%PROGRAMDATA%\wt.exe`; its macOS binary was named `com.apple.act.mond` under `/Library/Caches/`) exploits allowlist trust. The closer the masquerade is to a real signed system component, the higher the escalation.
- **Evasion appears in a library or dependency context.** `EVSN.SANDBOX` and `EVSN.DEBUG` checks have no legitimate purpose in a reusable library. In application code they are occasionally defensible (anti-cheat, licensing); in a dependency they are an immediate high-severity indicator.
- **`EVSN.TIMING` delays are calibrated near sandbox analysis windows.** Sleep or busy-wait delays of 3-7 minutes in dependency code are calibrated to outlast automated sandbox analysis (typically under 5 minutes). Delays in this range in install hooks or startup code are high-confidence evasion.
- **`EVSN.LOG` targets specific security tooling by name.** Generic logging suppression is lower severity; explicitly disabling named EDR agents, AV processes, or audit daemons by process name or service name indicates adversarial intent against a specific defensive stack.
- **Evasion is present in install-time hooks.** `postinstall`, `setup.py`, and equivalent hooks execute at package installation with no sandboxing in typical developer workflows. Evasion in these hooks is particularly dangerous because the analysis window is narrow and the execution context is trusted.
- **Multiple `EVSN` subtypes are present simultaneously.** A single environment check might be explained. The combination of `EVSN.ENVCHECK` + `EVSN.TIMING` + `EVSN.FORENSIC` in the same package indicates coordinated, multi-layered evasion — characteristic of supply chain attack tradecraft rather than accidental or defensive code.
- **`EVSN.SECDISABLE` targets multiple independent controls.** Disabling the firewall AND adding AV exclusions AND weakening AppLocker in the same package is staged infrastructure preparation — the host is being systematically softened before a payload lands.
- **`EVSN.SECDISABLE` creates inbound firewall rules with unrestricted scope.** Rules that bind to any program, any local IP, any remote IP, and require no authentication are indistinguishable from deliberate backdoor enablement. Any inbound rule in a dependency is suspicious; a permissive one is critical.
- **`EVSN.SECDISABLE` adds AV/EDR exclusions for specific paths.** When the excluded path matches a location where the same package writes files (especially `/tmp`, `%APPDATA%`, or the package's own install directory), the exclusion exists to protect a payload from detection. Trace whether the excluded path overlaps with any `FSYS.WRITE` targets in the same package.
- **`EVSN.SECDISABLE` precedes `NETW.LISTEN` or `PRST.*`.** Firewall weakening followed by a network listener, or exploit mitigation disabling followed by persistence installation, is a two-stage setup: create the opening, then exploit it.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **`EVSN.DEBUG` in an application with documented anti-cheat or licensing requirements.** Game engines, licensed commercial software, and DRM systems have publicly documented reasons to detect debuggers. Verify the explanation is in public documentation, not just a code comment. *(Caveat: supply chain attackers can include false documentation; confirm the explanation predates the suspicious commit.)*
- **`EVSN.ENVCHECK` checking CI variables to suppress noisy output or skip integration tests.** Checking `CI=true` or `GITHUB_ACTIONS` to disable interactive prompts or skip slow tests is common and legitimate. Escalate if the check gates network calls, file writes, or subprocess execution rather than UI behavior. *(Caveat: the same CI variable check can suppress payload activation in analysis environments while activating on developer machines — inspect what the check gates, not just that it exists.)*
- **`EVSN.TIMING` as an intentional rate limiter or retry backoff.** Exponential backoff, polling intervals, and API rate-limit compliance are legitimate reasons for sleep calls. De-escalate only when the delay is proportional to the stated purpose and not concentrated at startup or install time.
- **`EVSN.MASQ` as a documented compatibility shim.** Some cross-platform tools copy or rename binaries for path compatibility. De-escalate only when the destination path is documented in public changelogs and the binary is signed or hash-verified.
- **`EVSN.LOG` suppressing verbose debug output in production builds.** Suppressing `console.debug` or reducing log verbosity in a release build is standard practice. This de-escalation applies only when suppression is scoped to log level, not to specific security tooling processes or audit subsystems.
- **`EVSN.SECDISABLE` in a documented network configuration or system administration tool.** Firewall management CLIs, network configuration utilities, and security orchestration tools may legitimately modify firewall rules or security policy as their stated purpose. De-escalate only when the package's primary documented purpose is system or network administration, the modification is user-initiated (not automatic at install or import), and the scope of the change is bounded to what the user requested. *(Caveat: does not apply to general-purpose libraries, frameworks, or packages whose primary purpose is not security administration.)*

> **Important caveat:** Evasion techniques are by definition designed to appear benign. De-escalation based on a plausible explanation requires verification that the explanation is independently confirmable, predates the suspicious activity, and accounts for the specific implementation details observed. A debugger check in a library "because it does licensing" requires public licensing documentation, not just a comment.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `EVSN.ENVCHECK` + `EXEC.SHELL` | Environment check confirms victim profile; shell execution delivers payload only on matching hosts | Very high — targeted supply chain payload delivery |
| `EVSN.TIMING` + `EXEC.SHELL` | Delay calibrated to outlast sandbox analysis window, then execute payload | Very high — sandbox evasion followed by execution |
| `EVSN.FORENSIC` + `EVSN.MASQ` | Malicious artifacts replaced with clean stubs; processes or binaries disguised as legitimate components | Very high — the Axios compromise pattern; evidence replacement + masquerading |
| `EVSN.SANDBOX` + `EVSN.DEBUG` | Multi-layer analysis environment detection | High — coordinated refusal to execute under analysis; raises confidence that evasion is intentional |
| `OBFS.*` + `EVSN.ENVCHECK` | Encoded payload decoded and executed only when environment check passes | High — evasion controls activation; obfuscation conceals what activates |
| `EVSN.LOG` + `PRST.*` | Logging suppressed or disabled, persistence mechanism installed | High — persistent silent implant with no audit trail |
| `EVSN.MASQ` + `PRST.SCHED` | Scheduled task or launch daemon registered under a name mimicking a real OS component | High — legitimate-looking persistence |
| `EVSN.FORENSIC` + `EVSN.TIMING` | Payload executes, waits, then wipes evidence | High — delayed cleanup avoids correlation of execution and cleanup events in log analysis |
| `EVSN.ENVCHECK` + `OBFS.*` + `EXEC.SHELL` | Environment gate + encoded payload + shell execution | Very high — the canonical three-layer supply chain attack pattern |
| `EVSN.SECDISABLE` + `NETW.LISTEN` | Firewall weakened or opened, then network listener established — backdoor enablement | Very high — creating the network opening and then exploiting it |
| `EVSN.SECDISABLE` + `PRST.*` | Security controls disabled, then persistence installed — the payload is protected from detection and will survive reboot | Very high — staged infrastructure preparation |
| `EVSN.SECDISABLE` + `FSYS.WRITE` | AV exclusion injected for a path, then payload written to that path | Very high — exclusion protects the written file from endpoint detection |
| `EVSN.SECDISABLE` + `EXEC.*` | Exploit mitigations disabled, then code executed — the payload runs without ASLR/DEP/CFG protection | High — mitigation disabling enables exploitation techniques that would otherwise fail |
| `EVSN.SECDISABLE` + `CRPT.CERT` | Host security controls weakened and certificate trust chain manipulated — full MITM preparation | Very high — combined defensive degradation across multiple surfaces |

## Disambiguation

### EVSN vs. OBFS — The Core Distinction

This is the most important disambiguation in the taxonomy. **Obfuscation hides *what* code does. Evasion controls *when and where* it does it.**

A string encoded in base64 with no environmental conditioning is `OBFS.ENCODE` — the behavior is always present, merely concealed. The same encoded string decoded and executed only after an environment check passes is `EVSN.ENVCHECK` + `OBFS.ENCODE` — evasion gates activation, obfuscation conceals payload content. Both tags apply; neither subsumes the other.

When both are present, tag both. When only one is present, apply the test: *does this technique change when the code executes, or does it change what an analyst can read?* Changed execution condition = EVSN. Changed readability = OBFS.

### EVSN.MASQ vs. OBFS.RENAME

`OBFS.RENAME` applies to source-level identifiers: function names, variable names, class names in code that is read by humans or static analyzers. `EVSN.MASQ` applies to runtime artifacts: process names, binary file names, scheduled task names, service display names, network traffic patterns. A function named `a1b2()` is `OBFS.RENAME`. A binary copied to `svchost.exe` or a process spawned as `com.apple.mdmclient` is `EVSN.MASQ`. The distinction is the artifact type and the analysis surface being deceived.

### EVSN.ENVCHECK vs. Dead Code

`EVSN.ENVCHECK` is reachable code that executes conditionally based on a live environment query. The payload is real and will fire when conditions are met. Dead code (unreachable branches, hardcoded false conditions, commented-out paths) never executes under any conditions. If a conditional block queries `os.environ`, `platform.node()`, hostname, username, or external state, it is `EVSN.ENVCHECK` regardless of whether the triggering condition was ever observed to fire in analysis. If a block is provably unreachable, it is not `EVSN.ENVCHECK`.

### EVSN.TIMING vs. Normal Asynchronous Code

Not all sleep calls or delays are `EVSN.TIMING`. Apply `EVSN.TIMING` when:

- The delay appears in an install hook, module initialization, or package entry point with no stated operational purpose.
- The delay duration falls in the 3-10 minute range with no proportional justification (rate limiting, retry logic, polling interval).
- The delay precedes a network call, subprocess execution, or file write — not I/O it is waiting on.

Standard retry backoff, polling loops with proportional intervals, and UI debounce timers are not `EVSN.TIMING`.

### EVSN.SECDISABLE vs. EVSN.LOG

Both weaken the defender's position, but at different layers. `EVSN.LOG` suppresses the *recording* of events — clearing logs, disabling audit trails, redirecting monitoring output. The attack still happens; defenders just don't see the evidence. `EVSN.SECDISABLE` removes the *barriers* to the attack — disabling firewalls, adding AV exclusions, weakening exploit mitigations. The defensive control that would have prevented or detected the attack in real time is removed before the attack executes.

The practical test: does the modification affect whether an attack *succeeds* (SECDISABLE) or whether an analyst *notices afterward* (LOG)? Disabling a firewall rule is SECDISABLE. Clearing the firewall's connection log is LOG. Both may co-occur in a staged attack.

### EVSN.SECDISABLE vs. CRPT.CERT

`CRPT.CERT` specifically covers PKI trust chain operations: installing CA certificates, disabling TLS certificate validation, generating self-signed certificates. These operations specifically enable traffic interception by compromising the trust model. `EVSN.SECDISABLE` covers all other host-level security controls: firewalls, endpoint protection, exploit mitigations, OS security policy. When an attack both installs a CA certificate (CRPT.CERT) and disables the firewall (EVSN.SECDISABLE), both tags apply — the attack degrades security across multiple surfaces.

### EVSN.LOG vs. Normal Log Management

`EVSN.LOG` requires evidence that suppression targets security-relevant output or named monitoring components. Reducing log verbosity, rotating logs, or compressing old log files is routine. Apply `EVSN.LOG` when code terminates or suspends named EDR/AV processes, redirects security audit logs to `/dev/null`, modifies kernel audit rules or Windows Event Log permissions, or calls logging APIs to suppress evidence of surrounding malicious behavior.

## Investigation Questions

When an `EVSN` finding is detected, answer these questions to drive the investigation:

### For any EVSN subtype:
1. **What does the evasion technique gate?** Identify what executes when the evasion check passes (or when it fails, in the case of subtractive checks). If the gated code is network activity, process spawning, or file modification, severity is high regardless of how benign the check itself looks.
2. **Does the evasion appear in install-time hooks or module initialization?** `postinstall`, `setup.py`, `__init__.py`, and equivalent entry points execute at install or import time with narrow analysis windows. Evasion here is more dangerous than evasion in a rarely-called utility function.
3. **How many EVSN subtypes are present simultaneously?** A single environment check may have a legitimate explanation. Two or more distinct evasion techniques in the same package indicate layered, intentional evasion design.
4. **Was the evasion behavior introduced in the same commit as other suspicious changes?** Use version diffs or `git log -S` to identify when each evasion construct was introduced. Evasion added alongside payload delivery is stronger evidence of intent.

### For EVSN.ENVCHECK specifically:
5. **Is the check additive or subtractive?** Additive: payload fires when condition is true (targeted attack on specific hosts). Subtractive: payload is suppressed when condition is true (suppressed in analysis environments, active everywhere else). Subtractive checks are the dominant supply chain pattern.
6. **What specific environment properties are checked?** CI variables (`CI=true`), usernames, hostnames, domain membership, geographic indicators? The specificity of the check reveals whether this is targeted or opportunistic.

### For EVSN.FORENSIC specifically:
7. **Is evidence being replaced or merely deleted?** Deletion leaves an absence; replacement leaves a plausible artifact. Check for write operations targeting the same paths that were previously written by malicious code.
8. **What is the timestamp manipulation target value?** A zeroed timestamp might be accidental. A precise historical date indicates automation and intent. Check whether the target value is consistent across multiple artifacts.

### For EVSN.MASQ specifically:
9. **Does the masquerading name match a real signed OS component?** Look up whether the claimed name corresponds to a legitimate component. Verify the binary is not in a writable user-controlled path. Check whether a real binary with that name exists elsewhere on the system — dual presence is a strong indicator.

### For EVSN.TIMING specifically:
10. **Is the delay proportional to any stated operational purpose?** Identify the nearest stated purpose (retry logic, rate limiting, polling). Calculate whether the delay magnitude and placement are consistent with that purpose. A 5-minute sleep before a DNS lookup has no legitimate retry rationale.

### For EVSN.SECDISABLE specifically:
11. **What specific security control is being modified?** Identify the exact mechanism: firewall rule, AV exclusion, exploit mitigation setting, security policy, or security center status. Each has different blast radius and remediation requirements.
12. **Is the modification scoped or blanket?** A firewall rule allowing a specific program on a specific port differs from a rule allowing any program on any port from any source. An AV exclusion for a single file differs from excluding an entire directory tree. Blanket modifications are categorically more suspicious.
13. **Does the excluded or weakened path overlap with any `FSYS.WRITE` targets in the same package?** If the package writes to `/tmp/payload` and also adds an AV exclusion for `/tmp/`, the exclusion exists to protect the payload. This correlation is a critical escalation signal.
14. **Is the security modification reversed after use?** Legitimate tools that temporarily weaken a control (e.g., pausing a firewall for a network test) restore the prior state. Permanent weakening with no restoration path suggests the modification is infrastructure for a persistent attack.

### For EVSN.LOG specifically:
15. **Does the suppression target a specific named process or audit category, or is it generic?** Pull the exact process names, service names, or audit rule modifications. Generic log-level suppression is low-confidence; named EDR process termination is high-confidence.
