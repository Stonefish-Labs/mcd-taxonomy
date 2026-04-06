# RECN — System Reconnaissance

**Applies to:** Source and binary.

## Description

Operations that gather information about the host system, its users, its network position, or its software inventory. Reconnaissance is the intelligence-gathering phase that precedes targeted action. Malware that profiles its environment can decide whether to activate (is this a high-value target?), how to activate (what OS-specific techniques to use), and what to target (where are the credentials?).

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `RECN.OS` | OS / Architecture Detection | Querying operating system type, version, architecture, or kernel version. Benign in cross-platform libraries, suspicious when the information is transmitted externally or used to select payloads. |
| `RECN.USER` | User Enumeration | Querying current username, user ID, group membership, home directory, or listing system users. |
| `RECN.NET` | Network Enumeration | Querying network interfaces, IP addresses, routing tables, ARP caches, DNS configuration, or performing network scanning. |
| `RECN.PROC` | Process Enumeration | Listing running processes, checking for specific process names (security tools, debuggers, competing malware), or querying process attributes. |
| `RECN.SW` | Software Inventory | Querying installed software, package lists, browser versions, or checking for the presence of specific applications. |
| `RECN.HW` | Hardware Fingerprinting | Querying hardware identifiers: MAC addresses, serial numbers, CPU IDs, GPU information, disk identifiers. Used for machine fingerprinting and VM detection. |
| `RECN.PROCMEM` | Process Memory Access | Reading the memory of other running processes to extract data that exists only at runtime — never written to disk as files. Techniques include reading `/proc/[pid]/mem` or `/proc/[pid]/environ` on Linux, `process_vm_readv`, `ReadProcessMemory` on Windows, or dumping process memory via debug APIs. The extracted data may be credentials, cryptographic keys, session state, decrypted content, business logic, or any other runtime artifact. The Trivy compromise used this technique to scrape the `Runner.Worker` process memory for CI/CD secrets, but the POI is the *act of reading another process's memory*, not what is extracted from it — intent is determined at the behavioral pattern layer. Distinct from `EXEC.INJECT` (which injects code into a process) and `RECN.PROC` (which lists process metadata) — `RECN.PROCMEM` reads process *contents* without modifying the target. |

## Severity Baseline

Individual `RECN` subtypes are low-to-medium in isolation. `RECN.PROCMEM` is the exception: high-to-critical in isolation — reading another process's memory is almost never legitimate outside of debugging tools and profilers. All `RECN` subtypes become high when combined with `NETW` (exfiltrating the reconnaissance results) or `EVSN` (using results to decide whether to activate).

## Escalation Factors

The following conditions increase the suspicion level of any `RECN` finding:

- **Reconnaissance results are transmitted over the network.** Any `RECN` subtype paired with `NETW.*` elevates to high. The system profile becomes a dossier transmitted to an attacker-controlled endpoint or encoded into DNS queries.
- **Results feed an activation decision.** `RECN` results used in a conditional that gates payload execution — whether to activate, whether to suppress behavior, whether to select a platform-specific technique — indicate a targeted or evasive attack. This combination with `EVSN.*` is the defining signature of sophisticated supply chain implants.
- **`RECN.PROC` targets security tooling by name.** Process enumeration that checks for AV, EDR, sandbox agents, or analysis tools (Wireshark, Procmon, strace, x64dbg) by name implies evasion intent even without an explicit conditional branch.
- **`RECN.HW` collects VM/sandbox detection primitives.** Hardware fingerprinting that retrieves CPU core count, CPUID hypervisor bit, MAC address OUI, screen resolution, or GPU vendor are the standard primitives for sandbox detection. Treat as `EVSN.SANDBOX` overlap.
- **Cross-platform enumeration.** Code that checks OS-specific paths, environment variables, or registry keys for multiple platforms in a single execution path indicates a universal payload designed for heterogeneous environments.
- **Breadth of collection constitutes a full system profile.** A single `os.hostname()` is low. Collection spanning OS, user identity, network interfaces, installed software, and running processes in one session constitutes a system profile and warrants high severity regardless of whether exfiltration is observed.
- **Collection executes at install or import time.** `RECN` calls during `postinstall`, `setup.py`, or `__init__.py` rather than in a function the consuming application explicitly calls are strongly suspicious.
- **Reconnaissance code is obfuscated or encoded.** `RECN` calls wrapped in base64 decode chains, string concatenation, or eval patterns inherit the severity of the obfuscation layer.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **Declared and documented diagnostic purpose.** Logging libraries, crash reporters, and telemetry SDKs may legitimately collect OS version, architecture, and locale. De-escalation requires that collection is documented, scoped to declared functionality, and transmitted only to endpoints the consuming application controls or has opted into. *(Caveat: adversarial packages have included false READMEs. Verify collection scope matches documentation exactly.)*
- **Collection gated behind explicit caller opt-in.** If `RECN` calls are reachable only through an API the consuming application must explicitly invoke (e.g., `diagnostics.collect()`), with no auto-invocation at install or import time, the risk is lower. *(Caveat: confirm no unconditional call path exists via install hooks or module initialization.)*
- **Results used only locally and transiently.** `RECN` that collects environment information to configure runtime behavior (selecting a binary for the detected architecture, adjusting path separators) with no persistence and no exfiltration is lower risk. *(Caveat: verify collected values are consumed only by declared local logic and not passed to any network call.)*
- **Package category alignment.** System monitoring tools, infrastructure agents, and cross-platform build tools have plausible functional need for broad `RECN`. A JSON parser or HTTP client performing the same collection does not.

> **Important caveat:** Individual `RECN` subtypes are low severity in isolation, but they are the intelligence-gathering phase that precedes every targeted action. The absence of an observed exfiltration channel does not clear a `RECN` finding — the exfiltration may occur in a separate code path, a different module, or a subsequent version.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `RECN.*` + `NETW.*` | System profile exfiltration — fingerprinting for C2 targeting or sale as access intelligence | High |
| `RECN.PROC` + `EVSN.*` | Process enumeration feeding activation decision — security tool check before payload execution | High |
| `RECN.HW` + `EVSN.SANDBOX` | Hardware fingerprinting for VM/sandbox detection | High |
| `RECN.OS` + `RECN.USER` + `RECN.NET` | Multi-subtype profile collection — breadth alone escalates | Medium-high (high if any NETW present) |
| `RECN.PROCMEM` + `CRED.*` | Process memory scraping for runtime secrets — the Trivy CI/CD pattern | Critical |
| `RECN.SW` + `NETW.*` | Software inventory exfiltrated — enables targeted follow-on exploitation | High |
| `RECN.NET` + `NETW.SOCKET` | Network interface enumeration followed by subnet scanning or proxy setup — lateral movement preparation | High |
| `RECN.USER` + `EVSN.ENVCHECK` | Username or hostname matched against hardcoded target list — targeted attack signature | Critical |
| `RECN.*` + `OBFS.*` | Obfuscated reconnaissance code — the collection was hidden from static analysis | High |

## Disambiguation

### RECN vs. Normal Runtime Environment Detection

Many legitimate libraries call `os.platform()`, `process.arch`, `sys.platform` to select the correct binary or path format. This is not `RECN`. The distinguishing criteria are scope, destination, and timing:

- Legitimate: collects minimum information for declared function, no aggregation, no transmission, triggered by caller action.
- `RECN`: collection broader than declared function requires, results aggregated into a profile, or collection at install/import time without caller invocation.

### RECN.PROC vs. EVSN

Process enumeration is `RECN.PROC`. When the results feed an activation decision — whether to execute, suppress, or select behavior — add an `EVSN` tag. `RECN.PROC` alone does not require evidence of result usage; the enumeration itself is the observable. `EVSN` requires evidence of a conditional gate consuming the results. In ambiguous cases where a process list consists exclusively of known security tools, treat as `RECN.PROC` with an `EVSN` escalation note.

### RECN.HW vs. EVSN.SANDBOX

`RECN.HW` describes the mechanism (hardware fingerprinting calls). `EVSN.SANDBOX` describes the intent (VM/analysis environment detection). These are not mutually exclusive. A code block reading CPUID hypervisor flags, total RAM, and MAC address OUI should receive both tags. `RECN.HW` alone is appropriate when hardware information is collected as part of a general profile without evidence that the specific fields target VM detection. Fields most diagnostic for sandbox intent: hypervisor CPUID bit, CPU core count < 4, screen resolution < 800x600, MAC OUI matching VMware/VirtualBox/QEMU, total RAM < 4GB.

### RECN.PROCMEM vs. EXEC.INJECT

`RECN.PROCMEM` reads another process's memory to extract data. `EXEC.INJECT` writes to another process's memory to inject code or modify behavior. The distinction is directionality: read vs. write. Both target another process's memory space but represent different capabilities and different attack objectives. Both can co-occur in the same attack chain.

## Investigation Questions

When a `RECN` finding is detected, answer these questions to drive the investigation:

### For any RECN subtype:
1. **What is the full set of RECN subtypes present?** Individual subtypes are low severity. Enumerate all present subtypes before assessing. A package touching OS, user, network, process, and software inventory is building a profile regardless of whether transmission is observed.
2. **When does collection execute?** Install hooks, import time, or explicit function call? Collection that runs before the consuming application has invoked any function is highest risk.
3. **Where do the collected values go?** Trace the data flow. Do results feed a local configuration decision, get passed to a network call, get serialized to disk, or get discarded? Collection with no observable consumer warrants deeper analysis.
4. **Is there a `NETW` co-occurrence anywhere in the package?** Exfiltration may occur in a separate file or module. A package that collects a profile in one module and makes an outbound call in another is a candidate for `RECN` + `NETW`.

### For RECN.PROC specifically:
5. **What specific process names are in the checklist?** If the list consists of AV/EDR/analysis tools, it was curated for evasion. If it consists of application-specific processes the package would plausibly interact with, the risk is different.

### For RECN.HW specifically:
6. **Which hardware attributes are read, and do they map to VM detection primitives?** A graphics library reading GPU capabilities differs from a utility library reading CPUID hypervisor flags.

### For RECN.PROCMEM specifically:
7. **What is the target process?** Identify the process by name or PID resolution. Browser processes, password managers, CI/CD runners, and cloud agent processes are high-value targets.

### Cross-cutting:
8. **Does the package category create a plausible expectation for this collection?** A cross-platform build tool reading architecture is expected. A date formatting library reading MAC addresses is not.
9. **Are there hardcoded values in conditionals consuming RECN output?** Usernames, hostnames, domain names, or IP ranges as literals gating payload activation are the signature of targeted attacks.
10. **What is the version history of the RECN code?** Was it introduced in a minor bump with no changelog entry? Malicious additions are frequently isolated to small new files with no documentation.
