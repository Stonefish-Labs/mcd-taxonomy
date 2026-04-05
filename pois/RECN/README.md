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
