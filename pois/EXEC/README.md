# EXEC — Code Execution

**Applies to:** Source and binary.

## Description

Any mechanism by which code launches new processes, executes shell commands, or invokes system-level execution primitives. Code execution is the terminal capability — it is the step where intent becomes action. Malware that can execute arbitrary commands has effectively unlimited capability on the host system. In library and package code, direct shell execution is almost always suspicious.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `EXEC.SHELL` | Shell Command Execution | Invoking a system shell (bash, sh, cmd, powershell) to run commands. The most direct and dangerous execution primitive. |
| `EXEC.PROC` | Process Spawning | Creating child processes via fork/exec, CreateProcess, subprocess, or equivalent. Broader than shell execution — includes launching any executable. Includes **process orphaning/detachment** — deliberately spawning a process that outlives its parent by using `nohup`, `setsid`, `start /b`, double-fork, or similar techniques to detach from the process tree. The spawned process is reparented to PID 1 (init/systemd) and survives the termination of the installation or build context. The Axios compromise used `nohup python3 /tmp/ld.py` to orphan the Linux RAT to PID 1, making it independent of the npm process tree. Process orphaning is a lightweight persistence mechanism — less durable than a system service (`PRST.SERVICE`) but sufficient to survive beyond the immediate execution context without requiring elevated privileges or system configuration changes. |
| `EXEC.SYSCALL` | Direct System Calls | Invoking operating system calls directly, bypassing standard library wrappers. In managed languages, this is unusual and suggests an intent to avoid detection or logging. |
| `EXEC.INJECT` | Process Injection / Memory Manipulation | Writing to another running process's memory space. This includes injecting executable code (DLL injection, ptrace, process hollowing, thread hijacking, APC injection) but also non-code modifications: patching out security checks, modifying in-memory data structures, corrupting state, or manipulating control flow of a target process. Techniques include `WriteProcessMemory` on Windows, `ptrace(PTRACE_POKEDATA)` on Linux, Mach VM APIs on macOS, and `/proc/[pid]/mem` writes. The read counterpart is `RECN.PROCMEM`. Almost universally malicious outside of debugging tools and game modding. |
| `EXEC.CMDCON` | Command Construction | Building shell commands or executable invocations from string fragments, especially when fragments come from encoded, encrypted, or network-sourced data. The *construction* is the indicator — the command itself may not be visible at analysis time. |

## Severity Baseline

`EXEC.INJECT` is very high in isolation. `EXEC.SHELL` is high in dependency/library context. `EXEC.PROC` varies by what is being launched.

## Escalation Factors

The following conditions increase the suspicion level of any `EXEC` finding:

- **Execution occurs at install time or build time.** An `EXEC.SHELL` or `EXEC.PROC` inside a `postinstall` hook, `setup.py`, or equivalent build-phase script has access to the developer's machine during a routine dependency install. This is the primary vector for supply chain attacks. There is almost no legitimate reason for a library to launch processes during installation.
- **The command or process target is constructed rather than literal.** If the string passed to the shell or process launcher is assembled at runtime from fragments, decoded values, or network-sourced data (`EXEC.CMDCON`), the command was deliberately hidden from static analysis. The concealment itself is an indicator.
- **The spawned process is orphaned or detached from the parent.** Use of `nohup`, `setsid`, `start /b`, double-fork, or any technique that causes the child process to survive the parent's termination is a process-based persistence mechanism. Legitimate library code does not spawn processes intended to outlive the calling context.
- **The execution target resides in a temporary or user-writable directory.** Executing files from `/tmp`, `%TEMP%`, `~/.local`, or other writable paths that are not part of the package distribution suggests a staged payload. The Axios compromise executed `nohup python3 /tmp/ld.py` — the combination of a temp path, an orphaned process, and a downloaded file is characteristic.
- **Execution follows a network fetch or file write.** The sequence `NETW.FETCH` → `FSYS.WRITE` → `EXEC.PROC` or `EXEC.SHELL` describes payload staging and execution. Each transition in the chain is escalatory; the full chain is very high.
- **The command or binary is not consistent with the package's stated purpose.** A JSON parsing library that calls `curl`, a font renderer that invokes `powershell`, or a test utility that writes a cron entry has no documented reason for those capabilities.
- **Execution uses elevated privilege mechanisms or explicitly requests elevated context.** Calls to `sudo`, `runas`, `SetUID`, capability-setting APIs, or privilege escalation helpers alongside execution primitives indicate the payload is aware of privilege requirements.
- **`EXEC.INJECT` is present in any non-debug, non-game-modding context.** Writing executable content to another process's memory has essentially no legitimate application outside explicitly permitted contexts. Its presence in a library, service, or package is very high severity with no plausible benign explanation in most ecosystems.
- **The execution primitive is reached through a dynamic loading chain.** `OBFS.*` → `LOAD.EVAL` → `EXEC.SHELL` is a textbook three-stage delivery chain. Each intermediary layer exists specifically to hide the execution from the prior analysis stage.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **The package is a build tool, task runner, or test framework with documented shell execution.** Packages like linters, bundlers, compiler wrappers, and test harnesses legitimately invoke subprocesses as their core function. Verify that the execution is consistent with documented behavior, targets documented paths, and does not orphan processes.
- **The subprocess target is a fixed, well-known binary with a documented purpose.** Spawning the system's installed version of a documented tool (a compiler, a formatter, a known CLI) with visible, static arguments is less suspicious than spawning a dynamically-named or temp-path target. The target path and static nature of arguments both matter.
- **The execution is gated by explicit user configuration.** Shell execution that only occurs when the user has supplied a configuration value or explicitly invoked a command-mode of the library is meaningfully different from execution that fires automatically on import or install.
- **Source and build process are fully auditable and the execution is present in prior versions.** If the package is open-source, the execution pattern has existed across multiple versions, and the repository history shows it was intentional and consistent, the baseline suspicion is lower — but not zero. Legitimate-looking historical patterns have been used as cover for supply chain compromises introduced via repository takeover.

> **Important caveat:** A benign-seeming execution pattern is a common camouflage strategy. Compromised packages frequently add malicious execution alongside or embedded within legitimate execution flows. De-escalation of a known-good pattern does not grant a pass to adjacent code introduced by a new contributor or version bump.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `EXEC.SHELL` + `PKGM.INSTALL` | Shell command running during package installation | Very high — the canonical supply chain execution primitive |
| `EXEC.PROC` + `PRST.*` | Spawned process combined with any persistence mechanism | Very high — process launch is the activation step for persistent malware |
| `EXEC.CMDCON` + `OBFS.*` | Command constructed from obfuscated or encoded fragments | Very high — the construction exists specifically to hide the command from static analysis |
| `NETW.FETCH` + `FSYS.WRITE` + `EXEC.PROC` | Download, write, execute — staged payload delivery | Very high — this is the complete dropper sequence |
| `EXEC.PROC` + `EVSN.ENV` | Process spawned after environment check | High — environmental awareness before execution suggests targeted or evasive payload |
| `EXEC.PROC` (orphaned) + `PKGM.INSTALL` | Process detached from parent during installation | High — install-time orphaned process is a lightweight persistence mechanism without requiring elevated privileges |
| `EXEC.SHELL` + `CRED.*` | Shell execution combined with any credential access | High — execution in the context of credential access suggests exfiltration or lateral movement |
| `EXEC.INJECT` + `RECN.PROCMEM` | Write and read across process memory | Very high — full process manipulation capability; suggests surveillance or code injection with feedback |
| `EXEC.CMDCON` + `NETW.FETCH` | Command constructed from network-sourced data | Very high — remote command execution; the command itself is controlled externally |
| `OBFS.FILELESS` + `EXEC.SHELL` | In-memory decode chain terminating in shell execution | Very high — the LiteLLM pattern; staged in-memory delivery with shell as the terminal capability |

## Disambiguation

### EXEC.SHELL vs. EXEC.PROC
`EXEC.SHELL` specifically invokes a shell interpreter — bash, sh, cmd, powershell — to interpret a command string. `EXEC.PROC` covers direct process spawning without shell intermediation: launching a binary by path with arguments. The distinction matters because shell invocation adds a layer of string interpretation that enables injection and obfuscation — `EXEC.SHELL` is inherently higher severity because the command is a string that can be constructed or modified. `EXEC.PROC` with a computed binary path or arguments from an untrusted source approaches `EXEC.SHELL` in severity.

### EXEC.CMDCON vs. OBFS.STRCON
Both involve constructing strings from fragments at runtime. The distinction is purpose and target: `OBFS.STRCON` is the general pattern of building any string to defeat static analysis — it could produce a URL, a key, or a configuration value. `EXEC.CMDCON` is specifically constructing a shell command or executable invocation. When the constructed string is the input to a shell or process launcher, both apply and should both be flagged. When the constructed string is a URL or other non-execution value, `OBFS.STRCON` applies and `EXEC.CMDCON` does not.

### EXEC.PROC (orphaned) vs. PRST.*
Process orphaning via `nohup`, double-fork, or equivalent is classified under `EXEC.PROC` because it is a property of how the process is spawned, not a separate persistence mechanism. However, it achieves a lightweight form of persistence — the spawned process survives beyond the installation context. If the spawned process also installs a service, modifies startup entries, or writes cron jobs, those are additional `PRST.*` findings that co-occur with the orphaned `EXEC.PROC`. Orphaned process spawning alone is `EXEC.PROC` at elevated severity; combined with `PRST.*` it indicates multi-layered persistence intent.

### EXEC.INJECT vs. EXEC.PROC
`EXEC.PROC` creates a new, independent process. `EXEC.INJECT` targets an existing, running process — its purpose is to operate within the context of a process the attacker does not control, inheriting its privileges, memory, and trust relationships. These are distinct capabilities. `EXEC.PROC` is a broad capability that can be benign; `EXEC.INJECT` is almost universally malicious in non-debug contexts.

### EXEC.SYSCALL vs. EXEC.PROC
Direct system calls (`EXEC.SYSCALL`) and process spawning (`EXEC.PROC`) may achieve similar ends but are distinct in mechanism. `EXEC.PROC` uses standard library interfaces — `subprocess.Popen`, `Runtime.exec()`, `CreateProcess`. `EXEC.SYSCALL` bypasses those wrappers and calls the OS directly, which evades library-level hooks, logging, and monitoring. In managed-language code (Python, Java, JavaScript), the appearance of direct syscall invocations is unusual enough to be a significant escalation signal regardless of what the call does.

## Investigation Questions

When an `EXEC` finding is detected, answer these questions to drive the investigation:

### For any EXEC subtype:
1. **Where in the execution lifecycle does this occur?** Install time, import time, runtime on function call, or on a scheduled trigger? Earlier in the lifecycle means less user visibility and less opportunity to intercept.
2. **What is the full, resolved command or target?** If construction or encoding is involved, reconstruct the final string before assessing. The literal characters passed to the shell or process launcher are the finding.
3. **Is any execution primitive present in prior versions of this package?** Diff against the previous release. If process spawning or shell execution appeared in a new version, determine what changed and whether the change was authored by a known maintainer.
4. **Does the package's stated purpose explain why it needs to launch processes?** A library that parses data, handles HTTP, or provides UI components has no inherent need for shell execution. A build tool or compiler wrapper does.
5. **What happens to the spawned process or shell output?** Is the output captured and returned to the caller, or is the process detached? Captured output that feeds further logic is a data exfiltration or reconnaissance pattern. Detached processes suggest the intent is persistent execution, not a utility function.

### For EXEC.SHELL specifically:
6. **Is the command string fully static and visible at analysis time?** If not — if it is constructed, decoded, or received from an external source — apply `EXEC.CMDCON` and escalate. A static command invocation is analyzable; a dynamic one is not.
7. **Does the shell command pipe to an interpreter?** Patterns such as `sh -c "$(curl ...)"` or `bash <(wget ...)` download and execute content in a single step, bypassing all file-based analysis.

### For EXEC.PROC specifically:
8. **Is the spawned process detached from the parent?** Presence of `nohup`, `setsid`, `DETACHED_PROCESS` flags, double-fork patterns, or equivalent is process-based persistence. Determine what the orphaned process does and whether it was written to a temp or user-writable path before execution.
9. **What binary is being launched, and from what path?** A known system binary from its canonical path is different from an anonymous binary in `/tmp`. If the binary was written to that path earlier in the same execution context, the dropper sequence is complete.

### For EXEC.INJECT specifically:
10. **What is the target process?** Injection into a security tool, browser, authenticator, or privileged system process is an escalation within an already high-severity finding. Identify the target by PID resolution, process name lookup, or memory map inspection.
11. **What is being written?** Shellcode, a DLL path, a patched return address, or data structure corruption each imply different attack objectives but all represent unauthorized control over another process.

### For EXEC.CMDCON specifically:
12. **What are the sources of the fragments?** Trace each component of the constructed command to its origin: hardcoded, decoded from an embedded blob, environment variable, file read, or network fetch. Fragments from network or decoded sources represent externally-controlled command construction — functionally equivalent to remote code execution.
