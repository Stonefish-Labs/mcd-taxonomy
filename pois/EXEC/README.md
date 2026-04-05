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
