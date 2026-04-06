# PRIV — Privilege Escalation

**Applies to:** Source and binary.

## Description

Any attempt to gain higher privileges than those currently held by the executing process. Privilege escalation is often a prerequisite for persistence, credential access, or system modification that would otherwise be blocked by access controls.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `PRIV.SUDO` | Sudo / Runas Invocation | Executing commands via sudo, runas, pkexec, doas, or other privilege elevation utilities. Especially suspicious when combined with `EXEC.SHELL` and password-less sudo configurations. |
| `PRIV.SUID` | SUID / SGID Manipulation | Setting the SUID or SGID bit on executables, or exploiting existing SUID binaries for privilege escalation. |
| `PRIV.CAP` | Capability Manipulation | Modifying Linux capabilities on files or processes to grant specific elevated privileges without full root access. |
| `PRIV.TOKEN` | Token Manipulation | Duplicating, impersonating, or forging access tokens (Windows token manipulation, Kerberos ticket manipulation). |
| `PRIV.EXPLOIT` | Kernel / Driver Exploitation | Loading kernel modules, interacting with device drivers, or exploiting kernel interfaces for privilege escalation. |

## Severity Baseline

All `PRIV` subtypes are high in dependency/library context.

## Escalation Factors

The following conditions increase the suspicion level of any `PRIV` finding:

- **Passwordless or wildcard sudo configuration.** Invocations that modify `/etc/sudoers` or write `NOPASSWD` entries, or that use `sudo` with wildcard command specs (`ALL`), eliminate the authentication barrier entirely. Any dependency that touches sudoers is critical.
- **SUID binary creation or modification.** Setting the SUID/SGID bit on attacker-controlled binaries (especially shells, interpreters, or copy utilities) is a reliable privilege persistence mechanism. Escalate immediately.
- **Kernel-level interaction.** Any code path that loads kernel modules (`insmod`, `modprobe`), interacts with `/dev/mem` or `/proc/kcore`, or invokes driver IOCTLs falls under `PRIV.EXPLOIT` and is automatically critical. No legitimate library dependency does this.
- **Token manipulation without a clear identity boundary.** Windows token duplication or impersonation (`ImpersonateLoggedOnUser`, `DuplicateTokenEx`) not scoped to a documented privilege-separated subprocess model indicates abuse. Kerberos ticket manipulation is always critical.
- **Capability sets exceeding declared need.** Granting `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, or `CAP_SYS_PTRACE` in a library with no documented system administration purpose is a strong escalation signal. These capabilities are broadly equivalent to root.
- **Escalation precedes persistence or credential access.** When `PRIV` indicators appear immediately before `PRST.*` or `CRED.*` in execution flow, treat the chain as a confirmed attack sequence.
- **Execution under package manager or CI identity.** Privilege escalation in `pip install`, `npm install`, or build hooks executes under the developer or CI identity, which frequently has elevated implicit permissions.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion. The bar for reducing PRIV severity is higher than for most POIs because privilege escalation is a prerequisite for deeper system compromise.

- **Privilege escalation confined to a documented privilege-drop pattern.** Some legitimate tools escalate briefly to bind a privileged port or access a hardware resource, then immediately drop to a lower-privilege identity. De-escalate only when the escalation and drop are co-located, documented, and consistent with the package's declared purpose. *(Does not apply to `PRIV.EXPLOIT` or `PRIV.TOKEN`.)*
- **Test or simulation context with no production code path.** If the escalation exists exclusively in test scaffolding, gated behind a test-only flag, and unreachable by normal library consumers, severity may be reduced. *(Caveat: verify the test infrastructure cannot be subverted to reach the escalation path.)*
- **Platform-native package with OS-level attestation.** OS packages distributed through vendor-signed repositories (RPM with GPG, Debian APT chain of trust) that require elevated privileges as a stated, audited function carry lower investigative priority. *(Does not apply to npm, PyPI, or crates.io packages.)*

> **Important caveat:** No de-escalation factor reduces a `PRIV` finding below medium in a dependency context. Legitimate packages distributed through general-purpose registries almost never need privilege escalation.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `PRIV.SUDO` + `PRST.STARTUP` | Sudo escalation enabling system-wide persistence (systemd unit, launchd plist, registry key) | Critical |
| `PRIV.SUID` + `EXEC.SHELL` | SUID bit on a shell or interpreter — direct path to interactive root shell | Critical |
| `PRIV.CAP` + `NETW.LISTEN` | Capability grant enabling bind to privileged ports or raw socket access | High |
| `PRIV.TOKEN` + `CRED.*` | Token impersonation used to access credential stores under higher-privilege identity | Critical |
| `PRIV.EXPLOIT` + `EXEC.*` | Kernel exploitation followed by native code execution — full local privilege escalation chain | Critical |
| `PRIV.SUDO` + `PKGM.INSTALL` | Passwordless sudo invoked from a package install hook | Critical — escalation during routine dependency installation |
| `PRIV.CAP` + `FSYS.WRITE` | Broad capability grant enabling writes to privileged filesystem locations | High |

## Disambiguation

### PRIV vs. Legitimate Privilege-Separated Architecture

Some production software legitimately uses privilege separation as a security control — a low-privilege worker communicates with a privileged broker over a defined IPC channel. The distinction from malicious PRIV: (1) the escalation is documented and scoped to a minimal surface, (2) the elevated component does not perform arbitrary code execution on behalf of untrusted input, (3) the architecture is declared in security documentation. When all conditions are met, flag for review but do not auto-escalate. When any condition is absent, treat as PRIV.

### PRIV.EXPLOIT vs. Security Testing Tools

Security testing libraries (fuzzers, exploit development frameworks, kernel debugging utilities) may contain code that interacts with kernel interfaces in ways matching `PRIV.EXPLOIT` patterns. The investigative question is deployment context and reachability: is this code reachable from normal consumer usage, or isolated to opt-in testing tooling? A `ptrace` wrapper in a debugging library differs from a `ptrace` call triggered by an install hook. If the kernel interaction is reachable from the package's public interface without explicit security-tool configuration, treat as `PRIV.EXPLOIT`.

### PRIV.SUDO vs. Normal Administrative Tool Usage

Some packages are administrative tools that legitimately invoke `sudo` (e.g., system configuration utilities). The distinction: does the package's primary documented purpose require elevated privileges? A system administration CLI invoking sudo for its core function is different from a JSON parser that invokes sudo. Package category mismatch is itself an escalation signal.

## Investigation Questions

When a `PRIV` finding is detected, answer these questions to drive the investigation:

### For any PRIV subtype:
1. **What identity does the escalation target, and is it scoped?** Escalation to root or SYSTEM is categorically different from escalation to a specific service account with limited permissions.
2. **Is the escalation triggered at install time, import time, or runtime?** Install-time escalation is most dangerous; import-time requires no consumer action beyond including the dependency.
3. **Does a chain exist from PRIV to PRST or CRED?** An isolated PRIV indicator is serious; PRIV feeding into persistence or credential access confirms exploitation intent.
4. **Is there evidence of privilege state being restored after use?** Legitimate privilege separation drops privileges after use. Code that acquires elevated privileges and does not restore prior state suggests persistent escalation.

### For PRIV.SUID specifically:
5. **What binary is targeted, and is it an interpreter or shell?** SUID on bash, sh, python, perl, or ruby is a reliable root shell technique. SUID on a non-interpreter utility is lower severity but still suspicious in dependency context.

### For PRIV.TOKEN specifically:
6. **Is the manipulation scoped to process-local context or does it cross process/session boundaries?** Local adjustments differ from cross-process impersonation or pass-the-hash patterns.

### Cross-cutting:
7. **What is the dependency's declared purpose, and is any privilege escalation consistent with it?** Purpose mismatch is a strong independent indicator of malicious intent.
8. **Is the escalation path reachable without attacker-controlled input?** If escalation fires unconditionally, treat as confirmed active behavior rather than latent vulnerability.
