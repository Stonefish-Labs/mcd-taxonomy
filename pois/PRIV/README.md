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
