# BP-ROOTKIT — Rootkit / Self-Modification

## Description

Code that modifies the operating environment to hide its presence or the presence of other malicious components. Rootkits operate at a level below normal application code — intercepting system calls, modifying kernel structures, or altering the tools used to inspect the system so they report false information.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `PRST.HOOK` or `PRIV.EXPLOIT` | System-level modification capability |
| **Required** | `EVSN.LOG` or `EVSN.TAMPER` | Active concealment of presence |
| Supporting | `EXEC.INJECT` | Injecting into system processes |
| Supporting | `LOAD.DYLIB` | Loading interceptor libraries |
| Supporting | `FSYS.PERM` | Modifying file permissions to control visibility |
| Supporting | `PRIV.*` | Privilege escalation to gain modification access |

## Real-World Analogue

The XZ Utils compromise (2024) modified the sshd authentication path. User-space rootkits via LD_PRELOAD. Kernel rootkits via loadable kernel modules.

## Investigation Guidance

- **Verify:** What system components are being modified? What is being hidden? What level of system access is required?
- **Escalates:** Kernel-level modifications. System call interception. Modification of security tools or audit systems.
- **De-escalates:** Hook is a documented plugin mechanism. Modification is to the package's own files.
