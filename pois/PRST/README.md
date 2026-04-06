# PRST — Persistence

**Applies to:** Source and binary.

## Description

Any mechanism by which code ensures it will continue to execute across reboots, session changes, or user intervention. Persistence is what separates a one-shot exploit from an installed backdoor. Code that writes itself into startup sequences, schedules recurring execution, or registers itself as a system service is establishing a long-term foothold.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `PRST.STARTUP` | Startup / Login Item | Adding entries to system startup locations: Windows Run/RunOnce registry keys, macOS LaunchAgents/LaunchDaemons, Linux systemd units, XDG autostart, `.bashrc`/`.profile` modifications, or crontab entries. |
| `PRST.SCHED` | Scheduled Task | Creating scheduled tasks (cron, at, Windows Task Scheduler, launchd plists) that execute code at specified intervals or times. |
| `PRST.SERVICE` | System Service | Registering as a system service or daemon that starts automatically and restarts on failure. |
| `PRST.HOOK` | Hook / Callback Registration | Installing hooks into other software: Git hooks, shell function overrides, LD_PRELOAD entries, DLL search order manipulation, PATH manipulation, or import hook registration in interpreted languages. |
| `PRST.EXTENSION` | Browser / Application Extension | Installing or modifying browser extensions, IDE plugins, or application add-ons that execute in the context of trusted software. |
| `PRST.BOOTKIT` | Boot-Level Persistence | Modifying boot sectors, UEFI firmware, or bootloader configuration. Rare but represents the deepest form of persistence. |

## Severity Baseline

All `PRST` subtypes are high in dependency/library context. Legitimate packages almost never need to install startup items or scheduled tasks.

## Escalation Factors

The following conditions increase the suspicion level of any `PRST` finding:

- **Naming camouflage.** Persistence artifacts use system-resembling names (`com.apple.act.mond`, `svchost32.exe`, `systemd-updatedd`) to blend with legitimate OS components. Any such naming in a third-party package is a near-certain indicator of evasion intent. The Axios compromise named its macOS binary `com.apple.act.mond` under `/Library/Caches/`, mimicking Apple's reverse-DNS daemon naming convention.
- **Cross-user or system-wide scope.** Installation targets system-level paths (`/Library/LaunchDaemons`, `HKLM\...\Run`, `/etc/systemd/system`) rather than user-level paths, maximizing reach and survivability across all users on the host.
- **Persistence established at install time.** Setup scripts (`postinstall`, `setup.py`) register persistence without any trigger from the consuming application. The package installs itself independently of how or whether the library is ever called.
- **Combined with exfiltration or C2.** `PRST` co-occurring with `NETW.*` or `CRED.*` substantially raises severity. Persistence that phones home or exfiltrates data is an installed backdoor, not an anomaly.
- **Removal resistance.** The persistence mechanism re-registers itself if removed, uses watchdog processes to restore deleted artifacts, or writes to paths requiring elevated privileges to delete.
- **Multiple redundant mechanisms.** Installing both a `LaunchAgent` and a `crontab` entry, or both a registry Run key and a scheduled task, indicates the author anticipated detection and removal of one path.
- **`PRST.HOOK` targeting broad-scope interceptors.** `LD_PRELOAD` injection, PATH prepending with a shadowed binary name, or Python import hook registration affecting all processes in an environment is categorically more dangerous than a scoped hook. These intercept execution silently across unrelated processes.
- **Persistence survives package removal.** Artifacts written to paths outside the package's own installation directory (system cron, user home directory dotfiles, OS launch infrastructure) will persist after the package is uninstalled.

## De-escalation Factors

De-escalation for `PRST` findings is narrow. A package registering persistence of any kind in a dependency or library context is nearly always out of scope for what a library should do.

- **Explicit, documented opt-in by the consuming application.** The persistence registration is gated behind a function the developer must call explicitly (e.g., `daemon.install()`), documented in the package's public API, and not invoked during import or install. *(Caveat: verify the gate actually exists in code — do not rely on documentation alone.)*
- **Persistence scoped to the package's own managed environment.** Some developer tooling (version managers, environment managers) legitimately modifies shell initialization files or PATH as part of their stated purpose. Acceptable only when the package's primary purpose is environment management, the modification is fully disclosed, it targets the user's own home directory, and it is reversible with a documented uninstall path.
- **Short-lived or self-expiring artifacts.** A scheduled task clearly bounded to a finite operation (e.g., a post-install migration with a documented completion condition and self-removal) is less severe than indefinite persistence. *(Caveat: verify actual removal occurs; claimed self-removal is not sufficient.)*

> **Important caveat:** No de-escalation factor eliminates a `PRST` finding. Reduce priority if factors apply; do not dismiss. Escalate immediately if any escalation factor co-occurs, regardless of de-escalation context.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `PRST.STARTUP` + `NETW.*` | Installed backdoor with C2 or exfiltration capability | Critical — the canonical malware installation pattern |
| `PRST.HOOK` (`LD_PRELOAD`) + `CRED.*` | Credential interceptor injected into all processes in the environment | Critical — silent credential harvesting at the loader level |
| `PRST.SCHED` + `EXEC.SHELL` | Scheduled command execution on the host — polling backdoor pattern | High to Critical depending on command scope |
| `PRST.STARTUP` + `OBFS.*` | Persistence artifact with obfuscated payload or naming | High — obfuscation of persistence artifacts is a strong evasion signal |
| `PRST.SERVICE` + `EXEC.PROC` | Daemon registration spawning child processes | High — increases stealth and survivability |
| `PRST.EXTENSION` + `NETW.*` | Browser or IDE plugin exfiltrating data | High — extensions with network access and persistence are a common credential theft vector |
| `PRST.HOOK` (PATH manipulation) + `CRED.*` | Shadowed binary in prepended PATH capturing credentials passed to a legitimate tool | Critical |
| `PRST.BOOTKIT` + any | Boot-level persistence with any payload | Critical — recovery requires out-of-band remediation |
| `PRST.*` + `EVSN.MASQ` | Persistence artifact disguised as a legitimate OS component | High — the Axios macOS pattern |

## Disambiguation

### PRST.SCHED vs. TIME.SCHED

This is the most common confusion in the PRST family. The distinction is architectural:

**`TIME.SCHED`** describes code that uses time or scheduling logic to control its own execution behavior within the current process lifetime — delayed detonation, timed payload activation, sleeping between polling intervals.

**`PRST.SCHED`** describes code that registers a persistent scheduled task in the operating system or a job scheduler, causing the OS to invoke the code again in the future independently of the current process.

The test: does the scheduling artifact survive the termination of the current process? If a cron entry, Windows Task Scheduler task, or launchd plist is written to disk and will cause re-execution after the current process exits, classify as `PRST.SCHED`. If the code simply calls `sleep()`, checks the current time, or polls at intervals within its own lifecycle, classify as `TIME.SCHED`. Both may co-occur — a payload that sleeps before writing a cron entry warrants both tags.

### PRST.HOOK vs. Normal Hook Usage

Hook registration is legitimate in many contexts: Git hooks for commit validation, framework lifecycle hooks, event emitters, plugin APIs. `PRST.HOOK` applies specifically when hook registration achieves persistent code interception at the OS, loader, or runtime level.

Indicators that distinguish `PRST.HOOK` from normal usage:
- The hook intercepts execution outside the package's own process (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `SetWindowsHookEx`)
- The hook modifies PATH to shadow system or user-installed binaries
- The hook registers a language-level import/require hook affecting unrelated code
- The hook is installed at the OS or shell level (`.bashrc`, `.zshrc`, shell function overrides)

Git hooks in a repository's own `.git/hooks` directory as part of a developer tool's stated purpose are generally not `PRST.HOOK`. Git hooks injected into system-level template directories or into repositories the package does not own warrant the tag.

### PRST vs. EXEC.PROC (Process Orphaning)

Process orphaning — spawning a child process that continues after the parent exits — is classified under `EXEC.PROC`, not `PRST`. Orphaned processes are lightweight, in-memory persistence that does not survive reboot. `PRST` is reserved for mechanisms that register with the OS, scheduler, or shell environment such that the payload will be re-invoked in a future session.

In practice, orphaned processes frequently accompany `PRST` findings: a package may orphan a process for immediate C2 while separately registering a `LaunchAgent` for reboot persistence. Tag both when both are present.

## Investigation Questions

When a `PRST` finding is detected, answer these questions to drive the investigation:

### For any PRST subtype:
1. **What path was the persistence artifact written to, and does that path survive package removal?** Identify the exact filesystem location or registry key. Artifacts outside the package's installation prefix are a strong escalation signal.
2. **Was persistence registered during import or install, or only when explicitly invoked by consuming code?** Silent registration at install or import time is categorically different from an opt-in API.
3. **What command or binary does the persistence mechanism invoke?** Is that binary present in the package, or is it a system binary with attacker-controlled arguments, or a path that does not yet exist (filled later by a second stage)?
4. **What identity does the persistence artifact run under?** System-level persistence runs under higher privilege than user-level. Identify the effective user and whether privilege escalation was required.

### For PRST.HOOK specifically:
5. **What is the blast radius?** Determine which processes, users, or commands are affected. An `LD_PRELOAD` in `/etc/environment` intercepts all dynamically linked processes system-wide. A PATH prepend in `.zshrc` affects that user's sessions. Scope the impact.

### For PRST.STARTUP / PRST.SCHED specifically:
6. **Does the artifact use naming designed to blend with OS components?** Compare the name against known-good OS artifact lists. Reverse domain notation mimicking Apple, Microsoft, or canonical Linux service names in a third-party package is a high-confidence evasion indicator.

### Cross-cutting:
7. **Is there a corresponding network connection or exfiltration behavior?** Search for `NETW.*` co-occurrences. Review the binary or script invoked by the persistence mechanism for outbound connection logic.
8. **Is there evidence of removal resistance or self-restoration?** Look for watchdog processes or scheduled tasks whose sole function is to re-register the primary persistence artifact.
9. **What is the version history of the persistence registration?** Determine when persistence code was introduced. A sudden addition in a minor or patch version, particularly after a maintainer account change, is a strong supply chain compromise indicator.
10. **Has the artifact been observed executing, or is this a static finding?** Confirmed artifact presence on a host elevates the finding to an active incident rather than a risk assessment.
