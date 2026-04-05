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
