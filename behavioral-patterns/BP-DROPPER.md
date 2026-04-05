# BP-DROPPER — Dropper / Downloader

## Description

Code that retrieves a secondary payload from a remote source and executes it locally. The dropper itself may appear relatively benign — its purpose is to be small, inconspicuous, and to serve as the delivery vehicle for the real payload, which is never present in the analyzed artifact.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `NETW.HTTP` or `NETW.FTP` | Downloading the payload |
| **Required** | `FSYS.WRITE` | Writing the payload to disk |
| **Required** | `EXEC.SHELL` or `EXEC.PROC` or `LOAD.EVAL` | Executing the downloaded payload |
| Supporting | `FSYS.PERM` | Making the downloaded file executable |
| Supporting | `FSYS.TEMP` | Staging in temp directory |
| Supporting | `OBFS.*` | Concealing the download URL or execution logic |
| Supporting | `EVSN.*` | Only downloading when not under analysis |

## Real-World Analogue

Countless npm/PyPI attacks where the install script runs `curl <url> | sh` or downloads and executes a binary. The `LiteLLM` PyPI incident (2026).

## Investigation Guidance

- **Verify:** What URL is the payload downloaded from? Is the payload still available for analysis? What does the downloaded file contain?
- **Escalates:** Downloaded file is a binary. URL is an IP address or uses a URL shortener. Download occurs at install time. Downloaded file is immediately executed with elevated privileges.
- **De-escalates:** Downloaded file is a documented resource (font, data file, model weights). Download is from a well-known CDN. File is not executed.
