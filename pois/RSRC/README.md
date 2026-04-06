# RSRC — Resource Manipulation

**Applies to:** Source and binary.

## Description

Operations that consume, exhaust, or manipulate system resources — CPU, memory, GPU, disk, or network bandwidth — beyond what the stated functionality requires. Resource manipulation ranges from cryptomining (unauthorized use of compute resources for profit) to denial of service (exhausting resources to degrade system availability) to the more subtle: using your GPU for unauthorized AI inference workloads.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `RSRC.CPU` | CPU Exhaustion | Tight computational loops, mathematical operations consistent with mining algorithms, or deliberately inefficient algorithms designed to consume CPU. |
| `RSRC.MEM` | Memory Exhaustion | Allocating large memory regions, memory leaks by design, or operations designed to exhaust available memory. |
| `RSRC.GPU` | GPU Access | Accessing GPU compute capabilities (CUDA, OpenCL, Metal, Vulkan compute shaders) in code that has no documented graphics or ML functionality. GPU access in a utility library is suspicious. |
| `RSRC.DISK` | Disk Exhaustion | Writing large amounts of data to fill disk space, or creating many files to exhaust inode capacity. |
| `RSRC.FORK` | Fork Bomb / Process Exhaustion | Creating processes or threads in an unbounded or exponential fashion to exhaust system process limits. |
| `RSRC.NET` | Network Bandwidth Abuse | Generating large volumes of network traffic, participating in DDoS, or acting as a proxy/relay for third-party traffic. |

## Severity Baseline

`RSRC.GPU` in non-ML/graphics code is high. `RSRC.FORK` is high. Others depend on scale and context.

## Escalation Factors

The following conditions increase the suspicion level of any `RSRC` finding:

- **Cryptocurrency artifacts present.** Any combination of `RSRC.CPU` or `RSRC.GPU` with `ARTF.CRYPTO_ADDR` (wallet addresses, mining pool hostnames) is a near-certain cryptojacking indicator. Escalate to high without additional evidence.
- **GPU access in a non-ML, non-graphics library.** A utility, CLI tool, or backend service invoking CUDA, OpenCL, Metal, or Vulkan compute kernels has no plausible legitimate reason for GPU access. The asymmetry between expected behavior and observed capability is the signal.
- **Resource acquisition conditioned on environment checks.** Code that inspects for CI/CD variables, sandbox indicators, or analyst tooling before initiating resource consumption is actively evading detection. Any `EVSN` co-occurrence escalates the finding.
- **Unbounded or dynamically scaled resource consumption.** Consumption that scales with available cores, free memory, or available bandwidth toward system maximums indicates intent to consume rather than incidental use.
- **Resource activity routes through external C2 infrastructure.** `RSRC.CPU` or `RSRC.GPU` workloads that phone home for job parameters, submit results to external endpoints, or receive dynamic instructions are not self-contained. The external dependency converts resource abuse into an operational implant.
- **`RSRC.FORK` in any library context.** Unbounded process or thread creation has no defensible use case in a dependency. Escalate to high by default.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **Documented, bounded, and user-controlled resource limits.** If the code exposes configuration for resource ceilings (worker counts, memory caps, rate limits) documented in the public API, the pattern is consistent with legitimate resource management. *(Caveat: limits set by the library itself rather than the caller are not de-escalating — a cryptominer that caps itself at 50% CPU is still a cryptominer.)*
- **Resource use is load-bearing for the package's stated purpose.** A video transcoder using high CPU is expected. A distributed test runner using fork is expected. De-escalate only when the resource subtype directly corresponds to the package's primary documented function.
- **Resource use is transparent, metered, and opt-in with informed consent.** Some legitimate packages (build systems, parallelized data processors) consume significant resources visibly, with progress reporting and clear documentation. *(Caveat: consent buried in a README paragraph does not constitute informed consent in a supply chain context.)*

> **Important caveat:** Resource abuse findings require determining who benefits from the computation. If the result is returned to the calling application, the usage is likely legitimate. If the result is transmitted to an external endpoint, the usage is malicious regardless of the resource type.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `RSRC.CPU` + `ARTF.CRYPTO_ADDR` | Cryptojacking — mining pool address or wallet alongside CPU-intensive computation | Critical |
| `RSRC.GPU` + `ARTF.CRYPTO_ADDR` | GPU-accelerated cryptojacking or unauthorized ML inference | Critical |
| `RSRC.CPU` + `NETW.*` | Resource consumer with network exfiltration — may combine mining with data theft | Critical |
| `RSRC.NET` + `NETW.*` | DDoS participation or traffic relay with C2 callback — botnet node | Critical |
| `RSRC.FORK` + `TIME.DELAY` | Fork bomb with timing-conditioned trigger — activates after delay | High |
| `RSRC.CPU` + `LOAD.EVAL` | CPU-intensive computation loaded at runtime — mining payload delivered post-install | High |
| `RSRC.GPU` + `EVSN.*` | GPU access gated by environment check — activates only in non-analysis environments | High |

## Disambiguation

### RSRC.CPU vs. Legitimate Computational Libraries

High CPU use is not inherently malicious. Cryptographic libraries, compression codecs, scientific computing packages, and ML inference runtimes are all legitimately CPU-intensive. The distinguishing question: does the computation produce output useful to the calling application, or output useful only to a third party? A hashing library returns a hash to the caller. A cryptominer returns proof-of-work to a pool operator. Trace what happens to the result: if returned to the caller or written to a caller-controlled location, likely benign. If transmitted to an external endpoint with no caller involvement, escalate.

### RSRC.GPU vs. Legitimate ML/Graphics Dependencies

`RSRC.GPU` is flagged high specifically in non-ML, non-graphics code. In a tensor processing library, GPU access is expected. In a file format parser, HTTP client, or configuration loader, it is not. When the package's stated purpose is ambiguous or GPU access is in a transitive dependency far from any ML or graphics functionality, treat as suspicious.

### RSRC.NET (Bandwidth Abuse) vs. Normal Network Activity

`RSRC.NET` is not about packages that make network requests — that is `NETW.*`. This subtype covers participation in traffic amplification, relay, or DDoS patterns: receiving target lists and sending traffic, proxying third-party connections, or flooding endpoints on instruction. The distinguishing characteristic is that the network traffic serves no purpose for the calling application.

## Investigation Questions

When an `RSRC` finding is detected, answer these questions to drive the investigation:

### For any RSRC subtype:
1. **What is the output of the resource-intensive computation, and who receives it?** If the result is transmitted externally rather than returned to the caller, the finding is almost certainly malicious.
2. **Is resource acquisition conditioned on any environment check, time check, or flag?** Conditional activation is a strong evasion indicator.
3. **Does the package's stated purpose explain this level of resource consumption?** A markdown renderer consuming 100% CPU has no explanation.

### For RSRC.CPU and RSRC.GPU specifically:
4. **Are any cryptocurrency addresses, mining pool hostnames, or wallet identifiers present?** Pivot to `ARTF.CRYPTO_ADDR` if found. Check for dynamic string assembly that may construct these at runtime.
5. **For RSRC.GPU: is GPU compute reachable from any documented API entry point?** An unreachable GPU codepath is not less suspicious — it may be a payload not yet triggered.

### For RSRC.FORK specifically:
6. **What is the upper bound on process or thread creation, and is it enforced?** If there is no enforced ceiling, treat as high regardless of other context.

### Cross-cutting:
7. **What does the install-time and runtime network traffic profile look like?** Correlate `RSRC.CPU` findings against outbound connections to non-CDN endpoints — mining pool traffic uses recognizable patterns (stratum protocol, specific port ranges).
8. **Is the resource behavior present in the published package but absent from the source repository?** Build-artifact-only presence indicates a compromised build pipeline or intentional obfuscation of contribution history.
