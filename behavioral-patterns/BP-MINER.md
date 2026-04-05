# BP-MINER — Resource Hijacking

## Description

Code that uses the host system's compute resources — CPU, GPU, memory, or network — for unauthorized purposes. The classic case is cryptocurrency mining, but the pattern has evolved: unauthorized AI model training, distributed computing participation, proxy/relay networks, and using your infrastructure for the attacker's workloads.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `RSRC.CPU` or `RSRC.GPU` | Significant resource consumption |
| **Required** | `NETW.*` | Communication with a pool, coordinator, or beneficiary |
| Supporting | `EVSN.*` | Throttling when the user is active, activating when idle |
| Supporting | `OBFS.*` | Concealing the mining or compute logic |
| Supporting | `RECN.HW` | Profiling hardware capabilities (CPU cores, GPU model) |
| Supporting | `ARTF.CRYPTO_ADDR` | Mining pool address or wallet |

## Real-World Analogue

Cryptomining malware in npm packages. The evolution toward using compromised infrastructure for AI inference workloads.

## Investigation Guidance

- **Verify:** What computation is being performed? What is the network destination? Is resource consumption proportional to the package's stated functionality?
- **Escalates:** Mining pool addresses or protocols identified. GPU access in non-ML code. Resource consumption hidden behind evasion techniques.
- **De-escalates:** Resource usage is proportional to documented functionality (e.g., image processing, ML inference in an ML library).
