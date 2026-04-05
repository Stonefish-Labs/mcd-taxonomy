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
