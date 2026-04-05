# BP-LATERAL — Lateral Movement

## Description

Code that, once executing on one system, spreads its presence to other systems or nodes within the same environment without requiring external re-infection. Lateral movement is the bridge between compromising a single host and compromising an entire infrastructure. It is distinct from worm behavior (`BP-WORM`) in scope: worms propagate to *external* systems across network boundaries, while lateral movement operates *within* an environment the attacker already has a foothold in — moving from one Kubernetes node to all nodes, from one host to its SSH-accessible peers, from a CI runner to production servers using harvested credentials.

The LiteLLM attack demonstrated this pattern at its most devastating: after compromising a single container, the payload enumerated all Kubernetes cluster nodes, created privileged pods on each node with the host filesystem mounted, then used chroot to write persistence backdoors directly onto each node's host OS. One compromised package became a cluster-wide compromise in seconds.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `RECN.NET` or `RECN.PROC` or `RECN.SW` | Discovery of lateral movement targets — other hosts, nodes, containers, or services in the environment |
| **Required** | `CRED.*` or `PRIV.*` | Access mechanism to reach new targets — stolen credentials, escalated privileges, or abused trust relationships |
| **Required** | `EXEC.*` or `FSYS.WRITE` or `PRST.*` | Action on new target — executing commands, writing payloads, or installing persistence on the newly reached system |
| Supporting | `CRED.SSH` | Using stolen SSH keys to move between hosts |
| Supporting | `CRED.CLOUD` | Using harvested cloud credentials to access additional infrastructure |
| Supporting | `CRED.TOKEN` | Using Kubernetes service account tokens, API tokens, or session tokens to access adjacent services |
| Supporting | `RECN.PROCMEM` | Reading running process memory to extract credentials, tokens, or other runtime secrets for use against connected systems |
| Supporting | `PRIV.EXPLOIT` | Container escape or privilege escalation to reach the host from a confined context |
| Supporting | `NETW.HTTP` | API-based interaction with orchestration platforms (Kubernetes API, cloud control planes) |
| Supporting | `PRST.SERVICE` | Installing persistence on each newly compromised node |

## Real-World Analogue

The LiteLLM attack's Kubernetes lateral movement: enumerate nodes, create privileged pods per node, chroot to host filesystem, install systemd backdoor. The Trivy compromise's credential chain: harvest CI/CD runner secrets, use them to publish malicious packages to other ecosystems. Classic SSH key reuse: compromise one server, read its SSH keys, use them to access every server in `known_hosts`.

## Investigation Guidance

- **Verify:** What infrastructure discovery is being performed? What credentials or access mechanisms are being used to reach new targets? What actions are taken on each new target?
- **Escalates:** Multiple targets are being accessed in an automated loop. Privileged containers or pods are being created. Persistence is installed on each new target. The lateral movement uses harvested credentials rather than legitimately provisioned access. Container escape techniques are employed.
- **De-escalates:** Infrastructure interaction is consistent with documented orchestration or deployment tooling. Access uses the package's own legitimately scoped credentials. Operations are limited to the package's documented purpose (e.g., a deployment tool deploying to known targets).
