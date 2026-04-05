# Behavioral Patterns

A Behavioral Pattern is a named composition of POIs that, taken together, suggest a specific malicious intent. Individual POIs are evidence; behavioral patterns are hypotheses. A pattern is triggered when its constituent POIs are detected within a reachable scope — meaning the POIs are plausibly connected through execution flow, not merely co-located in an artifact by coincidence.

## Pattern Definition

Every behavioral pattern is defined by:

- **ID and Name** — A `BP-` prefixed identifier and a human-readable name.
- **Description** — What the pattern represents and what real-world attack it models.
- **Constituent POIs** — The combination of POIs that trigger the pattern, divided into *required* (must be present) and *supporting* (increase confidence when present).
- **Real-World Analogue** — A brief reference to the type of attack this pattern detects.
- **Investigation Guidance** — What to verify next, what escalates confidence, and what de-escalates it.

## On Reachability

The correct criterion for pattern matching is *reachability*: can the code path that exhibits POI A plausibly reach the code that exhibits POI B? The detection system should use the best available method to assess reachability — tree-sitter structural analysis, call graph approximation, LLM-based reasoning, or proximity heuristics — but the taxonomy defines the *what*, not the *how*.

## Patterns

| ID | Name | Description |
|---|---|---|
| [BP-SUPPLY](BP-SUPPLY.md) | Supply Chain Payload | Package executes malicious payload during installation or first use |
| [BP-CREDTHEFT](BP-CREDTHEFT.md) | Credential Theft | Locates, reads, and exfiltrates authentication material |
| [BP-BACKDOOR](BP-BACKDOOR.md) | Backdoor | Provides unauthorized access bypassing normal authentication |
| [BP-DROPPER](BP-DROPPER.md) | Dropper / Downloader | Retrieves secondary payload from remote source and executes it |
| [BP-EXFIL](BP-EXFIL.md) | Data Exfiltration | Collects data from local system and transmits it externally |
| [BP-RANSOM](BP-RANSOM.md) | Ransomware | Encrypts files and demands payment for decryption |
| [BP-TIMEBOMB](BP-TIMEBOMB.md) | Logic Bomb / Time Bomb | Remains dormant until a specific condition triggers activation |
| [BP-MINER](BP-MINER.md) | Resource Hijacking | Uses host compute resources for unauthorized purposes |
| [BP-ROOTKIT](BP-ROOTKIT.md) | Rootkit / Self-Modification | Modifies the operating environment to hide its presence |
| [BP-WORM](BP-WORM.md) | Worm / Propagation | Replicates to other systems or repositories without user initiation |
| [BP-TROJAN](BP-TROJAN.md) | Trojan / Disguised Payload | Presents legitimate interface while concealing malicious functionality |
| [BP-AGENTMANIP](BP-AGENTMANIP.md) | Agent Manipulation | Manipulates AI agents that process or act on the codebase |
| [BP-TYPOSQUAT](BP-TYPOSQUAT.md) | Typosquat / Dependency Confusion | Impersonates a legitimate package through name similarity |
| [BP-LATERAL](BP-LATERAL.md) | Lateral Movement | Spreads presence to other systems within the same environment |
