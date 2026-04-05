# BP-AGENTMANIP — Agent Manipulation

## Description

Code or content designed to manipulate AI agents that process, review, or act on the codebase. This is a new attack vector where the target is not the machine running the code but the AI system analyzing it. The attacker embeds instructions that cause AI agents to approve malicious changes, suppress security warnings, execute commands, or install additional malicious packages. The code does not need to execute — it only needs to be *read* by an agent with tool access.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `AITM.INJECT` or `AITM.TOOL` or `AITM.INVISIBLE` | AI-targeting content must be present |
| Supporting | `AITM.CONTEXT` | Misleading documentation or comments that support the manipulation |
| Supporting | `OBFS.UNICODE` | Unicode tricks to hide the injection from human review |
| Supporting | `EXEC.*` | Commands the agent is being instructed to run |
| Supporting | `PKGM.*` | Package operations the agent is being instructed to approve |

## Real-World Analogue

Prompt injection attacks embedded in GitHub issues, pull requests, and package documentation that target Copilot, code review bots, and automated security scanning agents. This is an emerging and rapidly evolving attack surface.

## Investigation Guidance

- **Verify:** What instructions are embedded? What AI system are they targeting? What would happen if an AI agent followed the instructions?
- **Escalates:** Instructions direct the agent to execute commands, approve changes, or suppress security findings. Injection is hidden with Unicode tricks or steganography. Multiple injection points reinforce the same instruction.
- **De-escalates:** Content is legitimate documentation or comments. No executable instructions directed at AI systems.
