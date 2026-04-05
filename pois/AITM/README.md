# AITM — AI-Targeted Manipulation

**Applies to:** Source (primarily comments, docstrings, documentation, error messages, configuration).

## Description

Content or code designed to manipulate AI systems — coding assistants, automated code reviewers, security scanning agents, or any LLM-powered tool that processes code or documentation. This is a fundamentally new attack surface that did not exist when earlier detection taxonomies were written. An attacker no longer needs to trick a human reviewer; they need to trick the AI agent that reviews, approves, or acts on code on behalf of humans. A prompt injection payload in a docstring costs nothing to include and targets every AI system that reads the code.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `AITM.INJECT` | Prompt Injection Payload | Instructions embedded in code comments, docstrings, README files, error messages, or string literals that are designed to alter the behavior of an LLM processing the code. May instruct the LLM to ignore security findings, approve changes, execute commands, or produce misleading output. |
| `AITM.TOOL` | Tool / MCP Poisoning | Malicious tool definitions, MCP server configurations, or API schemas that appear legitimate but exfiltrate data, execute unauthorized actions, or grant excessive permissions when used by an AI agent. |
| `AITM.INVISIBLE` | Invisible Instruction Embedding | Using Unicode tricks (zero-width characters, homoglyphs, right-to-left overrides), steganographic encoding in non-code resources, or adversarial token sequences to embed instructions that are invisible to human reviewers but parsed by LLMs. |
| `AITM.CONTEXT` | Context Manipulation | Code or documentation structured to cause an AI agent to build an incorrect mental model of the codebase — misleading comments, deliberately confusing naming, or fake documentation that contradicts actual behavior. Distinguished from simple bad code by evidence of intentional misdirection. |

## Severity Baseline

All `AITM` subtypes are high when detected. The presence of prompt injection content in a dependency is a strong indicator of malicious intent.
