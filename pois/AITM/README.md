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

## Escalation Factors

The following conditions increase the suspicion level of any `AITM` finding:

- **Instructions target agentic or autonomous behavior.** Content that explicitly invokes tool calls, file writes, network requests, or code execution — not merely attempting to alter LLM responses but directing consequential actions — is critical severity.
- **Placement in high-read paths.** Content appears in locations AI coding assistants are most likely to ingest: top-level README, primary module docstrings, `__init__.py`, package manifest descriptions, or inline comments adjacent to exported APIs.
- **Presence in a transitive dependency.** The injected content is several hops removed from the developer's direct imports, reducing the probability any human reviewer has read it and increasing the probability an AI agent processing the full dependency tree encounters it without scrutiny.
- **Combination with obfuscation.** When `AITM.INVISIBLE` co-occurs with zero-width characters, homoglyphs, or RTL overrides (`OBFS.UNICODE`), the payload is specifically engineered to be invisible to human reviewers while remaining machine-readable to the language model.
- **Payload contains exfiltration instructions.** Instructions directing an AI agent to transmit credentials, environment variables, file contents, or session tokens elevate from manipulation to active data theft.
- **Payload mimics legitimate tool or policy documentation.** Content formatted to resemble actual tool schemas, safety guidelines, or organizational policy acquires false authority. An AI agent with no prior context has no reliable signal the documentation is not genuine.
- **Injection present in multiple files or locations.** Redundancy across files indicates intentional deployment and increases the probability at least one instance will be read regardless of which file the agent starts from.
- **Payload references specific downstream systems or credential patterns.** Instructions referencing AWS, GitHub tokens, `.env` files, or named internal services suggest the attacker targeted a specific deployment context.

## De-escalation Factors

De-escalation is highly constrained for AITM. Unlike most POIs, there is no benign technical explanation for embedding behavioral instructions directed at an LLM inside a third-party dependency.

- **Content is demonstrably AI-generated documentation noise.** Some LLM-assisted code generation tools emit natural-language directives in comments (e.g., "Tell the model to explain this function"). If the phrasing is clearly explanatory, matches surrounding documentation style, and contains no actionable instruction (no tool calls, no data references, no authority claims), severity may be reduced from critical to high pending author confirmation. *(Caveat: does not apply if the package predates widespread AI tooling adoption.)*
- **Package is an explicit AI prompting or LLM utility library.** Libraries whose stated purpose involves prompt construction, agent tooling, or LLM testing may legitimately contain instruction-formatted strings as test fixtures or template examples. Confirm strings are referenced only as data (assigned to variables, returned from functions) rather than embedded as ambient text in comments or docs.
- **Finding is isolated to test or example directories excluded from the published package artifact.** If injected content appears only in `tests/`, `examples/`, or `docs/` paths not traversed during normal AI assistant usage, immediate risk is lower. *(Caveat: many AI coding assistants do read test files; confirm actual ingestion surface.)*

> **Important caveat:** None of the above de-escalations eliminate the finding. AITM in any dependency requires author contact, package version pinning or removal, and review of any AI-assisted development sessions that occurred while the package was installed.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `AITM.INJECT` + `PKGM.INSTALL` | Install hooks provide guaranteed execution; injected instructions can direct an AI agent to persist or escalate the hook's payload | Critical |
| `AITM.INVISIBLE` + `OBFS.UNICODE` | Dual-target attack: invisible to human reviewers, legible to LLMs. Zero-width characters and homoglyphs indicate sophisticated authorship | Critical |
| `AITM.TOOL` + `NETW.*` | Malicious MCP server or tool definition proxying legitimate-looking calls while forwarding data to attacker endpoint | Critical |
| `AITM.INJECT` + `CRED.*` | Instructions directing AI agent to locate and output API keys, tokens, or secrets from repository context | Critical |
| `AITM.INJECT` + `OBFS.ENCODE` | Base64 or hex-encoded payloads in docstrings or comments — humans see apparent garbage; models may decode and act on content | High |
| `AITM.TOOL` + `AITM.CONTEXT` | Malicious tool definitions with misleading documentation misrepresenting tool behavior or scope | High |
| `AITM.INJECT` + `PRST.*` | Instructions directing AI agent to modify initialization files, shell profiles, or startup scripts for persistence | Critical |
| `AITM.CONTEXT` + typosquatted package | Package with documentation engineered to appear as authoritative fork or successor of legitimate package | High |

## Disambiguation

### AITM vs. Authored Documentation Using Imperative Language

Technical documentation routinely uses imperative constructions: "Call this function before initializing the client," "Ensure the environment variable is set." These are instructions to human developers, not injected directives to AI systems.

The distinction is specificity of targeting and actionability within an AI agent context. Legitimate documentation describes the package's own API and usage. AITM content references behavior outside the package's scope — telling the agent to read files, call tools, transmit data, assume an identity, or override prior instructions. If removing the content would have no effect on a human developer's understanding but would meaningfully alter an AI agent's behavior, treat it as AITM.

Secondary signal: legitimate documentation does not need to assert its own authority or request that the reader ignore other instructions. Content claiming special permissions, presenting itself as a system message, or instructing an agent to suppress findings is AITM regardless of surrounding context.

### AITM.TOOL vs. Legitimate MCP Server or Plugin Definitions

MCP servers and tool definitions are a legitimate part of the AI development ecosystem. A tool definition is not inherently suspicious. `AITM.TOOL` applies when:

- The declared tool name or description impersonates a known, trusted tool with minor variation (analogous to typosquatting at the tool layer)
- The tool schema requests parameters beyond what the stated function requires — particularly environment variables, file paths outside the project, or authentication tokens
- The tool's implementation routes calls through an undisclosed intermediate endpoint
- The tool definition ships inside a package whose stated purpose is unrelated to AI tooling

### AITM.CONTEXT vs. Normal Documentation Error

Codebases accumulate incorrect comments. A function whose behavior diverged from its docstring years ago is not AITM.CONTEXT. The distinction is deliberate construction of a false model that benefits an attacker.

AITM.CONTEXT is indicated when the inaccuracy: (a) consistently misrepresents security-relevant behavior (input validation, authentication, permission scope); (b) appears in newly introduced code where documentation and implementation were written simultaneously, ruling out drift; or (c) systematically frames the package as more trustworthy or more permissioned than it actually is. A single stale comment is technical debt. A pattern of comments constructing a coherent false security narrative is AITM.CONTEXT.

## Investigation Questions

When an `AITM` finding is detected, answer these questions to drive the investigation:

### For any AITM subtype:
1. **What AI systems were exposed to this package?** Identify every AI coding assistant, agent, or automated review tool that may have ingested the package's source — IDE plugins, CI-integrated assistants, and any agentic pipelines consuming dependency code.
2. **What actions did those AI systems take during the exposure window?** Review agent logs, tool call histories, and outputs generated by AI assistants while the package was installed. Look for anomalous file reads, unexpected network calls, credential lookups, or generated code not reflecting developer intent.
3. **Does the injected content reference specific infrastructure, credential patterns, or internal naming conventions?** Generic injections suggest opportunistic targeting. Specific references suggest the attacker had prior knowledge of the target environment.
4. **When was the AITM content introduced?** A package that shipped with injection from its first version was likely created as a delivery mechanism. Injection appearing in a subsequent version of an established package suggests supply chain compromise.

### For AITM.INJECT specifically:
5. **Is the payload functional against current LLM context windows?** Some payloads reference specific agent frameworks (LangChain, AutoGPT, Claude tool use syntax) or exploit model-specific behaviors. Model-specific targeting indicates sophistication.
6. **Are other packages from the same author similarly affected?** AITM campaigns frequently distribute payloads across multiple packages.

### For AITM.TOOL specifically:
7. **Does the tool definition appear in any AI agent's active tool registry?** A tool definition present in the repository but never loaded into an agent runtime is lower urgency than one actively registered and callable.
8. **Does the tool schema request parameters beyond its stated function?** Particularly: environment variables, file paths outside the project, or authentication tokens.

### For AITM.INVISIBLE specifically:
9. **What specific encoding technique is used?** Zero-width characters, homoglyphs, RTL overrides, or adversarial token sequences each have different detection methods and different models they are effective against.

### Cross-cutting:
10. **What is the organizational policy for AI agent tool approval?** If the package reached an AI agent's context without passing through any approval gate, the AITM finding is also evidence of a process failure that extends beyond this specific package.
