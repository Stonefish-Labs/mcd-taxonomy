# LOAD — Dynamic Code Loading

**Applies to:** Source and binary.

## Description

Any mechanism by which code loads, compiles, interprets, or otherwise brings new executable logic into a running process at runtime. Dynamic loading is the hinge between static analysis and runtime behavior: it is the point where what you can see in the code diverges from what actually executes. Eval, dynamic imports, shared library loading, deserialization of executable objects, and runtime code generation all fall here.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `LOAD.EVAL` | Eval / Dynamic Interpretation | Using `eval()`, `exec()`, `Function()`, or equivalent to execute strings as code at runtime. The string may be hardcoded, decoded, fetched from the network, or constructed from fragments — in all cases, the actual behavior is opaque to static analysis. |
| `LOAD.IMPORT` | Dynamic Import / Require | Loading modules by computed name at runtime rather than static import. Enables loading of modules that are not visible in dependency declarations. |
| `LOAD.DYLIB` | Dynamic Library Loading | Loading shared libraries (`.so`, `.dll`, `.dylib`) at runtime via `dlopen`, `LoadLibrary`, or equivalent. May load libraries not declared in the build system. |
| `LOAD.REFLECT` | Reflection | Using language reflection capabilities to invoke methods, access fields, or instantiate classes by name at runtime. Circumvents static analysis of call graphs. |
| `LOAD.DESER` | Unsafe Deserialization | Deserializing data into executable objects (pickle, Java ObjectInputStream, YAML load, etc.). Deserialization of untrusted data is a well-known remote code execution vector. |
| `LOAD.CODEGEN` | Runtime Code Generation | Generating and executing code at runtime: JIT compilation, AST manipulation, bytecode generation, or writing and importing temporary modules. |
| `LOAD.WASM` | WebAssembly Loading | Loading and instantiating WebAssembly modules. WASM is effectively a portable binary — it can contain arbitrary compiled logic that is opaque to source-level analysis. |

## Severity Baseline

`LOAD.EVAL` with non-literal input is high. `LOAD.DESER` with untrusted data is high. `LOAD.DYLIB` depends on what is loaded.

## Escalation Factors

The following conditions increase the suspicion level of any `LOAD` finding:

- **The input to the LOAD call is attacker-influenced.** The string or object passed to `eval()`, `exec()`, `pickle.loads()`, or `importlib.import_module()` derives from network data, user input, environment variables, file content, or any external source. This is the single most determinative factor across all LOAD subtypes.
- **The LOAD call is preceded by OBFS activity.** The code being loaded was base64-decoded, XOR'd, decompressed, or otherwise transformed immediately before execution. The `OBFS` -> `LOAD` chain is the canonical payload delivery pattern; presence of both in the same call stack is a strong combined signal.
- **The module name is computed, not literal.** In `LOAD.IMPORT`, if the module string is constructed at runtime (string concatenation, format strings, dictionary lookup, environment variable interpolation), static analysis cannot determine what will load. This makes the import functionally equivalent to arbitrary code execution.
- **Deserialized object graph uses lifecycle hooks.** In `LOAD.DESER`, the payload actively controls `__reduce__`, `__wakeup`, `readObject()`, or equivalent. This is the direct RCE path in pickle and Java ObjectInputStream; the presence of these hooks in serialized data upgrades severity to critical.
- **WASM module arrives over the network or from disk at runtime.** `LOAD.WASM` loaded from a bundled, reviewed asset is a different risk profile than a module fetched, decrypted, or assembled at runtime. Dynamic WASM sourcing makes the loaded code opaque to all prior analysis.
- **Dynamic library is not in the declared dependency manifest.** A `dlopen()` or `LoadLibrary()` call targeting a path not present in the package's declared dependencies or build system indicates either an undeclared dependency or a payload dropped by a prior stage.
- **Reflection is used to invoke private or security-sensitive methods.** `LOAD.REFLECT` that bypasses access controls (`setAccessible(true)` in Java, `__getattribute__` override in Python) to invoke methods that are intentionally non-public suggests deliberate circumvention.
- **Code generation target is executable memory or a callable object.** `LOAD.CODEGEN` that produces bytecode, compiles to native instructions, or constructs a callable from a string and immediately invokes it collapses the distinction between code generation and execution.
- **Surrounding code suppresses errors or discards return values.** Bare `try/except: pass` blocks around LOAD calls, or deliberate discard of return values, suggest the author anticipated and masked failure cases — a behavioral signal for intent.
- **The LOAD site is in a dependency, not application code.** Malicious LOAD patterns in a transitive dependency represent supply chain risk where the author had deliberate opportunity to embed them.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **Input is a compile-time or load-time constant.** If the string evaluated or deserialized is a literal defined in the same file or a configuration value verified as static, the "arbitrary" in arbitrary code execution does not apply. *(Caveat: verify that no code path can substitute a non-literal value; this is harder than it appears in large codebases.)*
- **A strict allowlist gates what can be loaded.** `LOAD.IMPORT` with a pre-validated set of permitted module names, or `LOAD.DESER` using a restricted unpickler or class whitelist, meaningfully constrains the attack surface. *(Caveat: allowlist bypasses via canonicalization issues, inheritance chains, or partial-match logic are a documented vulnerability class.)*
- **The LOAD site is isolated in a sandbox with no meaningful capabilities.** If the dynamic code executes in a subprocess with dropped privileges, a seccomp filter, a language-level sandbox, or a WASM runtime with no imported host functions, the damage radius is bounded. *(Caveat: sandbox escapes exist and the isolation claim requires independent verification.)*
- **The pattern is idiomatic framework use with no runtime input.** Certain frameworks require `LOAD.REFLECT` or `LOAD.IMPORT` for plugin registration, dependency injection, or ORM operation. *(Caveat: this determination requires understanding the full data flow into the call, not just its local appearance.)*
- **Serialized data is integrity-verified before deserialization.** HMAC or signature verification of the serialized payload before passing it to the deserializer reduces the threat from external tampering. *(Caveat: this does not eliminate risk from a malicious internal producer.)*

> **Important caveat:** Dynamic code loading is the point where static analysis fails. Any de-escalation that relies on "the input is safe" must be verified through the complete data flow, not assumed from local context.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `OBFS.ENCODE` + `LOAD.EVAL` | Encoded string decoded immediately before eval/exec — the canonical single-stage payload delivery | Critical |
| `NETW.HTTP` + `LOAD.EVAL` | Code string retrieved over HTTP and executed — remote code execution with attacker-controlled server as payload source | Critical |
| `NETW.HTTP` + `LOAD.DESER` | Serialized object fetched from remote endpoint and deserialized without class restriction — standard RCE vector | Critical |
| `LOAD.IMPORT` + `FSYS.WRITE` | Computed module name resolving to a path written earlier in the same session — two-stage write-then-load | High |
| `LOAD.DYLIB` + `OBFS.ENCODE` | Native library path constructed from encoded or environment-derived string — conceals actual binary being loaded | High |
| `LOAD.REFLECT` + `PRIV.*` | Reflection used to invoke access-controlled methods gating privilege operations — common in Java deserialization gadget chains | High |
| `LOAD.CODEGEN` + `NETW.*` | Runtime code generation assembling exfiltration logic not visible in source | High |
| `LOAD.WASM` + `NETW.HTTP` | WASM module fetched at runtime and instantiated with host function imports — opaque binary with caller-granted capabilities | High |
| `OBFS.ENCODE` + `LOAD.DESER` | Serialized payload stored encoded; decoded immediately before deserialization — mirrors OBFS + LOAD.EVAL for non-eval environments | High |
| `LOAD.EVAL` + `EXEC.SHELL` | eval/exec constructs a string then passed to subprocess or os.system — two-step dynamic interpretation to shell execution | Critical |

## Disambiguation

### LOAD.EVAL vs. EXEC.SHELL

Both result in arbitrary code execution, but the execution substrate differs. `LOAD.EVAL` executes within the language runtime: `eval()` in Python evaluates a Python expression; `Function()` in JavaScript constructs a callable within the V8 context. The payload has access to the language's object model, imported modules, and in-process state.

`EXEC.SHELL` passes a string to the operating system shell or subprocess. The payload is interpreted by `sh`, `cmd.exe`, or equivalent and has access to the OS environment, filesystem, and process table.

The combination — `eval()` constructing a string that then calls `os.system()` — is classified as both and represents a two-stage chain. When LOAD.EVAL is the mechanism and the injected code itself calls a shell, both tags apply. Do not reduce a two-stage chain to a single tag.

### LOAD.IMPORT vs. Normal Imports

Static imports (`import os`, `from pathlib import Path`) are resolved at parse time, appear in the module's dependency graph, and are fully visible to static analysis. They are not LOAD.IMPORT.

`LOAD.IMPORT` requires that the module name is determined at runtime: constructed from variables, derived from configuration, or produced by any operation that prevents static determination of what will load. The test is whether a static analyzer, without executing the code, can enumerate all possible modules the call will load. If it cannot, the call is `LOAD.IMPORT`.

Plugin systems that load user-specified modules by design are `LOAD.IMPORT` with de-escalating context, not a different category. The mechanism is the same; the risk determination follows from who controls the module name.

### LOAD.DESER vs. LOAD.EVAL

Both can achieve arbitrary code execution, but through different mechanisms. `LOAD.EVAL` requires the payload to be a syntactically valid code string. The execution is explicit: a function named `eval` or `exec` appears in the call graph.

`LOAD.DESER` achieves code execution through object graph reconstruction. Code execution occurs as a side effect of the deserialization process via lifecycle hooks (`__reduce__` in pickle, `readObject()` chains in Java). There is no explicit `eval` call; the execution is implicit.

Do not require evidence of explicit eval-like syntax to classify `LOAD.DESER`. The deserialization of untrusted data with a permissive deserializer is the finding.

### LOAD.DYLIB vs. LOAD.IMPORT

`LOAD.IMPORT` operates at the language module level: Python packages, Node modules, JVM classpath entries. `LOAD.DYLIB` operates at the OS ABI level: ELF shared objects, PE DLLs, Mach-O dylibs loaded via `dlopen()`, `LoadLibrary()`, `ctypes.CDLL()`. The loaded artifact is native machine code linked into the calling process's address space, executing with the process's privileges and bypassing language-level sandboxing entirely. A Python sandbox that blocks `eval()` may have no control over `ctypes.CDLL("/tmp/payload.so")`.

### LOAD.WASM: Capability Boundary

WebAssembly modules are sandboxed by default — they cannot access the filesystem, network, or process table without explicit host function imports. The threat model for `LOAD.WASM` is determined by the import section: what capabilities does the host grant to the module? A WASM module with no host function imports can compute but not interact with the system. A module that imports filesystem, network, or execution functions from the host has explicit capability grants and should be treated accordingly.

## Investigation Questions

When a `LOAD` finding is detected, answer these questions to drive the investigation:

### For any LOAD subtype:
1. **What is the complete data flow from source to the LOAD call?** Trace the argument to `eval()`, `pickle.loads()`, `import_module()`, or the library path backward to its origin. Does the path include network I/O, file reads, environment variables, or user input?
2. **Is any transformation applied to the data before loading?** Look for decode, decompress, decrypt, or string manipulation calls in the preceding lines. OBFS indicators immediately before a LOAD site is the primary escalation signal.
3. **What modules, methods, or capabilities does the loaded code have access to?** In-process `LOAD.EVAL` executions inherit the caller's imports and globals. Identify what is in scope at the eval site.
4. **Is there a class restriction or allowlist in place?** For `LOAD.DESER`, does the deserializer restrict which classes can be instantiated? Review the allowlist implementation for bypass paths.
5. **When was this LOAD pattern introduced, and by whom?** Check version control history. A pattern introduced in a dependency update or a PR from an external contributor is higher priority.
6. **Does the LOAD site appear at install time, import time, or only at runtime on user action?** `LOAD.EVAL` in `setup.py`, `__init__.py`, or module-level code executes on install or first import without user action.

### For LOAD.EVAL specifically:
7. **What does the evaluated code do?** If the LOAD site can be reached in a test environment, instrument it to capture what actually executes. Static analysis tells you dynamic execution happens; only runtime observation tells you what executes.

### For LOAD.DESER specifically:
8. **What serialization format is used, and what class restrictions are in place?** Pickle with no restricted unpickler is critical. YAML with `safe_load` instead of `load` is substantially lower risk. Java `ObjectInputStream` with no `ObjectInputFilter` is critical.

### For LOAD.DYLIB specifically:
9. **What is the library path, and is the library present in the package distribution?** A `dlopen()` targeting a path not present in the package suggests a staged payload. Is the library signed or hash-verified before loading?

### For LOAD.WASM specifically:
10. **What host functions are imported by the module?** Review the import section of the WASM binary. A module that imports filesystem, network, or process execution functions has explicit capability grants.

### For LOAD.IMPORT specifically:
11. **Can the set of loadable modules be statically enumerated?** If the module name is derived from user input or network data, the import is functionally equivalent to arbitrary code execution.

### Cross-cutting:
12. **Is error handling around the LOAD site suppressive?** Bare exception handlers that swallow errors suggest the author anticipated failure conditions. This is a behavioral signal for intent.
