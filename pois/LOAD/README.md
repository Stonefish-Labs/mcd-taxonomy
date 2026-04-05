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
