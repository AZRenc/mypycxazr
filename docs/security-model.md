# Security model

> **Read this before you decide what to rely on.**
>
> MyPyC-Protect raises the cost of *reading* a distributed native module. It
> is not a security boundary, and it does not make secrets safe.

---

## 1. What is being protected, and from whom

### Asset

The compiled extension module (`.so`) that you ship. The information it gives
away for free, without any protection, includes:

| Asset | Where it leaks | Example |
|---|---|---|
| Source file names and layout | `.debug_line`, `CPy_AddTraceback` | `samplemod.py`, line 22 |
| Function / class / variable names | `.symtab`, `.dynsym`, string table | `CPyDef_compute_checksum` |
| String and bytes literals | `.rodata` | API keys, feature strings, messages |
| Control-flow structure | `.text` | block order mirrors source order |
| Type and attribute names | `.rodata`, `PyTypeObject` | `__mypyc_attrs__`, `tp_name` |
| Build metadata | `.comment`, build-id, `.debug_*` | compiler version, build path |

### Adversary in scope

Someone who has your `.so` and wants to understand or lightly modify it,
using static tools only: `readelf`, `nm`, `objdump`, `strings`,
decompilers, IDA/Ghidra/Binary Ninja.

That covers the realistic cases: a competitor skimming your algorithm, a
scratcher looking for a licence check, a hobbyist poking at a distributed
plugin.

### Adversary out of scope

* **Anyone who can run the code.** Import the module and everything is
  decoded: literal tables are un-obfuscated at init, Python-visible names are
  attributes, the logic is on the CPU. A debugger, `frida`, `ptrace`, or a
  patched `CPyProtect_VerifyIntegrity` all defeat this completely.
* **Anyone willing to put in real work.** Obfuscation is reversible by
  definition. Symbol renames are a naming problem, not a cryptographic one;
  CFG trampolines are locally trivial to flatten.
* **Anyone attacking the Python side.** Pure-Python callers, the `.pyi`, the
  bytecode of the importing package and any reflection
  (`obj.__class__.__name__`, `dir(obj)`) all expose the same names.

---

## 2. Feature-by-feature claims

### `debug_reduction`

**Claim:** the ELF carries no DWARF sections and no compiler identification
comment.

**Verified by:** `debug_sections == []` in
`tests/protection/measure_elf.py`.

**Residual:** traceback source paths survive (`CPy_AddTraceback("samplemod.py", ...)`).
Replacing them would change what Python prints in a traceback, which is
observable behaviour and is out of scope.

### `elf_hardening`

**Claim:** full RELRO, immediate binding, non-executable stack, no build-id —
each flag applied only if the toolchain probes as accepting it.

**Residual:** these are hardening against *runtime* exploits (GOT overwrite,
stack execution), not against static analysis. They are included because the
spec asks for them and they cost nothing.

### `symbol_visibility`

**Claim:** the dynamic symbol table contains only `PyInit_` (or `CPyInit_`)
instead of ~230 mypyc symbols.

**Verified by:** `exported dynamic symbols: 231 → 1`.

**Residual:** local symbols are still in `.symtab` unless the file is
stripped; `symbol_names` is what makes those unreadable.

### `symbol_names`

**Claim:** identifiers derived from source are replaced by seeded hashes, so
`nm` output no longer tells an analyst which functions exist.

**Verified by:** `source identifiers still recoverable: 47/61 → 36/61` on the
reference module.

**Residual — this is the important one.** The ratio does not go to zero, and
it never will. A large fraction of those identifiers are **Python-visible
names that must not change**:

* method names in the `PyModuleDef` table (`process_items`, `compute_checksum`);
* `tp_name` / `__name__` / `__qualname__`;
* attribute names in `__mypyc_attrs__`;
* string literals that Python code looks up by name.

Renaming any of these would break `hasattr()`, `getattr()`, pickling,
`help()`, and introspection — i.e. it would break Python semantics, which the
spec forbids. **The floor is a language requirement, not a bug.**

### `literal_mangling`

**Claim:** string/bytes literals are not readable with `strings(1)` until the
module has been imported and the decoder has run.

**Residual:** after import they are in memory in plain text. If a secret is
in a literal, it is recoverable by running the program. Do not put secrets in
literals.

### `control_flow`

**Claim:** the recovered CFG does not mirror the source structure, because
every edge has an extra hop and block order is permuted.

**Residual:** this only affects naive static recovery. A decompiler that
builds and simplifies a CFG (removes forwarding blocks, runs dominator
analysis) will reconstruct the original structure, because the transform is
deliberately semantics-preserving and introduces no opaque predicates, no
irreducible control flow and no computation that a solver could not fold.

That is on purpose: opaque predicates and bogus control flow would change
which paths are reachable and could change timing and error behaviour, and
the spec forbids breaking semantics.

### `integrity`

**Claim:** a byte-level modification of the shipped file makes the module
refuse to import.

**Verified by:** flipping one byte in `.text` produces
`RuntimeError: MyPyC-Protect: module failed its integrity check`
(`tests/protection/test_integrity.py` covers the hashing; the end-to-end
behaviour was checked against a real build).

**Residual — read carefully:**

1. **It is not tamper-proof.** The check is code in the same binary. Anyone
   who can edit the file can also NOP out `CPyProtect_VerifyIntegrity` or
   restore the digest. The goal is to make a *casual* byte-level patch fail
   loudly, not to stop a determined attacker.
2. **The threat is the file on disk, not memory.** A runtime patch of the
   in-memory image is not detected.
3. **The path must be discoverable.** The verifier resolves its own file with
   `dladdr()` (falling back to `module.__file__`). If neither works — an
   exotic loader, a memfd, a platform without `dladdr` — the check is
   **skipped rather than failing**. A verification that cannot run must not
   break a healthy import; that trade-off is deliberate.
4. **`module.__file__` alone is not enough.** For a single-phase extension,
   `__file__` is populated *after* the exec function returns, which is why
   `dladdr()` is the primary route.
5. **It detects the whole file, including the ELF headers.** Anything that
   legitimately rewrites the file after stamping (re-signing, `strip`,
   insertion into a bundle) will break it. Stamping is therefore the last
   build step.

---

## 3. What is deliberately *not* protected

| Thing | Why not |
|---|---|
| Python-visible names | Renaming changes Python semantics. |
| `PyInit_` / `CPyInit_` | Looked up by name by the import machinery. |
| Traceback source paths | Would change what Python prints. |
| Bytecode of importing Python modules | Out of scope; mypyc compiles `.py` to native code, it does not touch other modules. |
| Secrets | There is no safe way to hide a secret in a file the user can read and run. |
| Runtime behaviour | Timing, error messages and results must be identical to upstream mypyc. |

---

## 4. Non-goals

* **Not DRM.** Anything a user can run, a user can debug.
* **Not obfuscation-as-security.** No feature here is reversible only with a
  key; there is no key.
* **Not a substitute for server-side checks.** If a licence matters, verify it
  where the attacker cannot reach the verifier.
* **Not free.** Sizes are roughly flat (file size actually drops, because
  debug info is removed; `.text` grows ~4% from the trampolines). There is no
  intended performance regression: trampolines compile to fall-through edges.

---

## 5. Reproducibility

Symbol names and literal keys are derived from `(seed, module, name)` with
SHA-256. Identical inputs produce identical output, so two builds of the same
source with the same seed are byte-comparable — which is what makes the
integrity digest meaningful. Changing the seed changes every obfuscated name
and every literal key; `build_identity()` in `mypycxazr.protect.integrity` is the
stable fingerprint used by the tests.

---

## 6. Reporting a problem

If you find a feature that does not do what this document claims, that is a
bug — either in the code or in this file. The tests in `tests/protection/`
exist to keep the two honest: an advertised feature with no implementation
fails `test_every_enabled_feature_is_actually_implemented`, and a pass that
corrupts the IR fails `mypycxazr.analysis.ircheck`.
