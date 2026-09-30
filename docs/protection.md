# MyPyC-Protect — Protection levels and features

MyPyC-Protect is a fork of [mypyc](https://mypyc.readthedocs.io/) that adds an
optional **protection layer** to the native code it produces. It is off by
default: a build without `--protect` behaves exactly like upstream mypyc, and
the whole test suite (885 tests) passes unchanged.

Protection changes **how the binary looks**, never **what the program does**.
No feature may alter observable Python semantics — that invariant is enforced
by the tests in `tests/protection/` and by running the same suite with
protection enabled.

---

## Enabling protection

Three equivalent ways, in precedence order (highest first):

| Source | Example |
|---|---|
| CLI flag | `python -m mypycxazr --protect=strong samplemod.py` |
| Environment | `MYPYC_PROTECT=strong python -m mypycxazr samplemod.py` |
| Config file | `[tool.mypycxazr-protect]` in `pyproject.toml` |

```toml
[tool.mypycxazr-protect]
level = "strong"
strip = false
# Optional: force individual features on regardless of level
features = ["control_flow"]
```

From `setup.py`:

```python
from mypycxazr.build import mypycify
ext_modules = mypycify(["mypkg/*.py"], protect="strong", protect_strip=True)
```

Other CLI switches:

```
--protect=off|basic|strong|maximum   level (default: off, or the config file's)
--protect-strip                      force reduced debug metadata even at "off"
--protect=help                       print the level/feature matrix and exit
```

`MYPYC_PROTECT_STRIP=1` is the environment equivalent of `--protect-strip`.

A **debug build** (`MYPYC_OPT_LEVEL=0`, i.e. `-O0`) refuses protection: the
point of the layer is to make optimized native code harder to read, and a debug
build ships debug info by definition. The build stops with an explanatory error
rather than silently producing an unprotected module.

---

## The level matrix

Levels are **additive**: `basic` ⊂ `strong` ⊂ `maximum`.

| feature | off | basic | strong | maximum |
|---|:-:|:-:|:-:|:-:|
| `debug_reduction` — drop compiler debug info & `#line` directives | | ✓ | ✓ | ✓ |
| `elf_hardening` — RELRO, immediate binding, non-executable stack | | ✓ | ✓ | ✓ |
| `symbol_visibility` — hide everything behind the Python ABI | | ✓ | ✓ | ✓ |
| `symbol_names` — rename source-derived C symbols | | | ✓ | ✓ |
| `literal_mangling` — encode string/bytes literal tables | | | ✓ | ✓ |
| `control_flow` — reshape the CFG without changing it | | | ✓ | ✓ |
| `integrity` — detect post-link modification | | | | ✓ |

The matrix is asserted by `tests/protection/test_options.py`, and
`tests/protection/test_pipeline.py` fails the build if a level ever advertises
a feature that no pass, no flag and no code generator implements. That is the
guard against the project's own rule: **no fake features.**

---

## What each feature does

### `debug_reduction` (basic)

* `-g0 -fno-ident` appended to the compile flags, overriding mypyc's default
  `-g1`.
* Development-only artifacts (the per-function `ops.txt` trace) are not
  written.

Effect: every `.debug_*` section disappears from the ELF
(`.debug_aranges`, `.debug_info`, `.debug_abbrev`, `.debug_line`,
`.debug_str`, `.debug_line_str`, `.debug_rnglists`).

### `elf_hardening` (basic)

Passed to the linker **only after probing that the toolchain accepts them**,
so a toolchain that does not support a flag never receives it:

```
-Wl,-z,relro        read-only relocations
-Wl,-z,now          immediate symbol binding (full RELRO)
-Wl,-z,noexecstack  non-executable stack
-Wl,--build-id=none no build-id (reproducibility, less metadata)
```

### `symbol_visibility` (basic)

* `-fvisibility=hidden` (probed).
* The two names that *must* stay exported get an explicit
  `Py_EXPORTED_SYMBOL`: `PyInit_<mod>` / `CPyInit_<mod>`.

mypyc's runtime already communicates through capsules rather than exported
symbols, so hiding the rest costs nothing. Measured effect: **231 exported
dynamic symbols → 1** (only `PyInit_`).

### `symbol_names` (strong)

Every C identifier *derived from source* (`CPyDef_greet`, `CPyType_Greeter`,
`CPyStatic_something`) is replaced by `z` + 10 hex digits of a SHA-256 keyed by
a build seed.

Never renamed, because renaming them would change behaviour:

* `PyInit_`, `CPyInit_`, `CPyExec_`, `exports_` — looked up by name by the
  import machinery and by the shims;
* anything Python-visible: method names in `PyModuleDef`, `__name__`,
  `__qualname__`, attribute names, traceback names.

Two properties are load-bearing and are tested directly:

1. **Determinism** — the same inputs and seed always produce the same names,
   so builds stay reproducible.
2. **Composition consistency** — codegen sometimes builds a C name by
   *concatenating* a suffix onto an already-generated stem
   (`type_struct_name(cl) + "_template"`, `name_prefix +
   "_trait_vtable_setup"`), while the IR refers to the same variable as a
   whole string (`static_name(..., "Greeter_template")`). Hashing the whole
   string on one side and composing on the other splits the symbol in two and
   the build fails to link. `mypycxazr.protect.symbols.COMPOSED_SUFFIXES` makes
   the hash operate on the stem only and re-append the suffix, so both paths
   agree.

### `literal_mangling` (strong)

String and bytes literal tables are packed into a single XOR-obfuscated blob
(`CPyProtect_LitStrBlob`, `CPyProtect_LitBytesBlob`) instead of a plain C
array of string literals. A static decoder runs once at module init,
*before* `CPyStatics_Initialize` reads the tables, and un-obfuscates them in
place.

`strings(1)` no longer recovers source strings from `.rodata`. Python-visible
names still appear — they have to, they are part of the language.

### `control_flow` (strong)

One registered pass, `cfg_indirection`:

* every CFG edge is routed through a forwarding basic block (`a → t → b`
  instead of `a → b`), and
* non-entry blocks are permuted (the entry block must stay first — it is
  label 0 of the emitted function).

Only terminator targets and block layout change. Reference counts, error
values, traceback entries, `Branch.traceback_entry`/`rare`/`negated` and
`error_handler` links are untouched, so the emitted code is semantically
identical. Verified with `mypycxazr.analysis.ircheck` after the pass and with the
edge-by-edge assertions in `tests/protection/test_controlflow.py`.

Placement matters: the pass runs in `compile_scc_to_ir` **after**
uninitialised-variable analysis, exception handling, reference-count
insertion, spilling, lowering and the optimisations — so it can only move
blocks and rewrite terminators, never invalidate an earlier analysis.

### `integrity` (maximum)

Detects post-link modification of the extension module. Detection only — it
does not prevent tampering, and an attacker who can rewrite the binary can
also rewrite this check. See [`security-model.md`](security-model.md) for the
full threat model and the honest limits.

Mechanism:

1. codegen emits a fixed 16-byte block: 8-byte magic + 8-byte zero digest;
2. after linking, the digest is stamped into the slot
   (FNV-1a-64 over the file with the slot treated as zero);
3. at import, `CPyProtect_VerifyIntegrity` re-reads the module file and
   compares; a mismatch raises `RuntimeError` and the import fails.

Stamping runs from a hook on `build_ext.build_extension`, i.e. strictly after
the final link and after any strip, because both change the bytes being
hashed.

---

## Debug builds

```
$ MYPYC_OPT_LEVEL=0 python -m mypycxazr --protect=strong x.py
error: MyPyC-Protect: refusing to protect a debug build (opt level 0) ...
```

`--protect-strip` alone is still allowed: it only removes development
metadata, which is meaningful for any build.

---

## See also

* [`architecture.md`](architecture.md) — where each feature plugs into the
  compiler pipeline.
* [`security-model.md`](security-model.md) — what this does and does not
  defend against.
* [`benchmarks.md`](benchmarks.md) — how the numbers are measured and what
  they mean.
