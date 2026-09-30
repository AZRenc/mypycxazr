# MyPyC-Protect — Architecture

This document describes the **actual** compilation pipeline of the mypyc
codebase that MyPyC-Protect is built on (baseline: mypy/mypyc v1.18.2), and
marks the exact points where the optional *Protection* pipeline hooks in.

Nothing in here is aspirational: every file/function named below exists in this
source tree and was inspected before this document was written.

---

## 1. Top-level pipeline

```
Python source (foo.py)
   │
   ▼
mypy front end                    mypy/main.py, mypy/build.py
   │  parse → semantic analysis → type checking → typed AST (mypy.nodes)
   │  options come from mypy.process_options() (mypy/main.py)
   ▼
BuildResult { graph, types, trees }
   │
   ▼
mypyc front end                   mypyc/codegen/emitmodule.py:parse_and_typecheck
   │  adds mypyc plugins (MypycPlugin) and per-module "mypyc" flags
   ▼
IR construction                   mypyc/irbuild/main.py:build_ir
   │  typed AST  →  mypyc.ir (BasicBlock / Op / Value)
   │  produces ModuleIRs {module: ModuleIR(classes, functions, imports, ...)}
   ▼
IR transform pipeline             mypyc/codegen/emitmodule.py:compile_scc_to_ir
   │  per-function, in a fixed order (see §3)
   ▼
C generation                      mypyc/codegen/emitmodule.py:compile_ir_to_c
   │                            → generate_c_for_modules()
   │  emits __native.c / __native.h / __native_internal.h  (one set per group)
   ▼
C compile                         mypyc/build.py:mypycify
   │  cflags assembled in mypycify(); setuptools/distutils builds Extension
   ▼
Link                              setuptools build_ext
   │  produces .so (ELF shared object) on Linux
   ▼
Importable Python extension module
```

Entry points:

| Purpose | Function | File |
|---|---|---|
| Public build API | `mypycify(...)` | `mypyc/build.py:479` |
| Drive C generation | `mypyc_build(...)` | `mypyc/build.py:407` |
| Type check + IR + C | `compile_modules_to_c(...)` | `mypyc/codegen/emitmodule.py:422` |
| CLI (prototype/testing) | `main()` | `mypyc/__main__.py` |
| Options object | `CompilerOptions` | `mypyc/options.py` |

---

## 2. The IR

* `mypyc/ir/ops.py` — `Value` subclasses and `Op` subclasses (the instruction set).
* `mypyc/ir/func_ir.py` — `FuncIR` / `FuncDecl` / `BasicBlock` / `FuncSignature`.
  `FuncIR.cname()` (line 312) is **the** place where a function's C symbol name
  is computed from `NameGenerator`.
* `mypyc/ir/class_ir.py` — `ClassIR`, vtables, attribute layouts.
* `mypyc/ir/module_ir.py` — `ModuleIR`, `ModuleIRs`.
* `mypyc/irbuild/*` — AST → IR (`visitor.py` dispatch, `builder.py` state,
  `ll_builder.py` low-level builder).
* `mypyc/lower/*` — lowering of high-level ops to primitive ops.
* `mypyc/primitives/*` — mapping of Python/C-API operations to C calls.
* `mypyc/analysis/*` — dataflow (`dataflow.py`), definedness (`attrdefined.py`),
  `ircheck.py` (IR verifier), `selfleaks.py`, `blockfreq.py`.

Pretty printer used by tests: `mypyc/ir/pprint.py` (`format_modules`).

---

## 3. Transform pipeline (the natural home for Protection passes)

All IR transforms run per-function inside
`mypyc/codegen/emitmodule.py:compile_scc_to_ir`, lines 245–265:

```python
for module in modules.values():
    for fn in module.functions:
        insert_uninit_checks(fn)          # mypyc/transform/uninit.py
        insert_exception_handling(fn)     # mypyc/transform/exceptions.py
        insert_ref_count_opcodes(fn)      # mypyc/transform/refcount.py
        if fn in env_user_functions:
            insert_spills(fn, ...)        # mypyc/transform/spill.py
        if compiler_options.log_trace:
            insert_event_trace_logging(fn, compiler_options)
        lower_ir(fn, compiler_options)    # mypyc/transform/lower.py
        do_copy_propagation(fn, ...)      # mypyc/transform/copy_propagation.py
        do_flag_elimination(fn, ...)      # mypyc/transform/flag_elimination.py
```

Ordering constraint that matters for us:

* Everything **after** `insert_ref_count_opcodes` deals with *low-level* IR and
  already-inserted refcount ops. A pass placed there must not resurrect
  high-level ops.
* Everything **before** `lower_ir` still operates on high-level IR, which is
  where source-level structure (class names, method names, literal strings,
  branch shapes) is still directly visible.

**Insertion point chosen for Protection IR passes:**
after `do_flag_elimination` (i.e. last in the list above), so that

1. correctness-critical transforms (refcounts, exceptions, uninit) always run
   on *unmodified* IR first — protection can never break reference counting or
   exception semantics;
2. optimization has already simplified the graph, so hardening acts on the
   final shape of the code.

A second, *optional* hook exists earlier (after `insert_ref_count_opcodes`) for
passes that must see high-level IR — it is disabled by default.

The pipeline is registered in `mypyc/protect/pipeline.py` and executed from
`compile_scc_to_ir` only when `compiler_options.protect != "off"`.

---

## 4. C code generation

`mypyc/codegen/emitmodule.py:generate_c_for_modules` (line 540) produces per
compilation *group*:

| File | Content |
|---|---|
| `__native.c` | literals, globals init, all native function bodies, wrappers, module defs |
| `__native.h` | **external** header: type declarations, export table struct |
| `__native_internal.h` | `extern` declarations of every function/global in the group |

Supporting emitters:

* `mypyc/codegen/emit.py` — `Emitter`, `static_name()` (line 288), declaration
  registry (`HeaderDeclaration`, `needs_export`).
* `mypyc/codegen/emitfunc.py` — `native_function_header()` (line 108),
  `generate_native_function()`, wrapper generation.
* `mypyc/codegen/emitclass.py` — type objects, method tables, vtables.
* `mypyc/codegen/emitwrapper.py` — `CPyPy_*` C-API wrappers.
* `mypyc/codegen/literals.py`, `cstring.py` — literal tables and C strings.

### 4.1 Where symbols come from

Prefixes are defined in `mypyc/common.py`:

```
CPyPy_      Python-callable wrapper
CPyDef_     native function
CPyDunder_  dunder wrapper
CPyType_    type object struct
CPyStatic_  static variable (literals, globals)
CPyModule_  cached module
cpy_r_      register (function-local, never exported)
_           attribute name
```

Names are produced by `mypyc/namegen.py`:

* `NameGenerator.private_name(module, partial_name)` — build-local names.
* `exported_name(fullname)` — deterministic across builds (`.` → `___`).

### 4.2 Why symbols are currently visible

* `generate_function_declaration()` (`emitmodule.py:462`) registers every
  `FuncIR` with `needs_export=True`.
* `native_function_header()` emits `TYPE CPyDef_name(args)` — **no `static`**
  keyword, and no visibility attribute.
* The declaration is repeated as `extern ...` in `__native_internal.h`.
* `mypycify()` never passes `-fvisibility=hidden`.

Consequence: every `CPyDef_*`, `CPyPy_*`, `CPyType_*`, `CPyStatic_*` becomes a
global ELF symbol in the resulting `.so`. This is the single largest source of
static-analysis exposure and is addressed by **Symbol Reduction** (Phase 3).

Cross-group access does **not** need those symbols: when `separate=True`,
groups talk through the *export table* (`generate_export_table()`,
`emitmodule.py:745`), a `struct` of function pointers named
`exports_<group>`. That struct (and the group's `PyInit_`/`CPyInit_`) **must**
stay externally visible; everything else can be hidden.

---

## 5. Build / link configuration

`mypyc/build.py:mypycify()` (line 479):

* assembles `cflags` at lines 588–633 (`-O3 -g1 -Werror ...`);
* `build_using_shared_lib()` (line 269) — one real shared library
  `<group>__mypyc` plus one tiny shim `.so` per module (shim generated from
  `mypyc/lib-rt/module_shim.tmpl`);
* `build_single_module()` (line 317) — one `.so` per group;
* `include_dir()` → `mypyc/lib-rt/` (runtime C sources `RUNTIME_C_FILES` in
  `mypyc/common.py`).

There is currently **no** `extra_link_args` plumbing anywhere in the tree —
ELF hardening flags (Phase 9) therefore have to be added to `mypycify()` and
threaded into both `Extension(...)` construction sites.

Environment capability discovery lives in
`mypyc/protect/elfdetect.py` (feature-probes the compiler/linker rather than
assuming GNU ld is present).

---

## 6. Debug information and metadata

* Debug level defaults to `debug_level="1"` → `-g1`.
* Generated C contains `#line` directives pointing back at the Python source
  (see `mypyc/codegen/emitfunc.py` / `emit.py` line-number emission) — this is
  a direct source-structure leak.
* `.c`/`.h` files are written to `target_dir` (`build/`) and left behind after
  the build; `ops.txt` (pretty-printed IR) is written unconditionally by
  `mypyc_build()`.

Phase 4 (`--protect-strip`) covers: `-g0`, suppression of `#line`, and cleanup
of development-only artifacts — while explicitly **not** treating `strip(1)` as
a protection mechanism by itself.

---

## 7. Tests

| Suite | Runner | Notes |
|---|---|---|
| IR / analysis / emit unit tests | `mypyc/test/*.py` | data-driven, fast |
| Compile-and-run tests | `mypyc/test/test_run.py` | needs a working C toolchain |
| Command line tests | `mypyc/test/test_commandline.py` | slow |
| Data files | `mypyc/test-data/*.test` | |
| **Protection tests (new)** | `tests/protection/` | see §8 |

Baseline at the time of writing (mypy v1.18.2 tree, Python 3.12, aarch64):

```
885 passed in 160.36s     # mypyc/test/ minus the slow run/external/commandline suites
```

Run with:

```bash
PYTHONPATH="$PWD" python -m pytest mypyc/test/ -q \
    --ignore=mypyc/test/test_run.py \
    --ignore=mypyc/test/test_external.py \
    --ignore=mypyc/test/test_commandline.py
```

---

## 8. Protection pipeline — insertion points

```
                    ┌──────────────────────────────┐
 Normal build       │  compile_scc_to_ir           │   Protected build
 Python ──mypy──▶   │  uninit → exc → refcount     │
                    │  → spills → lower            │
                    │  → copy-prop → flag-elim     │
                    └──────────────┬───────────────┘
                                   │  NEW (only if protect != off)
                                   ▼
                          mypyc/protect/pipeline.py
                          ┌─────────────────────────────┐
                          │ IR passes                   │  §5, §6, §7 of spec
                          │  - name/metadata reduction  │
                          │  - control-flow hardening   │
                          │  - constant mangling        │
                          └──────────────┬──────────────┘
                                         ▼
                          codegen (emitmodule / emitfunc / namegen)
                          ┌─────────────────────────────┐
                          │ symbol reduction +          │  §3 of spec
                          │ visibility control          │
                          │ #line / debug reduction     │  §4 of spec
                          └──────────────┬──────────────┘
                                         ▼
                          build.py cflags / linker flags  §9 of spec
                                         ▼
                                             ELF
```

Concretely, the files that get new responsibilities:

| File | Change |
|---|---|
| `mypyc/options.py` | `protect`, `protect_strip` fields on `CompilerOptions` |
| `mypyc/build.py` | `protect=`/`protect_strip=` kwargs on `mypycify()`, config-file loading, cflags/link args |
| `mypyc/__main__.py` | `--protect=...`, `--protect-strip` CLI |
| `mypyc/codegen/emitmodule.py` | call `mypyc.protect.pipeline.run_protect_pipeline()`; visibility/`#line` control |
| `mypyc/codegen/emitfunc.py` | `#line` emission suppression |
| `mypyc/namegen.py` | deterministic obfuscated names when enabled |
| `mypyc/protect/**` | new package (Phase 2) |

Everything else in `mypyc/` stays untouched, which is what keeps the fork
reviewable and keeps upstream mypyc semantics intact.

---

## 9. Invariants we must not break

Verified against the current code, these are hard constraints for any
protection pass:

1. **Reference counting** — `insert_ref_count_opcodes` must run on IR whose
   ownership semantics are unchanged; no pass may add/remove `IncRef`/`DecRef`
   targets without also fixing them.
2. **Exception handling** — `insert_exception_handling` assigns error values
   and cleanup blocks; new basic blocks must be added *after* it (or must
   preserve its invariants) and must be re-checked with `mypyc/analysis/ircheck.py`.
3. **`PyInit_<mod>` / `CPyInit_<mod>`** must remain externally visible and
   un-renamed — the CPython import machinery looks them up by name.
4. **Export table** (`exports_<group>`) must remain visible when
   `separate=True` groups live in different `.so` files.
5. **Shims** (`mypyc/lib-rt/module_shim.tmpl`) resolve
   `CPyInit_<full_module_name>` by name through capsules — module init names
   are part of the ABI surface.
6. **Determinism** — protection must produce byte-identical output for
   identical input (no `hash()` randomization, no time-based seeds).
7. **Debug builds** — `protect` defaults to `off`; `opt_level="0"` builds must
   never silently enable hardening.
