# Benchmarks

Two kinds of number are produced by this project:

1. **`tests/protection/`** — correctness tests. They must all pass; they are
   not benchmarks and have no thresholds.
2. **`tests/protection/measure_elf.py`** — a *measurement harness* that
   compares compiled modules. These are benchmarks: descriptive, rough, and
   explicitly not security metrics.

```bash
# measure one or more modules
python tests/protection/measure_elf.py build/*.so

# before/after comparison as a markdown report
python tests/protection/measure_elf.py \
    normal.so protected_basic.so protected_strong.so protected_maximum.so \
    --label normal --label basic --label strong --label maximum \
    --source samplemod.py \
    --report report.md --json report.json
```

The harness shells out to GNU binutils (`readelf`, `nm`, `objdump`, `strings`).
If a tool is missing the corresponding metrics are reported as `None` rather
than guessed.

---

## The metrics

| metric | source | what it means |
|---|---|---|
| file size | `stat` | total bytes on disk |
| `.text` / `.rodata` size | `readelf -S` | code and read-only data |
| exported dynamic symbols | `readelf --dyn-syms` | what `dlsym` can see from outside |
| all symbols | `nm` | `.symtab` + `.dynsym` |
| function symbols | `nm` filtered to functions | how many callable symbols exist |
| readable strings | `strings -a -n 6` | human-readable byte sequences |
| long strings | `strings -a -n 16` | the same, minus short tokens |
| identifier-like strings | regex `[A-Za-z_][A-Za-z0-9_]{2,}` over `strings` | tokens that look like names |
| source identifiers still recoverable | intersection with identifiers in the `.py` source | **how much of your source vocabulary survives** |
| debug sections | `readelf -S` `.debug_*` | presence of DWARF |
| Python source paths | `strings` matched against `*.py` | file names embedded in the binary |
| link hardening | `readelf -d` / `-l` | `BIND_NOW`, `GNU_RELRO`, `GNU_STACK`, `TEXTREL` |

### `source identifiers still recoverable`

This is the metric that actually measures `symbol_names`, because a raw count
of identifier-like strings **cannot**: an obfuscated name is still an
identifier, so the count barely moves while the content changes completely.

The harness takes the set of identifier-like tokens in the Python source, and
counts how many of them still appear as strings in the ELF:

```
normal  47/61      every source name is in the binary
basic   47/61      no name obfuscation at this level -> unchanged
strong  36/61      the rest were obfuscated away
```

The floor is not zero and will never be: the remaining names are the
Python-visible ones that must not change (`process_items`, `tp_name`,
`__mypyc_attrs__`, …). See [`security-model.md`](security-model.md#symbol_names).

---

## `static_analysis_exposure`

A single weighted score in `[0, 1]` summarising how readable a static analyst
finds the module.

| component | weight | raw definition |
|---|---:|---|
| `debug_info` | 0.15 | DWARF present? |
| `exported_symbols` | 0.25 | leaked non-ABI exported names / 200 |
| `name_leakage` | 0.25 | source identifiers recoverable (or, without `--source`, identifier-like strings / 400) |
| `readable_strings` | 0.20 | readable strings / 1200 |
| `source_paths` | 0.15 | `*.py` paths embedded? |

**Normalization.** The raw denominators are guesses about a "typical" module
and saturate on large inputs — every component reads `1.0` and the score
stops telling you anything. So for a before/after comparison every component
is *re-expressed against the first (unprotected) build of the same module*:

```
component(protected) = min(1.0, raw(protected) / raw(normal))
score(protected)     = Σ component × weight
```

The unprotected build is therefore `1.0` **by construction**, and everything
else reads as "this much less readable than the same module built normally".
`normalize_exposure()` in `measure_elf.py` does this; it is applied
automatically when two or more files are measured.

> **This is a benchmark, not a security metric.** It has no relationship to
> the probability of an attack succeeding, and a low score does not mean the
> module is safe. It exists to let you compare two builds of the *same*
> module and to catch regressions in the protection layer.

---

## Reference results

Reference module: `samplemod` (2 classes, 1 method each, 4 module-level
functions, several string/bytes/int literals), built with mypy 1.18.2 on
Linux/aarch64, GCC, CPython 3.12.

| metric | normal | basic | strong | maximum |
|---|---:|---:|---:|---:|
| file size | 246360 B | 158320 B | 158808 B | 159240 B |
| `.text` size | 60008 B | 61624 B | 62420 B | 63220 B |
| exported dynamic symbols | 231 | 1 | 1 | 1 |
| debug sections | 7 | 0 | 0 | 0 |
| readable strings (≥6) | 1730 | 899 | 894 | 916 |
| source identifiers recoverable | 47/61 | 47/61 | 36/61 | 37/61 |
| `BIND_NOW` | no | yes | yes | yes |
| **`static_analysis_exposure`** | **1.0000** | **0.5039** | **0.4449** | **0.4527** |

The full four-way report is checked in as
[`elf-comparison.md`](elf-comparison.md).

Note that `maximum` scores *slightly worse* than `strong` (0.4527 vs 0.4449).
That is not a mistake: the integrity verifier contributes a handful of new
identifiers and three `MyPyC-Protect: ...` error strings, and `name_leakage`
rises from 0.766 to 0.787. Detection is bought with a small amount of
readability, and this table is where you see the price.

Reading the table:

* **basic** buys almost everything for almost nothing: it deletes the DWARF
  sections and collapses the exported symbol table from 231 to 1, and the file
  gets *35% smaller* because debug info is the bulk of a mypyc `.so`.
* **strong** buys the name-level protections: the source-vocabulary ratio
  drops by ~23% and the literal tables stop being readable.
* **maximum** adds detection, which no static metric measures — it is
  verified behaviourally, not by inspection. It also costs a little
  readability, see the note below the table.

`.text` grows ~4% across the levels: the control-flow trampolines plus the
integrity verifier. Trampolines are placed so the forwarding edge compiles to
a fall-through, so this is code size, not extra jumps at runtime.

---

## Reproducing

```bash
# 1. build the four variants
python -m mypycxazr samplemod.py                       # normal
python -m mypycxazr --protect=basic   samplemod.py
python -m mypycxazr --protect=strong  samplemod.py
python -m mypycxazr --protect=maximum samplemod.py

# 2. measure
python tests/protection/measure_elf.py \
    *.so --source samplemod.py \
    --label normal --label basic --label strong --label maximum \
    --report report.md --json report.json
```

Each measurement is a snapshot of one file; re-running on the same file
always gives the same numbers.

---

## Limitations of these benchmarks

* **Same module only.** Cross-module comparisons are meaningless: the
  denominators are absolute constants calibrated on one sample.
* **`strings(1)` is a blunt instrument.** It reports byte sequences, not
  semantics; a short or unusual name may be missed.
* **No dynamic measurement.** Nothing here says anything about performance,
  memory, or runtime behaviour. For that, run mypyc's own benchmark suite
  (`mypycxazr/test-data/run-bench.test`) with and without protection.
* **The score is not transitive.** `0.44` is not "56% safe".
