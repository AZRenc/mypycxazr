"""ELF exposure measurement harness for MyPyC-Protect.

Measures the properties of a compiled extension module that matter for
static analysis, and can compare two measurements ("normal" vs "protected").

This is a *benchmark*, not a security proof.  See docs/security-model.md.

Usage:
    python tests/protection/measure_elf.py path/to/mod.so [--json out.json]
    python tests/protection/measure_elf.py normal.so protected.so [--report out.md]

Requires GNU binutils (readelf/nm/objdump/strings).  When a tool is missing
the corresponding metrics are reported as ``None`` rather than guessed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

# Prefixes mypyc uses for generated C identifiers (mypycxazr/common.py).
MYPYC_PREFIXES = (
    "CPyDef_",
    "CPyPy_",
    "CPyDunder_",
    "CPyType_",
    "CPyStatic_",
    "CPyModule_",
    "CPyTypeVar_",
    "CPyExec_",
    "CPyInit_",
    "PyInit_",
    "exports_",
    "cpy_r_",
)

#: Sections that only exist to help a debugger/decompiler.
DEBUG_SECTIONS = re.compile(r"^\.(debug|gnu\.debuglto_|stab)")


def _run(cmd: list[str]) -> str | None:
    if shutil.which(cmd[0]) is None:
        return None
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace")


@dataclass
class ElfMetrics:
    path: str
    file_size: int = 0

    # symbols
    exported_symbols: int = 0
    exported_by_prefix: dict[str, int] = field(default_factory=dict)
    total_symbols: int = 0
    local_symbols: int = 0
    undefined_symbols: int = 0
    exported_name_samples: list[str] = field(default_factory=list)
    function_symbols: int = 0

    # sections / debug
    sections: list[str] = field(default_factory=list)
    debug_sections: list[str] = field(default_factory=list)
    has_debug_info: bool = False
    has_gnu_debuglink: bool = False

    # strings
    readable_strings: int = 0
    long_readable_strings: int = 0
    strings_total_bytes: int = 0
    python_source_paths: list[str] = field(default_factory=list)
    identifier_like_strings: int = 0
    #: number of identifiers that occur in the Python source file (only
    #: populated when ``--source`` is given)
    source_name_matches: int = 0
    #: number of distinct identifiers in the Python source file
    source_name_total: int = 0
    sample_strings: list[str] = field(default_factory=list)

    # linkage / hardening
    bind_now: bool | None = None
    relro: bool | None = None
    pie: bool | None = None
    stack_executable: bool | None = None
    textrel: bool | None = None
    gnu_stack_flags: str | None = None
    build_id: str | None = None
    dynamic_section: list[str] = field(default_factory=list)

    # code shape
    text_size: int | None = None
    rodata_size: int | None = None

    # derived benchmark
    static_analysis_exposure: float | None = None
    exposure_breakdown: dict[str, float] = field(default_factory=dict)
    #: unclamped component values, kept so that normalization is not
    #: performed against already-saturated scores
    exposure_raw: dict[str, float] = field(default_factory=dict)

    tools_missing: list[str] = field(default_factory=list)


def _symbol_prefix(name: str) -> str | None:
    for p in MYPYC_PREFIXES:
        if name.startswith(p):
            return p
    return None


def source_identifiers(path: str) -> set[str]:
    """Distinct identifier-like tokens in a Python source file.

    Used to measure how much of the *source* vocabulary survives into the
    binary.  Deliberately crude (a regex over the file): it only needs to be
    the same set on both sides of a before/after comparison.
    """
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return set()
    return {t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text)}


def measure(path: str, source: str | None = None) -> ElfMetrics:
    m = ElfMetrics(path=path, file_size=os.path.getsize(path))

    if shutil.which("readelf") is None:
        m.tools_missing.append("readelf")
    if shutil.which("nm") is None:
        m.tools_missing.append("nm")
    if shutil.which("strings") is None:
        m.tools_missing.append("strings")
    if shutil.which("objdump") is None:
        m.tools_missing.append("objdump")

    _measure_symbols(path, m)
    _measure_sections(path, m)
    _measure_strings(path, m)
    _measure_dynamic(path, m)
    _measure_layout(path, m)
    if source:
        names = source_identifiers(source)
        m.source_name_total = len(names)
        m.source_name_matches = _count_source_matches(path, names)
    _compute_exposure(m)
    return m


def _measure_symbols(path: str, m: ElfMetrics) -> None:
    out = _run(["nm", "-D", "--defined-only", path])
    if out is None:
        return
    names: list[str] = []
    prefixes: Counter[str] = Counter()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[2]
        names.append(name)
        p = _symbol_prefix(name)
        if p:
            prefixes[p] += 1
    m.exported_symbols = len(names)
    m.exported_by_prefix = dict(sorted(prefixes.items()))
    m.exported_name_samples = sorted(names)[:40]

    out2 = _run(["nm", path])
    if out2:
        total = 0
        local = 0
        undef = 0
        func = 0
        for line in out2.splitlines():
            parts = line.split()
            if len(parts) == 1 and parts[0].startswith("U"):
                undef += 1
                continue
            if len(parts) < 3:
                continue
            total += 1
            kind = parts[1] if len(parts) == 3 else parts[0]
            if kind[0].islower():
                local += 1
            if kind in ("T", "t", "W", "w"):
                func += 1
        m.total_symbols = total
        m.local_symbols = local
        m.undefined_symbols = undef
        m.function_symbols = func


def _measure_sections(path: str, m: ElfMetrics) -> None:
    out = _run(["readelf", "-S", "-W", path])
    if out is None:
        return
    sections = []
    for line in out.splitlines():
        mm = re.match(r"\s*\[\s*\d+\]\s+(\S+)", line)
        if mm:
            sections.append(mm.group(1))
    m.sections = sections
    m.debug_sections = [s for s in sections if DEBUG_SECTIONS.match(s)]
    m.has_debug_info = bool(m.debug_sections)


def _measure_strings(path: str, m: ElfMetrics) -> None:
    out = _run(["strings", "-a", "-n", "6", path])
    if out is None:
        return
    lines = [ln for ln in out.splitlines() if ln.strip()]
    m.readable_strings = len(lines)
    m.long_readable_strings = sum(1 for ln in lines if len(ln) >= 16)
    m.strings_total_bytes = sum(len(ln) for ln in lines)

    idents = set()
    for ln in lines:
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", ln):
            idents.add(tok)
    m.identifier_like_strings = len(idents)

    src = [ln for ln in lines if ln.endswith(".py") or os.sep + "src" + os.sep in ln]
    m.python_source_paths = sorted(set(src))[:40]

    # Prefer strings that look source-derived for the sample.
    interesting = [
        ln
        for ln in lines
        if re.search(r"(sample|greet|process_items|checksum|Greeter|welcome)", ln, re.I)
    ]
    m.sample_strings = sorted(set(interesting))[:40]


def _measure_dynamic(path: str, m: ElfMetrics) -> None:
    out = _run(["readelf", "-d", "-W", path])
    if out is None:
        return
    dynamic = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("0x") or line.startswith("Dynamic section"):
            dynamic.append(line)
    m.dynamic_section = dynamic
    text = "\n".join(dynamic)
    m.bind_now = "BIND_NOW" in text
    m.textrel = "TEXTREL" in text

    segs = _run(["readelf", "-l", "-W", path])
    if segs:
        m.relro = "GNU_RELRO" in segs
        m.pie = "Type: DYN" in segs or "Type: EXEC" not in segs
        gm = re.search(r"GNU_STACK\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+([RWE]*)", segs)
        if gm:
            m.gnu_stack_flags = gm.group(1) or "(none)"
            m.stack_executable = "E" in gm.group(1)
    notes = _run(["readelf", "-n", path])
    if notes:
        bm = re.search(r"Build ID:\s*([0-9a-f]+)", notes)
        if bm:
            m.build_id = bm.group(1)
        m.has_gnu_debuglink = "gnu.debuglink" in notes or ".gnu_debuglink" in notes


def _count_source_matches(path: str, names: set[str]) -> int:
    """How many source identifiers still appear as strings in the binary."""
    out = _run(["strings", "-a", "-n", "4", path])
    if out is None:
        return 0

    found = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", out))
    return len(found & names)


def _measure_layout(path: str, m: ElfMetrics) -> None:
    out = _run(["readelf", "-S", "-W", path])
    if out is None:
        return
    for line in out.splitlines():
        # e.g. "  [14] .text   PROGBITS  0000000000001000 001000 00abcd 00  AX  0   0 16"
        mm = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s",
            line,
        )
        if not mm:
            continue
        name, size = mm.group(1), int(mm.group(2), 16)
        if name == ".text":
            m.text_size = size
        elif name == ".rodata":
            m.rodata_size = size


# --------------------------------------------------------------------------
# static_analysis_exposure
# --------------------------------------------------------------------------

#: Weights of the exposure components.  Declared here so that reporting can
#: recombine normalized components with exactly the weights used to build the
#: raw score.
EXPOSURE_WEIGHTS: dict[str, float] = {
    "exported_symbols": 0.25,
    "name_leakage": 0.25,
    "readable_strings": 0.20,
    "source_paths": 0.15,
    "debug_info": 0.15,
}


def _compute_exposure(m: ElfMetrics) -> None:
    """A *rough benchmark* summarizing how much a static analyst can read.

    Not a security metric.  Every component is normalized to [0, 1] where 1
    means "as exposed as a typical unhardened mypyc build of a comparable
    module".  The score is a weighted sum; see docs/benchmarks.md.
    """
    # Values are deliberately left *unclamped* here: clamping at this stage
    # would saturate every component on a large module and hide the
    # difference between builds.  Clamping only applies to the absolute
    # score, which is why normalization (normalize_exposure) works off
    # exposure_raw instead of exposure_breakdown.
    raw: dict[str, float] = {}

    # 1. exported symbol surface (weighted by how leaky the names are)
    if m.exported_symbols:
        leaky = sum(v for k, v in m.exported_by_prefix.items() if k != "PyInit_")
        raw["exported_symbols"] = leaky / 200.0
    else:
        raw["exported_symbols"] = 0.0

    # 2. names that mirror source identifiers
    if m.source_name_total:
        # fraction of the source vocabulary still recoverable from the binary
        raw["name_leakage"] = m.source_name_matches / m.source_name_total
    else:
        raw["name_leakage"] = m.identifier_like_strings / 400.0

    # 3. readable strings
    raw["readable_strings"] = m.readable_strings / 1200.0

    # 4. explicit python source paths
    raw["source_paths"] = 1.0 if m.python_source_paths else 0.0

    # 5. debug info
    raw["debug_info"] = 1.0 if m.has_debug_info else 0.0

    m.exposure_raw = raw
    score = sum(min(1.0, raw[k]) * EXPOSURE_WEIGHTS[k] for k in EXPOSURE_WEIGHTS)
    m.static_analysis_exposure = round(score, 4)
    m.exposure_breakdown = {k: round(min(1.0, raw[k]), 4) for k in sorted(raw)}


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def compare(a: ElfMetrics, b: ElfMetrics) -> dict[str, Any]:
    """Return a detailed difference report between two measurements."""

    def delta(key: str) -> Any:
        va, vb = getattr(a, key), getattr(b, key)
        if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
            pct = None
            if va:
                pct = round((vb - va) / va * 100.0, 2)
            return {"normal": va, "protected": vb, "delta": vb - va, "pct": pct}
        return {"normal": va, "protected": vb}

    return {
        "file": {"normal": a.path, "protected": b.path},
        "size": delta("file_size"),
        "text_size": delta("text_size"),
        "rodata_size": delta("rodata_size"),
        "exported_symbols": delta("exported_symbols"),
        "total_symbols": delta("total_symbols"),
        "function_symbols": delta("function_symbols"),
        "readable_strings": delta("readable_strings"),
        "long_readable_strings": delta("long_readable_strings"),
        "identifier_like_strings": delta("identifier_like_strings"),
        "python_source_paths": {
            "normal": a.python_source_paths,
            "protected": b.python_source_paths,
        },
        "debug_sections": {"normal": a.debug_sections, "protected": b.debug_sections},
        "debug_info": {"normal": a.has_debug_info, "protected": b.has_debug_info},
        "linkage": {
            "normal": {
                "bind_now": a.bind_now,
                "relro": a.relro,
                "stack": a.gnu_stack_flags,
                "textrel": a.textrel,
            },
            "protected": {
                "bind_now": b.bind_now,
                "relro": b.relro,
                "stack": b.gnu_stack_flags,
                "textrel": b.textrel,
            },
        },
        "static_analysis_exposure": delta("static_analysis_exposure"),
        "exposure_breakdown": {
            "normal": a.exposure_breakdown,
            "protected": b.exposure_breakdown,
        },
        "exported_by_prefix": {
            "normal": a.exported_by_prefix,
            "protected": b.exported_by_prefix,
        },
    }


def _fmt(v: Any) -> str:
    if v is None:
        return "n/a"
    return str(v)


def render_markdown(a: ElfMetrics, b: ElfMetrics) -> str:
    c = compare(a, b)

    def row(label: str, key: str, unit: str = "") -> str:
        d = c[key]
        if not isinstance(d.get("delta"), (int, float)):
            return f"| {label} | {_fmt(d['normal'])} | {_fmt(d['protected'])} | - |"
        pct = d.get("pct")
        pct_s = f"{pct:+.2f}%" if pct is not None else "n/a"
        return (
            f"| {label} | {d['normal']}{unit} | {d['protected']}{unit} "
            f"| {d['delta']:+}{unit} ({pct_s}) |"
        )

    lines = [
        "# ELF comparison: normal mypycxazr vs protected build",
        "",
        f"* normal: `{a.path}`",
        f"* protected: `{b.path}`",
        "",
        "## Summary",
        "",
        "| metric | normal | protected | change |",
        "|---|---:|---:|---:|",
        row("file size", "size", " B"),
        row(".text size", "text_size", " B"),
        row(".rodata size", "rodata_size", " B"),
        row("exported dynamic symbols", "exported_symbols"),
        row("all symbols", "total_symbols"),
        row("function symbols", "function_symbols"),
        row("readable strings (>=6 chars)", "readable_strings"),
        row("long strings (>=16 chars)", "long_readable_strings"),
        row("distinct identifier-like strings", "identifier_like_strings"),
        row("static_analysis_exposure", "static_analysis_exposure"),
        "",
        "## Exported symbols by mypycxazr prefix",
        "",
        "| prefix | normal | protected |",
        "|---|---:|---:|",
    ]
    prefixes = sorted(
        set(a.exported_by_prefix) | set(b.exported_by_prefix)
    )
    for p in prefixes:
        lines.append(
            f"| `{p}` | {a.exported_by_prefix.get(p, 0)} "
            f"| {b.exported_by_prefix.get(p, 0)} |"
        )

    lines += [
        "",
        "## Debug / metadata",
        "",
        f"* normal debug sections: {', '.join(a.debug_sections) or 'none'}",
        f"* protected debug sections: {', '.join(b.debug_sections) or 'none'}",
        "",
        "## Python source paths embedded",
        "",
        f"* normal: {', '.join(a.python_source_paths) or 'none'}",
        f"* protected: {', '.join(b.python_source_paths) or 'none'}",
        "",
        "## Linkage hardening",
        "",
        "| flag | normal | protected |",
        "|---|---|---|",
        f"| BIND_NOW | {_fmt(c['linkage']['normal']['bind_now'])} "
        f"| {_fmt(c['linkage']['protected']['bind_now'])} |",
        f"| GNU_RELRO | {_fmt(c['linkage']['normal']['relro'])} "
        f"| {_fmt(c['linkage']['protected']['relro'])} |",
        f"| GNU_STACK flags | {_fmt(c['linkage']['normal']['stack'])} "
        f"| {_fmt(c['linkage']['protected']['stack'])} |",
        f"| TEXTREL | {_fmt(c['linkage']['normal']['textrel'])} "
        f"| {_fmt(c['linkage']['protected']['textrel'])} |",
        "",
        "## static_analysis_exposure breakdown",
        "",
        "Benchmark only — higher means more readable to a static analyst.",
        "",
        "| component | normal | protected |",
        "|---|---:|---:|",
    ]
    for k in sorted(a.exposure_breakdown):
        lines.append(
            f"| {k} | {a.exposure_breakdown.get(k, 'n/a')} "
            f"| {b.exposure_breakdown.get(k, 'n/a')} |"
        )
    lines.append(
        f"| **total (weighted)** | **{a.static_analysis_exposure}** "
        f"| **{b.static_analysis_exposure}** |"
    )
    lines.append("")
    return "\n".join(lines)


def normalize_exposure(ms: list[ElfMetrics]) -> None:
    """Re-express exposure components relative to ``ms[0]``.

    The absolute constants inside :func:`_compute_exposure` are guesses about
    a "typical" module, so they saturate on large inputs and hide the
    difference between builds.  For a before/after comparison the interesting
    quantity is the ratio against the *same* module compiled without
    protection, so every component is divided by the base value.  The base
    therefore scores 1.0 by construction; anything below it is how much less
    readable the protected build is.
    """
    if len(ms) < 2:
        return
    base = ms[0]
    for m in ms[1:]:
        parts: dict[str, float] = {}
        for k, v in base.exposure_raw.items():
            b = m.exposure_raw.get(k, 0.0)
            parts[k] = round(min(1.0, b / v) if v else (1.0 if b else 0.0), 4)
        m.exposure_breakdown = parts
        m.static_analysis_exposure = round(
            sum(parts[k] * w for k, w in EXPOSURE_WEIGHTS.items()), 4
        )
    base.exposure_breakdown = {k: 1.0 for k in base.exposure_raw}
    base.static_analysis_exposure = 1.0


def _default_label(path: str) -> str:
    stem = os.path.basename(path)
    for suffix in (".so", ".cpython-312-aarch64-linux-gnu"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
    if stem.startswith("protected_"):
        return stem[len("protected_"):]
    return stem


def _pct(base: Any, cur: Any) -> str:
    if isinstance(base, (int, float)) and isinstance(cur, (int, float)) and base:
        pct = (cur - base) / base * 100.0
        return f"{pct:+.2f}%"
    return "n/a"


def render_markdown_many(ms: list[ElfMetrics], labels: list[str]) -> str:
    """Multi-column report: one column per build, plus delta vs the first."""
    assert len(ms) == len(labels) and len(ms) >= 2
    base = ms[0]
    head = "| metric | " + " | ".join(f"{l} (base)" if l == labels[0] else l for l in labels) + " | vs base |"
    sep = "|---" * (len(labels) + 2) + "|"
    # tables that have no trailing "vs base" column
    sep_n = "|---" * (len(labels) + 1) + "|"

    out: list[str] = [
        "# ELF comparison: normal mypycxazr vs protected builds",
        "",
        "Generated by `tests/protection/measure_elf.py`. `vs base` is the",
        "relative change of the *last* column against the first column.",
        "",
        "| build | file |",
        "|---|---|",
    ]
    for lab, m in zip(labels, ms):
        out.append(f"| {lab} | `{os.path.basename(m.path)}` |")
    out += ["", "## Summary", "", head, sep]

    def row(label: str, key: str, fmt: Any = _fmt) -> str:
        vals = [fmt(getattr(m, key)) for m in ms]
        return f"| {label} | " + " | ".join(vals) + f" | {_pct(getattr(base, key), getattr(ms[-1], key))} |"

    out.append(f"| file size | " + " | ".join(f"{m.file_size} B" for m in ms) + f" | {_pct(base.file_size, ms[-1].file_size)} |")
    out.append(f"| .text size | " + " | ".join(f"{m.text_size} B" for m in ms) + f" | {_pct(base.text_size, ms[-1].text_size)} |")
    out.append(f"| .rodata size | " + " | ".join(f"{m.rodata_size} B" for m in ms) + f" | {_pct(base.rodata_size, ms[-1].rodata_size)} |")
    out.append(row("exported dynamic symbols", "exported_symbols"))
    out.append(row("all symbols", "total_symbols"))
    out.append(row("function symbols", "function_symbols"))
    out.append(row("readable strings (>=6 chars)", "readable_strings"))
    out.append(row("long strings (>=16 chars)", "long_readable_strings"))
    out.append(row("distinct identifier-like strings", "identifier_like_strings"))
    if any(m.source_name_total for m in ms):
        out.append(
            "| source identifiers still recoverable | "
            + " | ".join(
                f"{m.source_name_matches}/{m.source_name_total}" if m.source_name_total else "n/a"
                for m in ms
            )
            + " | "
            + (
                f"{(ms[-1].source_name_matches - base.source_name_matches) / base.source_name_matches * 100.0:+.2f}%"
                if base.source_name_matches
                else "n/a"
            )
            + " |"
        )
    out.append(row("static_analysis_exposure", "static_analysis_exposure",
                   lambda v: f"{v:.4f}"))

    prefixes = sorted({p for m in ms for p in m.exported_by_prefix})
    out += ["", "## Exported symbols by mypycxazr prefix", "",
            "| prefix | " + " | ".join(labels) + " |", sep_n]
    for pfx in prefixes:
        out.append(f"| `{pfx}` | " + " | ".join(str(m.exported_by_prefix.get(pfx, 0)) for m in ms) + " |")
    for extra in ("PyInit_",):
        if not any(extra in pfx for pfx in prefixes):
            out.append(f"| `{extra}` | " + " | ".join(str(m.exported_by_prefix.get(extra, 0)) for m in ms) + " |")

    out += ["", "## Debug / metadata", ""]
    for m, lab in zip(ms, labels):
        secs = ", ".join(m.debug_sections) if m.debug_sections else "none"
        out.append(f"* {lab}: {secs}")

    out += ["", "## Python source paths embedded", ""]
    for m, lab in zip(ms, labels):
        out.append(f"* {lab}: {', '.join(m.python_source_paths) or 'none'}")

    out += ["", "## Linkage hardening", "",
            "| flag | " + " | ".join(labels) + " |", sep_n,
            "| BIND_NOW | " + " | ".join(_fmt(m.bind_now) for m in ms) + " |",
            "| GNU_RELRO | " + " | ".join(_fmt(m.relro) for m in ms) + " |",
            "| GNU_STACK flags | " + " | ".join(_fmt(m.gnu_stack_flags) for m in ms) + " |",
            "| TEXTREL | " + " | ".join(_fmt(m.textrel) for m in ms) + " |"]

    out += ["", "## static_analysis_exposure breakdown", "",
            "Benchmark only — higher means more readable to a static analyst.", "",
            "Components are normalized against the first build, so `normal` is 1.0 by construction.", "",
            "| component | " + " | ".join(labels) + " |", sep_n]
    for k in sorted(base.exposure_raw):
        out.append(f"| {k} | " + " | ".join(str(m.exposure_breakdown.get(k, "n/a")) for m in ms) + " |")
    out.append("| **total (weighted)** | " + " | ".join(
        f"**{m.static_analysis_exposure}**" for m in ms) + " |")
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", help=".so file(s) to measure")
    parser.add_argument("--label", action="append", default=[],
                        help="column label for the corresponding file (repeatable)")
    parser.add_argument(
        "--source",
        help="Python source file; enables source-name leakage measurement",
    )
    parser.add_argument("--json", help="write raw metrics as JSON")
    parser.add_argument("--report", help="write a markdown comparison report")
    args = parser.parse_args(argv)

    metrics = [measure(f, source=args.source) for f in args.files]
    normalize_exposure(metrics)
    labels = list(args.label)
    while len(labels) < len(metrics):
        labels.append(_default_label(metrics[len(labels)].path))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([asdict(m) for m in metrics], f, indent=2, sort_keys=True)

    if args.report and len(metrics) >= 2:
        with open(args.report, "w", encoding="utf-8") as f:
            if len(metrics) == 2:
                f.write(render_markdown(metrics[0], metrics[1]))
            else:
                f.write(render_markdown_many(metrics, labels))
        print(f"wrote {args.report}")
    else:
        for m in metrics:
            print(json.dumps(asdict(m), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
