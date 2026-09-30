"""Orchestration of the MyPyC-Protect pipeline.

Two clearly separated halves:

* **IR half**   -- :func:`run_protect_pipeline`, applied per ``FuncIR`` inside
  ``mypycxazr.codegen.emitmodule.compile_scc_to_ir`` *after* the correctness
  critical transforms (refcounts, exceptions, uninitialized checks) and after
  optimization.  See docs/architecture.md §3.

* **build half** -- :func:`protect_cflags` / :func:`protect_link_args`,
  applied in ``mypycxazr.build.mypycify`` where compiler and linker flags are
  assembled.

Both halves are driven by the same :class:`~mypycxazr.protect.options.ProtectOptions`
so a build can never end up with C flags from one level and IR passes from
another.
"""

from __future__ import annotations

from typing import Any

from mypycxazr.options import CompilerOptions
from mypycxazr.protect import toolchain
from mypycxazr.protect.options import ProtectOptions, load_config
from mypycxazr.protect.pipeline.passes import all_passes, collect_passes  # noqa: F401

__all__ = [
    "ProtectOptions",
    "all_passes",
    "collect_passes",
    "options_from",
    "protect_cflags",
    "protect_link_args",
    "resolve_build_options",
    "resolve_options",
    "run_protect_pipeline",
]


def options_from(compiler_options: CompilerOptions) -> ProtectOptions:
    """Protection options for a build, from ``CompilerOptions`` alone.

    Deliberately free of file-system access: ``mypycxazr.build.mypycify`` is the
    only place that reads ``pyproject.toml`` / the environment, and it stores
    the resolved values into ``CompilerOptions``.  Everything downstream (IR
    passes, codegen) just reads them back, so a build cannot end up with two
    different notions of the active protection level.
    """
    return ProtectOptions(
        level=compiler_options.protect,
        strip=compiler_options.protect_strip,
        extra_features=frozenset(compiler_options.protect_features),
    )


def resolve_build_options(
    protect: str | None = None,
    protect_strip: bool | None = None,
    *,
    use_env: bool = True,
    config_path: str | None = None,
) -> ProtectOptions:
    """Resolve protection options for ``mypycify()``.

    ``protect=None`` / ``protect_strip=None`` mean "not specified by the
    caller", in which case the config file and the environment decide.  An
    explicit value always wins over configuration for the switches it sets.
    """
    explicit: ProtectOptions | None = None
    if protect is not None or protect_strip is not None:
        explicit = ProtectOptions(
            level=protect if protect is not None else "off",
            strip=bool(protect_strip),
        )
    return load_config(explicit, config_path=config_path, use_env=use_env)


# Backwards-compatible name used by the IR half of the pipeline.
resolve_options = options_from


# ---------------------------------------------------------------------------
# Build half
# ---------------------------------------------------------------------------

def protect_cflags(prot: ProtectOptions, compiler: Any | None = None) -> list[str]:
    """Compiler flags contributed by the protection level.

    Returns a (possibly empty) list of flags.  Every flag is capability
    probed; unsupported flags are silently dropped rather than breaking the
    build.
    """
    if not prot.enabled:
        return []

    flags: list[str] = []
    tc = toolchain.detect(compiler)

    # Debug / metadata reduction (-g0, -fno-ident).
    from mypycxazr.protect.metadata import metadata_cflags

    flags.extend(metadata_cflags(prot, compiler))

    if prot.has("symbol_visibility") and tc.supports_visibility:
        flags.append("-fvisibility=hidden")

    # De-duplicate while preserving order.
    seen: set[str] = set()
    return [f for f in flags if not (f in seen or seen.add(f))]


def protect_link_args(prot: ProtectOptions, compiler: Any | None = None) -> list[str]:
    """Linker flags contributed by the protection level."""
    if not prot.enabled or not prot.has("elf_hardening"):
        return []
    tc = toolchain.detect(compiler)
    return list(tc.linker_hardening)


# ---------------------------------------------------------------------------
# IR half
# ---------------------------------------------------------------------------

def run_protect_pipeline(fn: Any, prot: ProtectOptions) -> bool:
    """Run the protection IR passes over ``fn``.

    Returns True if the function was modified.

    The passes are registered in ``mypycxazr.protect.pipeline.passes``; each one
    declares the minimum level at which it runs and the invariants it relies
    on.  Everything here runs *after* refcount/exception/low-level lowering,
    so a pass may only add/rearrange basic blocks and rewrite leaf
    operations -- never change ownership semantics or error-value contracts.
    """
    if not prot.enabled:
        return False

    from mypycxazr.protect.pipeline.passes import collect_passes

    changed = False
    for p in collect_passes(prot):
        if p.run(fn, prot):
            changed = True
    return changed
