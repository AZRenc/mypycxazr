"""Debug / metadata reduction (spec section 4).

Stripping is **not** treated as a protection mechanism on its own: an analyst
can still recover most of the structure from a stripped binary.  What this
feature does is stop the *build* from adding development-only information in
the first place:

* compile without debug information (``-g0`` instead of mypyc's default
  ``-g1``), which removes ``.debug_info``/``.debug_line``/``.debug_str`` and
  with them the absolute build-host source paths;
* do not record the compiler identification string (``-fno-ident``);
* do not write the pretty-printed IR dump (``build/ops.txt``), which is a
  direct transcription of the source-level structure.

Information that Python itself needs at runtime -- traceback filenames,
line numbers, ``__qualname__``, method names in ``PyModuleDef`` -- is
**never** removed here, because removing it would change observable Python
behaviour.  See docs/security-model.md for the resulting residual exposure.
"""

from __future__ import annotations

from typing import Any

from mypycxazr.protect.options import ProtectOptions

#: Development-only files that mypyc writes next to the build output.
DEV_ARTIFACTS = ("ops.txt",)


def debug_level(prot: ProtectOptions, default: str) -> str:
    """Value for ``-g<n>``: no debug info when debug reduction is on."""
    if prot.enabled and prot.has("debug_reduction"):
        return "0"
    return default


def keep_ops_trace(prot: ProtectOptions) -> bool:
    """Whether mypyc may write ``build/ops.txt`` (the IR dump)."""
    if prot.enabled and prot.has("debug_reduction"):
        return False
    return True


def metadata_cflags(prot: ProtectOptions, compiler: Any | None = None) -> list[str]:
    """Compiler flags that avoid recording development metadata."""
    if not prot.enabled or not prot.has("debug_reduction"):
        return []
    from mypycxazr.protect import toolchain

    tc = toolchain.detect(compiler)
    flags: list[str] = []
    if toolchain.probe_flag(tc.compiler_cmd, "-g0"):
        flags.append("-g0")
    if toolchain.probe_flag(tc.compiler_cmd, "-fno-ident"):
        flags.append("-fno-ident")
    return flags


def describe(prot: ProtectOptions) -> str:
    if not prot.enabled or not prot.has("debug_reduction"):
        return "debug reduction: off (debug info and IR dump kept)"
    return (
        "debug reduction: on (-g0, -fno-ident, no ops.txt); "
        "Python-required names and traceback data are preserved"
    )
