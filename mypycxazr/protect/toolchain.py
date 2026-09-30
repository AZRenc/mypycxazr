"""Toolchain capability discovery for MyPyC-Protect.

The protection pipeline must never assume that a given compiler or linker
flag exists.  Every flag used by a protection feature is probed once against
the *same* compiler that will build the extension, and the result is cached.

Probing happens by invoking the compiler driver in "preprocess only" mode on
an empty translation unit: that exercises the flag driver but does not require
a working assembler/linker, and it is cheap (~ms).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any

_PROBE_CACHE: dict[tuple[str, str], bool] = {}


@dataclass
class ToolchainInfo:
    """What the build toolchain can actually do."""

    compiler_cmd: list[str]
    supports_visibility: bool = False
    supports_wl_flags: bool = False
    #: Linker hardening flags that were accepted, in the order they should be
    #: passed to the linker.  Empty when nothing is supported.
    linker_hardening: list[str] = field(default_factory=list)
    probe_errors: list[str] = field(default_factory=list)


def _compiler_argv(compiler: Any | None) -> list[str]:
    """Extract a usable argv from a distutils compiler object (or None)."""
    if compiler is None:
        cc = os.environ.get("CC")
        if cc:
            return cc.split()
        return ["cc"]
    cmd = getattr(compiler, "compiler_so", None) or getattr(compiler, "compiler", None)
    if isinstance(cmd, str):
        return cmd.split()
    if isinstance(cmd, (list, tuple)) and cmd:
        return [str(x) for x in cmd]
    return ["cc"]


def probe_flag(compiler_argv: list[str], flag: str) -> bool:
    """Return True if ``compiler_argv + [flag]`` accepts an empty source file."""
    key = (repr(compiler_argv), flag)
    if key in _PROBE_CACHE:
        return _PROBE_CACHE[key]

    result = False
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write("int mypyc_protect_probe(void) { return 0; }\n")
            path = f.name
        try:
            argv = list(compiler_argv) + [flag, "-E", "-o", os.devnull, path]
            proc = subprocess.run(
                argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
            )
            result = proc.returncode == 0
        finally:
            os.unlink(path)
    except OSError:
        result = False

    _PROBE_CACHE[key] = result
    return result


def probe_linker_flags(compiler_argv: list[str], flags: list[str]) -> list[str]:
    """Filter ``flags`` down to those the compiler driver accepts.

    ``-Wl,...`` options are validated through the compiler driver, which is
    the only place they can be used from distutils/setuptools anyway.
    """
    return [f for f in flags if probe_flag(compiler_argv, f)]


def detect(compiler: Any | None = None) -> ToolchainInfo:
    """Describe the toolchain.  Results are cached per compiler argv."""
    argv = _compiler_argv(compiler)
    info = ToolchainInfo(compiler_cmd=argv)

    info.supports_visibility = probe_flag(argv, "-fvisibility=hidden")

    # -z now      : immediate symbol binding (full RELRO when combined with relro)
    # -z noexecstack : non-executable stack
    # -z relro    : read-only relocations (usually already on via LDFLAGS)
    # --build-id=none : do not record a build-id (reproducibility / less metadata)
    wanted = [
        "-Wl,-z,relro",
        "-Wl,-z,now",
        "-Wl,-z,noexecstack",
        "-Wl,--build-id=none",
    ]
    info.linker_hardening = probe_linker_flags(argv, wanted)
    info.supports_wl_flags = bool(info.linker_hardening)
    return info


def is_gnu_like(compiler: Any | None = None) -> bool:
    """True for GCC/Clang-style drivers (as opposed to MSVC)."""
    argv = _compiler_argv(compiler)
    return any(a in ("gcc", "clang", "cc", "g++", "clang++") for a in argv) or any(
        a.endswith(("gcc", "clang")) for a in argv
    )
