"""MyPyC-Protect: an optional release-protection layer for mypyc.

The package is split by concern, mirroring the layout described in
docs/architecture.md:

    mypycxazr/protect/
    ├── options.py       levels, feature matrix, pyproject.toml config
    ├── toolchain.py     compiler/linker capability probing
    ├── pipeline/        orchestration + IR pass registry
    ├── symbols/         visibility control and symbol-name obfuscation
    ├── metadata/        debug / metadata reduction
    ├── controlflow/     semantics-preserving control-flow hardening
    ├── constants/       literal and data mangling
    └── integrity/       optional post-build integrity checks

Importing this package is cheap and never touches the file system; the
configuration file is read only when ``mypycxazr.build.mypycify`` resolves
options.
"""

from __future__ import annotations

from mypycxazr.protect.options import (
    FEATURE_DESCRIPTIONS,
    FEATURE_LEVELS,
    PROTECT_LEVELS,
    ProtectError,
    ProtectOptions,
)

__all__ = [
    "FEATURE_DESCRIPTIONS",
    "FEATURE_LEVELS",
    "PROTECT_LEVELS",
    "ProtectError",
    "ProtectOptions",
]
