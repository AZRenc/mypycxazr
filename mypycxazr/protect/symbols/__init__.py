"""Symbol-level protection: visibility control and name obfuscation.

Two independent features live here:

* ``symbol_visibility``  -- hide everything that is not part of the Python
  extension ABI (``PyInit_*``, ``CPyInit_*``, export tables) behind
  ``-fvisibility=hidden``.  Implemented by :func:`visibility_cflags` and by
  the explicit ``Py_EXPORTED_SYMBOL`` annotations emitted in codegen.

* ``symbol_names``       -- replace C symbol names that were *derived from
  source identifiers* (``CPyDef_greet`` -> ``CPyDef_a91f3c2b07``) with
  deterministic, content-free names.

Name obfuscation never touches:

* ``PyInit_<mod>`` / ``CPyInit_<mod>`` / ``CPyExec_<mod>`` -- looked up by
  name by the CPython import machinery and by the shim modules;
* ``exports_<group>`` -- part of the cross-group ABI;
* any Python-visible name (method names in ``PyModuleDef``, ``__name__``,
  ``__qualname__``, attribute names, traceback names) -- renaming those would
  change Python semantics.

The mapping is derived with SHA-256 from ``(module, partial_name)`` plus a
build seed, so identical inputs produce identical output (reproducible
builds) while the output carries no readable fragment of the input.
"""

from __future__ import annotations

import hashlib
from typing import Any, Final

#: C identifier prefix for obfuscated names.  Deliberately meaningless.
_OBF_PREFIX = "z"

#: Names that must never be obfuscated even though they flow through the
#: same naming helpers.
RESERVED_PREFIXES = ("PyInit_", "CPyInit_", "CPyExec_", "exports_")

#: Suffixes that codegen composes onto an already-processed stem rather than
#: hashing the whole identifier.  ``emitclass`` builds
#: ``type_struct_name(cl) + "_template"`` and ``name_prefix +
#: "_trait_vtable_setup"``, while the IR references the very same C names as
#: whole strings through ``static_name``/``native_function_name``.  Hashing
#: the stem and re-appending the suffix keeps both sides identical; hashing
#: the whole string would split them in two.
COMPOSED_SUFFIXES: Final = ("_trait_vtable_setup", "_template")


def split_composed_suffix(name: str) -> tuple[str, str]:
    """Split ``(stem, suffix)`` for a suffix in :data:`COMPOSED_SUFFIXES`."""
    for suffix in COMPOSED_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)], suffix
    return name, ""


def is_reserved_symbol(name: str) -> bool:
    return any(name.startswith(p) for p in RESERVED_PREFIXES)


class NameObfuscator:
    """Deterministic, collision-free mapping from source-derived keys to C names.

    The same ``(seed, module, partial_name)`` always maps to the same name,
    which keeps builds reproducible.  Collisions are resolved by extending the
    hash stream deterministically in first-seen order.
    """

    def __init__(self, seed: str = "") -> None:
        self.seed = seed
        self._forward: dict[tuple[str, str], str] = {}
        self._reverse: dict[str, tuple[str, str]] = {}
        self._counter = 0

    def name_for(self, module: str, partial_name: str) -> str:
        key = (module, partial_name)
        existing = self._forward.get(key)
        if existing is not None:
            return existing

        stem, suffix = split_composed_suffix(partial_name)
        digest = hashlib.sha256(
            f"{self.seed}\0{module}\0{stem}".encode("utf-8", "surrogateescape")
        )
        attempt = 0
        while True:
            material = (
                digest.digest()
                if attempt == 0
                else hashlib.sha256(digest.digest() + str(attempt).encode()).digest()
            )
            candidate = _OBF_PREFIX + material[:5].hex() + suffix
            # Only cross-key collisions reach here.
            if candidate not in self._reverse:
                self._forward[key] = candidate
                self._reverse[candidate] = key
                self._counter += 1
                return candidate
            attempt += 1

    @property
    def size(self) -> int:
        """Number of names handed out (used by tests)."""
        return len(self._forward)


def visibility_cflags(prot: Any, supports_visibility: bool) -> list[str]:
    """``-fvisibility=hidden`` when symbol visibility reduction is active.

    Kept separate from :func:`mypycxazr.protect.pipeline.protect_cflags` so that
    codegen can ask "is visibility reduced?" without recomputing flags.
    """
    if prot.enabled and prot.has("symbol_visibility") and supports_visibility:
        return ["-fvisibility=hidden"]
    return []
