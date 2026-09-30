"""Registry of protection IR passes.

Adding a pass means adding it to ``_REGISTRY`` with the feature it belongs to
and a docstring that states (a) what it does, (b) what invariants it relies
on and (c) how it is tested.  A pass whose feature is not enabled by the
current level is never executed.

Registration is lazy: importing this module never pulls in a pass module, so
``mypycxazr.protect.pipeline`` can be imported from inside a pass module without a
circular import.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from mypycxazr.protect.options import ProtectOptions


@dataclass(frozen=True)
class ProtectPass:
    #: Stable identifier, also used as the test/benchmark label.
    name: str
    #: The feature this pass implements (a key of options.FEATURE_LEVELS).
    feature: str
    #: One paragraph: what it does, invariants, where it is tested.
    doc: str
    #: ``run(fn, prot) -> bool``; returns True if ``fn`` was modified.
    runner: Callable[[Any, ProtectOptions], bool]

    def run(self, fn: Any, prot: ProtectOptions) -> bool:
        return self.runner(fn, prot)


_REGISTRY: list[ProtectPass] = []
_LOADED = False


def register(p: ProtectPass) -> ProtectPass:
    if any(existing.name == p.name for existing in _REGISTRY):
        raise ValueError(f"duplicate protection pass name {p.name!r}")
    _REGISTRY.append(p)
    return p


def _ensure_loaded() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    from mypycxazr.protect.controlflow import register_control_flow_passes

    register_control_flow_passes(register)


def all_passes() -> list[ProtectPass]:
    _ensure_loaded()
    return list(_REGISTRY)


def collect_passes(prot: ProtectOptions) -> list[ProtectPass]:
    """Passes enabled by ``prot``, in registration (= execution) order."""
    _ensure_loaded()
    return [p for p in _REGISTRY if prot.has(p.feature)]
