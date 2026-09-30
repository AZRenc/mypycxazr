"""Control-flow hardening passes.

Every transformation in this module must be:

* **semantics-preserving** -- identical observable Python behaviour,
  identical reference counting, identical exception propagation;
* **deterministic** -- no randomness, byte-identical output for identical
  input, so builds stay reproducible;
* **testable** -- covered by ``tests/protection/test_controlflow.py`` and by
  ``mypycxazr/analysis/ircheck.py`` after the pass runs;
* **off in debug builds** -- only runs when ``protect`` >= the feature's level.

They deliberately run *after* ``insert_ref_count_opcodes``,
``insert_exception_handling``, ``lower_ir`` and the optimizations, so they can
only move basic blocks around and rewrite terminators -- never change which
values are live or where an error value is consumed.
"""

from __future__ import annotations

from typing import Callable

from mypycxazr.ir.func_ir import FuncIR
from mypycxazr.ir.ops import BasicBlock, Branch, ControlOp, Goto
from mypycxazr.protect.options import ProtectOptions
from mypycxazr.protect.pipeline.passes import ProtectPass


def _split_edges(fn: FuncIR) -> bool:
    """Route every CFG edge through a trampoline basic block.

    Before::

        block0: ... ; if r goto L2 else L3
        block1: ...
        block2: ...

    After::

        block0: ... ; if r goto T0 else T1
        T0: goto L2
        T1: goto L3

    The set of paths through the function is unchanged: a trampoline has a
    single predecessor edge group and unconditionally forwards to the block it
    replaced.  Placement is chosen so that each trampoline sits immediately
    before its target, which makes the forwarding edge a fall-through in the
    emitted C (one extra label, no extra ``goto``), so code size and speed are
    essentially unaffected.

    Edges originating from a trampoline are never processed, so the transform
    terminates.  ``error_handler`` links and ``Op`` sources are untouched --
    only terminator targets change.
    """
    if len(fn.blocks) < 2:
        return False

    original = list(fn.blocks)
    entry = original[0]

    # (source block, target block) -> trampoline
    trampolines: dict[tuple[BasicBlock, BasicBlock], BasicBlock] = {}

    def trampoline(src: BasicBlock, target: BasicBlock) -> BasicBlock:
        key = (src, target)
        existing = trampolines.get(key)
        if existing is not None:
            return existing
        new = BasicBlock()
        new.ops.append(Goto(target))
        trampolines[key] = new
        return new

    for block in original:
        term = block.ops[-1]
        assert isinstance(term, ControlOp), term
        if isinstance(term, Goto):
            term.label = trampoline(block, term.label)
        elif isinstance(term, Branch):
            # Keep `Branch.traceback_entry`/`rare`/`negated` exactly as they
            # are: they are consumed by code generation.
            term.true = trampoline(block, term.true)
            term.false = trampoline(block, term.false)

    # Place every trampoline immediately before the block it forwards to so
    # that the forward edge compiles to a fall-through.  The entry block has
    # to stay first (it is the implicit label 0 of the emitted function).
    by_target: dict[BasicBlock, list[BasicBlock]] = {}
    for (src, target), new in trampolines.items():
        by_target.setdefault(target, []).append(new)

    new_order: list[BasicBlock] = [entry]
    placed: set[int] = {id(entry)}
    for block in original:
        if id(block) in placed:
            continue
        for t in by_target.get(block, ()):
            if id(t) not in placed:
                new_order.append(t)
                placed.add(id(t))
        new_order.append(block)
        placed.add(id(block))

    # Anything left over: trampolines whose target is the entry block, plus
    # blocks with no predecessors.
    for block in original:
        if id(block) not in placed:
            new_order.append(block)
            placed.add(id(block))
    for group in by_target.values():
        for t in group:
            if id(t) not in placed:
                new_order.append(t)
                placed.add(id(t))

    # A stale `referenced` flag would only add redundant labels; reset it and
    # let codegen recompute it for the new layout.
    for block in new_order:
        block.referenced = False

    fn.blocks = new_order
    return len(new_order) != len(original)


def _reorder_blocks(fn: FuncIR) -> bool:
    """Deterministically permute non-entry basic blocks.

    The entry block must stay at index 0 (it becomes label 0 in the emitted
    C function and there is no explicit jump to it).  Everything else is
    reversed, which destroys the "blocks appear in source order" heuristic
    that decompilers rely on while leaving every edge intact.

    Only runs when it actually changes something, so trivial functions are
    left alone.
    """
    if len(fn.blocks) < 4:
        return False
    rest = fn.blocks[1:]
    if len(set(map(id, rest))) != len(rest):
        return False
    new_rest = list(reversed(rest))
    if new_rest == rest:
        return False
    for block in fn.blocks:
        block.referenced = False
    fn.blocks = [fn.blocks[0]] + new_rest
    return True


def _run_indirection(fn: FuncIR, prot: ProtectOptions) -> bool:
    if len(fn.blocks) < 2:
        return False
    changed = _split_edges(fn)
    # Reordering is only meaningful once edges are indirected; running it on
    # its own would be a pure layout shuffle with no analytical benefit.
    if changed:
        _reorder_blocks(fn)
    return changed


def register_control_flow_passes(
    reg: Callable[[ProtectPass], ProtectPass],
) -> None:
    reg(
        ProtectPass(
            name="cfg_indirection",
            feature="control_flow",
            doc=(
                "Route every CFG edge through a forwarding basic block and "
                "permute the block order (entry block stays first). "
                "Semantics-preserving: only terminator targets and block "
                "layout change; refcounts, error values and traceback entries "
                "are untouched. Verified with mypycxazr.analysis.ircheck and "
                "tests/protection/test_controlflow.py."
            ),
            runner=_run_indirection,
        )
    )
