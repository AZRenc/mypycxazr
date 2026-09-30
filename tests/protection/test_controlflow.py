"""Tests for the control-flow hardening passes.

The contract: the CFG may be *reshaped* but never *reinterpreted*.  Every
test here asserts either (a) the IR is still well-formed according to
``mypycxazr.analysis.ircheck``, or (b) the set of paths through the function is
unchanged -- i.e. every original edge still exists, only via an extra hop.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
import textwrap
import unittest
from collections.abc import Iterator
from unittest import mock

from mypycxazr.analysis.ircheck import check_func_ir
from mypycxazr.ir.func_ir import FuncIR
from mypycxazr.ir.ops import Branch, ControlOp, Goto, Return, Unreachable
from mypycxazr.protect.controlflow import _reorder_blocks, _run_indirection, _split_edges
from mypycxazr.protect.options import ProtectOptions
from mypycxazr.protect.pipeline import run_protect_pipeline
from mypycxazr.test.testutil import ICODE_GEN_BUILTINS, build_ir_for_single_file

STRONG = ProtectOptions(level="strong")


@contextlib.contextmanager
def _ir_fixtures() -> Iterator[None]:
    """Give ``build_ir_for_single_file`` a private ``alt_lib_path``.

    The helper hardcodes ``mypy.test.config.test_temp_dir`` ("tmp"), which the
    data-driven suites create and share -- running these tests against it
    would race with them under xdist.  A private directory seeded with the
    same builtins fixture avoids that entirely.
    """
    path = tempfile.mkdtemp(prefix="mypycxazr-protect-")
    try:
        shutil.copyfile(ICODE_GEN_BUILTINS, os.path.join(path, "builtins.pyi"))
        with mock.patch("mypycxazr.test.testutil.test_temp_dir", path):
            yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def build(source: str) -> list[FuncIR]:
    with _ir_fixtures():
        return build_ir_for_single_file(textwrap.dedent(source).splitlines())


def blocks(fn: FuncIR) -> list:
    return list(fn.blocks)


def successors(fn: FuncIR) -> dict[int, set[int]]:
    out: dict[int, set[int]] = {}
    for b in fn.blocks:
        term = b.ops[-1]
        assert isinstance(term, ControlOp), term
        out[id(b)] = {id(t) for t in term.targets()}
    return out


def reachable(fn: FuncIR) -> set[int]:
    succ = successors(fn)
    seen: set[int] = set()
    stack = [id(fn.blocks[0])]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        stack.extend(succ.get(cur, set()) - seen)
    return seen


BRANCHY = """
def pick(x: int, y: int) -> int:
    total = 0
    if x > y:
        total += x
    else:
        total += y
    for i in range(10):
        if i == 3:
            total += i
        elif i % 2 == 0:
            total += 1
        else:
            total -= 1
    while total > 100:
        total //= 2
    return total
"""

LOOPY = """
def spin(n: int) -> int:
    acc = 0
    i = 0
    while i < n:
        try:
            acc += i * 2
        except ValueError:
            acc = -1
        i += 1
    return acc
"""


class TestValidation(unittest.TestCase):
    def test_branchy_is_valid_before_and_after(self) -> None:
        fn = build(BRANCHY)[0]
        self.assertEqual(check_func_ir(fn), [])
        self.assertTrue(_run_indirection(fn, STRONG))
        self.assertEqual(check_func_ir(fn), [])

    def test_loopy_is_valid_before_and_after(self) -> None:
        fn = build(LOOPY)[0]
        self.assertEqual(check_func_ir(fn), [])
        self.assertTrue(_run_indirection(fn, STRONG))
        self.assertEqual(check_func_ir(fn), [])

    def test_split_then_reorder_stays_valid(self) -> None:
        fn = build(LOOPY)[0]
        self.assertTrue(_split_edges(fn))
        self.assertTrue(_reorder_blocks(fn))
        self.assertEqual(check_func_ir(fn), [])


class TestShapeChange(unittest.TestCase):
    def test_branchy_gains_blocks(self) -> None:
        fn = build(BRANCHY)[0]
        n = len(fn.blocks)
        self.assertTrue(_run_indirection(fn, STRONG))
        self.assertGreater(len(fn.blocks), n)

    def test_entry_block_stays_first(self) -> None:
        fn = build(BRANCHY)[0]
        entry = fn.blocks[0]
        _run_indirection(fn, STRONG)
        self.assertIs(fn.blocks[0], entry)

    def test_reachable_block_set_is_unchanged(self) -> None:
        fn = build(BRANCHY)[0]
        before = blocks(fn)
        before_ids = {id(b) for b in before}
        before_reach = reachable(fn)

        _run_indirection(fn, STRONG)

        self.assertLessEqual(before_reach, reachable(fn))
        after_ids = {id(b) for b in fn.blocks}
        self.assertTrue(after_ids - before_ids, "no trampoline was added")
        self.assertEqual({i for i in after_ids if i in before_ids}, before_ids)

    def test_every_original_edge_goes_through_a_trampoline(self) -> None:
        fn = build(BRANCHY)[0]
        before = blocks(fn)
        before_succ = {id(b): {id(t) for t in b.ops[-1].targets()} for b in before}
        before_ids = {id(b) for b in before}

        _run_indirection(fn, STRONG)
        after_succ = successors(fn)
        by_id = {id(b): b for b in fn.blocks}

        checked = 0
        for src, targets in before_succ.items():
            if not targets:
                continue  # Return / Unreachable: nothing to indirect
            mids = after_succ.get(src, set())
            self.assertTrue(mids, "original block lost all successors")
            # every original target must be reachable through exactly one
            # freshly created, single-successor trampoline
            for tgt in targets:
                hops = [m for m in mids if tgt in after_succ.get(m, set())]
                self.assertEqual(len(hops), 1, "target not reached by exactly one hop")
                mid = hops[0]
                self.assertNotIn(mid, before_ids, "edge was not indirected")
                self.assertEqual(len(after_succ[mid]), 1, "trampoline forwards to more than one block")
                self.assertEqual(len(by_id[mid].ops), 1)
                self.assertIsInstance(by_id[mid].ops[0], Goto)
                checked += 1
            # ... and nothing else was invented: |targets| new hops, no more
            self.assertLessEqual(len(mids), len(targets))
            checked += 0
        self.assertGreater(checked, 0)

    def test_all_added_blocks_are_trampolines(self) -> None:
        fn = build(BRANCHY)[0]
        before_ids = {id(b) for b in fn.blocks}
        _run_indirection(fn, STRONG)
        for b in fn.blocks:
            if id(b) in before_ids:
                continue
            self.assertEqual(len(b.ops), 1)
            self.assertIsInstance(b.ops[0], Goto)


class TestSemanticsPreserved(unittest.TestCase):
    def test_error_handlers_are_untouched(self) -> None:
        fn = build(LOOPY)[0]
        before = {id(b): b.error_handler for b in fn.blocks}
        _run_indirection(fn, STRONG)
        for b in fn.blocks:
            if id(b) in before:
                self.assertIs(b.error_handler, before[id(b)])

    def test_branch_metadata_survives(self) -> None:
        fn = build(BRANCHY)[0]

        def shape(f: FuncIR) -> tuple[int, int, int, int]:
            n_true = n_false = n_tb = n_rare = 0
            for b in f.blocks:
                for op in b.ops:
                    if isinstance(op, Branch):
                        n_true += 1 if op.value else 0
                        n_false += 0 if op.value else 1
                        n_tb += 1 if op.traceback_entry else 0
                        n_rare += 1 if op.rare else 0
            return n_true, n_false, n_tb, n_rare

        before = shape(fn)
        _run_indirection(fn, STRONG)
        self.assertEqual(shape(fn), before)

    def test_return_and_unreachable_count_preserved(self) -> None:
        fn = build(BRANCHY)[0]

        def counts(f: FuncIR) -> tuple[int, int]:
            ret = unr = 0
            for b in f.blocks:
                for op in b.ops:
                    if isinstance(op, Return):
                        ret += 1
                    elif isinstance(op, Unreachable):
                        unr += 1
            return ret, unr

        before = counts(fn)
        _run_indirection(fn, STRONG)
        self.assertEqual(counts(fn), before)


class TestReorder(unittest.TestCase):
    def test_keeps_entry_first(self) -> None:
        fn = build(BRANCHY)[0]
        entry = fn.blocks[0]
        self.assertTrue(_reorder_blocks(fn))
        self.assertIs(fn.blocks[0], entry)

    def test_is_a_permutation(self) -> None:
        fn = build(BRANCHY)[0]
        before = {id(b) for b in fn.blocks}
        _reorder_blocks(fn)
        self.assertEqual({id(b) for b in fn.blocks}, before)
        self.assertEqual(check_func_ir(fn), [])

    def test_does_not_reorder_tiny_functions(self) -> None:
        fn = build("def tiny() -> int:\n    return 1\n")[0]
        if len(fn.blocks) < 4:
            self.assertFalse(_reorder_blocks(fn))


class TestDeterminism(unittest.TestCase):
    @staticmethod
    def _fingerprint(fn: FuncIR) -> tuple:
        succ = successors(fn)
        return (
            tuple(len(b.ops) for b in fn.blocks),
            tuple(sorted(len(v) for v in succ.values())),
            len(fn.blocks),
            len(reachable(fn)),
        )

    def test_two_runs_give_the_same_structure(self) -> None:
        a, b = build(BRANCHY)[0], build(BRANCHY)[0]
        self.assertEqual(self._fingerprint(a), self._fingerprint(b))
        self.assertTrue(_run_indirection(a, STRONG))
        self.assertTrue(_run_indirection(b, STRONG))
        self.assertEqual(self._fingerprint(a), self._fingerprint(b))

    def test_second_run_keeps_the_ir_valid(self) -> None:
        fn = build(BRANCHY)[0]
        _run_indirection(fn, STRONG)
        n = len(fn.blocks)
        _run_indirection(fn, STRONG)
        self.assertGreaterEqual(len(fn.blocks), n)
        self.assertEqual(check_func_ir(fn), [])


class TestLevelGating(unittest.TestCase):
    def test_pipeline_respects_level(self) -> None:
        fn = build(BRANCHY)[0]
        n = len(fn.blocks)

        self.assertFalse(run_protect_pipeline(fn, ProtectOptions(level="off")))
        self.assertEqual(len(fn.blocks), n)

        self.assertFalse(run_protect_pipeline(fn, ProtectOptions(level="basic")))
        self.assertEqual(len(fn.blocks), n)

        self.assertTrue(run_protect_pipeline(fn, ProtectOptions(level="strong")))
        self.assertGreater(len(fn.blocks), n)
        self.assertEqual(check_func_ir(fn), [])

    def test_single_block_function_is_left_alone(self) -> None:
        fn = build("def tiny() -> int:\n    return 1\n")[0]
        if len(fn.blocks) < 2:
            self.assertFalse(_split_edges(fn))
            self.assertFalse(_run_indirection(fn, STRONG))


if __name__ == "__main__":
    unittest.main()
