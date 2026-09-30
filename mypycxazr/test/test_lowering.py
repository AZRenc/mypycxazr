"""Runner for lowering transform tests."""

from __future__ import annotations

import os.path

from mypy.errors import CompileError
from mypy.test.config import test_temp_dir
from mypy.test.data import DataDrivenTestCase
from mypycxazr.common import TOP_LEVEL_NAME
from mypycxazr.ir.pprint import format_func
from mypycxazr.options import CompilerOptions
from mypycxazr.test.testutil import (
    ICODE_GEN_BUILTINS,
    MypycDataSuite,
    assert_test_output,
    build_ir_for_single_file,
    infer_ir_build_options_from_test_name,
    remove_comment_lines,
    replace_word_size,
    use_custom_builtins,
)
from mypycxazr.transform.exceptions import insert_exception_handling
from mypycxazr.transform.flag_elimination import do_flag_elimination
from mypycxazr.transform.lower import lower_ir
from mypycxazr.transform.refcount import insert_ref_count_opcodes
from mypycxazr.transform.uninit import insert_uninit_checks


class TestLowering(MypycDataSuite):
    files = ["lowering-int.test", "lowering-list.test"]
    base_path = test_temp_dir

    def run_case(self, testcase: DataDrivenTestCase) -> None:
        options = infer_ir_build_options_from_test_name(testcase.name)
        if options is None:
            # Skipped test case
            return
        with use_custom_builtins(os.path.join(self.data_prefix, ICODE_GEN_BUILTINS), testcase):
            expected_output = remove_comment_lines(testcase.output)
            expected_output = replace_word_size(expected_output)
            try:
                ir = build_ir_for_single_file(testcase.input, options)
            except CompileError as e:
                actual = e.messages
            else:
                actual = []
                for fn in ir:
                    if fn.name == TOP_LEVEL_NAME and not testcase.name.endswith("_toplevel"):
                        continue
                    options = CompilerOptions()
                    # Lowering happens after exception handling and ref count opcodes have
                    # been added. Any changes must maintain reference counting semantics.
                    insert_uninit_checks(fn)
                    insert_exception_handling(fn)
                    insert_ref_count_opcodes(fn)
                    lower_ir(fn, options)
                    do_flag_elimination(fn, options)
                    actual.extend(format_func(fn))

            assert_test_output(testcase, actual, "Invalid source code output", expected_output)
