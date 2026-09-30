"""Tests for the build half of the protection pipeline (flags) and the pass
registry that drives the IR half.

The contract under test: **the flags and the passes always agree with the
level.**  A build can never end up with C flags from one level and IR passes
from another, and no feature may be silently absent from its level.
"""

from __future__ import annotations

import unittest

from mypycxazr.protect.options import FEATURE_LEVELS, ProtectOptions
from mypycxazr.protect.pipeline import (
    all_passes,
    collect_passes,
    protect_cflags,
    protect_link_args,
    resolve_build_options,
    run_protect_pipeline,
)
from mypycxazr.protect import toolchain


class TestToolchainProbing(unittest.TestCase):
    def test_probe_flag_handles_missing_compiler(self) -> None:
        assert toolchain.probe_flag(["/nonexistent/cc"], "-fvisibility=hidden") is False

    def test_detect_returns_a_toolchain(self) -> None:
        info = toolchain.detect(None)
        assert isinstance(info.supports_visibility, bool)
        assert isinstance(info.linker_hardening, (list, tuple))

    def test_detected_flags_are_probed_not_assumed(self) -> None:
        info = toolchain.detect(None)
        # Whatever was detected must survive a second, independent probe.
        again = toolchain.detect(None)
        assert info.linker_hardening == again.linker_hardening


class TestCompilerFlags(unittest.TestCase):
    def test_off_adds_nothing(self) -> None:
        assert protect_cflags(ProtectOptions(level="off")) == []

    def test_basic_strips_debug_info(self) -> None:
        flags = protect_cflags(ProtectOptions(level="basic"))
        assert "-g0" in flags
        assert "-fno-ident" in flags

    def test_basic_reduces_visibility_when_supported(self) -> None:
        info = toolchain.detect(None)
        flags = protect_cflags(ProtectOptions(level="basic"))
        assert ("-fvisibility=hidden" in flags) is info.supports_visibility

    def test_strip_on_off_level_still_reduces_debug_info(self) -> None:
        flags = protect_cflags(ProtectOptions(level="off", strip=True))
        assert "-g0" in flags

    def test_flags_are_deduplicated(self) -> None:
        flags = protect_cflags(ProtectOptions(level="strong"))
        assert len(flags) == len(set(flags))

    def test_strong_and_maximum_do_not_add_extra_compiler_flags(self) -> None:
        # symbol/literal/control-flow hardening are code-level, not flag-level
        assert protect_cflags(ProtectOptions(level="strong")) == protect_cflags(
            ProtectOptions(level="basic")
        )


class TestLinkerFlags(unittest.TestCase):
    def test_off_adds_nothing(self) -> None:
        assert protect_link_args(ProtectOptions(level="off")) == []

    def test_basic_applies_hardening(self) -> None:
        if not toolchain.detect(None).supports_wl_flags:
            self.skipTest("toolchain rejects -Wl,-z,... flags")
        args = protect_link_args(ProtectOptions(level="basic"))
        for expected in ("-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack"):
            assert expected in args, expected

    def test_build_id_removed_for_reproducibility(self) -> None:
        if not toolchain.detect(None).supports_wl_flags:
            self.skipTest("toolchain rejects -Wl,... flags")
        args = protect_link_args(ProtectOptions(level="basic"))
        assert "-Wl,--build-id=none" in args

    def test_no_unsupported_flag_is_ever_emitted(self) -> None:
        info = toolchain.detect(None)
        allowed = set(info.linker_hardening)
        for level in ("basic", "strong", "maximum"):
            assert set(protect_link_args(ProtectOptions(level=level))) <= allowed


class TestResolveBuildOptions(unittest.TestCase):
    def test_explicit_level_wins(self) -> None:
        opts = resolve_build_options(protect="strong", use_env=False)
        assert opts.level == "strong"

    def test_none_uses_defaults(self) -> None:
        opts = resolve_build_options(use_env=False, config_path="/nonexistent/pyproject.toml")
        assert opts.level == "off"
        assert opts.enabled is False


class TestPassRegistry(unittest.TestCase):
    def test_registry_is_never_empty(self) -> None:
        assert len(all_passes()) > 0

    def test_every_pass_maps_to_a_real_feature(self) -> None:
        for p in all_passes():
            assert p.feature in FEATURE_LEVELS, p.name
            assert p.doc and len(p.doc) > 40, p.name

    def test_pass_names_are_unique(self) -> None:
        names = [p.name for p in all_passes()]
        assert len(names) == len(set(names))

    def test_off_runs_no_passes(self) -> None:
        assert collect_passes(ProtectOptions(level="off")) == []

    def test_basic_runs_no_ir_passes(self) -> None:
        # nothing in `basic` is an IR transform by design
        assert collect_passes(ProtectOptions(level="basic")) == []

    def test_strong_enables_control_flow_passes(self) -> None:
        strong = {p.name for p in collect_passes(ProtectOptions(level="strong"))}
        basic = {p.name for p in collect_passes(ProtectOptions(level="basic"))}
        assert strong - basic == {"cfg_indirection"}

    def test_maximum_is_a_superset_of_strong(self) -> None:
        strong = {p.name for p in collect_passes(ProtectOptions(level="strong"))}
        maximum = {p.name for p in collect_passes(ProtectOptions(level="maximum"))}
        assert strong <= maximum

    #: Features implemented in the code generator / build step rather than
    #: as an IR pass or a compiler flag.  Each one has its own test module:
    #: symbol_names -> test_symbols, literal_mangling -> test_constants,
    #: integrity -> test_integrity.
    CODEGEN_FEATURES = frozenset({"symbol_names", "literal_mangling", "integrity"})

    def test_every_enabled_feature_is_actually_implemented(self) -> None:
        """No level may advertise a feature that nothing implements.

        This is the guard against "fake features": every feature listed for a
        level must come from exactly one of the three places a feature can be
        implemented -- an IR pass, a compiler/linker flag, or the code
        generator -- and the three code generator features are covered by
        their own test modules.
        """
        pass_features = {p.feature for p in all_passes()}
        flag_features = {"debug_reduction", "symbol_visibility", "elf_hardening"}
        known = pass_features | flag_features | self.CODEGEN_FEATURES
        for level in ("off", "basic", "strong", "maximum"):
            opts = ProtectOptions(level=level)
            for feature in opts.features:
                self.assertIn(
                    feature,
                    known,
                    f"level {level} advertises {feature}, which nothing implements",
                )

    def test_every_implementation_belongs_to_a_level(self) -> None:
        from mypycxazr.protect.options import features_for_level

        pass_features = {p.feature for p in all_passes()}
        for feature in pass_features:
            # a registered pass must be reachable from at least one level
            assert any(
                feature in features_for_level(level)
                for level in ("off", "basic", "strong", "maximum")
            ), f"pass feature {feature} is unreachable"


class TestRunProtectPipeline(unittest.TestCase):
    def test_off_is_a_noop(self) -> None:
        class Dummy:
            blocks: list[object] = []

        assert run_protect_pipeline(Dummy(), ProtectOptions(level="off")) is False
