"""Tests for protection levels, features and configuration loading."""

from __future__ import annotations

import os
import tempfile
import textwrap
import unittest
from unittest import mock

from mypycxazr.protect.options import (
    FEATURE_DESCRIPTIONS,
    FEATURE_LEVELS,
    PROTECT_LEVELS,
    ProtectError,
    ProtectOptions,
    features_for_level,
    load_config,
    load_config_file,
)


class TestLevelMatrix(unittest.TestCase):
    def test_levels_are_ordered(self) -> None:
        self.assertEqual(PROTECT_LEVELS, ("off", "basic", "strong", "maximum"))

    def test_every_feature_is_documented(self) -> None:
        self.assertEqual(set(FEATURE_LEVELS), set(FEATURE_DESCRIPTIONS))

    def test_levels_are_additive(self) -> None:
        previous: frozenset[str] = frozenset()
        for level in PROTECT_LEVELS:
            current = features_for_level(level)
            self.assertLessEqual(
                previous, current, f"{level} dropped features from the previous level"
            )
            previous = current

    def test_off_enables_nothing(self) -> None:
        self.assertEqual(features_for_level("off"), frozenset())

    def test_basic_is_the_expected_set(self) -> None:
        self.assertEqual(
            features_for_level("basic"),
            frozenset({"debug_reduction", "elf_hardening", "symbol_visibility"}),
        )

    def test_strong_adds_the_named_features(self) -> None:
        added = features_for_level("strong") - features_for_level("basic")
        self.assertEqual(
            added, frozenset({"symbol_names", "literal_mangling", "control_flow"})
        )

    def test_maximum_adds_integrity(self) -> None:
        added = features_for_level("maximum") - features_for_level("strong")
        self.assertEqual(added, frozenset({"integrity"}))

    def test_every_level_covers_every_feature(self) -> None:
        for feature, first in FEATURE_LEVELS.items():
            self.assertIn(feature, features_for_level(first))
            for level in PROTECT_LEVELS:
                expected = PROTECT_LEVELS.index(level) >= PROTECT_LEVELS.index(first)
                self.assertEqual(
                    ProtectOptions(level=level).has(feature),
                    expected,
                    f"{level}/{feature}",
                )


class TestProtectOptions(unittest.TestCase):
    def test_invalid_level_rejected(self) -> None:
        with self.assertRaises(ProtectError):
            ProtectOptions(level="maximum+")

    def test_unknown_feature_rejected(self) -> None:
        with self.assertRaises(ProtectError):
            ProtectOptions(level="strong", extra_features=frozenset({"nope"}))

    def test_unknown_feature_query_rejected(self) -> None:
        with self.assertRaises(ProtectError):
            ProtectOptions(level="strong").has("not-a-feature")

    def test_off_is_disabled(self) -> None:
        self.assertFalse(ProtectOptions().enabled)

    def test_strip_alone_enables_debug_reduction(self) -> None:
        opts = ProtectOptions(level="off", strip=True)
        self.assertTrue(opts.enabled)
        self.assertTrue(opts.has("debug_reduction"))
        self.assertFalse(opts.has("symbol_names"))

    def test_describe(self) -> None:
        self.assertEqual(ProtectOptions().describe(), "protect=off")
        self.assertIn("protect=strong", ProtectOptions(level="strong").describe())


class _ConfigCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name

    def write_config(self, body: str) -> str:
        path = os.path.join(self.tmp, "pyproject.toml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(textwrap.dedent(body))
        return path

    @property
    def missing(self) -> str:
        return os.path.join(self.tmp, "does-not-exist.toml")


class TestConfigFile(_ConfigCase):
    def test_missing_file_is_off(self) -> None:
        self.assertEqual(load_config_file(self.missing).level, "off")

    def test_reads_level_and_strip(self) -> None:
        path = self.write_config(
            """
            [tool.mypycxazr-protect]
            level = "strong"
            strip = true
            """
        )
        opts = load_config_file(path)
        self.assertEqual(opts.level, "strong")
        self.assertTrue(opts.strip)

    def test_reads_feature_list(self) -> None:
        path = self.write_config(
            """
            [tool.mypycxazr-protect]
            level = "basic"
            features = ["control_flow"]
            """
        )
        opts = load_config_file(path)
        self.assertTrue(opts.has("control_flow"))
        self.assertTrue(opts.has("debug_reduction"))

    def test_unknown_key_rejected(self) -> None:
        path = self.write_config(
            """
            [tool.mypycxazr-protect]
            level = "basic"
            bogus = 1
            """
        )
        with self.assertRaises(ProtectError):
            load_config_file(path)

    def test_invalid_level_rejected(self) -> None:
        path = self.write_config(
            """
            [tool.mypycxazr-protect]
            level = "turbo"
            """
        )
        with self.assertRaises(ProtectError):
            load_config_file(path)

    def test_no_section_is_off(self) -> None:
        path = self.write_config("[tool.other]\nx = 1\n")
        self.assertEqual(load_config_file(path).level, "off")

    def test_legacy_table_name_still_read(self) -> None:
        # `[tool.mypyc-protect]` is the name the spec was written against;
        # it must keep working after the package was renamed.
        path = self.write_config(
            """
            [tool.mypyc-protect]
            level = "strong"
            """
        )
        opts = load_config_file(path)
        self.assertEqual(opts.level, "strong")

    def test_both_table_names_is_an_error(self) -> None:
        path = self.write_config(
            """
            [tool.mypycxazr-protect]
            level = "basic"
            [tool.mypyc-protect]
            level = "strong"
            """
        )
        with self.assertRaises(ProtectError) as ctx:
            load_config_file(path)
        self.assertIn("both", str(ctx.exception))

    def test_malformed_toml_rejected(self) -> None:
        path = self.write_config("[tool.mypycxazr-protect\n")
        with self.assertRaises(ProtectError):
            load_config_file(path)


class TestPrecedence(_ConfigCase):
    def write_level(self, level: str) -> str:
        return self.write_config(f'[tool.mypycxazr-protect]\nlevel = "{level}"\n')

    def clean_env(self, **extra: str) -> mock._patch:  # type: ignore[name-defined]
        env = {k: v for k, v in os.environ.items() if not k.startswith("MYPYC_PROTECT")}
        env.update(extra)
        return mock.patch.dict(os.environ, env, clear=True)

    def test_config_beats_default(self) -> None:
        path = self.write_level("strong")
        with self.clean_env():
            self.assertEqual(load_config(None, config_path=path, use_env=False).level, "strong")

    def test_explicit_beats_config(self) -> None:
        path = self.write_level("strong")
        with self.clean_env():
            opts = load_config(ProtectOptions(level="basic"), config_path=path, use_env=False)
        self.assertEqual(opts.level, "basic")

    def test_env_beats_config(self) -> None:
        path = self.write_level("strong")
        with self.clean_env(MYPYC_PROTECT="basic"):
            self.assertEqual(load_config(None, config_path=path).level, "basic")

    def test_env_strip_is_parsed(self) -> None:
        with self.clean_env(MYPYC_PROTECT_STRIP="1"):
            self.assertTrue(load_config(None, config_path=self.missing).strip)
        with self.clean_env(MYPYC_PROTECT_STRIP="0"):
            self.assertFalse(load_config(None, config_path=self.missing).strip)
        with self.clean_env(MYPYC_PROTECT_STRIP="off"):
            self.assertFalse(load_config(None, config_path=self.missing).strip)

    def test_invalid_env_level_rejected(self) -> None:
        with self.clean_env(MYPYC_PROTECT="nonsense"):
            with self.assertRaises(ProtectError):
                load_config(None, config_path=self.missing)

    def test_env_is_not_consulted_when_disabled(self) -> None:
        path = self.write_level("strong")
        with self.clean_env(MYPYC_PROTECT="basic"):
            self.assertEqual(
                load_config(None, config_path=path, use_env=False).level, "strong"
            )


if __name__ == "__main__":
    unittest.main()
