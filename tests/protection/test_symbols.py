"""Unit tests for symbol obfuscation and visibility reduction.

These tests pin down the two properties the rest of the build depends on:

* obfuscation is *deterministic* (reproducible builds) and *total* (every
  source-derived name is renamed);
* obfuscation *never splits a name that the compiler composes by string
  concatenation* -- that was a real regression, see
  ``mypycxazr/protect/symbols.COMPOSED_SUFFIXES``.
"""

from __future__ import annotations

import unittest

from mypycxazr.namegen import NameGenerator, exported_name
from mypycxazr.protect.symbols import (
    COMPOSED_SUFFIXES,
    NameObfuscator,
    RESERVED_PREFIXES,
    is_reserved_symbol,
    split_composed_suffix,
    visibility_cflags,
)

MODULES = [["samplemod"]]


def gen(**kwargs: object) -> NameGenerator:
    return NameGenerator(MODULES, **kwargs)  # type: ignore[arg-type]


class TestReservedNames(unittest.TestCase):
    def test_reserved_prefixes(self) -> None:
        for p in ("PyInit_", "CPyInit_", "CPyExec_", "exports_"):
            assert is_reserved_symbol(p + "mod")
            assert p in RESERVED_PREFIXES

    def test_ordinary_names_are_not_reserved(self) -> None:
        assert not is_reserved_symbol("CPyDef_greet")
        assert not is_reserved_symbol("CPyType_Greeter")
        assert not is_reserved_symbol("greet")


class TestDeterminism(unittest.TestCase):
    def test_same_seed_same_names(self) -> None:
        a, b = gen(obfuscate=True, seed="s"), gen(obfuscate=True, seed="s")
        for module, partial in [("samplemod", "greet"), ("samplemod", "Greeter"), ("", "helper")]:
            assert a.private_name(module, partial) == b.private_name(module, partial)

    def test_different_seed_different_names(self) -> None:
        a, b = gen(obfuscate=True, seed="s1"), gen(obfuscate=True, seed="s2")
        assert a.private_name("samplemod", "greet") != b.private_name("samplemod", "greet")

    def test_unobfuscated_matches_upstream(self) -> None:
        plain, obf = gen(), gen(obfuscate=True, seed="s")
        assert plain.private_name("samplemod", "greet") == "greet"
        assert obf.private_name("samplemod", "greet") != "greet"

    def test_deterministic_across_instances(self) -> None:
        seen = {gen(obfuscate=True, seed="k").private_name("samplemod", "greet") for _ in range(5)}
        assert len(seen) == 1

    def test_output_does_not_contain_source_text(self) -> None:
        name = gen(obfuscate=True, seed="k").private_name("samplemod", "very_secret_method")
        assert "secret" not in name
        assert "method" not in name
        assert name.startswith("z")
        assert len(name) == 11


class TestUniqueness(unittest.TestCase):
    def test_distinct_inputs_give_distinct_outputs(self) -> None:
        names = gen(obfuscate=True, seed="k")
        parts = ["greet", "Greeter", "LoudGreeter", "process_items", "compute_checksum"]
        out = [names.private_name("samplemod", p) for p in parts]
        assert len(set(out)) == len(parts)

    def test_aliasing_is_preserved(self) -> None:
        """The upstream generator maps ``(module, partial)`` many-to-one.

        For a single-module build ``private_name("samplemod", "x")`` and
        ``private_name("", "x")`` are both ``"x"``.  Obfuscation must keep
        them equal, otherwise declaration sites and use sites disagree.
        """
        names = gen(obfuscate=True, seed="k")
        assert names.private_name("samplemod", "x") == names.private_name("", "x")


class TestComposedSuffixes(unittest.TestCase):
    def test_split(self) -> None:
        assert split_composed_suffix("Greeter_template") == ("Greeter", "_template")
        assert (
            split_composed_suffix("Greeter_trait_vtable_setup")
            == ("Greeter", "_trait_vtable_setup")
        )
        assert split_composed_suffix("greet") == ("greet", "")
        assert split_composed_suffix("_template") == ("_template", "")

    def test_suffix_survives_obfuscation(self) -> None:
        """``type_struct_name(cl) + "_template"`` must equal the obfuscated
        form of ``cl.name + "_template"`` -- the two code paths that name the
        very same C variable."""
        names = gen(obfuscate=True, seed="k")
        stem = names.private_name("samplemod", "Greeter")
        composed = f"{stem}_template"
        whole = names.private_name("samplemod", "Greeter_template")
        assert composed == whole
        assert whole.endswith("_template")

    def test_trait_setup_suffix_matches_name_prefix(self) -> None:
        names = gen(obfuscate=True, seed="k")
        stem = names.private_name("samplemod", "Greeter")
        assert f"{stem}_trait_vtable_setup" == names.private_name(
            "samplemod", "Greeter_trait_vtable_setup"
        )

    def test_every_declared_suffix_roundtrips(self) -> None:
        names = gen(obfuscate=True, seed="k")
        for suffix in COMPOSED_SUFFIXES:
            got = names.private_name("samplemod", "Thing" + suffix)
            assert got.endswith(suffix)
            assert got[: -len(suffix)] == names.private_name("samplemod", "Thing")

    def test_suffixed_and_plain_names_stay_distinct(self) -> None:
        names = gen(obfuscate=True, seed="k")
        assert names.private_name("m", "Greeter") != names.private_name("m", "Greeter_template")


class TestObfuscatorAlone(unittest.TestCase):
    def test_collision_resolution_is_deterministic(self) -> None:
        """Two different keys that hash to the same candidate get a stable,
        order-independent-enough second attempt."""
        a = NameObfuscator("seed")
        first = a.name_for("m", "one")
        second = a.name_for("m", "two")
        assert first != second

        b = NameObfuscator("seed")
        assert b.name_for("m", "one") == first
        assert b.name_for("m", "two") == second

    def test_size_tracks_names_handed_out(self) -> None:
        o = NameObfuscator("s")
        assert o.size == 0
        o.name_for("m", "a")
        o.name_for("m", "b")
        assert o.size == 2

    def test_same_key_is_cached(self) -> None:
        o = NameObfuscator("s")
        assert o.name_for("m", "a") == o.name_for("m", "a")


class TestVisibility(unittest.TestCase):
    def test_no_flags_when_off(self) -> None:
        from mypycxazr.protect.options import ProtectOptions

        assert visibility_cflags(ProtectOptions(level="off"), True) == []

    def test_hidden_when_enabled(self) -> None:
        from mypycxazr.protect.options import ProtectOptions

        assert visibility_cflags(ProtectOptions(level="basic"), True) == ["-fvisibility=hidden"]
        # unsupported toolchains are not given a flag that would break them
        assert visibility_cflags(ProtectOptions(level="basic"), False) == []


class TestExportedNameUntouched(unittest.TestCase):
    def test_exported_name_is_not_obfuscated(self) -> None:
        names = gen(obfuscate=True, seed="k")
        # exported_name is a free function used for ABI names; obfuscation
        # must not be routed through it.
        assert exported_name("samplemod") == "samplemod"
        assert names.private_name("samplemod", None) != "samplemod"
