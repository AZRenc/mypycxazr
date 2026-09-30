"""Protection levels and configuration for MyPyC-Protect.

A protection *level* is a named bundle of features.  Levels are additive:
everything enabled by ``basic`` is also enabled by ``strong``, and so on.

Level matrix (see docs/protection.md for prose):

==========================  ========  =======  ========  =======
feature                     off       basic    strong    maximum
==========================  ========  =======  ========  =======
reduced debug information   no        yes      yes       yes
ELF/link hardening          no        yes      yes       yes
symbol visibility hiding    no        yes      yes       yes
symbol name obfuscation     no        no       yes       yes
literal/metadata mangling   no        no       yes       yes
control-flow hardening      no        no       yes       yes
integrity self-check        no        no       no        yes
==========================  ========  =======  ========  =======

``protect_strip`` is an independent switch that forces the "reduced debug
information" behaviour on regardless of level, so that a caller can strip
development metadata from an otherwise unprotected build.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

PROTECT_LEVELS: tuple[str, ...] = ("off", "basic", "strong", "maximum")

#: Ordered from least to most aggressive; a level enables its own features
#: plus every feature of all preceding levels.
_LEVEL_ORDER: tuple[str, ...] = PROTECT_LEVELS

#: Feature name -> the first level at which it becomes active.
FEATURE_LEVELS: dict[str, str] = {
    "debug_reduction": "basic",
    "elf_hardening": "basic",
    "symbol_visibility": "basic",
    "symbol_names": "strong",
    "literal_mangling": "strong",
    "control_flow": "strong",
    "integrity": "maximum",
}

#: Human readable description of every feature, used by ``--protect=help``
#: and by docs/protection.md.
FEATURE_DESCRIPTIONS: dict[str, str] = {
    "debug_reduction": (
        "Drop compiler debug information and Python #line directives from the "
        "generated C, and omit development-only build artifacts."
    ),
    "elf_hardening": (
        "Apply platform-appropriate linker hardening (RELRO, immediate binding, "
        "non-executable stack) when the toolchain supports it."
    ),
    "symbol_visibility": (
        "Hide internal symbols behind default-visibility-only ABI entry points "
        "so that only PyInit_/CPyInit_/export tables remain exported."
    ),
    "symbol_names": (
        "Replace derived-from-source C symbol names with deterministic "
        "content-free names. Python-visible names are never renamed."
    ),
    "literal_mangling": (
        "Encode string and bytes literals in the generated literal tables so "
        "they are not readable with `strings(1)`; decoded once at module init."
    ),
    "control_flow": (
        "Apply semantics-preserving control-flow transformations (branch "
        "inversion, jump trampolines, block reordering) so that the recovered "
        "CFG does not mirror the source structure."
    ),
    "integrity": (
        "Embed a build identity check that can detect post-link modification "
        "of the extension module. Detection only; it does not prevent tampering."
    ),
}


class ProtectError(Exception):
    """Raised for invalid protection configuration."""


def _level_rank(level: str) -> int:
    return _LEVEL_ORDER.index(level)


def features_for_level(level: str) -> frozenset[str]:
    """Return the set of feature names enabled by ``level``."""
    if level == "off":
        return frozenset()
    if level not in _LEVEL_ORDER:
        raise ProtectError(
            f"invalid protect level {level!r}; expected one of {', '.join(PROTECT_LEVELS)}"
        )
    rank = _level_rank(level)
    return frozenset(
        name for name, first in FEATURE_LEVELS.items() if _level_rank(first) <= rank
    )


@dataclass
class ProtectOptions:
    """Resolved protection configuration for a single build.

    This is deliberately a plain dataclass: it is constructed from three
    sources (config file, environment, explicit keyword/CLI argument) and then
    passed around unchanged so that every pass sees the same decision.
    """

    level: str = "off"
    strip: bool = False
    #: Extra features forced on regardless of level (used by the config file's
    #: `features` list and by tests).
    extra_features: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.level not in PROTECT_LEVELS:
            raise ProtectError(
                f"invalid protect level {self.level!r}; "
                f"expected one of {', '.join(PROTECT_LEVELS)}"
            )
        unknown = self.extra_features - FEATURE_LEVELS.keys()
        if unknown:
            raise ProtectError(
                "unknown protect feature(s): " + ", ".join(sorted(unknown))
            )

    @property
    def enabled(self) -> bool:
        return self.level != "off" or self.strip

    @property
    def features(self) -> frozenset[str]:
        base = features_for_level(self.level)
        if self.strip:
            base = base | {"debug_reduction"}
        return base | self.extra_features

    def has(self, feature: str) -> bool:
        if feature not in FEATURE_LEVELS:
            raise ProtectError(f"unknown protect feature {feature!r}")
        return feature in self.features

    def describe(self) -> str:
        """One-line summary suitable for verbose build logs."""
        if not self.enabled:
            return "protect=off"
        active = ", ".join(sorted(self.features))
        suffix = ", strip" if self.strip else ""
        return f"protect={self.level}{suffix} [{active}]"

    # -- construction -------------------------------------------------

    @classmethod
    def from_mapping(cls, data: Any, *, source: str = "config") -> ProtectOptions:
        """Build from a mapping (the parsed `[tool.mypycxazr-protect]` table)."""
        if data is None:
            return cls()
        if not isinstance(data, dict):
            raise ProtectError(f"{source}: expected a table, got {type(data).__name__}")

        kwargs: dict[str, Any] = {}
        known = {"protect", "level", "strip", "protect_strip", "features"}
        for key, value in data.items():
            if key not in known:
                raise ProtectError(f"{source}: unknown key {key!r}")
            if key in ("protect", "level"):
                kwargs["level"] = str(value)
            elif key in ("strip", "protect_strip"):
                kwargs["strip"] = bool(value)
            elif key == "features":
                if not isinstance(value, (list, tuple)):
                    raise ProtectError(f"{source}: 'features' must be a list")
                kwargs["extra_features"] = frozenset(str(v) for v in value)

        if "level" in kwargs and "protect" in data and kwargs["level"] != str(data["protect"]):
            raise ProtectError(f"{source}: both 'protect' and 'level' given but they differ")
        return cls(**kwargs)


def load_config_file(path: str | None = None) -> ProtectOptions:
    """Read `[tool.mypycxazr-protect]` from ``path`` (default: ./pyproject.toml).

    The pre-rename spelling `[tool.mypyc-protect]` is still accepted so a
    config file written for an earlier build keeps working, but naming both
    tables is a configuration error rather than a silent preference.

    Returns default (off) options when the file or the section is absent.
    """
    if path is None:
        path = os.path.join(os.getcwd(), "pyproject.toml")
    if not os.path.exists(path):
        return ProtectOptions()

    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as exc:  # noqa: BLE001 - report and continue with defaults
        raise ProtectError(f"{path}: {exc}") from exc

    tool: Any = data.get("tool", {})
    section = tool.get("mypycxazr-protect") if isinstance(tool, dict) else None
    legacy = tool.get("mypyc-protect") if isinstance(tool, dict) else None
    if section is not None and legacy is not None:
        raise ProtectError(
            f"{path}: both [tool.mypycxazr-protect] and [tool.mypyc-protect] are present; "
            "keep only the first"
        )
    if legacy is not None:
        return ProtectOptions.from_mapping(legacy, source=f"{path}:[tool.mypyc-protect]")
    return ProtectOptions.from_mapping(section, source=f"{path}:[tool.mypycxazr-protect]")


def load_config(
    explicit: ProtectOptions | None = None,
    *,
    config_path: str | None = None,
    use_env: bool = True,
) -> ProtectOptions:
    """Resolve protection options from all sources, in precedence order.

    1. environment variables (``MYPYC_PROTECT``, ``MYPYC_PROTECT_STRIP``)
    2. ``[tool.mypycxazr-protect]`` in pyproject.toml
    3. ``explicit`` options passed programmatically (highest precedence)

    Only the keys actually provided by a higher-precedence source override the
    lower ones, so a CLI flag does not silently discard a configured feature
    list.
    """
    result = load_config_file(config_path)

    if use_env:
        env_level = os.environ.get("MYPYC_PROTECT")
        if env_level:
            result.level = env_level.strip()
        env_strip = os.environ.get("MYPYC_PROTECT_STRIP")
        if env_strip:
            result.strip = env_strip.strip() not in ("", "0", "false", "no", "off")
        # Re-validate after mutation.
        result = ProtectOptions(
            level=result.level, strip=result.strip, extra_features=result.extra_features
        )

    if explicit is not None:
        result = ProtectOptions(
            level=explicit.level,
            strip=explicit.strip or result.strip,
            extra_features=explicit.extra_features | result.extra_features,
        )

    return result
