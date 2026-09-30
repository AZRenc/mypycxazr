from __future__ import annotations

import sys

PROTECT_LEVELS: tuple[str, ...] = ("off", "basic", "strong", "maximum")


class CompilerOptions:
    def __init__(
        self,
        strip_asserts: bool = False,
        multi_file: bool = False,
        verbose: bool = False,
        separate: bool = False,
        target_dir: str | None = None,
        include_runtime_files: bool | None = None,
        capi_version: tuple[int, int] | None = None,
        python_version: tuple[int, int] | None = None,
        strict_dunder_typing: bool = False,
        group_name: str | None = None,
        log_trace: bool = False,
        depends_on_native_internal: bool = False,
        protect: str = "off",
        protect_strip: bool = False,
        protect_features: tuple[str, ...] = (),
    ) -> None:
        self.strip_asserts = strip_asserts
        self.multi_file = multi_file
        self.verbose = verbose
        self.separate = separate
        self.global_opts = not separate
        self.target_dir = target_dir or "build"
        self.include_runtime_files = (
            include_runtime_files if include_runtime_files is not None else not multi_file
        )
        # The target Python C API version. Overriding this is mostly
        # useful in IR tests, since there's no guarantee that
        # binaries are backward compatible even if no recent API
        # features are used.
        self.capi_version = capi_version or sys.version_info[:2]
        self.python_version = python_version
        # Make possible to inline dunder methods in the generated code.
        # Typically, the convention is the dunder methods can return `NotImplemented`
        # even when its return type is just `bool`.
        # By enabling this option, this convention is no longer valid and the dunder
        # will assume the return type of the method strictly, which can lead to
        # more optimization opportunities.
        self.strict_dunders_typing = strict_dunder_typing
        # Override the automatic group name derived from the hash of module names.
        # This affects the names of generated .c, .h and shared library files.
        # This is only supported when compiling exactly one group, and a shared
        # library is generated (with shims). This can be used to make the output
        # file names more predictable.
        self.group_name = group_name
        # If enabled, write a trace log of events based on executed operations to
        # mypyc_trace.txt when compiled module is executed. This is useful for
        # performance analysis.
        self.log_trace = log_trace
        # If enabled, add capsule imports of native_internal API. This should be used
        # only for mypy itself, third-party code compiled with mypyc should not use
        # native_internal.
        self.depends_on_native_internal = depends_on_native_internal

        # ------------------------------------------------------------------
        # MyPyC-Protect
        # ------------------------------------------------------------------
        # Release protection level.  One of PROTECT_LEVELS.  This is *never*
        # enabled implicitly: a caller that wants protection has to ask for it
        # (CLI flag, mypycify() keyword, env var or [tool.mypycxazr-protect]).
        if protect not in PROTECT_LEVELS:
            raise ValueError(
                f"invalid protect level {protect!r}; expected one of "
                f"{', '.join(PROTECT_LEVELS)}"
            )
        self.protect = protect
        # Independent switch: drop development-only debug metadata even when
        # no other protection is requested.  See mypycxazr/protect/metadata.
        self.protect_strip = protect_strip
        # Individual features forced on regardless of the level (comes from
        # `[tool.mypycxazr-protect] features = [...]`).
        if protect_features:
            from mypycxazr.protect.options import FEATURE_LEVELS

            unknown = sorted(set(protect_features) - FEATURE_LEVELS.keys())
            if unknown:
                raise ValueError("unknown protect feature(s): " + ", ".join(unknown))
        self.protect_features = tuple(protect_features)
