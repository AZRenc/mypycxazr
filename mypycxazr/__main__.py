"""mypycxazr command-line tool (mypyc fork with MyPyC-Protect).

Usage:

    $ mypycxazr foo.py [...]
    $ python3 -c 'import foo'  # Uses compiled 'foo'

MyPyC-Protect options:

    $ mypycxazr --protect=basic foo.py      # hide symbols, drop debug metadata
    $ mypycxazr --protect=strong foo.py     # + obfuscated symbol names, literals,
                                        #   control-flow hardening
    $ mypycxazr --protect=maximum foo.py    # + integrity self-check
    $ mypycxazr --protect-strip foo.py      # only drop development metadata
    $ mypycxazr --protect=help              # list levels and features

The level can also be given in ``pyproject.toml``::

    [tool.mypycxazr-protect]
    protect = "strong"

or through the ``MYPYC_PROTECT`` / ``MYPYC_PROTECT_STRIP`` environment
variables.  An explicit command-line flag always wins.

This is just a thin wrapper that generates a setup.py file that uses
mypycify, suitable for prototyping and testing.
"""

from __future__ import annotations

import os
import os.path
import subprocess
import sys

from mypycxazr.protect.options import (
    FEATURE_DESCRIPTIONS,
    FEATURE_LEVELS,
    PROTECT_LEVELS,
    ProtectError,
)

base_path = os.path.join(os.path.dirname(__file__), "..")

setup_format = """\
from setuptools import setup
from mypycxazr.build import mypycify

setup(
    name='mypyc_output',
    ext_modules=mypycify(
        {},
        opt_level="{}",
        debug_level="{}",
        strict_dunder_typing={},
        log_trace={},
        protect={},
        protect_strip={},
    ),
)
"""


def _print_protect_help() -> None:
    print("MyPyC-Protect levels:")
    print()
    print("  --protect=off       no protection (default; identical to mypyc)")
    print("  --protect=basic     " + ", ".join(sorted(
        f for f, lvl in FEATURE_LEVELS.items() if lvl == "basic"
    )))
    print("  --protect=strong    adds " + ", ".join(sorted(
        f for f, lvl in FEATURE_LEVELS.items() if lvl == "strong"
    )))
    print("  --protect=maximum   adds " + ", ".join(sorted(
        f for f, lvl in FEATURE_LEVELS.items() if lvl == "maximum"
    )))
    print("  --protect-strip     drop development debug metadata only")
    print()
    print("Features:")
    for name in sorted(FEATURE_DESCRIPTIONS):
        print(f"  {name:20s} first level: {FEATURE_LEVELS[name]}")
        print(f"  {'':20s} {FEATURE_DESCRIPTIONS[name]}")
    print()
    print("Valid levels: " + ", ".join(PROTECT_LEVELS))


def parse_protect_args(argv: list[str]) -> tuple[list[str], str | None, bool]:
    """Split MyPyC-Protect options out of a mypyc command line.

    Returns ``(rest, protect, protect_strip)`` where ``protect`` is ``None``
    when the caller did not specify a level (and configuration decides).
    """
    rest: list[str] = []
    protect: str | None = None
    strip = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--protect=help" or arg == "--protect-help":
            _print_protect_help()
            raise SystemExit(0)
        if arg.startswith("--protect="):
            protect = arg.split("=", 1)[1]
        elif arg == "--protect":
            if i + 1 >= len(argv):
                raise SystemExit("error: --protect requires a value")
            i += 1
            protect = argv[i]
            if protect == "help":
                _print_protect_help()
                raise SystemExit(0)
        elif arg == "--protect-strip":
            strip = True
        else:
            rest.append(arg)
        i += 1

    if protect is not None and protect not in PROTECT_LEVELS:
        raise SystemExit(
            f"error: invalid --protect level {protect!r}; "
            f"expected one of {', '.join(PROTECT_LEVELS)} (try --protect=help)"
        )
    return rest, protect, strip


def main() -> None:
    build_dir = "build"  # can this be overridden??
    try:
        os.mkdir(build_dir)
    except FileExistsError:
        pass

    argv, protect, protect_strip = parse_protect_args(sys.argv[1:])

    opt_level = os.getenv("MYPYC_OPT_LEVEL", "3")
    debug_level = os.getenv("MYPYC_DEBUG_LEVEL", "1")
    strict_dunder_typing = bool(int(os.getenv("MYPYC_STRICT_DUNDER_TYPING", "0")))
    # If enabled, compiled code writes a sampled log of executed ops (or events) to
    # mypyc_trace.txt.
    log_trace = bool(int(os.getenv("MYPYC_LOG_TRACE", "0")))

    # A debug build must never silently acquire release protection.
    if opt_level == "0" and protect not in (None, "off"):
        print(
            f"error: --protect={protect} cannot be combined with MYPYC_OPT_LEVEL=0 "
            "(debug builds do not run protection passes)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if opt_level == "0" and protect_strip:
        print(
            "error: --protect-strip cannot be combined with MYPYC_OPT_LEVEL=0",
            file=sys.stderr,
        )
        raise SystemExit(2)

    setup_file = os.path.join(build_dir, "setup.py")
    with open(setup_file, "w") as f:
        f.write(
            setup_format.format(
                argv,
                opt_level,
                debug_level,
                strict_dunder_typing,
                log_trace,
                repr(protect),
                repr(bool(protect_strip)),
            )
        )

    # We don't use run_setup (like we do in the test suite) because it throws
    # away the error code from distutils, and we don't care about the slight
    # performance loss here.
    env = os.environ.copy()
    base_path = os.path.join(os.path.dirname(__file__), "..")
    env["PYTHONPATH"] = base_path + os.pathsep + env.get("PYTHONPATH", "")
    cmd = subprocess.run([sys.executable, setup_file, "build_ext", "--inplace"], env=env)
    sys.exit(cmd.returncode)


if __name__ == "__main__":
    try:
        main()
    except ProtectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
