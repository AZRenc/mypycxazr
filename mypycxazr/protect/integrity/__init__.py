"""Integrity self-check (``maximum`` only): detection, not prevention.

Threat model
------------
The other features make the module *harder to read*.  This one makes it
*louder* if somebody edits it after the build: an attacker who patches
``PyInit_`` to disable a check, swaps a literal, or rewrites a branch gets a
module that refuses to import instead of one that quietly does the wrong
thing.

It is explicitly **not** tamper-proof.  Anyone who can rewrite the binary can
also rewrite this check; the goal is to raise the bar from "edit a byte with
a hex editor" to "re-implement the scheme", and to make accidental corruption
and naive patching obvious.

How it works
------------
1. Codegen emits a fixed 16-byte block into the module: an 8-byte magic
   followed by an 8-byte, all-zero digest slot.
2. After linking, :func:`stamp` reads the finished file, computes
   FNV-1a-64 over every byte while treating the digest slot as zero, and
   writes the result into the slot.  Stamping is the last build step so that
   nothing (``strip`` included) invalidates it.
3. At import time the generated ``CPyProtect_VerifyIntegrity`` re-reads the
   module file through ``module.__file__``, recomputes the same hash and
   compares.  A mismatch raises ``RuntimeError`` and the import fails.

If ``__file__`` is unavailable the check is skipped rather than failing an
otherwise healthy import -- see ``docs/security-model.md``.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

#: First 8 bytes of the emitted block.  Chosen to be distinctive so that
#: scanning the file for it cannot be confused with ordinary data.
MAGIC = b"MyPyCPr1"

#: magic + u64 digest, laid out exactly as codegen emits it.
BLOCK_SIZE = len(MAGIC) + 8

assert len(MAGIC) == 8, "the emitted block hardcodes an 8-byte magic"

#: FNV-1a 64-bit parameters (public domain; identical on both sides).
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3

#: C name of the emitted block.
BLOCK_NAME = "CPyProtect_IntegrityBlock"

#: C name of the generated verifier.
VERIFY_NAME = "CPyProtect_VerifyIntegrity"


class IntegrityError(Exception):
    """Raised when a module file cannot be stamped or verified."""


def fnv1a64(data: bytes, h: int = FNV_OFFSET) -> int:
    """FNV-1a over ``data``, starting from ``h``."""
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def find_block(data: bytes) -> int:
    """Offset of the single integrity block, or raise :class:`IntegrityError`.

    A second match means the file was patched carelessly (or a future toolchain
    happened to reproduce the magic); either way the file is ambiguous and we
    refuse to touch it.
    """
    hits: list[int] = []
    start = 0
    while True:
        i = data.find(MAGIC, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
        if len(hits) > 1:
            break
    if not hits:
        raise IntegrityError("integrity block not found: was the module built with protect=maximum?")
    if len(hits) > 1:
        raise IntegrityError(f"integrity block found {len(hits)} times; refusing to guess")
    if hits[0] + BLOCK_SIZE > len(data):
        raise IntegrityError("integrity block is truncated")
    return hits[0]


def file_digest(data: bytes, block_offset: int) -> int:
    """FNV-1a of ``data`` with the 8-byte digest slot treated as zero."""
    head = data[: block_offset + len(MAGIC)]
    tail = data[block_offset + BLOCK_SIZE :]
    return fnv1a64(head + b"\0" * 8 + tail)


def read_digest(data: bytes, block_offset: int) -> int:
    start = block_offset + len(MAGIC)
    raw = data[start : start + 8]
    if len(raw) != 8:
        raise IntegrityError("integrity block is truncated")
    return int.from_bytes(raw, "little")


def stamp(path: str) -> int:
    """Write the digest of ``path`` into its integrity block.

    Returns the digest that was written.  Idempotent: stamping twice with an
    unchanged file yields the same value.
    """
    with open(path, "rb") as f:
        data = bytearray(f.read())
    offset = find_block(bytes(data))
    digest = file_digest(bytes(data), offset)
    data[offset + len(MAGIC) : offset + BLOCK_SIZE] = digest.to_bytes(8, "little")
    with open(path, "wb") as f:
        f.write(data)
    return digest


def verify(path: str) -> bool:
    """True when ``path`` matches the digest stamped into it."""
    with open(path, "rb") as f:
        data = f.read()
    offset = find_block(data)
    return file_digest(data, offset) == read_digest(data, offset)


def build_identity(*, level: str, seed: str, modules: list[str], extra: str = "") -> bytes:
    """Stable 32-byte identity of a protected build.

    Used by the reproducibility tests: two builds of the same inputs with the
    same seed must produce the same identity, and changing any input must
    change it.
    """
    h = hashlib.sha256()
    h.update(b"mypyc-protect\0")
    h.update(level.encode() + b"\0")
    h.update(seed.encode("utf-8", "surrogateescape") + b"\0")
    for m in modules:
        h.update(m.encode("utf-8", "surrogateescape") + b"\0")
    h.update(extra.encode("utf-8", "surrogateescape"))
    return h.digest()


def integrity_c_code() -> str:
    """C source for the runtime verifier, emitted into ``__native.c``.

    Kept here (rather than as a string literal in codegen) so that the C side
    and the Python side of the same scheme live in one file and can be
    reviewed together.

    Locating the module file is the fiddly part: ``module.__file__`` is not
    populated yet when a single-phase extension's exec function runs, so the
    primary route is ``dladdr()`` on the block itself, which answers "which
    object file is this address in?" for any linked-in symbol.  ``__file__``
    remains as a fallback for toolchains without dladdr.
    """
    magic = ", ".join(f"'{c}'" for c in MAGIC.decode("ascii"))
    lit = MAGIC.decode("ascii")
    return f"""#if defined(__unix__) || defined(__APPLE__)
#include <dlfcn.h>
#define MYPYC_PROTECT_DLADDR 1
#endif

/* volatile so the compiler cannot fold the check below into a constant and
   then delete the block as unused; const would let it do exactly that. */
static volatile unsigned char {BLOCK_NAME}[{BLOCK_SIZE}] = {{ {magic}, 0,0,0,0,0,0,0,0 }};

static unsigned long long CPyProtect_Fnv1a(const unsigned char *p, size_t n, unsigned long long h)
{{
    while (n--) {{
        h ^= (unsigned long long)*p++;
        h *= 1099511628211ULL;
    }}
    return h;
}}

/* Locate this object file on disk.  Returns 0 and sets *out to the path, or
   returns 0 without a path when the module cannot be located at all. */
static int CPyProtect_ModulePath(PyObject *module, const char **out)
{{
    PyObject *fileobj;
    static char buf[4096];
    const char *p;

    *out = NULL;
#ifdef MYPYC_PROTECT_DLADDR
    {{
        Dl_info info;
        if (dladdr((void *)(size_t)&{BLOCK_NAME}[0], &info) && info.dli_fname
            && info.dli_fname[0] == '/') {{
            *out = info.dli_fname;
            return 1;
        }}
    }}
#endif
    fileobj = PyObject_GetAttrString(module, "__file__");
    if (fileobj == NULL) {{
        PyErr_Clear();
        return 0;
    }}
    if (PyUnicode_Check(fileobj)) {{
        p = PyUnicode_AsUTF8(fileobj);
        if (p != NULL && strlen(p) < sizeof(buf)) {{
            strcpy(buf, p);
            *out = buf;
            Py_DECREF(fileobj);
            return 1;
        }}
    }}
    Py_DECREF(fileobj);
    PyErr_Clear();
    return 0;
}}

/* Recompute the digest of the module file and compare it with the value
   stamped in after linking.  Returns 0 when the file is intact or when it
   cannot be located (see docs/security-model.md); -1 with an exception set
   when the file has been modified. */
static int {VERIFY_NAME}(PyObject *module)
{{
    const char *path = NULL;
    FILE *f;
    long size;
    unsigned char *buf;
    size_t i, hit = 0, hits = 0;
    unsigned long long stored, calc;

    /* Keep the block alive even if nothing else references it. */
    if ({BLOCK_NAME}[0] != '{lit[0]}') {{
        PyErr_SetString(PyExc_RuntimeError, "MyPyC-Protect: integrity block corrupted");
        return -1;
    }}

    if (!CPyProtect_ModulePath(module, &path) || path == NULL)
        return 0;  /* nothing to verify against: do not break the import */

    f = fopen(path, "rb");
    if (f == NULL)
        return 0;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 || size < {BLOCK_SIZE}) {{
        fclose(f);
        return 0;
    }}
    rewind(f);
    buf = (unsigned char *)PyMem_Malloc((size_t)size);
    if (buf == NULL || fread(buf, 1, (size_t)size, f) != (size_t)size) {{
        PyMem_Free(buf);
        fclose(f);
        return 0;
    }}
    fclose(f);

    for (i = 0; i + {BLOCK_SIZE} <= (size_t)size; i++) {{
        if (memcmp(buf + i, "{lit}", {len(MAGIC)}) == 0) {{
            hits++;
            hit = i;
            if (hits > 1) break;
        }}
    }}
    if (hits != 1) {{
        PyErr_SetString(PyExc_RuntimeError, "MyPyC-Protect: integrity block not found or duplicated");
        PyMem_Free(buf);
        return -1;
    }}

    stored = 0;
    for (i = 0; i < 8; i++)
        stored |= ((unsigned long long)buf[hit + {len(MAGIC)} + i]) << (8 * i);
    memset(buf + hit + {len(MAGIC)}, 0, 8);
    calc = CPyProtect_Fnv1a(buf, (size_t)size, 14695981039346656037ULL);
    PyMem_Free(buf);

    if (calc != stored) {{
        PyErr_SetString(PyExc_RuntimeError, "MyPyC-Protect: module failed its integrity check");
        return -1;
    }}
    return 0;
}}
"""


def has_block(path: str) -> bool:
    """True when ``path`` contains an integrity block."""
    try:
        with open(path, "rb") as f:
            return MAGIC in f.read()
    except OSError:
        return False


def install_stamp_hook() -> bool:
    """Make setuptools stamp every extension it finishes linking.

    Stamping has to happen *after* the final link (and after any ``strip``),
    because both change the bytes being hashed.  The only place that reliably
    knows "the link is done" is ``build_ext.build_extension``, so that is what
    we wrap.  Extensions that carry no block -- helper libraries, or a build
    that is not running at ``maximum`` -- are left alone.

    Returns False when setuptools is unavailable, so callers can report that
    the build will produce an unstamped module.
    """
    try:
        from setuptools.command.build_ext import build_ext
    except ImportError:
        return False

    if getattr(build_ext, "_mypyc_protect_stamp", False):
        return True

    original = build_ext.build_extension

    def build_extension(self: Any, ext: Any) -> Any:
        result = original(self, ext)
        try:
            path = self.get_ext_fullpath(ext.name)
        except Exception:  # noqa: BLE001 - never fail the build over stamping
            path = None
        if path and os.path.exists(path) and has_block(path):
            stamp(path)
        return result

    build_extension.__name__ = "build_extension"
    build_extension.__doc__ = original.__doc__
    build_ext.build_extension = build_extension  # type: ignore[method-assign]
    build_ext._mypyc_protect_stamp = True  # type: ignore[attr-defined]
    return True
