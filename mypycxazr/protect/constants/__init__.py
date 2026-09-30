"""Constant / data handling (spec section 7).

What this does
--------------
String and bytes literals are one of the loudest sources of source-level
information in a compiled extension: ``strings(1)`` on a normal mypyc build
prints every literal the program contains, in order.

At ``strong`` and above the literal *descriptions* that mypyc writes into
``CPyLit_Str`` / ``CPyLit_Bytes`` are XOR-obfuscated with a per-group key.
The tables are emitted into a mutable blob and decoded once, in place, at the
top of ``CPyGlobalsInit()``, immediately before ``CPyStatics_Initialize()``.
Runtime behaviour is bit-for-bit identical: the decoder runs before any
literal is read, and Python objects are constructed from exactly the same
bytes as before.

What this does NOT do
---------------------
* It is **not** encryption in any meaningful sense.  The key and the decoding
  loop are both in the binary; anyone with a debugger can recover the
  plaintext.  The goal is only to defeat naive ``strings``/``hexdump``
  inspection and to raise the cost of bulk extraction.
* No private key, API token or other genuine secret may ever be placed in the
  compiler output.  If you need a secret, it does not belong in the binary.
* Names that Python requires at runtime (method names in ``PyModuleDef``,
  ``__qualname__``, traceback filenames, docstrings) are never touched,
  because changing them would change observable Python behaviour.

See docs/security-model.md for the resulting residual exposure.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field



def literal_key(seed: str) -> bytes:
    """Deterministic 16-byte key derived from ``seed``.

    The seed is the compilation group identity, so identical inputs give
    identical output (reproducible builds) while two unrelated projects do
    not share a key.
    """
    return hashlib.sha256(("mypyc-protect-literals\0" + seed).encode("utf-8")).digest()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


@dataclass
class EncodedBlob:
    """A mangled literal table, ready to be emitted as C."""

    #: Contents of the mutable blob (already obfuscated).
    blob: bytes
    #: Byte offset of each original table entry inside ``blob``.
    offsets: list[int] = field(default_factory=list)
    #: The key used, emitted verbatim so the decoder can reverse it.
    key: bytes = b""

    def pointer_initializer(self, blob_name: str) -> str:
        if not self.offsets:
            return "{ 0 }"
        return "{\n" + "".join(
            f"    &{blob_name}[{off}],\n" for off in self.offsets
        ) + "}"

    @property
    def size(self) -> int:
        return len(self.blob)


DECODER_NAME = "CPyProtect_DecodeLiterals"


def blob_name(kind: str) -> str:
    """Name of the mutable blob for a literal table (``kind``: ``Str``/``Bytes``)."""
    return f"CPyProtect_Lit{kind}Blob"


def encode_table(components: list[bytes], key: bytes) -> EncodedBlob:
    """Pack ``components`` into one obfuscated blob.

    Each component becomes a NUL-terminated record, matching what
    ``c_string_array_initializer`` would have produced unobfuscated, so the
    runtime parser in ``CPyStatics_Initialize`` sees exactly the same bytes
    after decoding.
    """
    offsets: list[int] = []
    plain = bytearray()
    for comp in components:
        offsets.append(len(plain))
        plain.extend(comp)
        plain.append(0)
    return EncodedBlob(blob=xor_bytes(bytes(plain), key), offsets=offsets, key=key)


def emit_decoder(blobs: list[tuple[str, EncodedBlob]]) -> str:
    """C source for the in-place decoder (a static function)."""
    if not blobs:
        return ""
    key = blobs[0][1].key
    lines = [
        "static void " + DECODER_NAME + "(void)",
        "{",
        "    static const unsigned char key[] = {"
        + ", ".join(str(b) for b in key)
        + "};",
        "    size_t i;",
        "    size_t klen = sizeof(key);",
    ]
    for name, blob in blobs:
        lines.append(f"    for (i = 0; i < {blob.size}u; i++)")
        lines.append(f"        {name}[i] ^= (char)key[i % klen];")
    lines.append("}")
    return "\n".join(lines) + "\n"

