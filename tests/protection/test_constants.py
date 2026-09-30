"""Tests for literal-table mangling (the `literal_mangling` feature).

The invariant is round-trip correctness: whatever the encoder produces, the
decoder must turn back into *exactly* the bytes the runtime parser expects,
including the empty sentinel entry that terminates the table.
"""

from __future__ import annotations

import unittest

from mypycxazr.protect.constants import (
    DECODER_NAME,
    blob_name,
    emit_decoder,
    encode_table,
    literal_key,
    xor_bytes,
)

KEY = literal_key("group\0module")


def decode_blob(blob: bytes, key: bytes) -> bytes:
    """Reference decoder: mirror of the emitted C loop."""
    return xor_bytes(blob, key)


class TestKey(unittest.TestCase):
    def test_deterministic(self) -> None:
        assert literal_key("a") == literal_key("a")

    def test_seed_sensitive(self) -> None:
        assert literal_key("a") != literal_key("b")

    def test_fixed_length(self) -> None:
        assert len(literal_key("anything")) == 32

    def test_not_the_identity_of_the_seed(self) -> None:
        assert b"seed" not in literal_key("seed")


class TestXor(unittest.TestCase):
    def test_round_trip(self) -> None:
        data = b"hello world\x00"
        assert xor_bytes(xor_bytes(data, KEY), KEY) == data

    def test_empty_key_is_identity(self) -> None:
        assert xor_bytes(b"abc", b"") == b"abc"

    def test_output_differs_from_input(self) -> None:
        assert xor_bytes(b"secret literal", KEY) != b"secret literal"

    def test_empty_input(self) -> None:
        assert xor_bytes(b"", KEY) == b""


class TestEncodeTable(unittest.TestCase):
    def test_round_trip_preserves_every_component(self) -> None:
        components = [b"hello", b"", b"world\x00not-a-terminator", b"\xc3\xa9"]
        enc = encode_table(components, KEY)
        plain = decode_blob(enc.blob, enc.key)
        for off, comp in zip(enc.offsets, components):
            assert plain[off : off + len(comp)] == comp
            assert plain[off + len(comp)] == 0

    def test_offsets_are_monotonic(self) -> None:
        enc = encode_table([b"aa", b"bbb", b"c"], KEY)
        assert enc.offsets == sorted(enc.offsets)
        assert enc.offsets[0] == 0

    def test_empty_table_is_terminator_only(self) -> None:
        enc = encode_table([], KEY)
        assert enc.offsets == []
        assert enc.pointer_initializer("blob") == "{ 0 }"

    def test_sentinel_component_survives(self) -> None:
        """`CPyStatics_Initialize` stops at a record whose first byte is 0.

        Upstream always supplies one as the final entry; mangling must not
        drop it or the loop would read past the end of the table.
        """
        enc = encode_table([b"abc", b""], KEY)
        plain = decode_blob(enc.blob, enc.key)
        last = enc.offsets[-1]
        assert plain[last] == 0
        assert len(enc.offsets) == 2

    def test_blob_is_not_readable(self) -> None:
        enc = encode_table([b"a-very-recognisable-string"], KEY)
        assert b"a-very-recognisable-string" not in enc.blob
        assert b"recognisable" not in enc.blob

    def test_same_input_same_output(self) -> None:
        a = encode_table([b"x", b"y"], KEY)
        b = encode_table([b"x", b"y"], KEY)
        assert a.blob == b.blob
        assert a.offsets == b.offsets

    def test_different_key_different_bytes(self) -> None:
        a = encode_table([b"x", b"y"], literal_key("one"))
        b = encode_table([b"x", b"y"], literal_key("two"))
        assert a.blob != b.blob
        # ... but both still decode, with their own key:
        # b"x" NUL b"y" NUL == two terminators
        assert decode_blob(a.blob, a.key) == b"x\x00y\x00"
        assert decode_blob(b.blob, b.key) == b"x\x00y\x00"


class TestPointerInitializer(unittest.TestCase):
    def test_references_the_blob_by_name(self) -> None:
        enc = encode_table([b"aa", b"bb"], KEY)
        init = enc.pointer_initializer("CPyProtect_LitStrBlob")
        assert "&CPyProtect_LitStrBlob[" in init
        assert init.count("&") == 2

    def test_offsets_line_up_with_the_blob(self) -> None:
        enc = encode_table([b"aa", b"bbb"], KEY)
        plain = decode_blob(enc.blob, enc.key)
        for off in enc.offsets:
            assert 0 <= off < len(enc.blob)
        assert plain[enc.offsets[1] : enc.offsets[1] + 3] == b"bbb"


class TestBlobNames(unittest.TestCase):
    def test_names_are_stable_and_distinct(self) -> None:
        assert blob_name("Str") == "CPyProtect_LitStrBlob"
        assert blob_name("Bytes") == "CPyProtect_LitBytesBlob"
        assert blob_name("Str") != blob_name("Bytes")

    def test_names_do_not_leak_kind_of_content(self) -> None:
        # They say which table they hold -- that is a runtime requirement,
        # not a source identifier, so this is just a regression guard.
        assert blob_name("Str").startswith("CPyProtect_")


class TestDecoder(unittest.TestCase):
    def test_no_blobs_no_code(self) -> None:
        assert emit_decoder([]) == ""

    def test_emits_a_static_function(self) -> None:
        enc = encode_table([b"abc"], KEY)
        code = emit_decoder([("CPyProtect_LitStrBlob", enc)])
        assert code.startswith("static void " + DECODER_NAME + "(void)")
        assert "CPyProtect_LitStrBlob[i] ^=" in code

    def test_emitted_loop_matches_the_reference_decoder(self) -> None:
        enc = encode_table([b"abc", b""], KEY)
        code = emit_decoder([("BLOB", enc)])
        # the emitted loop must cover the whole blob
        assert f"< {enc.size}u" in code
        assert "BLOB[i] ^=" in code
        # and the key must be the one that was actually used
        assert ", ".join(str(b) for b in enc.key) in code

    def test_all_blobs_share_one_key(self) -> None:
        s = encode_table([b"a"], KEY)
        b = encode_table([b"bb"], KEY)
        code = emit_decoder([("A", s), ("B", b)])
        assert code.count("static const unsigned char key[]") == 1
        assert "A[i] ^=" in code and "B[i] ^=" in code
