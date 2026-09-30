"""Tests for the integrity self-check (the `integrity` feature, `maximum` only).

Two halves are covered here: the pure-Python hashing/stamping side (fast,
always runnable) and the end-to-end behaviour of a real protected module
(skipped when no pre-built fixture is available).
"""

from __future__ import annotations

import os
import tempfile
import unittest

from mypycxazr.protect.integrity import (
    BLOCK_SIZE,
    MAGIC,
    VERIFY_NAME,
    build_identity,
    file_digest,
    find_block,
    fnv1a64,
    has_block,
    integrity_c_code,
    read_digest,
    stamp,
    verify,
)


def make_module(*payload: bytes) -> bytes:
    """A stand-in for an ELF file: payload, block, payload."""
    return b"".join(payload[:1]) + MAGIC + b"\0" * 8 + b"".join(payload[1:])


class TestConstants(unittest.TestCase):
    def test_magic_is_eight_bytes(self) -> None:
        self.assertEqual(len(MAGIC), 8)
        self.assertEqual(BLOCK_SIZE, 16)

    def test_magic_is_ascii(self) -> None:
        MAGIC.decode("ascii")


class TestFnv1a(unittest.TestCase):
    def test_known_vectors(self) -> None:
        # Published FNV-1a 64-bit test vectors.
        self.assertEqual(fnv1a64(b""), 0xCBF29CE484222325)
        self.assertEqual(fnv1a64(b"a"), 0xAF63DC4C8601EC8C)
        self.assertEqual(fnv1a64(b"foobar"), 0x85944171F73967E8)

    def test_single_byte_changes_the_hash(self) -> None:
        self.assertNotEqual(fnv1a64(b"aaaa"), fnv1a64(b"aaab"))

    def test_chained_calls_match_one_shot(self) -> None:
        h = fnv1a64(b"foo")
        self.assertEqual(fnv1a64(b"bar", h), fnv1a64(b"foobar"))


class TestFindBlock(unittest.TestCase):
    def test_finds_a_single_block(self) -> None:
        data = b"header" + MAGIC + b"\0" * 8 + b"trailer"
        self.assertEqual(find_block(data), 6)

    def test_missing_block_raises(self) -> None:
        with self.assertRaises(Exception) as ctx:
            find_block(b"no block here")
        self.assertIn("not found", str(ctx.exception))

    def test_duplicate_block_raises(self) -> None:
        data = MAGIC + b"\0" * 8 + b"x" + MAGIC + b"\0" * 8
        with self.assertRaises(Exception) as ctx:
            find_block(data)
        self.assertIn("2 times", str(ctx.exception))

    def test_truncated_block_raises(self) -> None:
        with self.assertRaises(Exception):
            find_block(b"prefix" + MAGIC[:4])

    def test_has_block(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            yes = os.path.join(d, "yes.bin")
            no = os.path.join(d, "no.bin")
            with open(yes, "wb") as f:
                f.write(make_module(b"a", b"b"))
            with open(no, "wb") as f:
                f.write(b"plain")
            self.assertTrue(has_block(yes))
            self.assertFalse(has_block(no))
            self.assertFalse(has_block(os.path.join(d, "missing.bin")))


class TestStampAndVerify(unittest.TestCase):
    def _write(self, payload: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        self.addCleanup(os.unlink, path)
        return path

    def test_round_trip(self) -> None:
        path = self._write(make_module(b"code-bytes-here", b"and-more"))
        stamp(path)
        self.assertTrue(verify(path))

    def test_stamp_writes_a_nonzero_digest(self) -> None:
        path = self._write(make_module(b"payload"))
        with open(path, "rb") as f:
            before = f.read()
        self.assertEqual(
            read_digest(before, find_block(before)), 0, "digest slot should start zeroed"
        )
        digest = stamp(path)
        self.assertNotEqual(digest, 0)
        with open(path, "rb") as f:
            after = f.read()
        self.assertEqual(read_digest(after, find_block(after)), digest)

    def test_tampering_is_detected(self) -> None:
        path = self._write(make_module(b"AAA", b"BBB"))
        stamp(path)
        self.assertTrue(verify(path))
        with open(path, "rb") as f:
            data = bytearray(f.read())
        data[0] ^= 0x01  # flip a byte outside the block
        with open(path, "wb") as f:
            f.write(data)
        self.assertFalse(verify(path))

    def test_tampering_inside_the_block_is_detected(self) -> None:
        path = self._write(make_module(b"AAA"))
        stamp(path)
        with open(path, "rb") as f:
            data = bytearray(f.read())
        data[find_block(bytes(data))] ^= 0x01  # corrupt the magic
        with open(path, "wb") as f:
            f.write(data)
        # the block is no longer recognisable, so this is a hard failure
        # rather than a quiet pass
        with self.assertRaises(Exception):
            verify(path)

    def test_stamp_is_idempotent(self) -> None:
        path = self._write(make_module(b"payload"))
        first = stamp(path)
        second = stamp(path)
        self.assertEqual(first, second)
        self.assertTrue(verify(path))

    def test_unstamped_block_does_not_verify(self) -> None:
        path = self._write(make_module(b"payload"))
        self.assertFalse(verify(path))

    def test_file_digest_ignores_the_digest_slot(self) -> None:
        a = MAGIC + b"\0" * 8 + b"tail"
        b = MAGIC + b"\xff" * 8 + b"tail"
        self.assertEqual(file_digest(a, 0), file_digest(b, 0))


class TestBuildIdentity(unittest.TestCase):
    def test_deterministic(self) -> None:
        kw = dict(level="maximum", seed="s", modules=["a", "b"])
        self.assertEqual(build_identity(**kw), build_identity(**kw))

    def test_seed_changes_it(self) -> None:
        self.assertNotEqual(
            build_identity(level="strong", seed="one", modules=["m"]),
            build_identity(level="strong", seed="two", modules=["m"]),
        )

    def test_modules_change_it(self) -> None:
        self.assertNotEqual(
            build_identity(level="strong", seed="s", modules=["a"]),
            build_identity(level="strong", seed="s", modules=["b"]),
        )

    def test_level_changes_it(self) -> None:
        self.assertNotEqual(
            build_identity(level="strong", seed="s", modules=["m"]),
            build_identity(level="maximum", seed="s", modules=["m"]),
        )

    def test_is_32_bytes(self) -> None:
        self.assertEqual(
            len(build_identity(level="strong", seed="", modules=[])), 32
        )


class TestEmittedCode(unittest.TestCase):
    def test_declares_the_block(self) -> None:
        code = integrity_c_code()
        self.assertIn(f"unsigned char CPyProtect_IntegrityBlock[{BLOCK_SIZE}]", code)
        self.assertIn("volatile", code)

    def test_declares_the_verifier(self) -> None:
        code = integrity_c_code()
        self.assertIn(f"static int {VERIFY_NAME}(PyObject *module)", code)
        self.assertIn("PyExc_RuntimeError", code)

    def test_falls_back_when_the_path_is_unknown(self) -> None:
        code = integrity_c_code()
        self.assertIn("CPyProtect_ModulePath", code)
        self.assertIn("return 0;", code)
        self.assertIn("dladdr", code)

    def test_contains_the_same_magic_as_python(self) -> None:
        self.assertIn(MAGIC.decode("ascii"), integrity_c_code())

    def test_uses_the_same_fnv_prime(self) -> None:
        self.assertIn("1099511628211ULL", integrity_c_code())

    def test_is_not_empty(self) -> None:
        self.assertGreater(len(integrity_c_code()), 500)


class TestStampHook(unittest.TestCase):
    def test_hook_installs_once(self) -> None:
        from mypycxazr.protect.integrity import install_stamp_hook

        try:
            from setuptools.command.build_ext import build_ext
        except ImportError:
            self.skipTest("setuptools not available")

        already = getattr(build_ext, "_mypyc_protect_stamp", False)
        self.assertTrue(install_stamp_hook())
        self.assertTrue(getattr(build_ext, "_mypyc_protect_stamp", False))
        # installing twice must not stack wrappers
        first = build_ext.build_extension
        self.assertTrue(install_stamp_hook())
        self.assertIs(build_ext.build_extension, first)
        if not already:
            # leave the interpreter as we found it for other test modules
            delattr(build_ext, "_mypyc_protect_stamp")
            del build_ext.build_extension


class TestCodegenIntegration(unittest.TestCase):
    """The generated C must contain the block -- and only when asked."""

    @staticmethod
    def _generate(tmp: str, level: str) -> str:
        from mypycxazr.build import mypycify

        src = os.path.join(tmp, "modprobe.py")
        with open(src, "w", encoding="utf-8") as f:
            f.write("def modprobe(x: int) -> int:\n    return x + 1\n")
        out = os.path.join(tmp, "out")
        mypycify([src], target_dir=out, protect=level)
        path = os.path.join(out, "__native.c")
        with open(path, encoding="utf-8") as f:
            return f.read()

    def test_maximum_emits_block_and_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code = self._generate(tmp, "maximum")
        self.assertIn("CPyProtect_IntegrityBlock", code)
        self.assertIn(f"static int {VERIFY_NAME}(PyObject *module)", code)
        self.assertIn(f"{VERIFY_NAME}(module)", code)

    def test_strong_emits_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code = self._generate(tmp, "strong")
        self.assertNotIn("CPyProtect_IntegrityBlock", code)
        self.assertNotIn(VERIFY_NAME, code)

    def test_off_emits_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code = self._generate(tmp, "off")
        self.assertNotIn(VERIFY_NAME, code)
        self.assertNotIn("CPyProtect_IntegrityBlock", code)


if __name__ == "__main__":
    unittest.main()
