"""Kiểm thử 2 chiều trace, vector chuẩn và dữ liệu nhiều khối."""
import random
import unittest

from des.core import encrypt_block, decrypt_block, generate_subkeys
from des.data import encrypt_data, decrypt_data, encrypt_file, decrypt_file
from des.trace import trace_encrypt_block, trace_decrypt_block
from des.examples import DEMO_CASES
from pathlib import Path
from tempfile import TemporaryDirectory


class TestDESWorkflow(unittest.TestCase):
    def test_demo_cases(self):
        for case in DEMO_CASES:
            with self.subTest(case=case.name):
                p, k = bytes.fromhex(case.plain_hex), bytes.fromhex(case.key_hex)
                c = encrypt_data(p, k)
                self.assertEqual(decrypt_data(c, k), p)
                if case.expected_cipher_hex:
                    self.assertEqual(c.hex().upper(), case.expected_cipher_hex)

    def test_trace_both_directions_40_pairs(self):
        rng = random.Random(20261021)
        for _ in range(40):
            p, k = rng.randbytes(8), rng.randbytes(8)
            encrypt_trace = trace_encrypt_block(p, k)
            c = encrypt_block(p, k)
            self.assertEqual(c, encrypt_trace.ciphertext)
            self.assertEqual(len(encrypt_trace.rounds), 16)
            self.assertEqual(tuple(r.subkey48 for r in encrypt_trace.rounds), tuple(generate_subkeys(k)))
            decrypt_trace = trace_decrypt_block(c, k)
            self.assertEqual(decrypt_trace.plaintext, p)
            self.assertEqual(decrypt_trace.output_block, decrypt_block(c, k))
            self.assertEqual(len(decrypt_trace.rounds), 16)
            self.assertEqual(tuple(r.key_index for r in decrypt_trace.rounds), tuple(range(16, 0, -1)))
            for t in (encrypt_trace, decrypt_trace):
                for r in t.rounds:
                    self.assertEqual(r.left_after, r.right_before)
                    self.assertEqual(r.right_after, r.left_before ^ r.f_output32)
                    self.assertEqual(r.expanded48 ^ r.subkey48, r.mixed48)
                    self.assertEqual(len(r.sboxes), 8)
                    x = 0
                    for s in r.sboxes:
                        self.assertTrue(0 <= s.row < 4)
                        self.assertTrue(0 <= s.column < 16)
                        x = (x << 4) | s.output4
                    self.assertEqual(x, r.sboxes_output32)

    def test_first_round_standard(self):
        t = trace_encrypt_block(bytes.fromhex('0123456789ABCDEF'), bytes.fromhex('133457799BBCDFF1'))
        self.assertEqual(t.ip_output64, 0xCC00CCFFF0AAF0AA)
        self.assertEqual(t.rounds[0].subkey48, 0x1B02EFFC7072)
        self.assertEqual(t.rounds[0].f_output32, 0x234AA9BB)
        self.assertEqual(t.rounds[0].right_after, 0xEF4A6544)
        self.assertEqual(t.ciphertext.hex().upper(), '85E813540F0AB405')

    def test_bad_lengths(self):
        for operation in (trace_encrypt_block, trace_decrypt_block):
            with self.assertRaises(ValueError):
                operation(b'123', b'12345678')
            with self.assertRaises(ValueError):
                operation(b'12345678', b'123')
        with self.assertRaises(ValueError):
            encrypt_data(b'ABC', b'12345678')

    def test_file_round_trip_and_no_overwrite(self):
        from des.data import encrypt_file, decrypt_file
        with TemporaryDirectory() as d:
            a, b, c = (Path(d) / name for name in ('source.txt', 'cipher.des', 'restored.txt'))
            a.write_bytes(b'ABCDEFGH' * 40)
            encrypt_file(a, b, b'8byteKEY')
            decrypt_file(b, c, b'8byteKEY')
            self.assertEqual(a.read_bytes(), c.read_bytes())
            with self.assertRaises(ValueError):
                encrypt_file(a, a, b'8byteKEY')


if __name__ == '__main__':
    unittest.main(verbosity=2)
