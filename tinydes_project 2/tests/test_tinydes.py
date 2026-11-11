"""
Bộ kiểm thử TinyDES.

Chạy:  python -m unittest -v tests.test_tinydes      (hoặc menu 3 trong main.py)

Gồm:
  1. Ví dụ trên lớp (slide 64–65): P = 5C, K = 9A -> C = 92, kiểm tra cả khoá con
     và kết quả từng vòng.
  2. Các ví dụ nhỏ trên slide: Expand(0110) = 101110, S-box(101010) = 0110.
  3. Ba ca kiểm thử do nhóm tự viết (giá trị kỳ vọng tính tay, xem README).
  4. Đối chiếu S-box với hộp S1 của DES chuẩn (FIPS 46-3).
  5. Đối chiếu với bản cài đặt tham chiếu độc lập trên toàn bộ 65.536 tổ hợp.
  6. Giải mã khôi phục đúng bản rõ với mọi khoá và mọi bản rõ.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinydes import expand, sbox, generate_subkeys, encrypt_block, decrypt_block
from tinydes.tables import SBOX
from tests.reference_impl import DES_S1, ref_encrypt, ref_decrypt

# Ba ca kiểm thử nhóm tự viết: (bản rõ, khoá, bản mã kỳ vọng)
GROUP_CASES = [
    ("00000000", "00000000", "00111011"),   # bản rõ và khoá toàn 0 (3B) – đã tính tay
    ("11111111", "11111111", "11000100"),   # bản rõ và khoá toàn 1 (C4)
    ("10101010", "11001100", "10101101"),   # mẫu bít xen kẽ (AA, CC -> AD)
]


class TestClassExample(unittest.TestCase):
    """Ví dụ đã học trên lớp – căn cứ đầu tiên để chấm tính đúng đắn."""

    P, K, C = "01011100", "10011010", "10010010"

    def test_subkeys(self):
        ks = generate_subkeys(self.K)
        self.assertEqual(ks.subkeys, ["101110", "110011", "001001"])
        self.assertEqual(ks.halves[1:], [("0011", "0101"), ("1100", "0101"), ("1001", "1010")])

    def test_rounds(self):
        trace = []
        encrypt_block(self.P, self.K, trace)
        text = "\n".join(line for _, line in trace)
        for expected in ["R1 = L0 ⊕ F1 = 0101 ⊕ 0100 = 0001",
                         "R2 = L1 ⊕ F2 = 1100 ⊕ 0101 = 1001",
                         "R3 = L2 ⊕ F3 = 0001 ⊕ 0011 = 0010"]:
            self.assertIn(expected, text)

    def test_encrypt(self):
        self.assertEqual(encrypt_block(self.P, self.K), self.C)

    def test_decrypt(self):
        self.assertEqual(decrypt_block(self.C, self.K), self.P)

    def test_slide_small_examples(self):
        self.assertEqual(expand("0110"), "101110")
        self.assertEqual(sbox("101010")[0], "0110")


class TestGroupCases(unittest.TestCase):
    def test_group_cases(self):
        for p, k, c in GROUP_CASES:
            with self.subTest(p=p, k=k):
                self.assertEqual(encrypt_block(p, k), c)
                self.assertEqual(decrypt_block(c, k), p)


class TestCrossCheck(unittest.TestCase):
    def test_sbox_equals_des_s1(self):
        self.assertEqual(SBOX, DES_S1)

    def test_against_reference_all_inputs(self):
        for k in range(256):
            kb = format(k, "08b")
            for p in range(256):
                c = int(encrypt_block(format(p, "08b"), kb), 2)
                self.assertEqual(c, ref_encrypt(p, k))
                self.assertEqual(ref_decrypt(c, k), p)

    def test_roundtrip_all_inputs(self):
        for k in range(256):
            kb = format(k, "08b")
            for p in range(256):
                pb = format(p, "08b")
                self.assertEqual(decrypt_block(encrypt_block(pb, kb), kb), pb)


if __name__ == "__main__":
    unittest.main(verbosity=2)
