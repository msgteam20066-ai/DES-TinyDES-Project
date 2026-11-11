"""Một nguồn dữ liệu ví dụ CHUNG cho GUI và bộ kiểm thử độc lập.

expected_cipher_hex là đáp án đã biết, KHÔNG được tính từ thuật toán đang kiểm tra.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class DemoCase:
    name: str
    key_hex: str
    plain_hex: str
    expected_cipher_hex: str | None = None
    note: str = ""


DEMO_CASES = (
    DemoCase("Ví dụ cho trước", "133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405", ""),
    DemoCase("NIST KAT 1", "0101010101010101", "8000000000000000", "95F8A5E5DD31D900"),
    DemoCase("NIST KAT 2", "0101010101010101", "4000000000000000", "DD7F121CA5015619"),
    DemoCase("NIST KAT 3", "0101010101010101", "2000000000000000", "2E8653104F3834EA"),
    DemoCase("Tự viết 1 — 1 khối", "3132333435363738", b"ABCDEFGH".hex().upper()),
    DemoCase("Tự viết 2 — 2 khối", "3132333435363738", b"ABCDEFGHIJKLMNOP".hex().upper()),
    DemoCase("Tự viết 3 — 3 khối", "3132333435363738", b"ABCDEFGHIJKLMNOPQRSTUVWX".hex().upper()),
)


def find_standard_case(plaintext: bytes, key: bytes) -> DemoCase | None:
    """Chỉ xem là vector chuẩn nếu dữ liệu hiện tại ĐÚNG cặp đầu vào."""
    for case in DEMO_CASES:
        if case.expected_cipher_hex and plaintext.hex().upper() == case.plain_hex and key.hex().upper() == case.key_hex:
            return case
    return None
