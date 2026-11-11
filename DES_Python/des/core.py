"""Cài đặt thuật toán DES từ đầu bằng Python.

Module này chỉ chứa phần lõi DES: sinh khóa con, hàm Feistel,
hoán vị và mã hóa/giải mã một khối 64 bit.
"""

from collections.abc import Callable

from .tables import IP, FP, E, P, PC1, PC2, SHIFTS, S_BOXES

BLOCK_SIZE = 8
KEY_SIZE = 8


def _permute(value: int, table: list[int], input_bits: int) -> int:
    """Hoán vị các bit của ``value`` theo bảng vị trí DES."""
    result = 0
    for position in table:
        bit = (value >> (input_bits - position)) & 1
        result = (result << 1) | bit
    return result


def _left_rotate_28(value: int, shift: int) -> int:
    """Dịch vòng trái trên một giá trị 28 bit."""
    mask = (1 << 28) - 1
    return ((value << shift) & mask) | (value >> (28 - shift))


def generate_subkeys(key: bytes) -> list[int]:
    """Sinh 16 khóa con 48 bit từ khóa DES 8 byte."""
    if len(key) != KEY_SIZE:
        raise ValueError("Khóa DES phải dài đúng 8 byte (64 bit).")

    key64 = int.from_bytes(key, "big")
    key56 = _permute(key64, PC1, 64)

    c = key56 >> 28
    d = key56 & ((1 << 28) - 1)

    subkeys: list[int] = []
    for shift in SHIFTS:
        c = _left_rotate_28(c, shift)
        d = _left_rotate_28(d, shift)
        cd = (c << 28) | d
        subkeys.append(_permute(cd, PC2, 56))

    return subkeys


def _feistel(right32: int, subkey48: int) -> int:
    """Hàm F của DES: E -> XOR khóa -> S-box -> P."""
    expanded = _permute(right32, E, 32)
    mixed = expanded ^ subkey48

    sbox_output = 0
    for index in range(8):
        block6 = (mixed >> (42 - 6 * index)) & 0b111111
        row = ((block6 & 0b100000) >> 4) | (block6 & 0b000001)
        col = (block6 >> 1) & 0b1111
        value4 = S_BOXES[index][row][col]
        sbox_output = (sbox_output << 4) | value4

    return _permute(sbox_output, P, 32)


def _crypt_block_with_subkeys(
    block: bytes,
    subkeys: list[int],
    round_observer: Callable[[int, int, int, int, int, int, int], None] | None = None,
) -> bytes:
    """Xử lý 1 khối; observer (tùy chọn) chỉ ghi trạng thái để mô phỏng.

    Observer nhận: (số vòng, L trước, R trước, Ki, F, L sau, R sau).
    Nếu không cung cấp observer, đường mã hóa/giải mã giữ nguyên như trước.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("Một khối DES phải dài đúng 8 byte.")

    block64 = int.from_bytes(block, "big")
    permuted = _permute(block64, IP, 64)

    left = permuted >> 32
    right = permuted & 0xFFFFFFFF

    for round_number, subkey in enumerate(subkeys, start=1):
        f_value = _feistel(right, subkey)
        new_left, new_right = right, left ^ f_value
        if round_observer is not None:
            round_observer(round_number, left, right, subkey, f_value, new_left, new_right)
        left, right = new_left, new_right

    preoutput = (right << 32) | left
    result64 = _permute(preoutput, FP, 64)
    return result64.to_bytes(BLOCK_SIZE, "big")


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Mã hóa một khối 8 byte bằng DES."""
    return _crypt_block_with_subkeys(block, generate_subkeys(key))


def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Giải mã một khối 8 byte bằng cách đảo thứ tự 16 khóa con."""
    subkeys = generate_subkeys(key)
    subkeys.reverse()
    return _crypt_block_with_subkeys(block, subkeys)
