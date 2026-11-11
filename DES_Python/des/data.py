"""Xử lý dữ liệu nhiều khối và tệp bằng DES.

Không sử dụng padding, IV hay chuỗi liên kết giữa các khối.
Dữ liệu được chia thành các khối 8 byte và mỗi khối gọi DES trực tiếp.
"""

from pathlib import Path

from .core import BLOCK_SIZE, encrypt_block, decrypt_block


def validate_block_aligned(data: bytes, label: str = "Dữ liệu") -> None:
    """Kiểm tra dữ liệu có thể chia chính xác thành các khối 8 byte."""
    if not data:
        raise ValueError(f"{label} không được để trống.")
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            f"{label} có {len(data)} byte. DES xử lý theo khối 8 byte, "
            "vì vậy độ dài phải là bội số của 8."
        )


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Mã hóa dữ liệu theo từng khối 8 byte."""
    validate_block_aligned(data, "Bản rõ")
    output = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        output.extend(encrypt_block(data[offset:offset + BLOCK_SIZE], key))

    return bytes(output)


def decrypt_data(ciphertext: bytes, key: bytes) -> bytes:
    """Giải mã dữ liệu theo từng khối 8 byte."""
    validate_block_aligned(ciphertext, "Bản mã")
    output = bytearray()

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        output.extend(decrypt_block(ciphertext[offset:offset + BLOCK_SIZE], key))

    return bytes(output)


def _validate_distinct_paths(input_path: str | Path, output_path: str | Path) -> None:
    """Không cho ghi đè file nguồn khi mã hóa/giải mã."""
    if Path(input_path).resolve() == Path(output_path).resolve():
        raise ValueError("Tệp đầu ra phải khác tệp nguồn để tránh ghi đè dữ liệu.")


def encrypt_file(input_path: str | Path, output_path: str | Path, key: bytes) -> int:
    """Mã hóa tệp và trả về số byte đã xử lý."""
    _validate_distinct_paths(input_path, output_path)
    data = Path(input_path).read_bytes()
    ciphertext = encrypt_data(data, key)
    Path(output_path).write_bytes(ciphertext)
    return len(data)


def decrypt_file(input_path: str | Path, output_path: str | Path, key: bytes) -> int:
    """Giải mã tệp và trả về số byte đã xử lý."""
    _validate_distinct_paths(input_path, output_path)
    ciphertext = Path(input_path).read_bytes()
    plaintext = decrypt_data(ciphertext, key)
    Path(output_path).write_bytes(plaintext)
    return len(ciphertext)
