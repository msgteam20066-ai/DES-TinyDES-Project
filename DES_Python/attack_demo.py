"""Minh họa nguyên lý brute-force đối với DES trên phạm vi khóa thực hành."""

from time import perf_counter

from des.core import encrypt_block


def make_demo_key(candidate12: int) -> bytes:
    """Tạo khóa 8 byte từ một giá trị ứng viên 12 bit."""
    if not 0 <= candidate12 < (1 << 12):
        raise ValueError("Giá trị khóa ứng viên phải nằm trong khoảng 0 đến 4095.")

    high7 = (candidate12 >> 5) & 0x7F
    low5 = candidate12 & 0x1F
    byte7 = high7 << 1
    byte8 = low5 << 3
    return b"DEMO12" + bytes([byte7, byte8])


def build_attack_report() -> str:
    known_plaintext = b"ATTACK!!"
    secret_candidate = 0xA5B
    target_ciphertext = encrypt_block(known_plaintext, make_demo_key(secret_candidate))

    start = perf_counter()
    found = None
    tries = 0

    for candidate in range(1 << 12):
        tries += 1
        if encrypt_block(known_plaintext, make_demo_key(candidate)) == target_ciphertext:
            found = candidate
            break

    elapsed = perf_counter() - start
    rate = tries / elapsed if elapsed > 0 else 0.0

    lines = [
        "=== MINH HỌA BRUTE-FORCE DES ===",
        "Phạm vi demo: 2^12 ứng viên, KHÔNG phải toàn bộ 2^56 khóa hữu hiệu DES.",
        f"Bản rõ đã biết : {known_plaintext!r}",
        f"Bản mã mục tiêu: {target_ciphertext.hex().upper()}",
        f"Số khóa đã thử : {tries}",
        f"Thời gian       : {elapsed:.6f} giây",
        f"Tốc độ          : {rate:,.0f} khóa/giây",
    ]

    if found is None:
        lines.append("Kết quả         : Không tìm thấy khóa.")
    else:
        lines.append(f"Ứng viên tìm được: 0x{found:03X}")
        lines.append(f"Khóa DES 8 byte  : {make_demo_key(found).hex().upper()}")
        lines.append(
            "Nguyên lý: thử lần lượt các khóa ứng viên, mã hóa bản rõ đã biết và "
            "so sánh với bản mã mục tiêu."
        )

    return "\n".join(lines)


def run_attack_demo() -> None:
    print(build_attack_report())


if __name__ == "__main__":
    run_attack_demo()
