"""Bộ test không có tab GUI riêng: chạy bằng `python tests.py` trước giờ học."""
from time import perf_counter

from des.data import encrypt_data, decrypt_data
from des.examples import DEMO_CASES


def build_test_report() -> tuple[bool, str]:
    start = perf_counter()
    lines = ["=== ĐỐI CHIẾU 4 VECTOR DES VÀ 3 CA TỰ VIẾT ==="]
    all_ok = True
    for case in DEMO_CASES:
        plain = bytes.fromhex(case.plain_hex)
        key = bytes.fromhex(case.key_hex)
        t0 = perf_counter()
        actual = encrypt_data(plain, key)
        restored = decrypt_data(actual, key)
        expected_match = (case.expected_cipher_hex is None or
                          actual.hex().upper() == case.expected_cipher_hex)
        ok = restored == plain and len(actual) == len(plain) and expected_match
        all_ok = all_ok and ok
        lines.append(f"[{'PASS' if ok else 'FAIL'}] {case.name}")
        lines.append(f"    Plain={case.plain_hex} | Key={case.key_hex}")
        if case.expected_cipher_hex:
            lines.append(f"    Expected={case.expected_cipher_hex}")
        lines.append(f"    Actual  ={actual.hex().upper()} | Round-trip={'PASS' if restored == plain else 'FAIL'}")
        lines.append(f"    {len(plain)} byte / {len(plain)//8} khối | {(perf_counter()-t0)*1000:.3f} ms")
    lines.append(f"\nKẾT LUẬN: {'TẤT CẢ PASS' if all_ok else 'CÓ CA FAIL'} | {(perf_counter()-start):.4f} s")
    return all_ok, "\n".join(lines)


if __name__ == "__main__":
    ok, report = build_test_report()
    print(report)
    raise SystemExit(0 if ok else 1)
