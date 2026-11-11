"""
Giao diện dòng lệnh (CLI có menu) cho TinyDES.
Phần này chỉ lo nhập/xuất; toàn bộ thuật toán nằm trong gói `tinydes`.
"""

import os
import subprocess
import sys

from tinydes import generate_subkeys, trace_key_schedule, encrypt_block, decrypt_block
from tinydes.bits import parse_block, bits_to_hex

LINE = "=" * 70
CLASS_P, CLASS_K = "01011100", "10011010"  


def _ask_block(prompt: str, default: str) -> str:
    """Nhập 8 bít (nhị phân hoặc hex)"""
    while True:
        raw = input(f"{prompt}: ").strip()
        if not raw:
            return default
        try:
            return parse_block(raw, prompt)
        except ValueError as e:
            print("  ✗", e)


def _print_trace(trace: list) -> None:
    for _, line in trace:
        print("\n" + line if line.startswith("---") else "  " + line)


def _show_key_schedule(key: str) -> None:
    print("\n[SINH KHOÁ CON]")
    for line in trace_key_schedule(generate_subkeys(key)):
        print("  " + line)


def menu_encrypt() -> None:
    print("\nNhập 8 bít nhị phân hoặc hex")
    p = _ask_block("Bản rõ P", CLASS_P)
    k = _ask_block("Khoá K", CLASS_K)
    print(LINE)
    _show_key_schedule(k)

    print("\n[MÃ HOÁ]")
    trace = []
    c = encrypt_block(p, k, trace)
    _print_trace(trace)
    print(f"\n➜ Bản mã C = {c} (hex {bits_to_hex(c)})")

    print("\n[GIẢI MÃ NGƯỢC ĐỂ KIỂM TRA]")
    trace = []
    p2 = decrypt_block(c, k, trace)
    _print_trace(trace)
    print(f"\n➜ Bản rõ khôi phục = {p2} (hex {bits_to_hex(p2)})  "
          f"{'✔ KHỚP bản rõ ban đầu' if p2 == p else '✗ KHÔNG KHỚP'}")
    print(LINE)


def menu_decrypt() -> None:
    c = _ask_block("Bản mã C", "10010010")
    k = _ask_block("Khoá K", CLASS_K)
    print(LINE)
    _show_key_schedule(k)
    print("\n[GIẢI MÃ]")
    trace = []
    p = decrypt_block(c, k, trace)
    _print_trace(trace)
    print(f"\n➜ Bản rõ P = {p} (hex {bits_to_hex(p)})")
    print(LINE)


def menu_tests() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    subprocess.run([sys.executable, "-m", "unittest", "-v", "tests.test_tinydes"], cwd=root)


MENU = [
    ("Mã hoá (in bước trung gian + giải mã kiểm tra)", menu_encrypt),
    ("Giải mã (in bước trung gian)", menu_decrypt),
    ("Chạy bộ kiểm thử", menu_tests),
]


def main() -> None:
    while True:
        print("\n" + LINE + "\n  HỆ MÃ TinyDES – Feistel 3 vòng, khối 8 bít, khoá 8 bít\n" + LINE)
        for i, (name, _) in enumerate(MENU, 1):
            print(f"  {i}. {name}")
        print("  0. Thoát")
        choice = input("Chọn: ").strip()
        if choice == "0":
            break
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            try:
                MENU[int(choice) - 1][1]()
            except (KeyboardInterrupt, EOFError):
                print()
        else:
            print("  ✗ Lựa chọn không hợp lệ")
