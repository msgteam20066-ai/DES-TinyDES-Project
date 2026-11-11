"""
Các hàm tiện ích thao tác trên chuỗi bít.

Toàn bộ thuật toán làm việc trên chuỗi ký tự '0'/'1' (ví dụ '0101') để
mỗi bước trung gian in ra giống hệt cách viết khi tính tay.
"""


def validate_bits(s: str, length: int, name: str = "giá trị") -> str:
    """Kiểm tra s là chuỗi nhị phân đúng độ dài; bỏ khoảng trắng và dấu chấm."""
    s = s.replace(" ", "").replace(".", "")
    if len(s) != length or any(c not in "01" for c in s):
        raise ValueError(f"{name} phải là chuỗi {length} bít 0/1, nhận được: {s!r}")
    return s


def permute(bits: str, table: list[int]) -> str:
    """Hoán vị / mở rộng / nén: lấy bits[i] với i lần lượt trong table (b0 bên trái)."""
    return "".join(bits[i] for i in table)


def rotl(bits: str, n: int) -> str:
    """Dịch vòng trái n bít."""
    n %= len(bits)
    return bits[n:] + bits[:n]


def xor(a: str, b: str) -> str:
    """XOR từng bít của hai chuỗi cùng độ dài."""
    if len(a) != len(b):
        raise ValueError("Hai chuỗi XOR phải cùng độ dài")
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def bits_to_hex(bits: str) -> str:
    """Chuỗi bít -> hex in hoa (2 chữ số cho 8 bít)."""
    return format(int(bits, 2), f"0{(len(bits) + 3) // 4}X")


def hex_to_bits(h: str, width: int = 8) -> str:
    """Chuỗi hex -> chuỗi bít."""
    return format(int(h, 16), f"0{width}b")


def parse_block(text: str, name: str = "giá trị") -> str:
    """
    Nhận đầu vào 8 bít ở dạng nhị phân ('01011100') hoặc hex ('5C', '0x5C').
    Trả về chuỗi 8 bít.
    """
    t = text.strip().replace(" ", "").replace(".", "")
    if t.lower().startswith("0x"):
        t = t[2:]
        return hex_to_bits(t)
    if len(t) == 8 and set(t) <= {"0", "1"}:
        return t
    if len(t) <= 2:
        try:
            return hex_to_bits(t)
        except ValueError:
            pass
    raise ValueError(f"{name} phải là 8 bít nhị phân (vd 01011100) hoặc 2 chữ số hex (vd 5C)")
