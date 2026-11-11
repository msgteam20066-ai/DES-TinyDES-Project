"""Chuyển đổi dữ liệu người dùng nhập giữa dạng Text và HEX."""

import string


def _compact_hex(text: str) -> str:
    """Bỏ khoảng trắng để cho phép nhập HEX theo nhóm byte."""
    return "".join(text.split())


def parse_hex(text: str, label: str) -> bytes:
    """Chuyển chuỗi HEX thành bytes và báo lỗi dễ hiểu."""
    compact = _compact_hex(text)
    if not compact:
        raise ValueError(f"{label} không được để trống.")
    if len(compact) % 2 != 0:
        raise ValueError(f"{label} HEX phải có số ký tự chẵn.")
    if any(ch not in string.hexdigits for ch in compact):
        raise ValueError(f"{label} HEX chỉ được chứa các ký tự 0-9, A-F.")
    return bytes.fromhex(compact)


def parse_plaintext(text: str, mode: str) -> bytes:
    """Đọc bản rõ theo chế độ 'text' hoặc 'hex'."""
    if mode == "text":
        if text == "":
            raise ValueError("Bản rõ không được để trống.")
        return text.encode("utf-8")
    if mode == "hex":
        return parse_hex(text, "Bản rõ")
    raise ValueError("Kiểu bản rõ không hợp lệ.")


def parse_key(text: str, mode: str) -> bytes:
    """Đọc khóa DES ở dạng Text hoặc HEX, kết quả luôn đúng 8 byte."""
    if mode == "text":
        key = text.encode("utf-8")
        if len(key) != 8:
            raise ValueError(
                f"Khóa dạng Text phải dài đúng 8 byte UTF-8; hiện tại là {len(key)} byte."
            )
        return key

    if mode == "hex":
        key = parse_hex(text, "Khóa")
        if len(key) != 8:
            raise ValueError("Khóa dạng HEX phải gồm đúng 16 ký tự HEX = 8 byte.")
        return key

    raise ValueError("Kiểu khóa không hợp lệ.")


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def bytes_to_text(data: bytes) -> str:
    """Giải mã UTF-8 để hiển thị; báo rõ nếu dữ liệu không phải UTF-8."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return "[Dữ liệu không biểu diễn được dưới dạng văn bản UTF-8]"
