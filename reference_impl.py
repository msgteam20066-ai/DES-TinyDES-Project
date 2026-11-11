"""
Bản cài đặt THAM CHIẾU ĐỘC LẬP của TinyDES, viết lại hoàn toàn bằng phép toán
trên số nguyên (dịch bít, AND, OR) thay vì chuỗi ký tự.

Mục đích: TinyDES không có bộ test vector chuẩn (NIST/RFC), nên nhóm đối chiếu
bản cài đặt chính với một bản viết theo cách khác hẳn trên toàn bộ
256 khoá × 256 bản rõ. Hai bản cho cùng kết quả thì khả năng cùng sai là rất thấp.

Bảng S-box ở đây chép từ hộp S1 của DES chuẩn trong FIPS 46-3
(bài giảng ghi chú: "hộp S1 của DES giống S-box của TinyDES"),
viết ở dạng thập phân để đối chiếu chéo với bảng hex trong tinydes/tables.py.
"""

# DES S1 – FIPS PUB 46-3, Appendix 1 (thập phân)
DES_S1 = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
]


def _bit(x: int, i: int, width: int) -> int:
    """Lấy bít thứ i (i = 0 là bít trái nhất) của x có độ rộng width."""
    return (x >> (width - 1 - i)) & 1


def _f(r: int, k: int) -> int:
    b = [_bit(r, i, 4) for i in range(4)]
    e = (b[2] << 5) | (b[3] << 4) | (b[1] << 3) | (b[2] << 2) | (b[1] << 1) | b[0]
    x = e ^ k
    row = (_bit(x, 0, 6) << 1) | _bit(x, 5, 6)
    col = (x >> 1) & 0xF
    s = DES_S1[row][col]
    sb = [_bit(s, i, 4) for i in range(4)]
    return (sb[2] << 3) | (sb[0] << 2) | (sb[3] << 1) | sb[1]


def _rotl4(x: int, n: int) -> int:
    return ((x << n) | (x >> (4 - n))) & 0xF


def _subkeys(key: int) -> list[int]:
    kl, kr = key >> 4, key & 0xF
    out = []
    for n in (1, 2, 1):
        kl, kr = _rotl4(kl, n), _rotl4(kr, n)
        k8 = (kl << 4) | kr
        kb = [_bit(k8, i, 8) for i in range(8)]
        out.append((kb[5] << 5) | (kb[1] << 4) | (kb[3] << 3) | (kb[2] << 2) | (kb[7] << 1) | kb[0])
    return out


def ref_encrypt(p: int, key: int) -> int:
    l, r = p >> 4, p & 0xF
    for k in _subkeys(key):
        l, r = r, l ^ _f(r, k)
    return (l << 4) | r


def ref_decrypt(c: int, key: int) -> int:
    l, r = c >> 4, c & 0xF
    for k in reversed(_subkeys(key)):
        l, r = r ^ _f(l, k), l
    return (l << 4) | r
