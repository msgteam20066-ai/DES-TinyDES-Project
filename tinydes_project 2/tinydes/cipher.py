"""
Lõi thuật toán TinyDES (tự cài đặt, không dùng thư viện mật mã).

Cấu trúc (theo bài giảng):
  - Mạng Feistel 3 vòng, khối 8 bít, khoá 8 bít, khoá con 6 bít.
  - Vòng i:  Li = R(i-1)
             Ri = L(i-1) XOR F(R(i-1), Ki)
             F(R, K) = P-box( S-box( Expand(R) XOR K ) )
  - Sinh khoá: KL0||KR0 = K; mỗi vòng dịch vòng trái hai nửa (1, 2, 1 bít),
               Ki = Compress(KLi || KRi).
  - Bản mã C = L3 || R3 (không đổi chỗ ở cuối).
  - Giải mã đi ngược các vòng:  R(i-1) = Li
                                L(i-1) = Ri XOR F(Li, Ki)

Mỗi hàm có thể ghi lại các bước trung gian vào một danh sách `trace`
để in ra khi thuyết trình và đối chiếu với phần tính tay trong báo cáo.
"""

from dataclasses import dataclass, field

from .bits import permute, rotl, xor, validate_bits
from .tables import EXPAND, PBOX, COMPRESS, SHIFTS, ROUNDS, SBOX


# ---------------------------------------------------------------- các hàm thành phần

def expand(r: str) -> str:
    """Expand 4 -> 6 bít: b0b1b2b3 -> b2 b3 b1 b2 b1 b0."""
    return permute(r, EXPAND)


def sbox(x: str) -> tuple[str, int, int]:
    """
    S-box 6 -> 4 bít. Hàng = b0b5, cột = b1b2b3b4.
    Trả về (4 bít đầu ra, chỉ số hàng, chỉ số cột) để tiện in giải thích.
    """
    row = int(x[0] + x[5], 2)
    col = int(x[1:5], 2)
    return format(SBOX[row][col], "04b"), row, col


def pbox(s: str) -> str:
    """P-box 4 bít: b0b1b2b3 -> b2 b0 b3 b1."""
    return permute(s, PBOX)


def compress(k8: str) -> str:
    """Compress 8 -> 6 bít: k0..k7 -> k5 k1 k3 k2 k7 k0."""
    return permute(k8, COMPRESS)


def f_function(r: str, k: str, trace: list | None = None, rnd: int | None = None) -> str:
    """Hàm vòng F(R, K) = P-box(S-box(Expand(R) XOR K))."""
    e = expand(r)
    x = xor(e, k)
    s, row, col = sbox(x)
    p = pbox(s)
    if trace is not None:
        trace.append(("Expand", f"Expand({r}) = {e}"))
        trace.append(("XOR", f"Expand ⊕ K{rnd} = {e} ⊕ {k} = {x}"))
        trace.append(("S-box", f"S-box({x}): hàng b0b5 = {x[0]}{x[5]} ({row}), "
                               f"cột b1b2b3b4 = {x[1:5]} ({col:X}) → {int(s, 2):X} = {s}"))
        trace.append(("P-box", f"F{rnd} = P-box({s}) = {p}"))
    return p


# ---------------------------------------------------------------- sinh khoá con

@dataclass
class KeySchedule:
    key: str
    halves: list[tuple[str, str]] = field(default_factory=list)  # (KLi, KRi), i = 0..3
    subkeys: list[str] = field(default_factory=list)              # K1, K2, K3


def generate_subkeys(key: str) -> KeySchedule:
    """Sinh 3 khoá con 6 bít từ khoá 8 bít."""
    key = validate_bits(key, 8, "Khoá K")
    kl, kr = key[:4], key[4:]
    ks = KeySchedule(key=key, halves=[(kl, kr)])
    for n in SHIFTS:
        kl, kr = rotl(kl, n), rotl(kr, n)
        ks.halves.append((kl, kr))
        ks.subkeys.append(compress(kl + kr))
    return ks


def trace_key_schedule(ks: KeySchedule) -> list[str]:
    """Các dòng mô tả quá trình sinh khoá (để in)."""
    lines = [f"K = {ks.key}  →  KL0 = {ks.halves[0][0]}, KR0 = {ks.halves[0][1]}"]
    for i, n in enumerate(SHIFTS, start=1):
        (pl, pr), (kl, kr) = ks.halves[i - 1], ks.halves[i]
        lines.append(f"Vòng {i}: KL{i} = KL{i-1} <<< {n} = {pl} → {kl};  "
                     f"KR{i} = KR{i-1} <<< {n} = {pr} → {kr};  "
                     f"K{i} = Compress({kl}{kr}) = {ks.subkeys[i-1]}")
    return lines


# ---------------------------------------------------------------- mã hoá / giải mã 1 khối

def encrypt_block(plaintext: str, key: str, trace: list | None = None) -> str:
    """Mã hoá 1 khối 8 bít. Nếu truyền `trace` (list) sẽ ghi lại từng bước."""
    p = validate_bits(plaintext, 8, "Bản rõ P")
    ks = generate_subkeys(key)
    l, r = p[:4], p[4:]
    if trace is not None:
        trace.append(("Khởi tạo", f"P = {p}  →  L0 = {l}, R0 = {r}"))
    for i in range(1, ROUNDS + 1):
        k = ks.subkeys[i - 1]
        if trace is not None:
            trace.append((f"Vòng {i}", f"--- Vòng {i} (K{i} = {k}) ---"))
            trace.append(("L", f"L{i} = R{i-1} = {r}"))
        f = f_function(r, k, trace, i)
        new_r = xor(l, f)
        if trace is not None:
            trace.append(("R", f"R{i} = L{i-1} ⊕ F{i} = {l} ⊕ {f} = {new_r}"))
        l, r = r, new_r
    c = l + r
    if trace is not None:
        trace.append(("Kết quả", f"C = L{ROUNDS} || R{ROUNDS} = {l}.{r}"))
    return c


def decrypt_block(ciphertext: str, key: str, trace: list | None = None) -> str:
    """Giải mã 1 khối 8 bít bằng cách đi ngược các vòng Feistel (K3, K2, K1)."""
    c = validate_bits(ciphertext, 8, "Bản mã C")
    ks = generate_subkeys(key)
    l, r = c[:4], c[4:]
    if trace is not None:
        trace.append(("Khởi tạo", f"C = {c}  →  L{ROUNDS} = {l}, R{ROUNDS} = {r}"))
    for i in range(ROUNDS, 0, -1):
        k = ks.subkeys[i - 1]
        if trace is not None:
            trace.append((f"Vòng {i}", f"--- Đảo vòng {i} (K{i} = {k}) ---"))
            trace.append(("R", f"R{i-1} = L{i} = {l}"))
        f = f_function(l, k, trace, i)
        prev_l = xor(r, f)
        if trace is not None:
            trace.append(("L", f"L{i-1} = R{i} ⊕ F{i} = {r} ⊕ {f} = {prev_l}"))
        l, r = prev_l, l
    p = l + r
    if trace is not None:
        trace.append(("Kết quả", f"P = L0 || R0 = {l}.{r}"))
    return p
