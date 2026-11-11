# TinyDES – Cài đặt hệ mã DES thu nhỏ

Đề tài: **Hệ mã DES / TinyDES** – môn An toàn và bảo mật thông tin.
Phần này: cài đặt **TinyDES** theo đúng bài giảng *Chương 2 – Mã hoá khoá đối xứng* (slide 60–65).

## 1. Đặc tả TinyDES được cài đặt

| Thành phần | Giá trị |
|---|---|
| Cấu trúc | Mạng Feistel **3 vòng** |
| Khối / Khoá / Khoá con | **8 bít / 8 bít / 6 bít** |
| Expand (4 → 6) | b0b1b2b3 → b2 b3 b1 b2 b1 b0 |
| S-box (6 → 4) | hàng = b0b5, cột = b1b2b3b4 (bảng giống hộp S1 của DES) |
| P-box (4 → 4) | b0b1b2b3 → b2 b0 b3 b1 |
| Sinh khoá | KL0‖KR0 = K, dịch vòng trái 1, 2, 1 bít; Ki = Compress(KLi‖KRi) = k5 k1 k3 k2 k7 k0 |
| Vòng i | Li = R(i-1); Ri = L(i-1) ⊕ P-box(S-box(Expand(R(i-1)) ⊕ Ki)) |
| Bản mã | C = L3 ‖ R3 |
| Giải mã | R(i-1) = Li; L(i-1) = Ri ⊕ F(Li, Ki), với i = 3, 2, 1 |

Ví dụ trên lớp: **P = 5C, K = 9A → C = 92**. Chương trình tái hiện đúng mọi bước trung gian.

## 2. Cài đặt và chạy

Yêu cầu: **Python 3.10+**, chỉ dùng thư viện chuẩn.

```bash
python main.py                              # chạy menu demo
python -m unittest -v tests.test_tinydes    # chạy bộ kiểm thử
```

Menu:

1. **Mã hoá** – in các bước trung gian (sinh khoá con, Expand, XOR, S-box, P-box, từng vòng), sau đó giải mã ngược để kiểm tra. Nhấn Enter để dùng ví dụ trên lớp.
2. **Giải mã** – in các bước trung gian.
3. **Chạy bộ kiểm thử.**

Đầu vào nhận dạng nhị phân 8 bít (`01011100`) hoặc hex (`5C`).

## 3. Cấu trúc mã nguồn

```
tinydes_project/
├── main.py                 # điểm vào chương trình
├── app/
│   └── cli.py              # GIAO DIỆN: menu, nhập/xuất, in bước trung gian
├── tinydes/                # THUẬT TOÁN (tách khỏi giao diện)
│   ├── tables.py           # bảng Expand, P-box, Compress, S-box, lịch dịch
│   ├── bits.py             # tiện ích chuỗi bít: hoán vị, dịch vòng, XOR
│   └── cipher.py           # sinh khoá con, hàm F, mã hoá / giải mã
└── tests/
    ├── test_tinydes.py     # bộ kiểm thử
    └── reference_impl.py   # bản cài đặt tham chiếu độc lập để đối chiếu
```

## 4. Bộ kiểm thử

| Nhóm | Nội dung | Kết quả |
|---|---|---|
| Ví dụ trên lớp | P = 5C, K = 9A: khoá con K1 = 101110, K2 = 110011, K3 = 001001; R1, R2, R3; C = 92; giải mã ra 5C; Expand(0110) = 101110; S-box(101010) = 0110 | ✔ |
| Ca tự viết 1 | P = 00, K = 00 → C = 3B | ✔ |
| Ca tự viết 2 | P = FF, K = FF → C = C4 | ✔ |
| Ca tự viết 3 | P = AA, K = CC → C = AD | ✔ |
| Đối chiếu chuẩn | Bảng S-box trùng hộp S1 của DES trong **FIPS PUB 46-3** | ✔ |
| Đối chiếu tham chiếu | So với bản cài đặt độc lập (dùng số nguyên) trên toàn bộ 256 × 256 = 65.536 tổ hợp | ✔ |
| Khôi phục bản rõ | Decrypt(Encrypt(P)) = P với mọi P và mọi K | ✔ |

> TinyDES là hệ mã dạy học nên không có test vector NIST/RFC. Vì vậy nhóm đối chiếu bằng ví dụ trong bài giảng, bảng S-box chuẩn FIPS 46-3 và một bản cài đặt tham chiếu viết độc lập.

## 5. Ghi chú

- Lõi thuật toán do nhóm tự cài đặt, **không dùng thư viện mật mã**.
- Công cụ AI được dùng để hỗ trợ viết khung mã nguồn và tài liệu. Nhóm đã kiểm tra lại và giải thích được toàn bộ mã khi bảo vệ.
