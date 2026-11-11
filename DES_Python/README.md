# Thuật toán DES bằng Python

Chương trình có ba phần: **Mã hóa / Giải mã**, **Mã hóa tệp**, **Demo tấn công**. Phần 1 tích hợp mô phỏng DES 16 vòng Feistel, không mở tab kiểm thử riêng. Mã nguồn DES được cài đặt trực tiếp bằng Python, không dùng thư viện mật mã có sẵn.

## Chuẩn bị
- Python 3.10 trở lên. Tải Python từ trang chính thức: https://www.python.org/downloads/.
- Toàn bộ thư mục mã nguồn của chương trình

- Cài Python trên Windows
+ Mở https://www.python.org/downloads/, tải bộ cài Python dành cho Windows.
+ Chạy bộ cài. Nếu có lựa chọn Add python.exe to PATH, hãy bật tùy chọn này trước khi cài.
+ Sau khi cài, mở Command Prompt (CMD) hoặc PowerShell và nhập:
    py -3 --version
Nếu lệnh trên không hoạt động, thử:
    python --version
Khi màn hình hiện Python 3.x.x (với x phù hợp), Python đã được nhận diện.

- Kiểm tra Python trên macOS / Linux
+ Mở ứng dụng Terminal và nhập:
python3 --version
Nếu chưa có Python, hãy cài Python 3.10+ theo hướng dẫn dành cho hệ điều hành của bạn.

## Tải và giải nén mã nguồn
1. Tải tệp ZIP chứa toàn bộ mã nguồn do nhóm chia sẻ. Nếu mã nguồn nằm trên GitHub, có thể chọn Code → Download ZIP
2. Nhấp chuột phải vào ZIP và chọn Extract All / Giải nén (Windows) hoặc giải nén bằng công cụ có sẵn trên máy.
3. Mở thư mục đã giải nén. Xác định thư mục chứa chương trình bạn muốn chạy:
   - DES: Thư mục có file app.py và thư mục con des/.
   - Tiny DES: Thư mục có file main.py và thư mục con tinydes/.

## Cách nhanh nhất trên Windows
- Mở thư mục DES, nhấp đúp CHAY_CHUONG_TRINH.bat (nếu có). Chương trình sẽ mở cửa sổ có ba tab: Mã hóa / Giải mã, Mã hóa tệp, Demo tấn công.
- Chạy DES bằng lệnh
    1. Mở thư mục có app.py.
    2. Trên Windows: nhấp vào thanh địa chỉ của File Explorer, nhập cmd rồi nhấn Enter. Cửa sổ CMD sẽ mở tại thư mục đó.
    3. Trên macOS/Linux: mở Terminal và dùng lệnh cd để chuyển đến thư mục chứa app.py.

## 1. Mã hóa / Giải mã

- Trong ô **Ví dụ**, chọn **Ví dụ cho trước** rồi bấm **Nạp ca**. Chương trình điền sẵn bản rõ `0123456789ABCDEF` và khóa `133457799BBCDFF1` dưới dạng HEX.
- Bấm **Mã hóa**. Kết quả đúng là `85E813540F0AB405`; dòng **Đối chiếu** cho biết kết quả thực tế có khớp vector đã biết hay không.
- Bấm **Giải mã** để giải mã lại bản mã đang có trong ô **Bản mã (HEX)**.
- Ngay phía dưới, phần mô phỏng hiển thị IP, PC-1, FP và thông tin các vòng. Chọn **Bảng 16 vòng** để xem trạng thái `L`, `R`, khóa con và hàm `F` của đủ 16 vòng. Nhấp đúp một vòng, hoặc chọn vòng và bấm **Xem chi tiết**, để xem từng phép tính.
- Trong **Chi tiết vòng**, có các nút **Sinh khóa**, **Hàm F**, **Feistel**, **Vòng trước**, **Vòng sau** và **Mở rộng**. Văn bản cuộn được bằng con lăn chuột hoặc thanh cuộn bên phải. Nút **Xem toàn bảng** mở cửa sổ riêng chứa bảng 16 vòng.
- Nếu dùng màn hình nhỏ hoặc trình chiếu, bấm **Mở rộng mô phỏng** để ẩn phần nhập và dành toàn bộ màn hình cho 16 vòng DES. Bấm **Hiện phần nhập** để quay lại nhập dữ liệu.
- Ví dụ một khối chỉ có khối số 1, ô chọn khối không hoạt động. Ví dụ hai hoặc ba khối cho phép chuyển tương ứng trong phạm vi 1–2 hoặc 1–3; không có tình trạng chọn khối 2/1 và gặp hộp thoại lỗi.

Danh sách ví dụ hiện có: **Ví dụ cho trước**, **NIST KAT 1–3**, **Tự viết 1–3**. Các ca tự viết có độ dài 8, 16 và 24 byte. Trong phần 1, bạn có thể kiểm tra trực tiếp kết quả mã hóa/giải mã và đối chiếu với vector chuẩn mà không cần một tab kiểm thử riêng.

**Lưu ý về dữ liệu:** Chương trình không bổ sung padding. Độ dài bản rõ, bản mã và tệp phải là bội số dương của 8 byte. Text được chuyển sang UTF-8; số ký tự không nhất thiết bằng số byte. Khóa cần có đúng 8 byte. Dữ liệu giải mã được hiển thị theo kiểu đang chọn: Text nếu giải mã được UTF-8, hoặc HEX.

## 2. Mã hóa tệp

- Giữ khóa mẫu `8byteKEY` hoặc nhập khóa 8 byte khác.
- Chọn `sample_data.txt` (304 byte) để mã hóa, lưu thành tệp `.des`.
- Giải mã `.des` ra tệp khác và so sánh nội dung với tệp gốc.
- Chương trình từ chối dùng cùng đường dẫn nguồn và đích, để tránh ghi đè tệp nguồn.

Mỗi khối được mã hóa độc lập, tương đương ECB; không có IV hoặc padding. Đây là một cách triển khai dùng để học thuật toán, **không phải giải pháp bảo vệ dữ liệu nhạy cảm**.

## 3. Demo tấn công

Bấm **Chạy tấn công**. Chương trình biết trước bản rõ `ATTACK!!` và bản mã tương ứng, thử 4.096 ứng viên khóa 12 bit, rồi dừng khi tìm được `0xA5B`. Đây là thử khóa trong phạm vi nhỏ để minh họa brute-force khi biết một cặp bản rõ–bản mã, **không phải duyệt toàn bộ 2^56 khóa hữu hiệu DES**.

## Mã nguồn

```text
DES_Python/
├── app.py                  Giao diện, ba tab chính
├── des_trace_ui.py         Bảng 16 vòng và chi tiết vòng
├── attack_demo.py          Vét cạn trong phạm vi khóa ví dụ
├── tests.py                Bảy ca kiểm thử
├── tests_trace.py          Kiểm tra 16 vòng và dữ liệu tệp
├── sample_data.txt         Tệp mẫu
├── CHAY_CHUONG_TRINH.bat   Chạy trên Windows
└── des/
    ├── core.py             DES 16 vòng, sinh khóa và hàm Feistel
    ├── tables.py           Các bảng IP, FP, E, P, PC-1, PC-2, S-box
    ├── trace.py            Ghi giá trị trung gian của 16 vòng
    ├── data.py             Xử lý nhiều khối, tệp
    ├── formats.py          Chuyển Text và HEX
    ├── examples.py         Vector chuẩn và ba ca tự viết
    └── __init__.py
```
