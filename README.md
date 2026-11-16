# DES và TinyDES — Python

Thuật toán được trình bày theo phong cách `BTL ATBMTT.py`: hàm nhỏ, danh sách bit, tên biến L/R/K, chú thích tiếng Việt và log từng bước. Giao diện Tkinter lấy từ dự án ZIP, giữ bố cục bốn tab. Không cần DLL, trình biên dịch C hoặc mạng để mã hóa/giải mã bằng lõi tự viết.

## Chạy trên Windows

1. Cài Python 3.10 trở lên có Tkinter (bản Python cài đặt thông thường trên Windows có sẵn).
2. Giải nén toàn bộ thư mục này.
3. Nháy đúp `Chay_chuong_trinh.bat`, hoặc mở Terminal trong thư mục rồi chạy:

```sh
python app.py
```

Nếu máy dùng lệnh `py` thay cho `python`, chạy `py app.py`.

Để sử dụng tab **Kiểm thử** đối chiếu với thư viện chuẩn:

```sh
python -m pip install -r requirements.txt
```

PyCryptodome chỉ là bộ đối chiếu độc lập. Các tab TinyDES, DES và vét cạn dùng thuật toán Python tự viết. Trên Linux cần có gói Tkinter của hệ điều hành và phiên làm việc đồ họa.

## Các tệp chính

| Tệp | Nội dung |
|---|---|
| `app.py` | Điểm chạy chương trình |
| `core/tinydes.py` | Tiện ích bit, Expand, S-box, P-box, sinh 3 khóa con, mã hóa/giải mã TinyDES |
| `core/des.py` | Sinh 16 khóa con, hàm F, mã hóa/giải mã DES, xử lý byte và PKCS#7 |
| `core/des_tables.py` | Bảng IP, FP, E, P, PC-1, PC-2, lịch dịch và 8 S-box |
| `core/bits.py` | Kiểm tra và thao tác danh sách bit dùng cho DES |
| `gui/cipher_library.py` | Kiểm tra đầu vào, gọi thuật toán, đối chiếu và vét cạn |
| `gui/app.py` | Giao diện 4 tab theo ZIP |
| `test_algorithms.py` | Kiểm thử có thể chạy lại |

## Cách sử dụng

- **TinyDES:** nhập khối và khóa dưới dạng 8 bit hoặc 2 ký tự hex. Bấm Mã hóa hoặc Giải mã. Kết quả có dạng nhị phân/hex, thời gian và log sinh khóa, Expand, XOR, S-box, P-box.
- **DES:** phần trên xử lý đúng một khối 64 bit (16 ký tự hex), không đệm; mỗi lần chạy mở cửa sổ log 16 vòng. Phần dưới xử lý văn bản UTF-8 hoặc tệp bằng ECB + PKCS#7. Khóa hex dài 16 ký tự hoặc khóa chữ dài đúng 8 **byte UTF-8**.
- **Kiểm thử:** đối chiếu một khối với PyCryptodome, hoặc chạy văn bản/tệp bằng thư viện chuẩn.
- **Tấn công vét cạn:** thử cả 256 khóa TinyDES; mô phỏng DES khi biết phần lớn khóa, còn thiếu 8–20 bit có hiệu lực. Bắt đầu với 8 bit; Python chạy chậm hơn C ở mức lớn. Tác vụ DES chạy nền, có đồng hồ và nút hủy.

Ở phần văn bản, bấm **Dùng kết quả làm đầu vào** để tiếp tục giải mã. Nút này đồng thời bỏ lựa chọn tệp cũ. **Lưu kết quả** lưu bản mã dưới dạng hex; khi giải mã, lưu đúng byte đã phục hồi. Ô hiển thị dùng UTF-8; tệp nhị phân có thể không hiển thị thành chữ nhưng vẫn lưu đúng byte.

Nếu đã chọn tệp, chương trình ưu tiên dữ liệu từ tệp. Bấm **Bỏ tệp** để dùng ô nhập. Tệp bản mã cần chứa chuỗi hex. Chương trình cho phép mã hóa cả dữ liệu rỗng với một khối đệm.

## Điểm khác nhau giữa hai nguồn

TinyDES không có một bộ bảng duy nhất trong hai file nguồn. Bản này chọn **các bảng từ BTL ATBMTT.py**, không chọn bảng TinyDES của ZIP. Chỉ số dưới đây bắt đầu từ 0, tính từ bit trái nhất:

| Thành phần | Bản này / BTL ATBMTT.py | ZIP ban đầu |
|---|---|---|
| Expand 4 → 6 | `[2, 3, 1, 2, 3, 0]` | `[2, 3, 1, 2, 1, 0]` |
| Compress 8 → 6 | `[5, 2, 6, 3, 1, 0]` | `[5, 1, 3, 2, 7, 0]` |
| P-box | `[2, 0, 3, 1]` | Giống nhau |
| Dịch khóa | `[1, 2, 1]` | Giống nhau |

TinyDES xuất `L3 || R3`, không đổi chỗ cuối. Vì vậy giải mã dùng nghịch đảo từng vòng: `R_trước = L_sau`, `L_trước = R_sau XOR F(L_sau, Ki)`, với khóa K3, K2, K1. Bản mã TinyDES từ ZIP cũ có thể không tương thích với bản này.

DES dùng IP → 16 vòng Feistel → R16 || L16 → FP. Giải mã giữ cùng cấu trúc và đảo thứ tự 16 khóa con. Khóa nhập 64 bit, PC-1 bỏ 8 bit parity, còn 56 bit có hiệu lực.

## Ví dụ đã kiểm tra

- TinyDES: P = `01011100` (5C), K = `10011110` (9E) → C = `11100001` (E1). Giải mã E1 với 9E thu lại 5C.
- DES: P = `0123456789ABCDEF`, K = `133457799BBCDFF1` → C = `85E813540F0AB405`.

## Kiểm thử

```sh
python -m unittest -v test_algorithms.py
```

Đã chạy đạt 6 nhóm kiểm thử: vector DES; toàn bộ 65.536 cặp khóa/khối TinyDES và tính hoán vị; 100 khối DES ngẫu nhiên đối chiếu PyCryptodome; dữ liệu rỗng, ranh giới khối, Unicode và byte nhị phân; đầu vào lỗi, đệm sai; vét cạn 8 bit và hủy tác vụ. Đã đối chiếu thêm tất cả 256 bộ khóa con và 768 ca TinyDES với file Python gốc.

Môi trường tạo gói không có màn hình đồ họa nên chưa kiểm tra trực quan cửa sổ Tkinter. Giao diện được tái sử dụng từ ZIP, mã nguồn đã qua kiểm tra cú pháp và import.

Ghi chú: Đây là chương trình học thuật. DES/TinyDES và chế độ ECB dùng để minh họa; kiểm tra đệm không phải kiểm tra tính toàn vẹn hay bảo đảm phát hiện mọi khóa sai. Log hiển thị khóa và trạng thái trung gian phục vụ học tập. Thời gian đo phản ánh bản Python trên máy chạy, không đại diện tốc độ mọi cách triển khai DES.
