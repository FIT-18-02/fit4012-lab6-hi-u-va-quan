# Report 1 page - Lab 6 AES-CBC Socket

## Thông tin nhóm

- Thành viên 1: Phạm Anh Quân
- Thành viên 2: Ngô Văn Hiếu

## Mục tiêu
//hihahaa
Phạm Anh Quân : Bài lab nhằm xây dựng hệ thống gửi và nhận dữ liệu qua socket TCP với mã hóa AES-CBC. Hệ thống tách biệt hai kênh truyền: **key channel** để gửi AES key và IV, **data channel** để gửi ciphertext. Sinh viên hiểu được luồng hoạt động của mã hóa đối xứng trong ứng dụng mạng, cách sử dụng PKCS#7 padding, length header, và phân tích các điểm yếu bảo mật khi key được gửi ở dạng plaintext.

## Phân công thực hiện

| Vai trò | Phụ trách chính |
|---------|----------------|
| **Sender** (mã hóa, key channel, data channel) | Ngô Văn Hiếu |
| **Receiver** (giải mã, nhận packet, xử lý lỗi) | Phạm Anh Quân |
| **Test cases** (pytest, wrong key, tamper) | Cả hai |
| **Log & Minh chứng** | Ngô Văn Hiếu |
| **Threat model** | Phạm Anh Quân |
| **Báo cáo & Phần chung** | Cả hai |

## Cách làm


### 1. Sender (Ngô Văn Hiếu thực hiện)
- Đọc dữ liệu từ biến môi trường `MESSAGE` hoặc file `INPUT_FILE`
- Sinh AES key (16 byte) và IV (16 byte) ngẫu nhiên
- Mã hóa plaintext bằng AES-CBC, thêm PKCS#7 padding
- Xây dựng **key packet**: `[key_length:4 bytes][key:16][iv:16]`
- Xây dựng **data packet**: `[ciphertext_length:4 bytes][ciphertext:N]`
- Gửi lần lượt qua KEY_PORT và DATA_PORT

### 2. Receiver (Phạm Anh Quân thực hiện)
- Lắng nghe trên KEY_PORT và DATA_PORT (chạy trước)
- Nhận key packet bằng hàm `recv_exact()` (đọc đủ 4 byte length header, sau đó đọc đúng số byte data)
- Parse key packet để lấy key và IV
- Nhận data packet tương tự, parse lấy ciphertext
- Giải mã bằng AES-CBC, bỏ padding, xuất plaintext ra màn hình hoặc file `OUTPUT_FILE`

### 3. Xử lý lỗi và test (Cả hai)
- **Wrong key test**: dùng sai key → giải mã thất bại (lỗi padding hoặc ra dữ liệu sai)
- **Tamper test**: sửa 1 byte ciphertext → giải mã lỗi hoặc ra plaintext sai
- **Padding test**: kiểm tra đúng PKCS#7
- **Packet format test**: kiểm tra length header đúng cấu trúc


## Kết quả

### Chạy thành công với biến môi trường
```bash
# Terminal 1 - Receiver
RECEIVER_HOST=127.0.0.1 KEY_PORT=6001 DATA_PORT=6000 python receiver.py

# Terminal 2 - Sender
SERVER_IP=127.0.0.1 KEY_PORT=6001 DATA_PORT=6000 MESSAGE="Xin chao FIT4012" python sender.py
## Kết quả

Ngô Văn Hiếu : Tóm tắt kết quả chạy, log minh chứng, output nhận được và các test quan trọng.
Hệ thống Sender và Receiver hoạt động ổn định trên localhost thông qua giao thức TCP socket. Sender thực hiện mã hóa plaintext bằng AES-CBC với khóa AES và IV được sinh ngẫu nhiên, sau đó gửi key packet và data packet qua hai cổng riêng biệt. Receiver nhận đúng packet, parse dữ liệu thành công và giải mã lại chính xác nội dung ban đầu.

Trong quá trình kiểm thử:

Chương trình gửi và nhận thành công với nhiều dữ liệu có độ dài khác nhau.
Receiver hiển thị đúng plaintext sau khi giải mã.
Wrong key test làm dữ liệu giải mã bị lỗi hoặc xuất hiện lỗi padding.
Tamper test cho thấy chỉ cần thay đổi 1 byte ciphertext thì plaintext nhận được sẽ sai hoặc không giải mã được.
Packet length header hoạt động đúng, giúp Receiver đọc đủ dữ liệu và tránh mất packet.

## Kết luận

Phạm Anh Quân : Rút ra bài học kỹ thuật và bài học bảo mật từ bài lab.
Qua bài lab, nhóm hiểu được cách triển khai AES-CBC trong ứng dụng socket TCP thực tế, bao gồm quy trình sinh khóa, padding dữ liệu, mã hóa, truyền packet và giải mã. Bài lab cũng cho thấy tầm quan trọng của việc bảo vệ khóa bí mật trong truyền thông mạng. Việc gửi AES key dưới dạng plaintext là một điểm yếu lớn vì attacker có thể nghe lén và giải mã toàn bộ dữ liệu. Từ đó, nhóm nhận thấy cần kết hợp thêm các cơ chế như RSA, Diffie-Hellman hoặc TLS để trao đổi khóa an toàn hơn trong hệ thống thực tế.
