import os
import socket
from pathlib import Path

# Đảm bảo file aes_socket_utils.py đã có đủ các hàm này
from aes_socket_utils import (
    parse_key_packet,
    parse_length_header,
    recv_exact,
    decrypt_aes_cbc
)

# Cấu hình từ biến môi trường hoặc dùng mặc định
RECEIVER_HOST = os.getenv("RECEIVER_HOST", "127.0.0.1")
DATA_PORT = int(os.getenv("DATA_PORT", "6000"))
KEY_PORT = int(os.getenv("KEY_PORT", "6001"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "sample_output.txt")
LOG_FILE = os.getenv("RECEIVER_LOG_FILE", "logs/receiver.log")
TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))

def run_receiver():
    print(f"--- [RECEIVER] Đang lắng nghe tại {RECEIVER_HOST} ---")

    # Khởi tạo socket cho Kênh Khóa và Kênh Dữ liệu
    key_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Cấu hình cho phép tái sử dụng port nếu vừa tắt server
        key_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        data_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        key_server.bind((RECEIVER_HOST, KEY_PORT))
        data_server.bind((RECEIVER_HOST, DATA_PORT))

        key_server.listen(1)
        data_server.listen(1)
//qh
        print(f"[*] Chờ kết nối Kênh Khóa (Cổng {KEY_PORT})...")
        print(f"[*] Chờ kết nối Kênh Dữ liệu (Cổng {DATA_PORT})...")

        # 1. NHẬN KEY & IV (Key Channel)
        conn_key, addr_key = key_server.accept()
        print(f"[+] Đã kết nối Kênh Khóa từ: {addr_key}")
        
        with conn_key:
            conn_key.settimeout(TIMEOUT)
            # Nhận 4 bytes header để biết độ dài key
            header = recv_exact(conn_key, 4)
            key_len = parse_length_header(header)
            
            # Nhận toàn bộ packet (Header + Key + 16 bytes IV)
            packet = header + recv_exact(conn_key, key_len + 16)
            key, iv = parse_key_packet(packet)
            print("[OK] Đã nhận và trích xuất Key/IV thành công.")

        # 2. NHẬN BẢN MÃ (Data Channel)
        conn_data, addr_data = data_server.accept()
        print(f"[+] Đã kết nối Kênh Dữ liệu từ: {addr_data}")
        
        with conn_data:
            conn_data.settimeout(TIMEOUT)
            # Nhận 4 bytes header để biết độ dài ciphertext
            header_data = recv_exact(conn_data, 4)
            ciphertext_len = parse_length_header(header_data)
            
            # Nhận bản mã dựa trên độ dài đã biết
            ciphertext = recv_exact(conn_data, ciphertext_len)
            print(f"[OK] Đã nhận bản mã ({ciphertext_len} bytes).")

        # 3. GIẢI MÃ VÀ XỬ LÝ KẾT QUẢ
        plaintext_bytes = decrypt_aes_cbc(key, iv, ciphertext)
        plaintext_str = plaintext_bytes.decode("utf-8")

        print("-" * 40)
        print(f"🔓 Nội dung giải mã: {plaintext_str}")
        print("-" * 40)

        # Ghi nội dung ra file output
        Path(OUTPUT_FILE).write_text(plaintext_str, encoding="utf-8")

        # Ghi log nếu cấu hình LOG_FILE có tồn tại
        if LOG_FILE:
            log_path = Path(LOG_FILE)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            log_content = (
                "==========================================\n"
                "[+] TRẠNG THÁI: Thành công!\n"
                f"[+] Nội dung: {plaintext_str}\n"
                "==========================================\n"
            )
            # Dùng mode "a" để append log thay vì ghi đè nếu muốn lưu lịch sử
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(log_content)
//qh
    except Exception as e:
        print(f"[!] Lỗi hệ thống: {e}")

    finally:
        key_server.close()
        data_server.close()
        print("[*] Đã đóng các kết nối Server.")

if __name__ == "__main__":
    run_receiver()
