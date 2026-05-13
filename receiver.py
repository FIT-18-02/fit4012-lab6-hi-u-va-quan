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

RECEIVER_HOST = os.getenv("RECEIVER_HOST", "127.0.0.1")
DATA_PORT = int(os.getenv("DATA_PORT", "6000"))
KEY_PORT = int(os.getenv("KEY_PORT", "6001"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "sample_output.txt")
LOG_FILE = os.getenv("RECEIVER_LOG_FILE", "")
TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))

def run_receiver():
    # Giữ đúng từ khóa "đang" để file test nhận diện receiver đã sẵn sàng
    print(f"--- [RECEIVER] Đang lắng nghe tại {RECEIVER_HOST} ---")

    key_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        key_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        data_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        key_server.bind((RECEIVER_HOST, KEY_PORT))
        data_server.bind((RECEIVER_HOST, DATA_PORT))

        key_server.listen(1)
        data_server.listen(1)

        print(f"[*] Chờ kết nối Kênh Khóa (Cổng {KEY_PORT})...")
        print(f"[*] Chờ kết nối Kênh Dữ liệu (Cổng {DATA_PORT})...")

        # 1. Nhận KEY CHANNEL
        conn_key, _ = key_server.accept()
        with conn_key:
            conn_key.settimeout(TIMEOUT)
            header = recv_exact(conn_key, 4)
            key_len = parse_length_header(header)
            packet = header + recv_exact(conn_key, key_len + 16)
            key, iv = parse_key_packet(packet)
        print("[OK] Đã nhận Key và IV thành công.")

        # 2. Nhận DATA CHANNEL
        conn_data, _ = data_server.accept()
        with conn_data:
            conn_data.settimeout(TIMEOUT)
            header_data = recv_exact(conn_data, 4)
            ciphertext_len = parse_length_header(header_data)
            ciphertext = recv_exact(conn_data, ciphertext_len)
        print(f"[OK] Đã nhận bản mã ({ciphertext_len} bytes).") #hieuquan

        # 3. Giải mã - QUAN TRỌNG: Phải in đúng cụm từ "[+] Bản tin gốc:"
        plaintext_bytes = decrypt_aes_cbc(key, iv, ciphertext)
        plaintext_str = plaintext_bytes.decode("utf-8")

        print(f"[+] Bản tin gốc: {plaintext_str}")

        Path(OUTPUT_FILE).write_text(plaintext_str, encoding="utf-8")

        if LOG_FILE:
            log_path = Path(LOG_FILE)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_content = f"[+] Bản tin gốc: {plaintext_str}\n"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(log_content) #hieuquan
#qh
    except Exception as e:
        print(f"[!] Lỗi: {e}")

    finally:
        key_server.close()
        data_server.close()
        print("[*] Đã đóng các kết nối Server.")

if __name__ == "__main__":
    run_receiver()
