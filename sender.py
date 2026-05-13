#!/usr/bin/env python3
import os
import socket
from pathlib import Path

# Đảm bảo các hàm này đã được định nghĩa trong aes_socket_utils.py
from aes_socket_utils import build_data_packet, build_key_packet, encrypt_aes_cbc

# Cấu hình hệ thống từ Environment Variables hoặc mặc định
SERVER_IP = os.getenv("SERVER_IP", "127.0.0.1")
DATA_PORT = int(os.getenv("DATA_PORT", "6000"))
KEY_PORT = int(os.getenv("KEY_PORT", "6001"))
AES_KEY_SIZE = int(os.getenv("AES_KEY_SIZE", "16"))
MESSAGE_ENV = os.getenv("MESSAGE")
INPUT_FILE = os.getenv("INPUT_FILE", "sample_input.txt")
LOG_FILE = os.getenv("SENDER_LOG_FILE", "logs/sender.log")
TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))


def get_plaintext() -> bytes:
    """Đọc bản tin từ file, biến môi trường hoặc nhập từ bàn phím."""
    if INPUT_FILE and Path(INPUT_FILE).exists():
        return Path(INPUT_FILE).read_bytes()
    if MESSAGE_ENV is not None:
        return MESSAGE_ENV.encode("utf-8")
    return input("Nhập bản tin: ").encode("utf-8")


def send_packet(host: str, port: int, packet: bytes) -> None:
    """Mở kết nối TCP và gửi gói tin."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((host, port))
            sock.sendall(packet)
    except ConnectionRefusedError:
        print(f"[!] Lỗi: Không thể kết nối tới {host}:{port}.")
        exit(1)
    except Exception:
        exit(1)


def main() -> None:
    # 1. Chuẩn bị dữ liệu
    plaintext = get_plaintext()
    
    # 2. Mã hóa AES-CBC
    key, iv, ciphertext = encrypt_aes_cbc(plaintext, key_size=AES_KEY_SIZE)

    # 3. Đóng gói gói tin
    key_packet = build_key_packet(key, iv)
    data_packet = build_data_packet(ciphertext)

    # 4. Gửi qua 2 kênh riêng biệt
    send_packet(SERVER_IP, KEY_PORT, key_packet)
    send_packet(SERVER_IP, DATA_PORT, data_packet)

    # 5. Hiển thị kết quả THEO ĐÚNG ĐỊNH DẠNG TEST
    lines = [
        "[+] Đã tạo AES key và IV.",
        "[+] Đã gửi key/IV qua kênh khóa.",
        "[+] Đã gửi ciphertext qua kênh dữ liệu.",
        f"Server: {SERVER_IP}",
        f"Key port: {KEY_PORT}",
        f"Data port: {DATA_PORT}",
        f"AES key size: {len(key)} bytes",
        f"Key: {key.hex()}",
        f"IV: {iv.hex()}",
        f"Plaintext length: {len(plaintext)} bytes",
        f"Ciphertext length: {len(ciphertext)} bytes",
        f"Ciphertext: {ciphertext.hex()}",
    ]

    for line in lines:
        print(line)

    # 6. Ghi log tự động
    if LOG_FILE:
        log_path = Path(LOG_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n\n")


if __name__ == "__main__":
    main()
