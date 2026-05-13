import os
import socket
import subprocess
import sys
import time
from pathlib import Path

# Đảm bảo đường dẫn trỏ đúng về thư mục gốc của repository
REPO_ROOT = Path(__file__).resolve().parents[1]

def find_free_port() -> int:
    """Tìm một cổng còn trống để chạy test tránh xung đột."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def wait_for_output(process, text: str, timeout: float = 5.0) -> str:
    """Đợi một chuỗi văn bản cụ thể xuất hiện trong stdout của process."""
    collected = []
    start = time.time()
    while time.time() - start < timeout:
        line = process.stdout.readline()
        if line:
            collected.append(line)
            # Dùng in để kiểm tra xem text có xuất hiện trong dòng không (không phân biệt hoa thường)
            if text.lower() in line.lower():
                return "".join(collected)
    raise AssertionError(f"Không thấy output '{text}'. Output nhận được:\n{''.join(collected)}")

def test_local_sender_receiver_roundtrip():
    data_port = find_free_port()
    key_port = find_free_port()

    # Thiết lập môi trường cho Receiver
    receiver_env = os.environ.copy()
    receiver_env.update({
        "PYTHONUNBUFFERED": "1",
        "RECEIVER_HOST": "127.0.0.1",
        "DATA_PORT": str(data_port),
        "KEY_PORT": str(key_port),
        "SOCKET_TIMEOUT": "5",
    })

    # Thiết lập môi trường cho Sender với tin nhắn mẫu của test
    test_message = "Xin chao FIT4012 - local AES integration test"
    sender_env = os.environ.copy()
    sender_env.update({
        "PYTHONUNBUFFERED": "1",
        "SERVER_IP": "127.0.0.1",
        "DATA_PORT": str(data_port),
        "KEY_PORT": str(key_port),
        "MESSAGE": test_message,
    })

    # 1. Chạy Receiver
    receiver = subprocess.Popen(
        [sys.executable, "-u", "receiver.py"],
        cwd=REPO_ROOT,
        env=receiver_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        # Đợi Receiver sẵn sàng (tìm từ khóa 'lắng nghe' hoặc 'chờ')
        # Lưu ý: Receiver của Quân cần print dòng có chữ 'lắng nghe' hoặc 'đang chờ'
        wait_for_output(receiver, "đang") 

        # 2. Chạy Sender
        sender = subprocess.run(
            [sys.executable, "sender.py"],
            cwd=REPO_ROOT,
            env=sender_env,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )

        # 3. Lấy toàn bộ output từ Receiver
        receiver_out, _ = receiver.communicate(timeout=10)

        # 4. Kiểm tra Output của SENDER
        assert "[+] Đã gửi key/IV qua kênh khóa." in sender.stdout
        assert "[+] Đã gửi ciphertext qua kênh dữ liệu." in sender.stdout
        assert "Key:" in sender.stdout
        assert "IV:" in sender.stdout

        # 5. Kiểm tra Output của RECEIVER (Quan trọng nhất)
        # Kiểm tra xem Receiver có in ra đúng tin nhắn đã giải mã không
        assert test_message in receiver_out
        assert "[+] Bản tin gốc:" in receiver_out

    finally:
        if receiver.poll() is None:
            receiver.kill()
