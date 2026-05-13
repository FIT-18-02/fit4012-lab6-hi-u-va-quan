import os
import socket
import subprocess
import sys
import time
from pathlib import Path

# Đảm bảo đường dẫn trỏ đúng về thư mục gốc của repository (Lab 6)
REPO_ROOT = Path(__file__).resolve().parents[1]

def find_free_port() -> int:
    """Tìm một cổng còn trống để chạy test tránh xung đột port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def wait_for_output(process, text: str, timeout: float = 5.0) -> str:
    """Đợi một chuỗi văn bản cụ thể xuất hiện trong stdout của process."""
    collected = []
    start = time.time()
    while time.time() - start < timeout:
        # Đọc từng dòng từ stdout của process đang chạy ngầm
        line = process.stdout.readline()
        if line:
            collected.append(line)
            # Kiểm tra xem từ khóa (ví dụ: 'đang') có trong dòng log không
            if text.lower() in line.lower():
                return "".join(collected)
        time.sleep(0.1) # Tránh chiếm dụng CPU quá mức
    raise AssertionError(f"Không thấy output '{text}' từ Receiver. Output nhận được:\n{''.join(collected)}")

def test_local_sender_receiver_roundtrip():
    """
    Test toàn trình: Chạy Receiver ngầm -> Chạy Sender gửi tin -> 
    Kiểm tra Receiver có giải mã đúng tin nhắn đó không.
    """
    data_port = find_free_port()
    key_port = find_free_port()

    # 1. Thiết lập môi trường cho Receiver
    receiver_env = os.environ.copy()
    receiver_env.update({
        "PYTHONUNBUFFERED": "1", # Ép Python in log ngay lập tức
        "RECEIVER_HOST": "127.0.0.1",
        "DATA_PORT": str(data_port),
        "KEY_PORT": str(key_port),
        "SOCKET_TIMEOUT": "5",
        "OUTPUT_FILE": "test_output.txt"
    })

    # 2. Thiết lập môi trường cho Sender
    test_message = "Xin chao FIT4012 - local AES integration test"
    sender_env = os.environ.copy() #hieuquan
    sender_env.update({
        "PYTHONUNBUFFERED": "1",
        "SERVER_IP": "127.0.0.1",
        "DATA_PORT": str(data_port),
        "KEY_PORT": str(key_port),
        "MESSAGE": test_message,
    }) #hieuquan

    # Bước A: Khởi chạy Receiver dưới dạng process ngầm
    receiver = subprocess.Popen(
        [sys.executable, "-u", "receiver.py"],
        cwd=REPO_ROOT,
        env=receiver_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        # Chờ cho đến khi Receiver in dòng "Đang lắng nghe..."
        wait_for_output(receiver, "đang") 

        # Bước B: Chạy Sender để gửi dữ liệu
        sender_process = subprocess.run(
            [sys.executable, "sender.py"],
            cwd=REPO_ROOT,
            env=sender_env,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ) #hieuquan

        # Bước C: Thu thập log cuối cùng từ Receiver
        receiver_out, _ = receiver.communicate(timeout=10)

        # Bước D: Kiểm tra kết quả SENDER
        # (Lưu ý: Đảm bảo sender.py của ông có in các dòng này)
        assert "Key:" in sender_process.stdout
        assert "IV:" in sender_process.stdout
        # Nếu sender.py in tiếng Việt, hãy chỉnh lại chuỗi assert bên dưới
        assert "gửi" in sender_process.stdout.lower()

        # Bước E: Kiểm tra kết quả RECEIVER (Quan trọng nhất)
        assert "[+] Bản tin gốc:" in receiver_out
        assert test_message in receiver_out
        print("\n[OK] Test Roundtrip thành công! Tin nhắn đã đi từ Sender qua Receiver an toàn.")

    finally:
        # Đảm bảo tắt hẳn Receiver sau khi test xong hoặc nếu test fail
        if receiver.poll() is None:
            receiver.kill()
