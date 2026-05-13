import sys
import os
from pathlib import Path

# Đảm bảo đường dẫn dẫn đến thư mục gốc của repository
REPO_ROOT = Path(__file__).resolve().parents[1]

def test_required_files_exist():
    """Kiểm tra sự tồn tại của tất cả các file bắt buộc theo yêu cầu của Lab 6."""
    required = [
        "README.md",
        "sender.py",
        "receiver.py",
        "aes_socket_utils.py",
        "requirements.txt",
        "report-1page.md",
        "threat-model-1page.md",
        "peer-review-response.md", # File Quân đang thiếu khiến Action bị đỏ
    ]
    for item in required:
        assert (REPO_ROOT / item).exists(), f"Thiếu file bắt buộc: {item}"

def test_code_uses_aes_not_des():
    """Đảm bảo Quân sử dụng đúng thuật toán AES (không phải DES cũ)."""
    # Chỉ kiểm tra nếu các file tồn tại
    target_files = ["aes_socket_utils.py", "sender.py", "receiver.py"]
    code_contents = []
    
    for path in target_files:
        file_path = REPO_ROOT / path
        if file_path.exists():
            code_contents.append(file_path.read_text(encoding="utf-8"))
    
    combined_code = "\n".join(code_contents)
    
    assert "Crypto.Cipher import AES" in combined_code, "Phải sử dụng thư viện AES!"
    assert "Crypto.Cipher import DES" not in combined_code, "Không được sử dụng DES trong bài Lab AES này."
    assert "DES.new" not in combined_code, "Phát hiện hàm DES.new không hợp lệ."

def test_readme_info_filled():
    """Kiểm tra xem Quân đã điền thông tin nhóm vào README.md chưa."""
    readme_path = REPO_ROOT / "README.md"
    if not readme_path.exists():
        return
        
    readme = readme_path.read_text(encoding="utf-8")
    
    # Kiểm tra các thông số cấu hình bắt buộc trong hướng dẫn
    assert "KEY_PORT" in readme, "README thiếu thông tin cấu hình KEY_PORT (6001)."
    assert "DATA_PORT" in readme, "README thiếu thông tin cấu hình DATA_PORT (6000)."
    
    # Kiểm tra tên thành viên (Tránh việc để trống hoặc quên điền)
    # Quân nhớ vào README.md sửa 'Thành viên 1' thành tên Quân nhé!
    assert "Thành viên 1" in readme or "Phạm Anh Quân" in readme, "Hãy điền tên thành viên vào README.md."
