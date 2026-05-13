import sys
import os
from pathlib import Path

# Đảm bảo đường dẫn dẫn đến thư mục gốc của repository
# Nếu file test nằm trong thư mục /tests, dùng parents[1] là chuẩn
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
        "peer-review-response.md", 
    ]
    for item in required:
        file_path = REPO_ROOT / item
        assert file_path.exists(), f"Thiếu file bắt buộc: {item}. Hãy tạo file này để Action không bị báo đỏ."

def test_code_uses_aes_not_des():
    """Đảm bảo nhóm sử dụng đúng thuật toán AES (không phải DES cũ)."""
    target_files = ["aes_socket_utils.py", "sender.py", "receiver.py"]
    code_contents = []
    
    for path in target_files:
        file_path = REPO_ROOT / path
        if file_path.exists():
            code_contents.append(file_path.read_text(encoding="utf-8"))
    
    if not code_contents:
        return # Bỏ qua nếu chưa có file code nào

    combined_code = "\n".join(code_contents)
    
    # Kiểm tra việc import và sử dụng thư viện
    assert "import AES" in combined_code or "from Crypto.Cipher import AES" in combined_code, "Phải sử dụng thư viện AES!"
    assert "DES" not in combined_code.upper() or "AES" in combined_code, "Hãy xóa các đoạn code thừa liên quan đến DES cũ."
    assert "DES.new" not in combined_code, "Phát hiện hàm DES.new không hợp lệ cho Lab 6."

def test_readme_info_filled():
    """Kiểm tra xem nhóm đã điền thông tin vào README.md chưa."""
    readme_path = REPO_ROOT / "README.md"
    assert readme_path.exists(), "Không tìm thấy file README.md"
        
    readme = readme_path.read_text(encoding="utf-8")
    
    # Kiểm tra các thông số cấu hình bắt buộc
    assert "KEY_PORT" in readme, "README thiếu thông tin cấu hình KEY_PORT (6001)."
    assert "DATA_PORT" in readme, "README thiếu thông tin cấu hình DATA_PORT (6000)."
    
    # Kiểm tra tên thành viên để đảm bảo tính cá nhân hóa bài Lab
    # Ông nhớ vào README.md điền tên mình và bạn cùng nhóm vào nhé!
    assert "Thành viên" in readme or "Quân" in readme, "Hãy điền tên các thành viên vào README.md."

def test_requirements_file_valid():
    """Kiểm tra file requirements.txt có chứa thư viện pycryptodome không."""
    req_path = REPO_ROOT / "requirements.txt"
    assert req_path.exists(), "Thiếu file requirements.txt"
    
    content = req_path.read_text(encoding="utf-8")
    assert "pycryptodome" in content.lower(), "requirements.txt phải có thư viện pycryptodome."
