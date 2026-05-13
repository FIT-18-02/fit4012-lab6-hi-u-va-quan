import sys
import os
import pytest

# Đảm bảo import được aes_socket_utils từ thư mục gốc
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aes_socket_utils import decrypt_aes_cbc, encrypt_aes_cbc

def test_tampered_ciphertext_should_fail_padding():
    """Kiểm tra xem việc thay đổi ciphertext có khiến giải mã thất bại do sai Padding không."""
    plain = b"Thong diep dung de test tamper"
    key = b"1" * 16
    iv = b"2" * 16
    _, _, cipher_bytes = encrypt_aes_cbc(plain, key=key, iv=iv)

    # Thực hiện Tamper: Đảo 1 bit cuối cùng của bản mã
    tampered = bytearray(cipher_bytes)
    tampered[-1] ^= 0x01

    # Trong AES-CBC, thay đổi byte cuối thường làm hỏng cấu trúc PKCS#7 Padding
    # Match với thông báo lỗi trong aes_socket_utils.py của ông
    with pytest.raises(ValueError, match="Padding"):
        decrypt_aes_cbc(key, iv, bytes(tampered))

def test_tampered_iv_changes_first_block():
    """Kiểm tra xem việc thay đổi IV có làm sai lệch khối dữ liệu đầu tiên không."""
    plain = b"Tin nhan rat quan trong cho Lab 6 DNU"
    key = os.urandom(16)
    iv = os.urandom(16)
    _, _, cipher_bytes = encrypt_aes_cbc(plain, key=key, iv=iv)

    # Tamper IV: Đổi byte đầu tiên của IV
    tampered_iv = bytearray(iv)
    tampered_iv[0] ^= 0x01

    # Khi IV sai, dữ liệu giải mã ra sẽ bị rác ở block đầu tiên
    try:
        recovered = decrypt_aes_cbc(key, bytes(tampered_iv), cipher_bytes)
        assert recovered != plain, "Du lieu giai ma phai khac ban goc khi IV bi thay doi"
    except ValueError as e:
        # Nếu dữ liệu rác vô tình tạo ra byte padding sai quy tắc, unpad() sẽ ném lỗi.
        # Đây vẫn là hành vi an toàn.
        assert "Padding" in str(e)

def test_empty_input_decryption_fail():
    """Đảm bảo không thể giải mã nếu không có dữ liệu."""
    key = b"k" * 16
    iv = b"i" * 16
    
    # Kiểm tra lỗi khi ciphertext rỗng (theo logic trong decrypt_aes_cbc)
    with pytest.raises(ValueError, match="Ciphertext không được rỗng"):
        decrypt_aes_cbc(key, iv, b"")

def test_invalid_ciphertext_length_fail():
    """Kiểm tra lỗi khi ciphertext không phải là bội số của BLOCK_SIZE (16)."""
    key = b"k" * 16
    iv = b"i" * 16
    invalid_cipher = b"abc" # Không chia hết cho 16
    
    with pytest.raises(ValueError, match="Sai block"):
        decrypt_aes_cbc(key, iv, invalid_cipher)
