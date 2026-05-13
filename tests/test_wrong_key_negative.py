from aes_socket_utils import decrypt_aes_cbc, encrypt_aes_cbc

def test_wrong_key_should_not_recover_original_plaintext():
    """Kiểm tra xem khi dùng sai khóa thì không thể khôi phục bản tin gốc."""
    # 1. Chuẩn bị dữ liệu mẫu
    plain = b"Thong diep dung de test wrong key"
    key = b"1" * 16  # Khóa đúng
    iv = b"2" * 16   # Vector khởi tạo
    
    # 2. Thực hiện mã hóa với khóa đúng
    _, _, cipher_bytes = encrypt_aes_cbc(plain, key=key, iv=iv)

    # 3. Thử giải mã với khóa sai (wrong_key)
    wrong_key = b"3" * 16

    try:
        # Khi dùng sai khóa, kết quả giải mã thường là dữ liệu rác (Garbage data)
        recovered = decrypt_aes_cbc(wrong_key, iv, cipher_bytes)
        
        # Nếu không có lỗi Padding xảy ra, kết quả giải mã PHẢI khác với bản tin gốc
        assert recovered != plain
        
    except ValueError:
        # Trong mã hóa CBC, dùng sai khóa rất dễ dẫn đến sai lệch Padding PKCS#7
        # Nếu hàm decrypt ném lỗi ValueError (Padding error), coi như test đạt yêu cầu
        assert True
    except Exception as e:
        # Nếu có lỗi khác phát sinh thì fail test
        print(f"Lỗi không mong muốn: {e}")
        assert False
