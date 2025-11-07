#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CHƯƠNG TRÌNH INTERACTIVE AES-256
Cho phép người dùng nhập plaintext và key, sau đó chọn mã hóa hoặc giải mã
"""

from aes256 import aes256_encrypt_block, aes256_decrypt_block, aes256_encrypt, aes256_decrypt

def print_header():
    """In tiêu đề chương trình"""
    print("=" * 70)
    print(" " * 20 + "🔐 AES-256 INTERACTIVE 🔐")
    print("=" * 70)
    print()

def print_menu():
    """In menu lựa chọn"""
    print("\n" + "=" * 70)
    print("CHỌN CHỨC NĂNG:")
    print("  [1] Mã hóa (Encrypt)")
    print("  [2] Giải mã (Decrypt)")
    print("  [3] Thoát (Exit)")
    print("=" * 70)

def get_hex_input(prompt, expected_length, data_type="hex"):
    """
    Nhận input dạng hex từ người dùng
    
    Args:
        prompt: Thông báo nhắc nhở
        expected_length: Độ dài mong đợi (bytes)
        data_type: Loại dữ liệu ("hex" hoặc "text")
    """
    while True:
        print(f"\n{prompt}")
        print(f"  → Nhập {expected_length} bytes ({expected_length * 2} ký tự hex)")
        print(f"  → Ví dụ: {'00112233445566778899aabbccddeeff' if expected_length == 16 else '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'}")
        
        user_input = input("  → Nhập: ").strip().replace(" ", "").replace("-", "")
        
        # Kiểm tra độ dài
        if len(user_input) != expected_length * 2:
            print(f"  ❌ Lỗi: Cần {expected_length * 2} ký tự hex, bạn nhập {len(user_input)} ký tự")
            retry = input("  → Nhập lại? (y/n): ").strip().lower()
            if retry != 'y':
                return None
            continue
        
        # Kiểm tra định dạng hex
        try:
            bytes_data = bytes.fromhex(user_input)
            print(f"  ✅ Đã nhận {expected_length} bytes")
            return bytes_data
        except ValueError:
            print(f"  ❌ Lỗi: Định dạng hex không hợp lệ")
            retry = input("  → Nhập lại? (y/n): ").strip().lower()
            if retry != 'y':
                return None

def format_hex_output(data, bytes_per_line=16):
    """Format dữ liệu hex để dễ đọc"""
    hex_str = data.hex()
    lines = []
    for i in range(0, len(hex_str), bytes_per_line * 2):
        line = hex_str[i:i + bytes_per_line * 2]
        # Thêm khoảng trắng giữa các byte
        formatted = ' '.join([line[j:j+2] for j in range(0, len(line), 2)])
        lines.append(formatted)
    return '\n    '.join(lines)

def encrypt_mode():
    """Chế độ mã hóa"""
    print("\n" + "🔒" * 35)
    print("CHẾ ĐỘ MÃ HÓA (ENCRYPTION)")
    print("🔒" * 35)
    
    # Chọn chế độ
    print("\n📌 CHỌN CHẾ ĐỘ:")
    print("  [1] Mã hóa block thuần (16 bytes → 16 bytes, KHÔNG padding)")
    print("  [2] Mã hóa với padding (tự động thêm padding)")
    mode_choice = input("\n→ Chọn [1/2]: ").strip()
    
    use_block_mode = (mode_choice == '1')
    
    # Nhập plaintext
    plaintext = get_hex_input(
        "📝 NHẬP PLAINTEXT (Dữ liệu gốc):",
        16,
        "plaintext"
    )
    if plaintext is None:
        print("  ⚠️  Hủy mã hóa")
        return
    
    # Nhập key
    key = get_hex_input(
        "🔑 NHẬP KEY (Khóa 256-bit):",
        32,
        "key"
    )
    if key is None:
        print("  ⚠️  Hủy mã hóa")
        return
    
    # Thực hiện mã hóa
    print("\n⏳ Đang mã hóa...")
    try:
        if use_block_mode:
            # Mã hóa block thuần (16 bytes → 16 bytes)
            ciphertext = aes256_encrypt_block(plaintext, key)
            print("   [Chế độ: Block thuần - KHÔNG padding]")
        else:
            # Mã hóa với padding (16 bytes → 32 bytes)
            ciphertext = aes256_encrypt(plaintext, key)
            print("   [Chế độ: Có PKCS#7 padding]")
        
        # Hiển thị kết quả
        print("\n" + "=" * 70)
        print("✅ MÃ HÓA THÀNH CÔNG!")
        print("=" * 70)
        print(f"\n📝 Plaintext  (16 bytes):")
        print(f"    {format_hex_output(plaintext)}")
        print(f"\n🔑 Key        (32 bytes):")
        print(f"    {format_hex_output(key)}")
        print(f"\n🔒 Ciphertext (16 bytes):")
        print(f"    {format_hex_output(ciphertext)}")
        print("\n" + "=" * 70)
        
        # Lưu kết quả
        save = input("\n💾 Lưu kết quả vào file? (y/n): ").strip().lower()
        if save == 'y':
            filename = input("  → Tên file (mặc định: result.txt): ").strip()
            if not filename:
                filename = "result.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("AES-256 ENCRYPTION RESULT\n")
                f.write("=" * 70 + "\n\n")
                f.write(f"Plaintext  (16 bytes): {plaintext.hex()}\n")
                f.write(f"Key        (32 bytes): {key.hex()}\n")
                f.write(f"Ciphertext (16 bytes): {ciphertext.hex()}\n")
            
            print(f"  ✅ Đã lưu vào file: {filename}")
    
    except Exception as e:
        print(f"\n❌ LỖI: {e}")

def decrypt_mode():
    """Chế độ giải mã"""
    print("\n" + "🔓" * 35)
    print("CHẾ ĐỘ GIẢI MÃ (DECRYPTION)")
    print("🔓" * 35)
    
    # Chọn chế độ
    print("\n📌 CHỌN CHẾ ĐỘ:")
    print("  [1] Giải mã block thuần (16 bytes → 16 bytes, KHÔNG unpadding)")
    print("  [2] Giải mã với unpadding (tự động loại bỏ padding)")
    mode_choice = input("\n→ Chọn [1/2]: ").strip()
    
    use_block_mode = (mode_choice == '1')
    
    # Nhập ciphertext
    ciphertext = get_hex_input(
        "🔒 NHẬP CIPHERTEXT (Dữ liệu đã mã hóa):",
        16,
        "ciphertext"
    )
    if ciphertext is None:
        print("  ⚠️  Hủy giải mã")
        return
    
    # Nhập key
    key = get_hex_input(
        "🔑 NHẬP KEY (Khóa 256-bit - phải giống key mã hóa):",
        32,
        "key"
    )
    if key is None:
        print("  ⚠️  Hủy giải mã")
        return
    
    # Thực hiện giải mã
    print("\n⏳ Đang giải mã...")
    try:
        if use_block_mode:
            # Giải mã block thuần (16 bytes → 16 bytes)
            plaintext = aes256_decrypt_block(ciphertext, key)
            print("   [Chế độ: Block thuần - KHÔNG unpadding]")
        else:
            # Giải mã với unpadding (32 bytes → 16 bytes)
            plaintext = aes256_decrypt(ciphertext, key)
            print("   [Chế độ: Có PKCS#7 unpadding]")
        
        # Hiển thị kết quả
        print("\n" + "=" * 70)
        print("✅ GIẢI MÃ THÀNH CÔNG!")
        print("=" * 70)
        print(f"\n🔒 Ciphertext (16 bytes):")
        print(f"    {format_hex_output(ciphertext)}")
        print(f"\n🔑 Key        (32 bytes):")
        print(f"    {format_hex_output(key)}")
        print(f"\n📝 Plaintext  (16 bytes):")
        print(f"    {format_hex_output(plaintext)}")
        print("\n" + "=" * 70)
        
        # Thử hiển thị dạng text
        try:
            text = plaintext.decode('utf-8', errors='ignore')
            if text.isprintable():
                print(f"\n💬 Plaintext dạng text: {text}")
        except:
            pass
        
        # Lưu kết quả
        save = input("\n💾 Lưu kết quả vào file? (y/n): ").strip().lower()
        if save == 'y':
            filename = input("  → Tên file (mặc định: result.txt): ").strip()
            if not filename:
                filename = "result.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("AES-256 DECRYPTION RESULT\n")
                f.write("=" * 70 + "\n\n")
                f.write(f"Ciphertext (16 bytes): {ciphertext.hex()}\n")
                f.write(f"Key        (32 bytes): {key.hex()}\n")
                f.write(f"Plaintext  (16 bytes): {plaintext.hex()}\n")
            
            print(f"  ✅ Đã lưu vào file: {filename}")
    
    except Exception as e:
        print(f"\n❌ LỖI: {e}")

def main():
    """Hàm chính"""
    print_header()
    
    print("📖 HƯỚNG DẪN:")
    print("  • Plaintext: 16 bytes (128 bits) - dữ liệu cần mã hóa/giải mã")
    print("  • Key: 32 bytes (256 bits) - khóa bí mật")
    print("  • Định dạng: Nhập hex (ví dụ: 00112233...)")
    print("  • Mã hóa: Plaintext + Key → Ciphertext")
    print("  • Giải mã: Ciphertext + Key → Plaintext")
    
    while True:
        print_menu()
        
        choice = input("\n→ Chọn [1/2/3]: ").strip()
        
        if choice == '1':
            encrypt_mode()
        elif choice == '2':
            decrypt_mode()
        elif choice == '3':
            print("\n👋 Tạm biệt!")
            print("=" * 70)
            break
        else:
            print("\n❌ Lựa chọn không hợp lệ. Vui lòng chọn 1, 2 hoặc 3.")
        
        if choice in ['1', '2']:
            continue_choice = input("\n🔄 Tiếp tục? (y/n): ").strip().lower()
            if continue_choice != 'y':
                print("\n👋 Tạm biệt!")
                print("=" * 70)
                break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Đã dừng chương trình (Ctrl+C)")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ LỖI KHÔNG MÔN: {e}")
        import traceback
        traceback.print_exc()
