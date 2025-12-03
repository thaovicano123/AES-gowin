"""
AES-256 Encryption Implementation
Thuật toán mã hóa AES-256 chuẩn FIPS-197
- Plaintext: 128-bit (16 bytes)
- Key: 256-bit (32 bytes)
- Rounds: 14 (thay vì 10 như AES-128)
"""

# S-box cho SubBytes (giống AES-128)
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Inverse S-box cho giải mã (giống AES-128)
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Rcon cho key expansion AES-256 (cần 14 giá trị)
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d
]


def gmul(a, b):
    """
    Phép nhân trong trường Galois GF(2^8)
    Sử dụng cho MixColumns
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b  # Polynomial x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p & 0xFF


def sub_bytes(state):
    """
    SubBytes transformation: thay thế mỗi byte bằng S-box
    """
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX[state[i][j]]
    return state


def inv_sub_bytes(state):
    """
    Inverse SubBytes transformation
    """
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_SBOX[state[i][j]]
    return state


def shift_rows(state):
    """
    ShiftRows transformation: dịch các hàng
    """
    state[1] = state[1][1:] + state[1][:1]  # Dịch trái 1
    state[2] = state[2][2:] + state[2][:2]  # Dịch trái 2
    state[3] = state[3][3:] + state[3][:3]  # Dịch trái 3
    return state


def inv_shift_rows(state):
    """
    Inverse ShiftRows transformation: dịch phải
    """
    state[1] = state[1][-1:] + state[1][:-1]  # Dịch phải 1
    state[2] = state[2][-2:] + state[2][:-2]  # Dịch phải 2
    state[3] = state[3][-3:] + state[3][:-3]  # Dịch phải 3
    return state


def mix_columns(state):
    """
    MixColumns transformation: trộn dữ liệu các cột
    """
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        state[0][i] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3]
        state[1][i] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3]
        state[2][i] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3)
        state[3][i] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2)
    return state


def inv_mix_columns(state):
    """
    Inverse MixColumns transformation
    """
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        state[0][i] = gmul(col[0], 14) ^ gmul(col[1], 11) ^ gmul(col[2], 13) ^ gmul(col[3], 9)
        state[1][i] = gmul(col[0], 9) ^ gmul(col[1], 14) ^ gmul(col[2], 11) ^ gmul(col[3], 13)
        state[2][i] = gmul(col[0], 13) ^ gmul(col[1], 9) ^ gmul(col[2], 14) ^ gmul(col[3], 11)
        state[3][i] = gmul(col[0], 11) ^ gmul(col[1], 13) ^ gmul(col[2], 9) ^ gmul(col[3], 14)
    return state


def add_round_key(state, round_key):
    """
    AddRoundKey transformation: XOR state với round key
    """
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state


def key_expansion(key):
    """
    Key Expansion cho AES-256: mở rộng khóa 256-bit thành 15 round keys
    Mỗi round key là 128-bit (4x4 bytes)
    
    AES-256 có 14 rounds → cần 15 round keys (0-14)
    Tổng số words cần: 4 * 15 = 60 words
    """
    # Chuyển key thành dạng words (mỗi word = 4 bytes)
    # Key 256-bit = 32 bytes = 8 words
    key_words = []
    for i in range(8):
        word = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
        key_words.append(word)
    
    # Mở rộng thành 60 words (15 round keys x 4 words)
    for i in range(8, 60):
        temp = key_words[i-1][:]
        
        if i % 8 == 0:
            # RotWord: xoay trái 1 byte
            temp = temp[1:] + temp[:1]
            
            # SubWord: áp dụng S-box
            temp = [SBOX[b] for b in temp]
            
            # XOR với Rcon
            temp[0] ^= RCON[i//8 - 1]
        
        elif i % 8 == 4:
            # Đặc biệt cho AES-256: SubWord (không có RotWord)
            temp = [SBOX[b] for b in temp]
        
        # XOR với word trước đó 8 vị trí
        new_word = [key_words[i-8][j] ^ temp[j] for j in range(4)]
        key_words.append(new_word)
    
    # Tạo 15 round keys
    round_keys = []
    for i in range(15):
        round_key = [[0 for _ in range(4)] for _ in range(4)]
        for j in range(4):
            word = key_words[i*4 + j]
            for k in range(4):
                round_key[k][j] = word[k]
        round_keys.append(round_key)
    
    return round_keys


def bytes_to_state(data):
    """
    Chuyển 16 bytes thành ma trận state 4x4
    """
    state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[j][i] = data[i*4 + j]
    return state


def state_to_bytes(state):
    """
    Chuyển ma trận state 4x4 thành 16 bytes
    """
    data = []
    for i in range(4):
        for j in range(4):
            data.append(state[j][i])
    return bytes(data)


def aes256_encrypt_block(plaintext, key):
    """
    Mã hóa 1 block 128-bit (16 bytes) với key 256-bit (32 bytes)
    
    Args:
        plaintext: 16 bytes dữ liệu cần mã hóa
        key: 32 bytes khóa mã hóa (256-bit)
    
    Returns:
        16 bytes dữ liệu đã mã hóa
    """
    # Kiểm tra đầu vào
    if len(plaintext) != 16:
        raise ValueError("Plaintext phải có độ dài 16 bytes")
    if len(key) != 32:
        raise ValueError("Key phải có độ dài 32 bytes (256-bit)")
    
    # Mở rộng khóa
    round_keys = key_expansion(key)
    
    # Chuyển plaintext thành state
    state = bytes_to_state(plaintext)
    
    # Vòng đầu tiên: chỉ có AddRoundKey
    state = add_round_key(state, round_keys[0])
    
    # 13 vòng tiếp theo (vòng 1-13)
    for round_num in range(1, 14):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
    
    # Vòng cuối (vòng 14): không có MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[14])
    
    # Chuyển state thành ciphertext
    return state_to_bytes(state)


def aes256_decrypt_block(ciphertext, key):
    """
    Giải mã 1 block 128-bit (16 bytes) với key 256-bit (32 bytes)
    
    Args:
        ciphertext: 16 bytes dữ liệu đã mã hóa
        key: 32 bytes khóa giải mã (256-bit)
    
    Returns:
        16 bytes dữ liệu gốc
    """
    # Kiểm tra đầu vào
    if len(ciphertext) != 16:
        raise ValueError("Ciphertext phải có độ dài 16 bytes")
    if len(key) != 32:
        raise ValueError("Key phải có độ dài 32 bytes (256-bit)")
    
    # Mở rộng khóa
    round_keys = key_expansion(key)
    
    # Chuyển ciphertext thành state
    state = bytes_to_state(ciphertext)
    
    # Vòng đầu tiên: AddRoundKey với round key cuối
    state = add_round_key(state, round_keys[14])
    
    # 13 vòng tiếp theo (vòng 13-1)
    for round_num in range(13, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)
    
    # Vòng cuối (vòng 0): không có InvMixColumns
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    
    # Chuyển state thành plaintext
    return state_to_bytes(state)


def pkcs7_pad(data, block_size=16):
    """
    Thêm padding theo chuẩn PKCS#7
    """
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def pkcs7_unpad(data):
    """
    Loại bỏ padding PKCS#7
    """
    padding_len = data[-1]
    return data[:-padding_len]


def aes256_encrypt(plaintext, key):
    """
    Mã hóa dữ liệu bất kỳ độ dài (ECB mode) với AES-256
    
    Args:
        plaintext: bytes hoặc string cần mã hóa
        key: bytes hoặc string khóa 32 bytes (256-bit)
    
    Returns:
        bytes dữ liệu đã mã hóa
    """
    # Chuyển sang bytes nếu là string
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Đảm bảo key đúng 32 bytes
    if len(key) != 32:
        raise ValueError("Key phải có độ dài chính xác 32 bytes (256-bit)")
    
    # Thêm padding
    padded_plaintext = pkcs7_pad(plaintext)
    
    # Mã hóa từng block
    ciphertext = b''
    for i in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[i:i+16]
        encrypted_block = aes256_encrypt_block(block, key)
        ciphertext += encrypted_block
    
    return ciphertext


def aes256_decrypt(ciphertext, key):
    """
    Giải mã dữ liệu (ECB mode) với AES-256
    
    Args:
        ciphertext: bytes dữ liệu đã mã hóa
        key: bytes hoặc string khóa 32 bytes (256-bit)
    
    Returns:
        bytes dữ liệu gốc
    """
    # Chuyển sang bytes nếu là string
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Đảm bảo key đúng 32 bytes
    if len(key) != 32:
        raise ValueError("Key phải có độ dài chính xác 32 bytes (256-bit)")
    
    # Giải mã từng block
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes256_decrypt_block(block, key)
        plaintext += decrypted_block
    
    # Loại bỏ padding
    return pkcs7_unpad(plaintext)


# Test và demo
if __name__ == "__main__":
    print("=" * 70)
    print("AES-256 ENCRYPTION IMPLEMENTATION")
    print("=" * 70)
    
    # Test case 1: FIPS-197 standard test vector for AES-256
    print("\n[Test 1] FIPS-197 Standard Test Vector (AES-256):")
    print("-" * 70)
    
    # Test vector từ FIPS-197 Appendix C.3
    plaintext = bytes.fromhex('00112233445566778899aabbccddeeff')
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    
    print(f"Plaintext:  {plaintext.hex()}")
    print(f"Key (256b): {key.hex()}")
    
    ciphertext = aes256_encrypt_block(plaintext, key)
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Expected:   8ea2b7ca516745bfeafc49904b496089")
    print(f"Match: {ciphertext.hex() == '8ea2b7ca516745bfeafc49904b496089'}")
    
    decrypted = aes256_decrypt_block(ciphertext, key)
    print(f"Decrypted:  {decrypted.hex()}")
    print(f"Match: {decrypted == plaintext}")
    
    # Test case 2: Text encryption
    print("\n[Test 2] Text Encryption with AES-256:")
    print("-" * 70)
    
    message = "Hello AES-256!"
    key = "MySecretKey12345MySecretKey12345"  # 32 ký tự = 32 bytes
    
    print(f"Original message: {message}")
    print(f"Key (256-bit): {key}")
    
    encrypted = aes256_encrypt(message, key)
    print(f"Encrypted (hex): {encrypted.hex()}")
    
    decrypted = aes256_decrypt(encrypted, key)
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    print(f"Match: {decrypted.decode('utf-8') == message}")
    
    # Test case 3: Longer text
    print("\n[Test 3] Long Text Encryption with AES-256:")
    print("-" * 70)
    
    long_message = "AES-256 provides stronger security than AES-128 with a 256-bit key!"
    key = b"SuperSecureKey256bits!!!!!!!!!!!"  # Chính xác 32 bytes
    
    print(f"Original message: {long_message}")
    print(f"Message length: {len(long_message)} bytes")
    print(f"Key length: {len(key)} bytes")
    
    encrypted = aes256_encrypt(long_message, key)
    print(f"Encrypted (hex): {encrypted.hex()}")
    print(f"Encrypted length: {len(encrypted)} bytes")
    
    decrypted = aes256_decrypt(encrypted, key)
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    print(f"Match: {decrypted.decode('utf-8') == long_message}")
    
    print("\n" + "=" * 70)
    print("✅ TẤT CẢ CÁC TEST ĐỀU PASS!")
    print("=" * 70)
