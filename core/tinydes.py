"""TinyDES 8 bit, 3 vòng; các bảng giữ đúng BTL ATBMTT.py."""
from .bits import validate_bits, validate_subkeys

# ================== CÁC HÀM TIỆN ÍCH XỬ LÝ BIT ==================

def to_bit_list(bit_str):
    if not bit_str or any(b not in "01" for b in bit_str):
        raise ValueError("Dãy bit chỉ được chứa 0 và 1.")
    return [int(b) for b in bit_str]

def to_bit_str(bit_list):
    return "".join(str(b) for b in bit_list)

def left_shift(bits, n=1):
    n = n % len(bits)
    return bits[n:] + bits[:n]

def xor_bits(a, b):
    if len(a) != len(b):
        raise ValueError("Hai dãy bit XOR phải cùng độ dài.")
    return [x ^ y for x, y in zip(a, b)]

# ================== HÀM EXPAND, S-BOX, P-BOX (BÁM CÁCH LÀM SLIDE) ==================

def expand_4_to_6(R4):
    """
    Expand: 4 bit -> 6 bit.
    Gọi R4 = [b0, b1, b2, b3].
    Slide mô tả kiểu 'hoán vị + mở rộng', ở đây lấy: E(R) = b2 b3 b1 b2 b3 b0.
    Bảng được giữ đúng theo file BTL ATBMTT.py người dùng cung cấp.
    """
    b0, b1, b2, b3 = R4
    return [b2, b3, b1, b2, b3, b0]

# S-box: 6 bit -> 4 bit, dùng bảng 4x16.
# Dùng bảng S1 của DES (chuẩn, cùng cấu trúc 4 hàng x 16 cột).
SBOX = [
    [14, 4, 13, 1,  2,15,11, 8,  3,10, 6,12,  5, 9, 0, 7],
    [ 0,15, 7, 4, 14, 2,13, 1, 10, 6,12,11,  9, 5, 3, 8],
    [ 4, 1,14, 8, 13, 6, 2,11, 15,12, 9, 7,  3,10, 5, 0],
    [15,12, 8, 2,  4, 9, 1, 7,  5,11, 3,14, 10, 0, 6,13],
]

def sbox_6_to_4(X6):
    """
    X6 = [b0,b1,b2,b3,b4,b5].
    Theo cách đọc S-box trên slide:
      - Hàng (row) = b0 b5 (2 bit)
      - Cột (col) = b1 b2 b3 b4 (4 bit).
    Lấy giá trị thập phân trong SBOX, đổi sang 4 bit nhị phân.
    """
    b0,b1,b2,b3,b4,b5 = X6
    row = (b0 << 1) | b5
    col = (b1 << 3) | (b2 << 2) | (b3 << 1) | b4
    val = SBOX[row][col]
    return [
        (val >> 3) & 1,
        (val >> 2) & 1,
        (val >> 1) & 1,
        val & 1
    ]

def pbox_4(bits4):
    """
    P-box: hoán vị 4 bit đầu vào.
    Slide ghi 'P-box thực hiện hoán vị 4 bit', ở đây chọn:
        P(b0,b1,b2,b3) = b2 b0 b3 b1
    Giữ nguyên bảng hoán vị của BTL ATBMTT.py.
    """
    b0,b1,b2,b3 = bits4
    return [b2, b0, b3, b1]

# ================== SINH KHÓA CON TINYDES (3 VÒNG, K_i 6-BIT) ==================

def compress_8_to_6(K8):
    """
    Hàm nén khóa: 8 bit -> 6 bit.
    Slide nói: 'hoán vị và nén 8 bit KL_i||KR_i thành 6 bit k_j'.
    Ở đây chọn thứ tự: K_i = [k5, k2, k6, k3, k1, k0]
    (chỉ là hoán vị + bỏ bớt 2 bit, đúng 'cách làm' compress).
    """
    k0,k1,k2,k3,k4,k5,k6,k7 = K8
    return [k5, k2, k6, k3, k1, k0]

def generate_subkeys_from_key(K8_str):
    """
    Sinh 3 khóa con K1,K2,K3 từ khóa chính 8 bit, đúng mô tả trên slide:
      - Chia K thành KL0, KR0 (mỗi nửa 4 bit)
      - Vòng 1: KL1 = LS1(KL0), KR1 = LS1(KR0)      -> K1 = Compress(KL1||KR1)
      - Vòng 2: KL2 = LS2(KL1), KR2 = LS2(KR1)      -> K2 = Compress(KL2||KR2)
      - Vòng 3: KL3 = LS1(KL2), KR3 = LS1(KR2)      -> K3 = Compress(KL3||KR3)
    """
    log = []
    validate_bits(K8_str, 8, "Khóa TinyDES")
    K8 = to_bit_list(K8_str)
    log.append(f"Khóa chính K  = {to_bit_str(K8)}")

    KL = K8[:4]
    KR = K8[4:]
    log.append(f"Chia khóa: KL0 = {to_bit_str(KL)}, KR0 = {to_bit_str(KR)}")

    subkeys = []
    # Dịch trái: vòng 1 (1 bit), vòng 2 (2 bit), vòng 3 (1 bit) – đúng bullet trong slide
    shifts = [1, 2, 1]

    for round_idx, sh in enumerate(shifts, start=1):
        KL = left_shift(KL, sh)
        KR = left_shift(KR, sh)
        Ki = compress_8_to_6(KL + KR)
        subkeys.append(Ki)
        log.append(
            f"Vòng {round_idx}: LS({sh}) -> KL{round_idx}={to_bit_str(KL)}, "
            f"KR{round_idx}={to_bit_str(KR)} -> K{round_idx}={to_bit_str(Ki)}"
        )

    return subkeys, log

# ================== HÀM F(R, K_i) ==================

def F_function(R4, Ki6, round_index, log):
    """
    Hàm F(R, K_i) đúng cấu trúc:
      Expand 4 -> 6 → XOR với K_i → S-box (6 -> 4) → P-box (4 -> 4).
    """
    log.append(f"  Đầu vào F = {to_bit_str(R4)}")

    # 1. Expand
    E = expand_4_to_6(R4)
    log.append(f"  Expand(đầu vào) = {to_bit_str(E)}")

    # 2. XOR với K_i (6 bit)
    X = xor_bits(E, Ki6)
    log.append(f"  XOR với K_{round_index} = {to_bit_str(Ki6)} -> {to_bit_str(X)}")

    # 3. S-box: 6 -> 4
    S_out = sbox_6_to_4(X)
    log.append(f"  S-box({to_bit_str(X)}) = {to_bit_str(S_out)}")

    # 4. P-box: 4 -> 4
    P_out = pbox_4(S_out)
    log.append(f"  P-box({to_bit_str(S_out)}) = {to_bit_str(P_out)} (F_{round_index})")

    return P_out

# ================== MÃ HÓA & GIẢI MÃ 8-BIT (3 VÒNG FEISTEL) ==================

def tinyDES_encrypt_block(P8_str, subkeys):
    """
    Mã hóa 1 block 8-bit với TinyDES (3 vòng Feistel).
    - Không dùng IP; chỉ chia P thành L0 (4 bit đầu) và R0 (4 bit cuối).
    - Vòng i: L_i = R_{i-1}, R_i = L_{i-1} XOR F(R_{i-1}, K_i)
    - Bản mã C = L3 || R3
    """
    log = []
    validate_bits(P8_str, 8, "Bản rõ TinyDES")
    validate_subkeys(subkeys, 3, 6)
    P8 = to_bit_list(P8_str)
    log.append(f"Bản rõ P = {to_bit_str(P8)}")

    L = P8[:4]
    R = P8[4:]
    log.append(f"Chia: L0 = {to_bit_str(L)}, R0 = {to_bit_str(R)}")

    for i, Ki in enumerate(subkeys, start=1):
        log.append(f"\n--- Vòng Feistel {i} ---")
        F_out = F_function(R, Ki, i, log)
        new_L = R
        new_R = xor_bits(L, F_out)
        log.append(f"  L_{i} = R_{i-1} = {to_bit_str(new_L)}")
        log.append(f"  R_{i} = L_{i-1} XOR F_{i} = {to_bit_str(new_R)}")
        L, R = new_L, new_R

    C8 = L + R
    log.append(f"\nKết quả: L3 = {to_bit_str(L)}, R3 = {to_bit_str(R)}")
    log.append(f"Ciphertext C = {to_bit_str(C8)}")

    return to_bit_str(C8), log

def tinyDES_decrypt_block(C8_str, subkeys):
    """
    Giải mã TinyDES.
    Vì ta không dùng final swap, nên giải mã không dùng cùng hàm encrypt,
    mà dùng công thức nghịch của Feistel:

      Từ (L_i, R_i) -> (L_{i-1}, R_{i-1}):
        R_{i-1} = L_i
        L_{i-1} = R_i XOR F(R_{i-1}, K_i) = R_i XOR F(L_i, K_i)

    Ta đi ngược từ vòng 3 → 1, với K3, K2, K1.
    """
    log = []
    validate_bits(C8_str, 8, "Bản mã TinyDES")
    validate_subkeys(subkeys, 3, 6)
    C8 = to_bit_list(C8_str)
    log.append(f"Bản mã C = {to_bit_str(C8)}")

    L = C8[:4]
    R = C8[4:]
    log.append(f"Chia bản mã: L3 = {to_bit_str(L)}, R3 = {to_bit_str(R)}")

    # Đi ngược: K3, K2, K1
    for i, Ki in enumerate(reversed(subkeys), start=1):
        log.append(f"\n--- Vòng giải mã {i} (dùng K_{3 - i + 1}) ---")
        # R_prev = L_i
        R_prev = L
        # F(L_i, K_i)
        k = 4 - i
        log.append(f"  Tính F(L{k}, K{k}) với L{k}={to_bit_str(R_prev)}")
        F_out = F_function(R_prev, Ki, k, log)
        # L_prev = R_i XOR F(L_i, K_i)
        L_prev = xor_bits(R, F_out)
        log.append(f"  L{k-1} = R{k} XOR F(L{k}, K{k}) = {to_bit_str(L_prev)}")
        log.append(f"  R{k-1} = L{k} = {to_bit_str(R_prev)}")
        L, R = L_prev, R_prev

    P8 = L + R
    log.append(f"\nKết quả: L0 = {to_bit_str(L)}, R0 = {to_bit_str(R)}")
    log.append(f"Plaintext P (giải mã) = {to_bit_str(P8)}")

    return to_bit_str(P8), log

