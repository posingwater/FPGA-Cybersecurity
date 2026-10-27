import hashlib
import secrets

Q = 3329       # Prime modulus: 3329 = 2^8 * 13 + 1
N = 256        # Ring polynomial degree: R_q = Z_q[X] / (X^256 + 1)
K = 3          # Module rank (K=2 for ML-KEM-512, K=3 for 768, K=4 for 1024)
ETA_1 = 2      # CBD noise width for secret s, error e, and ephemeral r
ETA_2 = 2      # CBD noise width for ciphertext errors e1, e2
DU = 10        # Ciphertext vector u compression bit-width
DV = 4         # Ciphertext scalar v compression bit-width

def _bitrev7(x: int) -> int:
    return int(f"{x:07b}"[::-1], 2)

ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]

def poly_add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(a, b)]

def poly_sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % Q for x, y in zip(a, b)]

def ntt(f: list[int]) -> list[int]:
    f_hat = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % Q
                f_hat[j + length] = (f_hat[j] - t) % Q
                f_hat[j] = (f_hat[j] + t) % Q
        length //= 2
    return f_hat

def inv_ntt(f_hat: list[int]) -> list[int]:
    f = list(f_hat)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (f[j + length] - t)) % Q
        length *= 2

    return [(x * 3303) % Q for x in f]

def multiply_ntts(f_hat: list[int], g_hat: list[int]) -> list[int]:
    h_hat = [0] * 256
    for i in range(128):
        a0, a1 = f_hat[2 * i], f_hat[2 * i + 1]
        b0, b1 = g_hat[2 * i], g_hat[2 * i + 1]
        gamma = ZETAS[64 + (i // 2)]
        if i % 2 == 1:
            gamma = Q - gamma  
        h_hat[2 * i] = (a0 * b0 + a1 * b1 * gamma) % Q
        h_hat[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h_hat

def vec_dot_ntt(u_hat: list[list[int]], v_hat: list[list[int]]) -> list[int]:
    """Inner product of two K-element vectors in the NTT domain."""
    acc = [0] * 256
    for i in range(K):
        acc = poly_add(acc, multiply_ntts(u_hat[i], v_hat[i]))
    return acc


def compress_poly(poly: list[int], d: int) -> list[int]:
    mask = (1 << d) - 1
    return [(((x << d) + (Q // 2)) // Q) & mask for x in poly]

def decompress_poly(poly: list[int], d: int) -> list[int]:
    half = 1 << (d - 1)
    return [(y * Q + half) >> d for y in poly]

def byte_encode(poly: list[int], d: int) -> bytes:
    out = bytearray(32 * d)
    bit_idx = 0
    for coeff in poly:
        val = coeff
        for _ in range(d):
            if val & 1:
                out[bit_idx >> 3] |= 1 << (bit_idx & 7)
            val >>= 1
            bit_idx += 1
    return bytes(out)

def byte_decode(data: bytes, d: int) -> list[int]:
    poly = [0] * 256
    bit_idx = 0
    modulus = Q if d == 12 else (1 << d)
    for i in range(256):
        val = 0
        for b in range(d):
            bit = (data[bit_idx >> 3] >> (bit_idx & 7)) & 1
            val |= bit << b
            bit_idx += 1
        poly[i] = val % modulus
    return poly


def hash_h(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def hash_g(data: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha3_512(data).digest()
    return digest[:32], digest[32:]

def hash_j(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(32)

def prf(eta: int, seed_sigma: bytes, nonce: int) -> bytes:
    return hashlib.shake_256(seed_sigma + bytes([nonce])).digest(64 * eta)

def sample_ntt(seed_rho: bytes, col_j: int, row_i: int) -> list[int]:
    stream = hashlib.shake_128(seed_rho + bytes([col_j, row_i])).digest(840)
    a_hat = []
    idx = 0
    while len(a_hat) < 256:
        d1 = stream[idx] + 256 * (stream[idx + 1] & 0x0F)
        d2 = (stream[idx + 1] >> 4) + 16 * stream[idx + 2]
        if d1 < Q:
            a_hat.append(d1)
        if d2 < Q and len(a_hat) < 256:
            a_hat.append(d2)
        idx += 3
    return a_hat

def sample_poly_cbd(raw_bytes: bytes, eta: int) -> list[int]:
    poly = [0] * 256
    bit_idx = 0
    for i in range(256):
        x = 0
        for _ in range(eta):
            x += (raw_bytes[bit_idx >> 3] >> (bit_idx & 7)) & 1
            bit_idx += 1
        y = 0
        for _ in range(eta):
            y += (raw_bytes[bit_idx >> 3] >> (bit_idx & 7)) & 1
            bit_idx += 1
        poly[i] = (x - y) % Q
    return poly

def k_pke_keygen(d_seed: bytes) -> tuple[bytes, bytes]:
    rho, sigma = hash_g(d_seed + bytes([K]))

    A_hat = [[sample_ntt(rho, j, i) for j in range(K)] for i in range(K)]

    s = [sample_poly_cbd(prf(ETA_1, sigma, r), ETA_1) for r in range(K)]
    e = [sample_poly_cbd(prf(ETA_1, sigma, K + r), ETA_1) for r in range(K)]

    s_hat = [ntt(poly) for poly in s]
    e_hat = [ntt(poly) for poly in e]

    t_hat = [
        poly_add(vec_dot_ntt(A_hat[i], s_hat), e_hat[i])
        for i in range(K)
    ]

    ek_pke = b"".join(byte_encode(t_hat[i], 12) for i in range(K)) + rho
    dk_pke = b"".join(byte_encode(s_hat[i], 12) for i in range(K))
    return ek_pke, dk_pke

def k_pke_encrypt(ek_pke: bytes, m: bytes, r_coins: bytes) -> bytes:
    t_hat = [byte_decode(ek_pke[384 * i : 384 * (i + 1)], 12) for i in range(K)]
    rho = ek_pke[384 * K : 384 * K + 32]

    A_hat_T = [[sample_ntt(rho, i, j) for j in range(K)] for i in range(K)]

    y = [sample_poly_cbd(prf(ETA_1, r_coins, i), ETA_1) for i in range(K)]
    e1 = [sample_poly_cbd(prf(ETA_2, r_coins, K + i), ETA_2) for i in range(K)]
    e2 = sample_poly_cbd(prf(ETA_2, r_coins, 2 * K), ETA_2)

    y_hat = [ntt(poly) for poly in y]
    u = [
        poly_add(inv_ntt(vec_dot_ntt(A_hat_T[i], y_hat)), e1[i])
        for i in range(K)
    ]

    mu = decompress_poly(byte_decode(m, 1), 1)

    v = poly_add(poly_add(inv_ntt(vec_dot_ntt(t_hat, y_hat)), e2), mu)

    c1 = b"".join(byte_encode(compress_poly(u[i], DU), DU) for i in range(K))
    c2 = byte_encode(compress_poly(v, DV), DV)
    return c1 + c2

def k_pke_decrypt(dk_pke: bytes, ciphertext: bytes) -> bytes:
    c1_len = 32 * DU * K
    c1, c2 = ciphertext[:c1_len], ciphertext[c1_len:]

    step = 32 * DU
    u_prime = [
        decompress_poly(byte_decode(c1[step * i : step * (i + 1)], DU), DU)
        for i in range(K)
    ]
    v_prime = decompress_poly(byte_decode(c2, DV), DV)

    s_hat = [byte_decode(dk_pke[384 * i : 384 * (i + 1)], 12) for i in range(K)]

    u_hat = [ntt(poly) for poly in u_prime]
    w = poly_sub(v_prime, inv_ntt(vec_dot_ntt(s_hat, u_hat)))

    return byte_encode(compress_poly(w, 1), 1)


def ml_kem_keygen(d: bytes = None, z: bytes = None) -> tuple[bytes, bytes]:
    if d is None:
        d = secrets.token_bytes(32)
    if z is None:
        z = secrets.token_bytes(32)

    ek_pke, dk_pke = k_pke_keygen(d)
    ek = ek_pke
    dk = dk_pke + ek + hash_h(ek) + z
    return ek, dk

def ml_kem_encaps(ek: bytes, m: bytes = None) -> tuple[bytes, bytes]:
    if m is None:
        m = secrets.token_bytes(32)

    shared_k, r_coins = hash_g(m + hash_h(ek))
    ciphertext = k_pke_encrypt(ek, m, r_coins)
    return shared_k, ciphertext

def ml_kem_decaps(dk: bytes, ciphertext: bytes) -> bytes:
    dk_pke = dk[0 : 384 * K]
    ek_pke = dk[384 * K : 768 * K + 32]
    h_ek = dk[768 * K + 32 : 768 * K + 64]
    z = dk[768 * K + 64 : 768 * K + 96]

    m_prime = k_pke_decrypt(dk_pke, ciphertext)

    k_prime, r_prime = hash_g(m_prime + h_ek)

    k_bar = hash_j(z + ciphertext)

    c_prime = k_pke_encrypt(ek_pke, m_prime, r_prime)

    if secrets.compare_digest(ciphertext, c_prime):
        return k_prime
    return k_bar


if __name__ == "__main__":
    print("=== NIST FIPS 203 ML-KEM-768 From-Scratch Verification ===")

    # 1. Key Generation
    ek, dk = ml_kem_keygen()
    print(f"[1] KeyGen Complete:")
    print(f"    Encapsulation Key (ek) size : {len(ek)} bytes (FIPS 203 spec: 1184)")
    print(f"    Decapsulation Key (dk) size : {len(dk)} bytes (FIPS 203 spec: 2400)")

    # 2. Encapsulation
    shared_key_bob, ct = ml_kem_encaps(ek)
    print(f"\n[2] Encaps Complete:")
    print(f"    Ciphertext (c) size         : {len(ct)} bytes (FIPS 203 spec: 1088)")
    print(f"    Bob's Shared Secret (K)     : {shared_key_bob.hex()}")

    # 3. Decapsulation
    shared_key_alice = ml_kem_decaps(dk, ct)
    print(f"\n[3] Decaps Complete:")
    print(f"    Alice's Shared Secret (K')  : {shared_key_alice.hex()}")
    assert shared_key_bob == shared_key_alice, "Shared secrets did not match!"
    print("    -> SUCCESS: Bob and Alice derived the exact same 256-bit secret!")

    # 4. Implicit Rejection Test (Tampered Ciphertext)
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0x01  # Flip 1 bit in the ciphertext
    rejected_key = ml_kem_decaps(dk, bytes(tampered_ct))
    print(f"\n[4] Implicit Rejection Test (1 bit flipped in ciphertext):")
    print(f"    Implicit Rejection Key      : {rejected_key.hex()}")
    assert rejected_key != shared_key_bob, "Tampered ciphertext was not rejected!"
    print("    -> SUCCESS: Tampered ciphertext safely returned pseudorandom K_bar.")