"""
Complete, Runnable NIST FIPS 203 (ML-KEM-768) Implementation from Scratch
-------------------------------------------------------------------------
Pure Python 3 implementation using only standard library `hashlib` and `secrets`.
Strictly follows the algorithm numbering and math of NIST FIPS 203.
"""

import hashlib
import secrets

# ==============================================================================
# 1. ML-KEM-768 PARAMETERS & NTT TWIDDLE FACTORS (FIPS 203 Section 4 & Table 2)
# ==============================================================================
Q = 3329       # Prime modulus: 3329 = 2^8 * 13 + 1
N = 256        # Ring polynomial degree: R_q = Z_q[X] / (X^256 + 1)
K = 3          # Module rank (K=2 for ML-KEM-512, K=3 for 768, K=4 for 1024)
ETA_1 = 2      # CBD noise width for secret s, error e, and ephemeral r
ETA_2 = 2      # CBD noise width for ciphertext errors e1, e2
DU = 10        # Ciphertext vector u compression bit-width
DV = 4         # Ciphertext scalar v compression bit-width

# 17 is a primitive 256-th root of unity modulo 3329 (17^128 == -1 mod 3329).
# FIPS 203 precomputes powers of 17 in 7-bit bit-reversed order.
def _bitrev7(x: int) -> int:
    return int(f"{x:07b}"[::-1], 2)

ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]


# ==============================================================================
# 2. POLYNOMIAL & NTT ARITHMETIC (FIPS 203 Algorithms 9, 10, 11, 12)
# ==============================================================================
def poly_add(a: list[int], b: list[int]) -> list[int]:
    """Component-wise addition of two 256-element polynomials modulo Q."""
    return [(x + y) % Q for x, y in zip(a, b)]

def poly_sub(a: list[int], b: list[int]) -> list[int]:
    """Component-wise subtraction of two 256-element polynomials modulo Q."""
    return [(x - y) % Q for x, y in zip(a, b)]

def ntt(f: list[int]) -> list[int]:
    """
    FIPS 203 Algorithm 9: NTT(f)
    Transforms a polynomial f in R_q into its 128 degree-1 residue polynomials
    modulo (X^2 - zeta^(2*bitrev7(i) + 1)) using Cooley-Tukey butterflies.
    """
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
    """
    FIPS 203 Algorithm 10: NTT^-1(f_hat)
    Inverts the NTT using Gentleman-Sande butterflies and scales by 128^-1 mod Q.
    """
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
                # Note: ZETAS[127-k] == -ZETAS[64+k]^-1 mod Q, so (f[j+length] - t)
                # cancels the minus sign and divides by the forward twiddle factor.
                f[j + length] = (zeta * (f[j + length] - t)) % Q
        length *= 2

    # 3303 is the modular inverse of 128 modulo 3329 (128 * 3303 == 1 mod 3329)
    return [(x * 3303) % Q for x in f]

def multiply_ntts(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """
    FIPS 203 Algorithms 11 & 12: MultiplyNTTs(f_hat, g_hat) and BaseCaseMultiply.
    Multiplies 128 pairs of degree-1 polynomials:
      (a0 + a1*X) * (b0 + b1*X) mod (X^2 - gamma)
    where gamma = +ZETAS[64 + i//2] for even i, and -ZETAS[64 + i//2] for odd i.
    """
    h_hat = [0] * 256
    for i in range(128):
        a0, a1 = f_hat[2 * i], f_hat[2 * i + 1]
        b0, b1 = g_hat[2 * i], g_hat[2 * i + 1]
        gamma = ZETAS[64 + (i // 2)]
        if i % 2 == 1:
            gamma = Q - gamma  # Negate gamma for odd-indexed quadratic factors
        h_hat[2 * i] = (a0 * b0 + a1 * b1 * gamma) % Q
        h_hat[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h_hat

def vec_dot_ntt(u_hat: list[list[int]], v_hat: list[list[int]]) -> list[int]:
    """Inner product of two K-element vectors in the NTT domain."""
    acc = [0] * 256
    for i in range(K):
        acc = poly_add(acc, multiply_ntts(u_hat[i], v_hat[i]))
    return acc


# ==============================================================================
# 3. COMPRESSION, DECOMPRESSION & SERIALIZATION (FIPS 203 Algorithms 3, 4, 5, 6)
# ==============================================================================
def compress_poly(poly: list[int], d: int) -> list[int]:
    """
    FIPS 203 Eq (4.7): Compress_d(x) = round((2^d / Q) * x) mod 2^d.
    Drops low-order bits from polynomial coefficients to shrink ciphertexts.
    """
    mask = (1 << d) - 1
    return [(((x << d) + (Q // 2)) // Q) & mask for x in poly]

def decompress_poly(poly: list[int], d: int) -> list[int]:
    """
    FIPS 203 Eq (4.8): Decompress_d(y) = round((Q / 2^d) * y).
    Maps d-bit compressed integers back to approximate values in [0, Q-1].
    """
    half = 1 << (d - 1)
    return [(y * Q + half) >> d for y in poly]

def byte_encode(poly: list[int], d: int) -> bytes:
    """
    FIPS 203 Algorithm 5: ByteEncode_d(F)
    Packs 256 d-bit integers into 32*d bytes (little-endian bit packing).
    """
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
    """
    FIPS 203 Algorithm 6: ByteDecode_d(B)
    Unpacks 32*d bytes into 256 d-bit integers (reduced mod Q when d == 12).
    """
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


# ==============================================================================
# 4. CRYPTOGRAPHIC SAMPLING & HASH WRAPPERS (FIPS 203 Section 4.1 & Alg 7, 8)
# ==============================================================================
def hash_h(data: bytes) -> bytes:
    """FIPS 203 H(s): SHA3-256 (returns 32 bytes)."""
    return hashlib.sha3_256(data).digest()

def hash_g(data: bytes) -> tuple[bytes, bytes]:
    """FIPS 203 G(c): SHA3-512 split into two 32-byte halves (a, b)."""
    digest = hashlib.sha3_512(data).digest()
    return digest[:32], digest[32:]

def hash_j(data: bytes) -> bytes:
    """FIPS 203 J(s): SHAKE-256 returning 32 bytes (used for implicit rejection)."""
    return hashlib.shake_256(data).digest(32)

def prf(eta: int, seed_sigma: bytes, nonce: int) -> bytes:
    """FIPS 203 PRF_eta(sigma, N): SHAKE-256 returning 64*eta pseudorandom bytes."""
    return hashlib.shake_256(seed_sigma + bytes([nonce])).digest(64 * eta)

def sample_ntt(seed_rho: bytes, col_j: int, row_i: int) -> list[int]:
    """
    FIPS 203 Algorithm 7: SampleNTT(B)
    Uniformly samples a polynomial directly in the NTT domain from SHAKE-128
    using rejection sampling on 12-bit integers (3 bytes -> two 12-bit values).
    """
    # Absorb 32-byte seed rho + 2-byte matrix coordinates (j, i)
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
    """
    FIPS 203 Algorithm 8: SamplePolyCBD_eta(B)
    Samples a polynomial with small error/secret coefficients in [-eta, +eta]
    from a Centered Binomial Distribution.
    """
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


# ==============================================================================
# 5. INTERNAL K-PKE SCHEME (FIPS 203 Algorithms 13, 14, 15)
# ==============================================================================
def k_pke_keygen(d_seed: bytes) -> tuple[bytes, bytes]:
    """
    FIPS 203 Algorithm 13: K-PKE.KeyGen(d)
    Generates the serialized CPA-secure encryption key `ek_pke` and `dk_pke`.
    Notice FIPS 203 appends domain separator K to d_seed before hashing with G!
    """
    rho, sigma = hash_g(d_seed + bytes([K]))

    # 1. Sample K x K public matrix A_hat directly in the NTT domain
    A_hat = [[sample_ntt(rho, j, i) for j in range(K)] for i in range(K)]

    # 2. Sample secret vector s and error vector e from CBD_eta1
    s = [sample_poly_cbd(prf(ETA_1, sigma, r), ETA_1) for r in range(K)]
    e = [sample_poly_cbd(prf(ETA_1, sigma, K + r), ETA_1) for r in range(K)]

    # 3. Transform s and e into the NTT domain
    s_hat = [ntt(poly) for poly in s]
    e_hat = [ntt(poly) for poly in e]

    # 4. Compute public vector t_hat = A_hat * s_hat + e_hat
    t_hat = [
        poly_add(vec_dot_ntt(A_hat[i], s_hat), e_hat[i])
        for i in range(K)
    ]

    # 5. Serialize keys to bytes
    ek_pke = b"".join(byte_encode(t_hat[i], 12) for i in range(K)) + rho
    dk_pke = b"".join(byte_encode(s_hat[i], 12) for i in range(K))
    return ek_pke, dk_pke

def k_pke_encrypt(ek_pke: bytes, m: bytes, r_coins: bytes) -> bytes:
    """
    FIPS 203 Algorithm 14: K-PKE.Encrypt(ek_pke, m, r)
    Deterministically encrypts 32-byte message `m` using randomness `r_coins`.
    """
    # 1. Unpack public key vector t_hat and matrix seed rho
    t_hat = [byte_decode(ek_pke[384 * i : 384 * (i + 1)], 12) for i in range(K)]
    rho = ek_pke[384 * K : 384 * K + 32]

    # 2. Regenerate A_hat^T (note swapped indices i, j for transpose!)
    A_hat_T = [[sample_ntt(rho, i, j) for j in range(K)] for i in range(K)]

    # 3. Sample ephemeral vector y, error vector e1, and scalar error polynomial e2
    y = [sample_poly_cbd(prf(ETA_1, r_coins, i), ETA_1) for i in range(K)]
    e1 = [sample_poly_cbd(prf(ETA_2, r_coins, K + i), ETA_2) for i in range(K)]
    e2 = sample_poly_cbd(prf(ETA_2, r_coins, 2 * K), ETA_2)

    # 4. Compute u = NTT^-1(A_hat^T * NTT(y)) + e1
    y_hat = [ntt(poly) for poly in y]
    u = [
        poly_add(inv_ntt(vec_dot_ntt(A_hat_T[i], y_hat)), e1[i])
        for i in range(K)
    ]

    # 5. Decode 256-bit message m into polynomial mu (0 -> 0, 1 -> 1665)
    mu = decompress_poly(byte_decode(m, 1), 1)

    # 6. Compute v = NTT^-1(t_hat^T * y_hat) + e2 + mu
    v = poly_add(poly_add(inv_ntt(vec_dot_ntt(t_hat, y_hat)), e2), mu)

    # 7. Compress and serialize ciphertext c = (c1 || c2)
    c1 = b"".join(byte_encode(compress_poly(u[i], DU), DU) for i in range(K))
    c2 = byte_encode(compress_poly(v, DV), DV)
    return c1 + c2

def k_pke_decrypt(dk_pke: bytes, ciphertext: bytes) -> bytes:
    """
    FIPS 203 Algorithm 15: K-PKE.Decrypt(dk_pke, c)
    Recovers the 32-byte message `m` by computing w = v' - NTT^-1(s_hat^T * NTT(u')).
    """
    c1_len = 32 * DU * K
    c1, c2 = ciphertext[:c1_len], ciphertext[c1_len:]

    # 1. Decompress u' and v' from ciphertext bytes
    step = 32 * DU
    u_prime = [
        decompress_poly(byte_decode(c1[step * i : step * (i + 1)], DU), DU)
        for i in range(K)
    ]
    v_prime = decompress_poly(byte_decode(c2, DV), DV)

    # 2. Unpack secret key vector s_hat
    s_hat = [byte_decode(dk_pke[384 * i : 384 * (i + 1)], 12) for i in range(K)]

    # 3. Compute noisy message w = v' - NTT^-1(s_hat^T * NTT(u'))
    u_hat = [ntt(poly) for poly in u_prime]
    w = poly_sub(v_prime, inv_ntt(vec_dot_ntt(s_hat, u_hat)))

    # 4. Compress each coefficient to 1 bit (closest to 0 or Q/2) and pack to 32 bytes
    return byte_encode(compress_poly(w, 1), 1)


# ==============================================================================
# 6. CCA-SECURE ML-KEM INTERFACE (FIPS 203 Algorithms 16, 17, 18, 19, 20, 21)
# ==============================================================================
def ml_kem_keygen(d: bytes = None, z: bytes = None) -> tuple[bytes, bytes]:
    """
    FIPS 203 Algorithms 16 & 19: ML-KEM.KeyGen()
    Produces encapsulation key `ek` (1184 bytes) and decapsulation key `dk` (2400 bytes).
    """
    if d is None:
        d = secrets.token_bytes(32)
    if z is None:
        z = secrets.token_bytes(32)

    ek_pke, dk_pke = k_pke_keygen(d)
    ek = ek_pke
    # dk packs: dk_pke || ek || H(ek) || z
    dk = dk_pke + ek + hash_h(ek) + z
    return ek, dk

def ml_kem_encaps(ek: bytes, m: bytes = None) -> tuple[bytes, bytes]:
    """
    FIPS 203 Algorithms 17 & 20: ML-KEM.Encaps(ek)
    Returns (shared_secret_K, ciphertext_c).
    """
    if m is None:
        m = secrets.token_bytes(32)

    # Derive shared secret K and deterministic encryption coins r from (m || H(ek))
    shared_k, r_coins = hash_g(m + hash_h(ek))
    ciphertext = k_pke_encrypt(ek, m, r_coins)
    return shared_k, ciphertext

def ml_kem_decaps(dk: bytes, ciphertext: bytes) -> bytes:
    """
    FIPS 203 Algorithms 18 & 21: ML-KEM.Decaps(dk, c)
    Decapsulates `ciphertext` using the Fujisaki-Okamoto re-encryption check
    and constant-time implicit rejection.
    """
    # 1. Slice components out of the 2400-byte decapsulation key (for K=3)
    dk_pke = dk[0 : 384 * K]
    ek_pke = dk[384 * K : 768 * K + 32]
    h_ek = dk[768 * K + 32 : 768 * K + 64]
    z = dk[768 * K + 64 : 768 * K + 96]

    # 2. Decrypt ciphertext to obtain candidate message m'
    m_prime = k_pke_decrypt(dk_pke, ciphertext)

    # 3. Re-derive candidate shared secret K' and encryption coins r'
    k_prime, r_prime = hash_g(m_prime + h_ek)

    # 4. Compute implicit rejection key K_bar = J(z || c) in case c was tampered with
    k_bar = hash_j(z + ciphertext)

    # 5. Re-encrypt candidate message m' using r'
    c_prime = k_pke_encrypt(ek_pke, m_prime, r_prime)

    # 6. Constant-time comparison: return K' if c == c', else K_bar
    if secrets.compare_digest(ciphertext, c_prime):
        return k_prime
    return k_bar


# ==============================================================================
# 7. SELF-TEST & VERIFICATION
# ==============================================================================
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