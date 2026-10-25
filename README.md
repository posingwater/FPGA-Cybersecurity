## Phase 1: Key Generation (`ml_kem_keygen` & `k_pke_keygen`)

The generation phase creates the public encapsulation key (`ek`) and the private decapsulation key (`dk`).

1. **Seed Generation:** Generate two 32-byte random seeds: $d$ (for public key encryption setup) and $z$ (for implicit rejection).
2. **Key Expansion:** Hash seed $d$ using SHA3-512 to deterministically produce two new 32-byte seeds: $\rho$ (matrix seed) and $\sigma$ (noise seed).
3. **Public Matrix Construction:** Use SHAKE-128 on seed $\rho$ to deterministically sample a $3 \times 3$ matrix of polynomials, $\mathbf{A}$, directly in the Number Theoretic Transform (NTT) domain.
4. **Secret and Error Sampling:** Use SHAKE-256 on seed $\sigma$ to generate pseudorandom bytes, which are then fed into a Centered Binomial Distribution (CBD) to create a secret vector $\mathbf{s}$ and an error vector $\mathbf{e}$ containing small coefficients.
5. **Polynomial Math:** Transform $\mathbf{s}$ and $\mathbf{e}$ into the NTT domain, then compute the public key vector $\mathbf{t} = \mathbf{A} \cdot \mathbf{s} + \mathbf{e}$.
6. **Serialization:** Compress and encode $\mathbf{t}$ into bytes, appending the seed $\rho$ to form the public encapsulation key (`ek`).
7. **Decapsulation Key Assembly:** Package the PKE secret key $\mathbf{s}$, the full encapsulation key, a hash of the encapsulation key, and the implicit rejection seed $z$ into a single decapsulation key (`dk`).

## Phase 2: Key Encapsulation (`ml_kem_encaps` & `k_pke_encrypt`)

The encapsulation phase allows a sender to establish a shared secret $K$ and safely encrypt it for the recipient.

1. **Message Generation:** Generate a completely random 32-byte message $m$.
2. **Secret and Randomness Derivation:** Hash the message $m$ concatenated with the hash of the recipient's public key using SHA3-512. Split the 64-byte output into the 32-byte shared secret $K$ and 32-byte encryption randomness $r$.
3. **Matrix Regeneration:** Extract seed $\rho$ from the recipient's public key and regenerate the transposed matrix $\mathbf{A}^T$.
4. **Ephemeral Error Sampling:** Use randomness $r$ and SHAKE-256 to sample an ephemeral secret vector $\mathbf{y}$, an error vector $\mathbf{e}_1$, and a scalar error polynomial $e_2$ using the CBD.
5. **Vector Multiplication (Part 1):** Compute the first part of the ciphertext by multiplying the matrix by the ephemeral secret and adding noise: $\mathbf{u} = \mathbf{A}^T \cdot \mathbf{y} + \mathbf{e}_1$.
6. **Message Encoding & Multiplication (Part 2):** Encode the 32-byte message $m$ into a polynomial where bits map to either $0$ or $Q/2$. Compute the second part of the ciphertext: $v = \mathbf{t}^T \cdot \mathbf{y} + e_2 + m$.
7. **Quantization:** Compress the coefficients of $\mathbf{u}$ and $v$ (dropping lower bits to save space) and serialize them into the final byte array ciphertext $c$.

## Phase 3: Key Decapsulation (`ml_kem_decaps` & `k_pke_decrypt`)

The decapsulation phase uses the Fujisaki-Okamoto (FO) transform to safely recover the shared secret while preventing chosen-ciphertext attacks.

1. **Key Unpacking:** Extract the secret vector $\mathbf{s}$, the embedded public key, its hash, and the rejection seed $z$ from the decapsulation key (`dk`).
2. **Decompression:** Unpack the incoming ciphertext bytes and decompress them back into the polynomial vector $\mathbf{u}'$ and scalar polynomial $v'$.
3. **Decryption:** Compute the noisy message polynomial $w = v' - \mathbf{s}^T \cdot \mathbf{u}'$.
4. **Decoding:** Decode $w$ bit-by-bit by checking if each coefficient is closer to $0$ (decodes to bit 0) or $Q/2$ (decodes to bit 1), recovering a candidate message $m'$.
5. **Re-derivation:** Hash $m'$ alongside the public key hash to re-derive a candidate shared secret $K'$ and candidate encryption randomness $r'$.
6. **Re-encryption:** Re-encrypt $m'$ using $r'$ exactly as the sender did to produce a candidate ciphertext $c'$.
7. **Constant-Time Verification:** Compare the newly generated $c'$ against the originally received ciphertext $c$ using a constant-time memory comparison.
8. **Implicit Rejection:** If $c$ and $c'$ match exactly, output the derived shared secret $K'$. If any bits differ (indicating tampering or a transmission error), compute and output a pseudorandom "implicit rejection" key derived from $z$ and $c$ to prevent leaking information about the private key.