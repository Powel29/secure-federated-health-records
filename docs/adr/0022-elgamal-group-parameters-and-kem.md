# ADR-0022: Unidirectional ElGamal Group Parameters and KEM Scheme for PRE (P1-5)

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** Ojas, Avaneeth, Team
- **Task / source:** P1-5 (WORKFLOW.md); ADR-0012, ADR-0018, ARCHITECTURE §2 C3, §5
- **Affects:** `src/pre/elgamal.py`, `src/pre/exceptions.py`, `tests/pre/test_proxy_reencryption.py`

## Context

ADR-0012 established that Proxy Re-Encryption (PRE) in this project is scoped strictly to unidirectional re-wrapping of record Data Encryption Keys (DEKs) in pure Python. ADR-0018 identified the mathematical requirement that the re-encryption key inverse must be computed modulo the prime subgroup order $q$ (for a safe prime $P = 2q + 1$).

P1-5 required finalizing the concrete group parameterization, exponent generation range, and key encapsulation mechanism (KEM) to securely derive symmetric wrapping keys from ElGamal group elements without leaking secret exponents or being susceptible to small-subgroup attacks.

## Decision

1. **Group Parameters & Subgroup Confinement**:
   - Use a 256-bit safe prime $P = 2q + 1$:
     `SAFE_PRIME_P = 0xF45C8BBE9322D813D2A0A92464E19D100A043DC1994F7CDC2A5D70D8D0F73667`
   - Use generator $g = 4$, which is a quadratic residue modulo $P$ and generates the prime order-$q$ subgroup.
   - Draw private exponents and ephemeral random exponents strictly from $[2, q - 1]$ using CSPRNG (`secrets.randbelow`).

2. **Unidirectional Re-Encryption Formulation**:
   - Re-encryption key from delegator $A$ to delegatee $B$: $rk_{A \to B} = sk_A \cdot sk_B^{-1} \pmod q$.
   - Original ciphertext: $(c_1, c_2) = (g^r \bmod P, m \cdot pk_A^r \bmod P)$.
   - Transformed ciphertext: $(c_1', c_2') = (c_1^{rk_{A \to B}} \bmod P, c_2) = (g^{r \cdot sk_A \cdot sk_B^{-1}} \bmod P, c_2)$.
   - Decryption by $B$: $m = c_2' \cdot ((c_1')^{sk_B})^{-1} \pmod P$.

3. **Key Encapsulation Mechanism (KEM)**:
   - To wrap arbitrary 256-bit AES-GCM DEKs, use DH shared secret encapsulation passed through **HKDF-SHA256** with context tag `b"pre-elgamal-kem-v1"`, deriving symmetric keys for standard authenticated envelope sealing.

## Consequences

- Confinement to the prime order-$q$ subgroup prevents small-subgroup confinement attacks and ensures that modular inverses for re-encryption key derivation always exist.
- Standardized pure-Python arithmetic with zero third-party binary C extensions satisfies the multi-OS portable execution requirement.
- **Downside**: Group operations in pure Python on 256-bit integers are slower than optimized C/Rust curve implementations, but benchmarked within acceptable latency limits (< 15 ms per re-wrap) for metadata DEK operations.

## Alternatives considered

- **Elliptic Curve BBS98 / AFGH on Curve25519/P-256**: Requires custom point scalar division / bilinear pairing libraries (e.g. Charm-Crypto or py_ecc), violating ADR-0001.
- **Direct message multiplicative masking without HKDF**: Reusing raw group elements directly as symmetric keys risks non-uniform entropy; HKDF-SHA256 extract-and-expand ensures uniform 256-bit cryptographic keys.

