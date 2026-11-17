
"""
QuantumShield - Cryptographic Performance Benchmarking

Compares:
    RSA-2048
    ML-KEM-768
    RSA-PSS
    ML-DSA-65
    AES-256-GCM

Measurements:
    Key generation
    Key establishment
    Digital signing and verification
    File encryption and decryption
    Cryptographic key and signature sizes

All timing measurements are performed locally.
"""
import cryptography
import oqs
import os
import platform
import sys

from datetime import datetime, timezone
from statistics import mean, median
from time import perf_counter_ns

from cryptography.hazmat.primitives import hashes, serialization

from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantumshield.crypto.classical import (
    encrypt_aes_key,
    decrypt_aes_key,
    sign_data as rsa_sign_data,
    verify_signature as rsa_verify_signature
)

from quantumshield.crypto.pqc import (
    generate_kem_keypair,
    encapsulate_key,
    decapsulate_key,
    derive_aes_key,
    generate_signature_keys,
    sign_data as mldsa_sign_data,
    verify_signature as mldsa_verify_signature
)

# =====================================================
# CONFIGURATION
# =====================================================

DEFAULT_FILE_SIZES = (
    100 * 1024,          # 100 KB
    1024 * 1024,         # 1 MB
    10 * 1024 * 1024     # 10 MB
)

DEFAULT_REPETITIONS = 5

RSA_KEY_SIZE = 2048

MESSAGE = (
    b"QuantumShield cryptographic benchmarking message "
    b"for RSA-PSS and ML-DSA performance evaluation."
)


# =====================================================
# TIMING UTILITIES
# =====================================================

def measure_operation(operation, repetitions: int = 5):
    """
    Measure an operation in milliseconds.

    One warm-up execution is excluded from the results.
    """

    if not isinstance(repetitions, int) or not 1 <= repetitions <= 50:
        raise ValueError("Repetitions must be between 1 and 50.")

    # Warm-up
    operation()

    timings = []

    for _ in range(repetitions):

        start = perf_counter_ns()

        operation()

        end = perf_counter_ns()

        elapsed_ms = (end - start) / 1_000_000

        timings.append(elapsed_ms)

    return {
        "mean_ms": round(mean(timings), 4),
        "median_ms": round(median(timings), 4),
        "min_ms": round(min(timings), 4),
        "samples_ms": [round(value, 4) for value in timings]
    }


# =====================================================
# KEY SERIALIZATION UTILITIES
# =====================================================

def rsa_public_key_size(public_key) -> int:
    """Return RSA public-key size in DER encoding."""

    return len(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def rsa_private_key_size(private_key) -> int:
    """Return unencrypted PKCS8 DER size for measurement only."""

    return len(
        private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )


# =====================================================
# KEY GENERATION BENCHMARKS
# =====================================================

def benchmark_key_generation(repetitions: int):
    """Compare RSA, ML-KEM and ML-DSA key generation."""

    def generate_rsa():
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE
        )

    return {
        "rsa_2048": measure_operation(
            generate_rsa,
            repetitions
        ),

        "ml_kem_768": measure_operation(
            generate_kem_keypair,
            repetitions
        ),

        "ml_dsa_65": measure_operation(
            generate_signature_keys,
            repetitions
        )
    }


# =====================================================
# KEY ESTABLISHMENT BENCHMARKS
# =====================================================

def benchmark_key_establishment(
    rsa_public,
    rsa_private,
    kem_public: bytes,
    kem_private: bytes,
    repetitions: int
):
    """Compare RSA-OAEP and ML-KEM key establishment."""

    aes_key = os.urandom(32)

    # ---------------- RSA ----------------

    encrypted_aes_key = encrypt_aes_key(
        aes_key,
        rsa_public
    )

    def rsa_encrypt():
        return encrypt_aes_key(
            aes_key,
            rsa_public
        )

    def rsa_decrypt():
        recovered = decrypt_aes_key(
            encrypted_aes_key,
            rsa_private
        )

        assert recovered == aes_key

    def rsa_round_trip():
        encrypted = encrypt_aes_key(
            aes_key,
            rsa_public
        )

        recovered = decrypt_aes_key(
            encrypted,
            rsa_private
        )

        assert recovered == aes_key

    # ---------------- ML-KEM ----------------

    kem_ciphertext, sender_secret = encapsulate_key(
        kem_public
    )

    receiver_secret = decapsulate_key(
        kem_ciphertext,
        kem_private
    )

    assert sender_secret == receiver_secret

    shared_salt = os.urandom(16)

    def kem_encapsulation():
        return encapsulate_key(kem_public)

    def kem_decapsulation():
        recovered = decapsulate_key(
            kem_ciphertext,
            kem_private
        )

        assert recovered == receiver_secret

    def kem_round_trip():

        ciphertext, sender_shared_secret = encapsulate_key(
            kem_public
        )

        receiver_shared_secret = decapsulate_key(
            ciphertext,
            kem_private
        )

        sender_aes_key, _ = derive_aes_key(
            sender_shared_secret,
            salt=shared_salt
        )

        receiver_aes_key, _ = derive_aes_key(
            receiver_shared_secret,
            salt=shared_salt
        )

        assert sender_aes_key == receiver_aes_key

    return {
        "rsa_oaep": {
            "encryption": measure_operation(
                rsa_encrypt,
                repetitions
            ),
            "decryption": measure_operation(
                rsa_decrypt,
                repetitions
            ),
            "round_trip": measure_operation(
                rsa_round_trip,
                repetitions
            )
        },

        "ml_kem_768": {
            "encapsulation": measure_operation(
                kem_encapsulation,
                repetitions
            ),
            "decapsulation": measure_operation(
                kem_decapsulation,
                repetitions
            ),
            "round_trip_with_hkdf": measure_operation(
                kem_round_trip,
                repetitions
            )
        }
    }


# =====================================================
# DIGITAL SIGNATURE BENCHMARKS
# =====================================================


def benchmark_signatures(
    rsa_private,
    rsa_public,
    mldsa_public: bytes,
    mldsa_private: bytes,
    repetitions: int
):
    """Compare RSA-PSS and ML-DSA signing performance."""

    # ---------------- RSA-PSS ----------------

    rsa_signature = rsa_sign_data(
        MESSAGE,
        rsa_private
    )

    def rsa_sign():
        return rsa_sign_data(
            MESSAGE,
            rsa_private
        )

    def rsa_verify():
        assert rsa_verify_signature(
            MESSAGE,
            rsa_signature,
            rsa_public
        )

    # ---------------- ML-DSA ----------------

    mldsa_signature = mldsa_sign_data(
        MESSAGE,
        mldsa_private
    )

    def mldsa_sign():
        return mldsa_sign_data(
            MESSAGE,
            mldsa_private
        )

    def mldsa_verify():
        assert mldsa_verify_signature(
            MESSAGE,
            mldsa_signature,
            mldsa_public
        )

    return {
        "rsa_pss": {
            "signing": measure_operation(
                rsa_sign,
                repetitions
            ),
            "verification": measure_operation(
                rsa_verify,
                repetitions
            )
        },

        "ml_dsa_65": {
            "signing": measure_operation(
                mldsa_sign,
                repetitions
            ),
            "verification": measure_operation(
                mldsa_verify,
                repetitions
            )
        }
    }


# =====================================================
# AES FILE ENCRYPTION BENCHMARKS
# =====================================================

def benchmark_file_encryption(
    file_sizes: tuple,
    repetitions: int
):
    """
    Benchmark AES-256-GCM for different file sizes.

    Both cryptographic modes use this same file
    encryption algorithm, so these results are shared.
    """

    results = []

    aes_key = AESGCM.generate_key(
        bit_length=256
    )

    aesgcm = AESGCM(aes_key)

    for size in file_sizes:

        if not isinstance(size, int) or size <= 0:
            raise ValueError("File sizes must be positive integers.")

        file_data = os.urandom(size)

        def encrypt():
            nonce = os.urandom(12)

            return nonce, aesgcm.encrypt(
                nonce,
                file_data,
                None
            )

        # Prepare one valid encrypted sample for decryption.
        nonce, encrypted_data = encrypt()

        def decrypt():
            recovered = aesgcm.decrypt(
                nonce,
                encrypted_data,
                None
            )

            assert recovered == file_data

        results.append({
            "size_bytes": size,
            "encryption": measure_operation(
                encrypt,
                repetitions
            ),
            "decryption": measure_operation(
                decrypt,
                repetitions
            ),
            "ciphertext_size_bytes": len(encrypted_data),
            "authentication_overhead_bytes": 16
        })

    return results


# =====================================================
# CRYPTOGRAPHIC SIZE COMPARISON
# =====================================================

def benchmark_key_sizes(
    rsa_private,
    rsa_public,
    kem_public,
    kem_private,
    mldsa_public,
    mldsa_private
):
    """Measure the actual serialized/raw key and output sizes."""

    aes_key = os.urandom(32)

    rsa_ciphertext = encrypt_aes_key(
        aes_key,
        rsa_public
    )

    kem_ciphertext, _ = encapsulate_key(
        kem_public
    )

    rsa_signature = rsa_sign_data(
        MESSAGE,
        rsa_private
    )

    mldsa_signature = mldsa_sign_data(
        MESSAGE,
        mldsa_private
    )
    return {
        "rsa_2048": {
            "public_key_bytes": rsa_public_key_size(rsa_public),
            "private_key_bytes_der": rsa_private_key_size(rsa_private),
            "encrypted_aes_key_bytes": len(rsa_ciphertext),
            "signature_bytes": len(rsa_signature)
        },

        "ml_kem_768": {
            "public_key_bytes": len(kem_public),
            "private_key_bytes": len(kem_private),
            "encapsulated_ciphertext_bytes": len(kem_ciphertext),
            "shared_secret_bytes": 32
        },

        "ml_dsa_65": {
            "public_key_bytes": len(mldsa_public),
            "private_key_bytes": len(mldsa_private),
            "signature_bytes": len(mldsa_signature)
        },

        "aes_256_gcm": {
            "key_bytes": len(aes_key),
            "nonce_bytes": 12,
            "authentication_tag_bytes": 16
        }
    }


# =====================================================
# MAIN BENCHMARK RUNNER
# =====================================================

def run_crypto_benchmark(
    repetitions: int = DEFAULT_REPETITIONS,
    file_sizes: tuple = DEFAULT_FILE_SIZES
):
    """
    Execute all cryptographic benchmarks.

    Returns a JSON-serializable results dictionary.
    """

    if not isinstance(repetitions, int) or not 1 <= repetitions <= 50:
        raise ValueError("Repetitions must be between 1 and 50.")

    if not file_sizes:
        raise ValueError("At least one file size is required.")

    # ---------------- Create benchmark keys ----------------

    rsa_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    rsa_public = rsa_private.public_key()

    kem_public, kem_private = generate_kem_keypair()

    mldsa_public, mldsa_private = generate_signature_keys()

    # ---------------- Execute benchmarks ----------------

    key_generation = benchmark_key_generation(
        repetitions
    )

    key_establishment = benchmark_key_establishment(
        rsa_public,
        rsa_private,
        kem_public,
        kem_private,
        repetitions
    )

    signatures = benchmark_signatures(
        rsa_private,
        rsa_public,
        mldsa_public,
        mldsa_private,
        repetitions
    )

    file_encryption = benchmark_file_encryption(
        file_sizes,
        repetitions
    )

    key_sizes = benchmark_key_sizes(
        rsa_private,
        rsa_public,
        kem_public,
        kem_private,
        mldsa_public,
        mldsa_private
    )

    return {
        "metadata": {
            "project": "QuantumShield",
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "processor": platform.processor() or "Not reported",
            "repetitions": repetitions,
            "file_sizes_bytes": list(file_sizes),
            "warmup_runs": 1,
            "library_versions": {
                "cryptography": cryptography.__version__,
                "liboqs": oqs.oqs_version(),
                "liboqs_python": oqs.oqs_python_version()
            }
        },

        "key_generation": key_generation,

        "key_establishment": key_establishment,

        "digital_signatures": signatures,

        "file_encryption": file_encryption,

        "key_sizes": key_sizes,

        "notes": [
            "Measurements are local application-level timings.",
            "Results depend on hardware, software versions and system load.",
            "File encryption uses AES-256-GCM in both modes.",
            "RSA private-key size is measured in unencrypted PKCS8 DER for comparison only.",
            "No private keys or original file contents are stored in benchmark results."
        ]
    }

