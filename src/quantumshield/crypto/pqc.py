
"""
QuantumShield - Post-Quantum Cryptography Engine

Algorithms:
    ML-KEM-768   : Key Encapsulation Mechanism
    ML-DSA-65    : Digital Signatures
    HKDF-SHA256  : AES key derivation
    AES-256-GCM  : File encryption (implemented separately)

Library:
    Open Quantum Safe (liboqs-python)
"""
from functools import lru_cache
import os
from typing import Optional

import oqs

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# =====================================================
# ALGORITHM CONFIGURATION
# =====================================================

KEM_ALGORITHM = "ML-KEM-768"
SIGNATURE_ALGORITHM = "ML-DSA-65"

AES_KEY_SIZE = 32
HKDF_SALT_SIZE = 16

HKDF_INFO = b"QuantumShield-v1-AES-256-GCM"


# =====================================================
# INPUT VALIDATION
# =====================================================

def _validate_bytes(
    value: bytes,
    field_name: str,
    allow_empty: bool = False
):
    """Validate binary input."""

    if not isinstance(value, bytes):
        raise TypeError(f"{field_name} must be bytes.")

    if not allow_empty and not value:
        raise ValueError(f"{field_name} cannot be empty.")

@lru_cache(maxsize=1)
def _check_algorithm_availability():
    """Ensure required PQC algorithms are enabled."""

    available_kems = oqs.get_enabled_kem_mechanisms()
    available_signatures = oqs.get_enabled_sig_mechanisms()

    if KEM_ALGORITHM not in available_kems:
        raise RuntimeError(
            f"{KEM_ALGORITHM} is not enabled in liboqs."
        )

    if SIGNATURE_ALGORITHM not in available_signatures:
        raise RuntimeError(
            f"{SIGNATURE_ALGORITHM} is not enabled in liboqs."
        )


# =====================================================
# 1. ML-KEM-768 KEY GENERATION
# =====================================================

def generate_kem_keypair() -> tuple[bytes, bytes]:
    """
    Generate an ML-KEM-768 key pair.

    Returns:
        public_key: Shareable public key.
        secret_key: Private key that must remain protected.
    """

    _check_algorithm_availability()

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:

        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    return public_key, secret_key


# =====================================================
# 2. ML-KEM-768 ENCAPSULATION
# =====================================================

def encapsulate_key(
    recipient_public_key: bytes
) -> tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using recipient's public key.

    Returns:
        ciphertext: Encapsulated KEM ciphertext.
        shared_secret: Secret used for AES key derivation.
    """

    _validate_bytes(
        recipient_public_key,
        "Recipient public key"
    )

    _check_algorithm_availability()

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:

        ciphertext, shared_secret = kem.encap_secret(
            recipient_public_key
        )

    return ciphertext, shared_secret


# =====================================================
# 3. ML-KEM-768 DECAPSULATION
# =====================================================

def decapsulate_key(
    ciphertext: bytes,
    recipient_secret_key: bytes
) -> bytes:
    """
    Recover the shared secret using recipient's private key.

    Returns:
        shared_secret
    """

    _validate_bytes(ciphertext, "KEM ciphertext")
    _validate_bytes(recipient_secret_key, "KEM private key")

    _check_algorithm_availability()

    with oqs.KeyEncapsulation(
        KEM_ALGORITHM,
        secret_key=recipient_secret_key
    ) as kem:

        shared_secret = kem.decap_secret(ciphertext)

    return shared_secret


# =====================================================
# 4. HKDF-SHA256 AES KEY DERIVATION
# =====================================================

def derive_aes_key(
    shared_secret: bytes,
    salt: Optional[bytes] = None,
    info: bytes = HKDF_INFO
) -> tuple[bytes, bytes]:
    """
    Derive a 256-bit AES key using HKDF-SHA256.

    Args:
        shared_secret: ML-KEM shared secret.
        salt: Optional 16-byte salt. Generated if omitted.
        info: Application-specific derivation context.

    Returns:
        aes_key: 32-byte AES-256 key.
        salt: Salt required to reproduce the same key.
    """

    _validate_bytes(shared_secret, "Shared secret")
    _validate_bytes(info, "HKDF info")

    if salt is None:
        salt = os.urandom(HKDF_SALT_SIZE)

    if not isinstance(salt, bytes):
        raise TypeError("HKDF salt must be bytes.")

    if len(salt) != HKDF_SALT_SIZE:
        raise ValueError(
            f"HKDF salt must be {HKDF_SALT_SIZE} bytes."
        )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=info
    )

    aes_key = hkdf.derive(shared_secret)

    return aes_key, salt


# =====================================================
# 5. ML-DSA-65 KEY GENERATION
# =====================================================

def generate_signature_keys() -> tuple[bytes, bytes]:
    """
    Generate an ML-DSA-65 signing key pair.

    Returns:
        public_key: Public verification key.
        secret_key: Private signing key.
    """

    _check_algorithm_availability()

    with oqs.Signature(SIGNATURE_ALGORITHM) as signer:

        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    return public_key, secret_key


# =====================================================
# 6. ML-DSA-65 SIGNING
# =====================================================

def sign_data(
    message: bytes,
    secret_key: bytes
) -> bytes:
    """
    Sign a message using ML-DSA-65.

    Returns:
        Digital signature.
    """

    _validate_bytes(
        message,
        "Message",
        allow_empty=True
    )

    _validate_bytes(secret_key, "ML-DSA private key")

    _check_algorithm_availability()

    with oqs.Signature(
        SIGNATURE_ALGORITHM,
        secret_key=secret_key
    ) as signer:

        signature = signer.sign(message)

    return signature


# =====================================================
# 7. ML-DSA-65 SIGNATURE VERIFICATION
# =====================================================

def verify_signature(
    message: bytes,
    signature: bytes,
    public_key: bytes
) -> bool:
    """
    Verify an ML-DSA-65 digital signature.

    Returns:
        True: Signature is valid.
        False: Signature is invalid.
    """

    _validate_bytes(
        message,
        "Message",
        allow_empty=True
    )

    _validate_bytes(signature, "Signature")
    _validate_bytes(public_key, "Public key")

    _check_algorithm_availability()

    with oqs.Signature(SIGNATURE_ALGORITHM) as verifier:

        return verifier.verify(
            message,
            signature,
            public_key
        )


# =====================================================
# 8. ALGORITHM INFORMATION
# =====================================================

def get_pqc_information() -> dict:
    """
    Return information about the configured algorithms.
    Useful for the QuantumShield dashboard.
    """

    _check_algorithm_availability()

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        kem_details = kem.details

    with oqs.Signature(SIGNATURE_ALGORITHM) as signature:
        signature_details = signature.details

    return {
        "kem": {
            "name": KEM_ALGORITHM,
            "public_key_size": kem_details["length_public_key"],
            "secret_key_size": kem_details["length_secret_key"],
            "ciphertext_size": kem_details["length_ciphertext"],
            "shared_secret_size": kem_details["length_shared_secret"]
        },
        "signature": {
            "name": SIGNATURE_ALGORITHM,
            "public_key_size": signature_details["length_public_key"],
            "secret_key_size": signature_details["length_secret_key"],
            "signature_size": signature_details["length_signature"]
        },
        "symmetric": {
            "name": "AES-256-GCM",
            "key_size": AES_KEY_SIZE
        },
        "kdf": {
            "name": "HKDF-SHA256",
            "salt_size": HKDF_SALT_SIZE
        }
    }

