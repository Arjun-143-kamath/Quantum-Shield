
import os
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =====================================================
# AES-256-GCM
# =====================================================

def encrypt_file(file_data: bytes):
    """
    Encrypt file bytes using AES-256-GCM.

    Returns:
        encrypted_data
        aes_key
        nonce
    """

    aes_key = AESGCM.generate_key(bit_length=256)

    # GCM uses a 96-bit nonce (12 bytes).
    nonce = os.urandom(12)

    aesgcm = AESGCM(aes_key)

    encrypted_data = aesgcm.encrypt(
        nonce,
        file_data,
        None
    )

    return encrypted_data, aes_key, nonce


def decrypt_file(
    encrypted_data: bytes,
    aes_key: bytes,
    nonce: bytes
):
    """Decrypt and authenticate AES-256-GCM ciphertext."""

    aesgcm = AESGCM(aes_key)

    return aesgcm.decrypt(
        nonce,
        encrypted_data,
        None
    )


# =====================================================
# RSA-OAEP
# =====================================================

def encrypt_aes_key(aes_key: bytes, recipient_public_key):
    """Encrypt the AES key using recipient's RSA public key."""

    return recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_aes_key(encrypted_key: bytes, recipient_private_key):
    """Recover AES key using recipient's RSA private key."""

    return recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# =====================================================
# RSA-PSS DIGITAL SIGNATURES
# =====================================================

def sign_data(data: bytes, private_key):
    """Sign data using RSA-PSS and SHA-256."""

    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(data: bytes, signature: bytes, public_key):
    """
    Verify an RSA-PSS signature.

    Returns True if valid, otherwise raises an exception.
    """

    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return True


# =====================================================
# SHA-256 HASH
# =====================================================

def calculate_hash(data: bytes):
    """Calculate SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()

