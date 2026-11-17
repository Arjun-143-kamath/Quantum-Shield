
"""QuantumShield - Post-Quantum Secure File Transfer Packages."""

import base64
import json
import os
import re
import uuid

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantumshield.crypto.pqc import (
    encapsulate_key,
    decapsulate_key,
    derive_aes_key,
    sign_data,
    verify_signature
)


PACKAGE_VERSION = "1.0"
PQC_ALGORITHM = "ML-KEM-768 + AES-256-GCM"


def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode(data: str) -> bytes:
    if not isinstance(data, str):
        raise ValueError("Expected Base64 text.")

    return base64.b64decode(data, validate=True)


def canonical_json(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True
    ).encode("utf-8")


def canonical_signed_data(package: dict) -> bytes:
    """Return deterministic serialization excluding signature."""

    signed_fields = {
        key: value
        for key, value in package.items()
        if key != "signature"
    }

    return canonical_json(signed_fields)


def validate_filename(filename: str):
    """Reject path traversal and invalid filenames."""

    if (
        not isinstance(filename, str)
        or not filename
        or filename in {".", ".."}
        or Path(filename).name != filename
        or "/" in filename
        or "\\" in filename
    ):
        raise ValueError("Invalid transfer filename.")


def _associated_data(package: dict) -> bytes:
    """
    Bind AES-GCM authentication to transfer metadata.

    These fields must be identical on both sides.
    """

    fields = (
        "version",
        "transfer_id",
        "mode",
        "sender",
        "recipient",
        "filename",
        "algorithm",
        "key_algorithm",
        "signature_algorithm",
        "kdf",
        "kdf_salt",
        "nonce",
        "encapsulated_key"
    )

    return canonical_json({
        key: package[key]
        for key in fields
    })


# =====================================================
# CREATE PQC TRANSFER PACKAGE
# =====================================================

def create_pqc_transfer_package(
    file_data: bytes,
    filename: str,
    sender: str,
    recipient: str,
    recipient_kem_public_key: bytes,
    sender_signature_secret_key: bytes,
    transfer_id: str | None = None
):
    """Create an encrypted and ML-DSA-signed transfer package."""

    if not isinstance(file_data, bytes):
        raise TypeError("File data must be bytes.")

    validate_filename(filename)

    if not sender or not recipient:
        raise ValueError("Sender and recipient are required.")

    if transfer_id is None:
        transfer_id = uuid.uuid4().hex

    if not isinstance(transfer_id, str) or not re.fullmatch(
        r"[a-fA-F0-9]{32}", transfer_id
    ):
        raise ValueError("Invalid transfer ID.")

    # 1. Establish shared secret using ML-KEM.
    encapsulated_key, shared_secret = encapsulate_key(
        recipient_kem_public_key
    )

    # 2. Derive AES-256 key using HKDF.
    aes_key, salt = derive_aes_key(shared_secret)

    # 3. Generate AES-GCM nonce.
    nonce = os.urandom(12)

    # 4. Construct signed metadata.
    package = {
        "version": PACKAGE_VERSION,
        "transfer_id": transfer_id,
        "mode": "pqc",
        "sender": sender,
        "recipient": recipient,
        "filename": filename,
        "algorithm": PQC_ALGORITHM,
        "key_algorithm": "ML-KEM-768",
        "signature_algorithm": "ML-DSA-65",
        "kdf": "HKDF-SHA256",
        "kdf_salt": encode(salt),
        "nonce": encode(nonce),
        "encapsulated_key": encode(encapsulated_key)
    }

    # 5. Encrypt the actual file with authenticated metadata.
    encrypted_data = AESGCM(aes_key).encrypt(
        nonce,
        file_data,
        _associated_data(package)
    )

    package["ciphertext"] = encode(encrypted_data)

    # 6. Sign the complete package.
    signature = sign_data(
        canonical_signed_data(package),
        sender_signature_secret_key
    )

    package["signature"] = encode(signature)

    return package


# =====================================================
# DECRYPT PQC TRANSFER PACKAGE
# =====================================================

def decrypt_pqc_transfer_package(
    package: dict,
    recipient: str,
    recipient_kem_secret_key: bytes,
    sender_signature_public_key: bytes
) -> bytes:
    """
    Verify, recover the AES key and decrypt a PQC package.

    Returns:
        Original file bytes.
    """

    if not isinstance(package, dict):
        raise ValueError("Invalid transfer package.")

    if (
        package.get("version") != PACKAGE_VERSION
        or package.get("mode") != "pqc"
        or package.get("algorithm") != PQC_ALGORITHM
        or package.get("key_algorithm") != "ML-KEM-768"
        or package.get("signature_algorithm") != "ML-DSA-65"
        or package.get("kdf") != "HKDF-SHA256"
    ):
        raise ValueError("Unsupported PQC package format.")

    if package.get("recipient", "").lower() != recipient.lower():
        raise PermissionError("This transfer belongs to another user.")

    validate_filename(package.get("filename"))

    if not package.get("sender"):
        raise ValueError("Sender information is missing.")

    # 1. Verify sender's signature FIRST.
    signature = decode(package["signature"])

    valid = verify_signature(
        canonical_signed_data(package),
        signature,
        sender_signature_public_key
    )

    if not valid:
        raise InvalidSignature("PQC signature verification failed.")

    # 2. Recover ML-KEM shared secret.
    encapsulated_key = decode(package["encapsulated_key"])

    shared_secret = decapsulate_key(
        encapsulated_key,
        recipient_kem_secret_key
    )

    # 3. Re-derive identical AES key.
    salt = decode(package["kdf_salt"])

    aes_key, _ = derive_aes_key(
        shared_secret,
        salt=salt
    )

    # 4. Decrypt and authenticate file.
    nonce = decode(package["nonce"])
    ciphertext = decode(package["ciphertext"])

    return AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        _associated_data(package)
    )

