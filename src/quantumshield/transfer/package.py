
import base64
import json
import uuid

from pathlib import Path

from quantumshield.crypto.classical import (
    encrypt_file,
    encrypt_aes_key,
    sign_data
)


# =====================================================
# BASE64 ENCODING / DECODING
# =====================================================

def encode(data: bytes) -> str:
    """Encode binary data into Base64 text."""
    return base64.b64encode(data).decode("ascii")


def decode(data: str) -> bytes:
    """Decode Base64 text into binary data."""
    return base64.b64decode(data, validate=True)


# =====================================================
# CANONICAL PACKAGE METADATA
# =====================================================

def canonical_metadata(package: dict) -> bytes:
    """
    Serialize package fields deterministically.

    The signature field is excluded because it is
    generated from the other package fields.
    """

    signed_fields = {
        key: value
        for key, value in package.items()
        if key != "signature"
    }

    return json.dumps(
        signed_fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True
    ).encode("utf-8")


# =====================================================
# CREATE TRANSFER PACKAGE
# =====================================================

def create_transfer_package(
    file_path: str,
    sender: str,
    recipient: str,
    recipient_public_key,
    sender_private_key,
    transfer_id: str | None = None
):
    """
    Encrypt a file and create a signed transfer package.

    Args:
        file_path: Path to the original file.
        sender: Sender's username.
        recipient: Recipient's username.
        recipient_public_key: Recipient's RSA public key.
        sender_private_key: Sender's RSA private key.
        transfer_id: Optional unique transfer identifier.

    Returns:
        Complete encrypted and signed transfer package.
    """

    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError("Selected file does not exist.")

    if not sender or not recipient:
        raise ValueError("Sender and recipient are required.")

    # Generate an ID automatically if not provided.
    if transfer_id is None:
        transfer_id = uuid.uuid4().hex

    if not isinstance(transfer_id, str) or not transfer_id:
        raise ValueError("Invalid transfer ID.")

    # Read original file.
    file_data = file_path.read_bytes()

    # Encrypt file using AES-256-GCM.
    encrypted_data, aes_key, nonce = encrypt_file(file_data)

    # Encrypt AES key using recipient's RSA public key.
    encrypted_aes_key = encrypt_aes_key(
        aes_key,
        recipient_public_key
    )

    # Construct transfer package.
    package = {
        "version": "1.0",
        "transfer_id": transfer_id,
        "sender": sender,
        "recipient": recipient,
        "filename": file_path.name,
        "algorithm": "RSA-2048 + AES-256-GCM",
        "key_algorithm": "RSA-OAEP-SHA256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "encrypted_key": encode(encrypted_aes_key),
        "nonce": encode(nonce),
        "ciphertext": encode(encrypted_data)
    }

    # Generate canonical representation of package.
    signed_data = canonical_metadata(package)

    # Sign the complete package metadata and ciphertext.
    signature = sign_data(
        signed_data,
        sender_private_key
    )

    # Attach signature after signing.
    package["signature"] = encode(signature)

    return package


# =====================================================
# SAVE TRANSFER PACKAGE
# =====================================================

def save_transfer_package(package: dict, output_path: str):
    """Save the encrypted transfer package as JSON."""

    output_path = Path(output_path)

    # Create destination directory if required.
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    output_path.write_text(
        json.dumps(
            package,
            indent=4,
            ensure_ascii=True
        ),
        encoding="utf-8"
    )

    return output_path

