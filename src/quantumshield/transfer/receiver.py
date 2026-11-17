
import base64
import json

from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag

from quantumshield.crypto.classical import (
    decrypt_file,
    decrypt_aes_key,
    verify_signature
)

from quantumshield.transfer.package import canonical_metadata


def decode(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def receive_transfer(
    package_path: str,
    recipient: str,
    recipient_private_key,
    sender_public_key,
    output_directory: str
):
    """
    Verify sender, decrypt the AES key,
    authenticate and decrypt the file.
    """

    package_path = Path(package_path)

    package = json.loads(
        package_path.read_text(encoding="utf-8")
    )

    # 1. Validate package format
    if package.get("version") != "1.0":
        raise ValueError("Unsupported transfer package version.")

    if package.get("algorithm") != "RSA-2048 + AES-256-GCM":
        raise ValueError("Unsupported encryption algorithm.")

    # 2. Check recipient
    if package.get("recipient", "").lower() != recipient.lower():
        raise PermissionError("This transfer is intended for another user.")

    # 3. Verify sender signature BEFORE decryption
    signature = decode(package["signature"])

    signed_data = canonical_metadata(package)

    verify_signature(
        signed_data,
        signature,
        sender_public_key
    )

    # 4. Recover encrypted AES key
    encrypted_key = decode(package["encrypted_key"])

    aes_key = decrypt_aes_key(
        encrypted_key,
        recipient_private_key
    )

    # 5. Decode encrypted file data
    encrypted_data = decode(package["ciphertext"])
    nonce = decode(package["nonce"])

    # 6. Authenticate and decrypt
    original_data = decrypt_file(
        encrypted_data,
        aes_key,
        nonce
    )

    # 7. Save recovered file safely
    filename = package["filename"]

    if (
        not isinstance(filename, str)
        or not filename
        or Path(filename).name != filename
        or filename in {".", ".."}
    ):
        raise ValueError("Invalid filename in transfer package.")

    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)

    output_path = output_directory / filename

    if output_path.exists():
        raise FileExistsError(
            "Output file already exists. Choose another output directory."
        )

    output_path.write_bytes(original_data)

    return {
        "sender": package["sender"],
        "recipient": recipient,
        "filename": filename,
        "output_path": str(output_path),
        "size": len(original_data),
        "signature_verified": True,
        "integrity_verified": True
    }

