
"""QuantumShield - Hardened dual-mode transfer service."""

import hashlib
import json
import os
import re
import uuid
import base64

from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantumshield.crypto.key_manager import (
    generate_key_pair,
    load_private_key,
    load_public_key
)

from quantumshield.crypto.pqc_key_manager import (
    generate_pqc_user_keys,
    load_pqc_public_key,
    load_pqc_private_key,
    pqc_user_initialized
)

from quantumshield.transfer.package import (
    create_transfer_package,
    save_transfer_package
)

from quantumshield.transfer.pqc_package import (
    create_pqc_transfer_package,
    decrypt_pqc_transfer_package,
    validate_filename
)

from quantumshield.transfer.receiver import receive_transfer

from quantumshield.storage.security_store import (
    claim_transfer,
    complete_transfer,
    release_transfer_claim,
    record_audit_event,
    TransferAlreadyProcessed
)


# =====================================================
# CONFIGURATION
# =====================================================

BASE_DIR = Path(__file__).resolve().parents[3]

INCOMING_DIR = BASE_DIR / "data" / "incoming"
OUTGOING_DIR = BASE_DIR / "data" / "outgoing"

MAX_TRANSFER_FILE_BYTES = 50 * 1024 * 1024
MAX_PACKAGE_BYTES = 70 * 1024 * 1024


# =====================================================
# VALIDATION
# =====================================================

def _validate_username(username: str):
    if (
        not isinstance(username, str)
        or not re.fullmatch(r"[a-zA-Z0-9]{1,32}", username)
    ):
        raise ValueError("Invalid username.")


def _validate_transfer_input(
    file_data: bytes,
    filename: str,
    sender: str,
    recipient: str
):
    if not isinstance(file_data, bytes):
        raise TypeError("File data must be bytes.")

    if len(file_data) > MAX_TRANSFER_FILE_BYTES:
        raise ValueError(
            "File exceeds the maximum allowed size of 50 MB."
        )

    validate_filename(filename)

    _validate_username(sender)
    _validate_username(recipient)

    if sender.lower() == recipient.lower():
        raise ValueError("Sender and recipient must be different.")


def _validate_transfer_id(transfer_id: str):
    if (
        not isinstance(transfer_id, str)
        or not re.fullmatch(r"[a-fA-F0-9]{32}", transfer_id)
    ):
        raise ValueError("Invalid transfer ID.")


def _audit_event(
    event_type: str,
    outcome: str,
    username: str = None,
    transfer_id: str = None,
    mode: str = None,
    details: str = None
):
    """Write an audit event without exposing sensitive data."""

    try:
        record_audit_event(
            event_type=event_type,
            outcome=outcome,
            username=username,
            transfer_id=transfer_id,
            mode=mode,
            details=details
        )
    except Exception:
        # A logging failure must not convert an already
        # completed encryption/decryption into a false failure.
        pass


# =====================================================
# IDENTITY MANAGEMENT
# =====================================================

def user_initialized(username: str) -> bool:
    """Check whether classical RSA keys exist."""

    try:
        _validate_username(username)
    except ValueError:
        return False

    user_dir = BASE_DIR / "data" / "keys" / username.lower()

    return (
        (user_dir / "private.pem").is_file()
        and (user_dir / "public.pem").is_file()
    )


def initialize_user(username: str, password: str):
    """Generate a classical RSA identity."""

    _validate_username(username)

    return generate_key_pair(username, password)


def initialize_pqc_user(username: str, password: str):
    """Generate ML-KEM and ML-DSA identities."""

    _validate_username(username)

    return generate_pqc_user_keys(username, password)


def user_pqc_initialized(username: str) -> bool:
    """Check whether both PQC key pairs exist."""

    try:
        _validate_username(username)
    except ValueError:
        return False

    return pqc_user_initialized(username)


# =====================================================
# SEND FILE
# =====================================================

def send_file(
    file_data: bytes,
    filename: str,
    sender: str,
    recipient: str,
    sender_password: str,
    mode: str = "classical"
):
    """Encrypt and package a file for local transfer."""

    _validate_transfer_input(
        file_data,
        filename,
        sender,
        recipient
    )

    sender = sender.lower()
    recipient = recipient.lower()

    if not isinstance(sender_password, str) or not sender_password:
        raise ValueError("Sender password is required.")

    if mode not in ("classical", "pqc"):
        raise ValueError("Unsupported cryptographic mode.")

    transfer_id = uuid.uuid4().hex

    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    OUTGOING_DIR.mkdir(parents=True, exist_ok=True)

    package_path = INCOMING_DIR / f"{transfer_id}.qshield"

    if package_path.exists():
        raise FileExistsError("Transfer ID collision.")

    # -------------------------------------------------
    # CLASSICAL MODE
    # -------------------------------------------------

    if mode == "classical":

        if not user_initialized(sender):
            raise FileNotFoundError("Sender's RSA keys are missing.")

        if not user_initialized(recipient):
            raise FileNotFoundError("Recipient's RSA keys are missing.")

        sender_private = load_private_key(
            sender,
            sender_password
        )

        recipient_public = load_public_key(recipient)

        temp_directory = OUTGOING_DIR / transfer_id
        temp_directory.mkdir(parents=True, exist_ok=False)

        temp_source = temp_directory / filename

        try:
            temp_source.write_bytes(file_data)

            package = create_transfer_package(
                str(temp_source),
                sender,
                recipient,
                recipient_public,
                sender_private,
                transfer_id
            )

            save_transfer_package(
                package,
                package_path
            )

        finally:
            temp_source.unlink(missing_ok=True)
            temp_directory.rmdir()

        algorithm = "RSA-2048 + AES-256-GCM"

    # -------------------------------------------------
    # POST-QUANTUM MODE
    # -------------------------------------------------

    else:

        if not user_pqc_initialized(sender):
            raise FileNotFoundError("Sender's PQC keys are missing.")

        if not user_pqc_initialized(recipient):
            raise FileNotFoundError("Recipient's PQC keys are missing.")

        sender_signature_private = load_pqc_private_key(
            sender,
            "signature",
            sender_password
        )

        recipient_kem_public = load_pqc_public_key(
            recipient,
            "kem"
        )

        package = create_pqc_transfer_package(
            file_data=file_data,
            filename=filename,
            sender=sender,
            recipient=recipient,
            recipient_kem_public_key=recipient_kem_public,
            sender_signature_secret_key=sender_signature_private,
            transfer_id=transfer_id
        )

        save_transfer_package(
            package,
            package_path
        )

        algorithm = (
            "ML-KEM-768 + AES-256-GCM + ML-DSA-65"
        )

    _audit_event(
        event_type="transfer_created",
        outcome="success",
        username=sender,
        transfer_id=transfer_id,
        mode=mode,
        details=f"Recipient: {recipient}; filename: {filename}"
    )

    return {
        "transfer_id": transfer_id,
        "filename": filename,
        "sender": sender,
        "recipient": recipient,
        "mode": mode,
        "algorithm": algorithm,
        "package_path": str(package_path),
        "size": len(file_data),
        "status": "Encrypted and transferred"
    }


# =====================================================
# LIST INCOMING TRANSFERS
# =====================================================

def list_incoming_transfers(username: str):
    """List valid transfer packages addressed to a user."""

    _validate_username(username)

    INCOMING_DIR.mkdir(parents=True, exist_ok=True)

    username = username.lower()

    transfers = []

    for package_path in INCOMING_DIR.glob("*.qshield"):

        try:

            if package_path.stat().st_size > MAX_PACKAGE_BYTES:
                continue

            package = json.loads(
                package_path.read_text(encoding="utf-8")
            )

            if not isinstance(package, dict):
                continue

            if package.get("recipient", "").lower() != username:
                continue

            _validate_username(package.get("sender"))
            validate_filename(package.get("filename"))
            _validate_transfer_id(package.get("transfer_id"))

            transfers.append({
                "transfer_id": package["transfer_id"],
                "sender": package["sender"],
                "recipient": package["recipient"],
                "filename": package["filename"],
                "algorithm": package.get("algorithm", "Unknown"),
                "mode": package.get("mode", "classical"),
                "path": str(package_path)
            })

        except (
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            json.JSONDecodeError
        ):
            continue

    return sorted(
        transfers,
        key=lambda item: item["transfer_id"]
    )


# =====================================================
# RECEIVE FILE
# =====================================================

def receive_file(
    package_path: str,
    recipient: str,
    recipient_password: str,
    output_directory: str
):
    """
    Verify and decrypt an incoming package.

    Enforces:
        - Package size limit
        - Metadata validation
        - Recipient validation
        - Replay protection
        - Digital signature verification
        - Authenticated decryption
    """

    _validate_username(recipient)

    package_path = Path(package_path)

    if not package_path.is_file():
        raise FileNotFoundError("Transfer package not found.")

    package_size = package_path.stat().st_size

    if package_size > MAX_PACKAGE_BYTES:
        raise ValueError("Transfer package exceeds the 70 MB limit.")

    # Read package and calculate its SHA-256 fingerprint.
    raw_package = package_path.read_bytes()

    package_hash = hashlib.sha256(
        raw_package
    ).hexdigest()

    package = json.loads(
        raw_package.decode("utf-8")
    )

    if not isinstance(package, dict):
        raise ValueError("Invalid transfer package.")

    sender = package.get("sender")
    package_recipient = package.get("recipient")

    _validate_username(sender)
    _validate_username(package_recipient)

    transfer_id = package.get("transfer_id")

    _validate_transfer_id(transfer_id)
    validate_filename(package.get("filename"))

    recipient = recipient.lower()
    sender = sender.lower()

    if package_recipient.lower() != recipient:
        raise PermissionError(
            "This transfer belongs to another user."
        )

    mode = package.get("mode", "classical")

    if mode not in ("classical", "pqc"):
        raise ValueError("Unknown transfer mode.")

    if not isinstance(recipient_password, str) or not recipient_password:
        raise ValueError("Recipient password is required.")
    
    # Validate encrypted payload size before decryption.
    encoded_ciphertext = package.get("ciphertext")

    if not isinstance(encoded_ciphertext, str):
        raise ValueError("Missing encrypted payload.")

    try:
        encrypted_payload = base64.b64decode(
            encoded_ciphertext,
            validate=True
        )
    except (ValueError, TypeError) as error:
        raise ValueError("Invalid encrypted payload encoding.") from error

    # AES-GCM adds a 16-byte authentication tag.
    if len(encrypted_payload) > MAX_TRANSFER_FILE_BYTES + 16:
        raise ValueError("Encrypted payload exceeds the allowed file size.")
    # -------------------------------------------------
    # REPLAY PROTECTION
    # -------------------------------------------------

    claimed = claim_transfer(
        transfer_id,
        recipient,
        package_hash
    )

    if not claimed:

        _audit_event(
            event_type="replay_detected",
            outcome="blocked",
            username=recipient,
            transfer_id=transfer_id,
            mode=mode,
            details="Transfer ID is already processing or completed."
        )

        raise TransferAlreadyProcessed(
            "This transfer has already been processed "
            "or is currently being processed."
        )

    # -------------------------------------------------
    # PROCESS TRANSFER
    # -------------------------------------------------

    try:

        if mode == "classical":

            recipient_private = load_private_key(
                recipient,
                recipient_password
            )

            sender_public = load_public_key(sender)

            result = receive_transfer(
                str(package_path),
                recipient,
                recipient_private,
                sender_public,
                output_directory
            )

            result["mode"] = "classical"
            result["algorithm"] = package.get("algorithm")

        elif mode == "pqc":

            recipient_kem_private = load_pqc_private_key(
                recipient,
                "kem",
                recipient_password
            )

            sender_signature_public = load_pqc_public_key(
                sender,
                "signature"
            )

            original_data = decrypt_pqc_transfer_package(
                package,
                recipient,
                recipient_kem_private,
                sender_signature_public
            )

            filename = package["filename"]

            output_directory = Path(output_directory)
            output_directory.mkdir(
                parents=True,
                exist_ok=True
            )

            output_path = output_directory / filename

            if output_path.exists():
                raise FileExistsError(
                    "Output file already exists."
                )

            temporary_path = output_directory / (
                f".{uuid.uuid4().hex}.tmp"
            )

            try:
                temporary_path.write_bytes(original_data)
                os.chmod(temporary_path, 0o600)
                temporary_path.replace(output_path)

            except Exception:
                temporary_path.unlink(missing_ok=True)
                raise

            result = {
                "sender": sender,
                "recipient": recipient,
                "filename": filename,
                "output_path": str(output_path),
                "size": len(original_data),
                "signature_verified": True,
                "integrity_verified": True,
                "mode": "pqc",
                "algorithm": package["algorithm"]
            }

        else:
            raise ValueError("Unsupported transfer mode.")

        # Mark completed only after successful decryption
        # and saving of the recovered file.
        complete_transfer(transfer_id)

        _audit_event(
            event_type="transfer_received",
            outcome="success",
            username=recipient,
            transfer_id=transfer_id,
            mode=mode,
            details=f"Sender: {sender}; filename: {package['filename']}"
        )

        return result

    except Exception as error:

        # Failed operations may be retried.
        release_transfer_claim(transfer_id)

        _audit_event(
            event_type="transfer_received",
            outcome="failure",
            username=recipient,
            transfer_id=transfer_id,
            mode=mode,
            details=f"Rejected operation: {type(error).__name__}"
        )

        raise

