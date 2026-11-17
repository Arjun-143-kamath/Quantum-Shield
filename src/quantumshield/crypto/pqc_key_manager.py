
"""QuantumShield - Encrypted PQC private-key storage."""

import base64
import json
import os
import re

from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from quantumshield.crypto.pqc import (
    generate_kem_keypair,
    generate_signature_keys
)


BASE_DIR = Path(__file__).resolve().parents[3]
KEYS_DIR = BASE_DIR / "data" / "keys"

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


def _validate_username(username: str):
    if not isinstance(username, str) or not re.fullmatch(
        r"[a-zA-Z0-9_-]{1,32}", username
    ):
        raise ValueError("Invalid username.")


def _paths(username: str, key_type: str):
    _validate_username(username)

    if key_type not in ("kem", "signature"):
        raise ValueError("Unsupported PQC key type.")

    directory = KEYS_DIR / username.lower() / "pqc"

    if key_type == "kem":
        return directory, directory / "kem_public.bin", directory / "kem_private.enc"

    return directory, directory / "signature_public.bin", directory / "signature_private.enc"


def _derive_storage_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")

    return Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P
    ).derive(password.encode("utf-8"))


def _associated_data(username: str, key_type: str) -> bytes:
    return f"QuantumShield-PQC-Key-v1:{username.lower()}:{key_type}".encode()


def _encrypt_private_key(
    private_key: bytes,
    username: str,
    key_type: str,
    password: str
) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    storage_key = _derive_storage_key(password, salt)

    encrypted = AESGCM(storage_key).encrypt(
        nonce,
        private_key,
        _associated_data(username, key_type)
    )

    record = {
        "version": 1,
        "kdf": "Scrypt",
        "scrypt_n": SCRYPT_N,
        "scrypt_r": SCRYPT_R,
        "scrypt_p": SCRYPT_P,
        "cipher": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(encrypted).decode("ascii")
    }

    return json.dumps(record, indent=2).encode("utf-8")


def _decrypt_private_key(
    encrypted_file: bytes,
    username: str,
    key_type: str,
    password: str
) -> bytes:
    record = json.loads(encrypted_file)

    if (
        record.get("version") != 1
        or record.get("kdf") != "Scrypt"
        or record.get("cipher") != "AES-256-GCM"
        or record.get("scrypt_n") != SCRYPT_N
        or record.get("scrypt_r") != SCRYPT_R
        or record.get("scrypt_p") != SCRYPT_P
    ):
        raise ValueError("Unsupported private-key storage format.")

    salt = base64.b64decode(record["salt"], validate=True)
    nonce = base64.b64decode(record["nonce"], validate=True)
    ciphertext = base64.b64decode(record["ciphertext"], validate=True)

    if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid private-key storage parameters.")

    storage_key = _derive_storage_key(password, salt)

    try:
        return AESGCM(storage_key).decrypt(
            nonce,
            ciphertext,
            _associated_data(username, key_type)
        )
    except InvalidTag as error:
        raise ValueError(
            "Incorrect password or corrupted private key."
        ) from error


def generate_pqc_user_keys(username: str, password: str):
    """Generate and securely store both PQC key pairs."""

    _validate_username(username)

    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")

    directory = KEYS_DIR / username.lower() / "pqc"

    paths = [
        _paths(username, "kem"),
        _paths(username, "signature")
    ]

    expected_files = [
        path
        for _, public_path, private_path in paths
        for path in (public_path, private_path)
    ]

    if any(path.exists() for path in expected_files):
        raise FileExistsError(
            "PQC keys already exist or are partially initialized. "
            "Existing keys will not be overwritten."
        )

    # Generate keys before writing anything.
    kem_public, kem_private = generate_kem_keypair()

    sig_public, sig_private = generate_signature_keys()

    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)

    written_files = []

    try:
        for key_type, public_key, private_key in (
            ("kem", kem_public, kem_private),
            ("signature", sig_public, sig_private)
        ):
            _, public_path, private_path = _paths(username, key_type)

            public_path.write_bytes(public_key)
            os.chmod(public_path, 0o644)
            written_files.append(public_path)

            encrypted_private = _encrypt_private_key(
                private_key,
                username,
                key_type,
                password
            )

            temporary_path = private_path.with_suffix(".tmp")
            temporary_path.write_bytes(encrypted_private)
            os.chmod(temporary_path, 0o600)
            temporary_path.replace(private_path)

            written_files.append(private_path)

    except Exception:
        for path in written_files:
            path.unlink(missing_ok=True)
        raise

    return {
        "username": username,
        "kem_public_key": str(_paths(username, "kem")[1]),
        "signature_public_key": str(_paths(username, "signature")[1]),
        "status": "PQC keys generated successfully"
    }


def load_pqc_public_key(username: str, key_type: str) -> bytes:
    """Load a public PQC key."""

    _, public_path, _ = _paths(username, key_type)

    if not public_path.exists():
        raise FileNotFoundError("PQC public key not found.")

    return public_path.read_bytes()


def load_pqc_private_key(
    username: str,
    key_type: str,
    password: str
) -> bytes:
    """Decrypt and load a password-protected PQC private key."""

    _, _, private_path = _paths(username, key_type)

    if not private_path.exists():
        raise FileNotFoundError("PQC private key not found.")

    return _decrypt_private_key(
        private_path.read_bytes(),
        username,
        key_type,
        password
    )


def pqc_user_initialized(username: str) -> bool:
    """Check whether both PQC key pairs exist."""

    try:
        paths = [
            _paths(username, "kem"),
            _paths(username, "signature")
        ]
    except ValueError:
        return False

    return all(
        public_path.is_file() and private_path.is_file()
        for _, public_path, private_path in paths
    )

