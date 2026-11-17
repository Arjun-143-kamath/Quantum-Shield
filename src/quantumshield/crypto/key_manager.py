
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR = Path(__file__).resolve().parents[3]
KEYS_DIR = BASE_DIR / "data" / "keys"


def generate_key_pair(username: str, password: str):
    """
    Generate an RSA-2048 key pair for a user.
    Private key is encrypted before storage.
    """

    if not username.isalnum():
        raise ValueError("Username must contain only letters and numbers.")

    if not password or len(password) < 12:
        raise ValueError("Use a password of at least 12 characters.")

    user_dir = KEYS_DIR / username.lower()
    user_dir.mkdir(parents=True, exist_ok=True)

    private_path = user_dir / "private.pem"
    public_path = user_dir / "public.pem"

    if private_path.exists() or public_path.exists():
        raise FileExistsError("Keys already exist for this user.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    encrypted_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        )
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_path.write_bytes(encrypted_private)
    public_path.write_bytes(public_pem)

    return {
        "username": username,
        "private_key": str(private_path),
        "public_key": str(public_path)
    }


def load_private_key(username: str, password: str):
    """Load a user's encrypted RSA private key."""

    private_path = KEYS_DIR / username.lower() / "private.pem"

    if not private_path.exists():
        raise FileNotFoundError("Private key not found.")

    return serialization.load_pem_private_key(
        private_path.read_bytes(),
        password=password.encode("utf-8")
    )


def load_public_key(username: str):
    """Load a user's RSA public key."""

    public_path = KEYS_DIR / username.lower() / "public.pem"

    if not public_path.exists():
        raise FileNotFoundError("Public key not found.")

    return serialization.load_pem_public_key(
        public_path.read_bytes()
    )

