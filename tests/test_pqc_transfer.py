
import pytest

from cryptography.exceptions import InvalidSignature, InvalidTag

from quantumshield.crypto.pqc import (
    generate_kem_keypair,
    generate_signature_keys
)

from quantumshield.crypto.pqc_key_manager import (
    generate_pqc_user_keys,
    load_pqc_public_key,
    load_pqc_private_key,
    pqc_user_initialized
)

from quantumshield.transfer.pqc_package import (
    create_pqc_transfer_package,
    decrypt_pqc_transfer_package,
    encode
)


@pytest.fixture
def pqc_users():
    alice_sig_public, alice_sig_private = generate_signature_keys()

    bob_kem_public, bob_kem_private = generate_kem_keypair()

    return {
        "alice_sig_public": alice_sig_public,
        "alice_sig_private": alice_sig_private,
        "bob_kem_public": bob_kem_public,
        "bob_kem_private": bob_kem_private
    }


def test_successful_pqc_transfer(pqc_users):

    original_data = b"QuantumShield quantum-safe transfer."

    package = create_pqc_transfer_package(
        original_data,
        "document.txt",
        "alice",
        "bob",
        pqc_users["bob_kem_public"],
        pqc_users["alice_sig_private"]
    )

    recovered_data = decrypt_pqc_transfer_package(
        package,
        "bob",
        pqc_users["bob_kem_private"],
        pqc_users["alice_sig_public"]
    )

    assert recovered_data == original_data


def test_pqc_wrong_recipient(pqc_users):

    package = create_pqc_transfer_package(
        b"Secret data",
        "secret.txt",
        "alice",
        "bob",
        pqc_users["bob_kem_public"],
        pqc_users["alice_sig_private"]
    )

    with pytest.raises(PermissionError):

        decrypt_pqc_transfer_package(
            package,
            "alice",
            pqc_users["bob_kem_private"],
            pqc_users["alice_sig_public"]
        )


def test_pqc_tampered_ciphertext(pqc_users):

    package = create_pqc_transfer_package(
        b"Original contents",
        "document.txt",
        "alice",
        "bob",
        pqc_users["bob_kem_public"],
        pqc_users["alice_sig_private"]
    )

    package["ciphertext"] = encode(b"Modified ciphertext")

    with pytest.raises(InvalidSignature):

        decrypt_pqc_transfer_package(
            package,
            "bob",
            pqc_users["bob_kem_private"],
            pqc_users["alice_sig_public"]
        )


def test_pqc_wrong_signing_key(pqc_users):

    package = create_pqc_transfer_package(
        b"Secure message",
        "message.txt",
        "alice",
        "bob",
        pqc_users["bob_kem_public"],
        pqc_users["alice_sig_private"]
    )

    wrong_public, _ = generate_signature_keys()

    with pytest.raises(InvalidSignature):

        decrypt_pqc_transfer_package(
            package,
            "bob",
            pqc_users["bob_kem_private"],
            wrong_public
        )


def test_pqc_key_storage(tmp_path, monkeypatch):

    import quantumshield.crypto.pqc_key_manager as manager

    monkeypatch.setattr(
        manager,
        "KEYS_DIR",
        tmp_path / "keys"
    )

    result = generate_pqc_user_keys(
        "alice",
        "AliceSecurePassword123!"
    )

    assert result["username"] == "alice"
    assert pqc_user_initialized("alice")

    public_key = load_pqc_public_key("alice", "kem")

    private_key = load_pqc_private_key(
        "alice",
        "kem",
        "AliceSecurePassword123!"
    )

    assert len(public_key) == 1184
    assert len(private_key) == 2400


def test_pqc_private_key_wrong_password(tmp_path, monkeypatch):

    import quantumshield.crypto.pqc_key_manager as manager

    monkeypatch.setattr(
        manager,
        "KEYS_DIR",
        tmp_path / "keys"
    )

    generate_pqc_user_keys(
        "bob",
        "BobSecurePassword123!"
    )

    with pytest.raises(ValueError):

        load_pqc_private_key(
            "bob",
            "kem",
            "WrongPassword123!"
        )

