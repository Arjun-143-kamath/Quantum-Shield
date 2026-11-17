
import json
import pytest

from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag

from quantumshield.crypto.key_manager import (
    generate_key_pair,
    load_private_key,
    load_public_key
)

from quantumshield.transfer.package import (
    create_transfer_package,
    save_transfer_package
)

from quantumshield.transfer.receiver import receive_transfer


@pytest.fixture
def users(tmp_path, monkeypatch):
    import quantumshield.crypto.key_manager as km

    monkeypatch.setattr(km, "KEYS_DIR", tmp_path / "keys")

    alice = generate_key_pair("alice", "AliceSecurePassword123!")
    bob = generate_key_pair("bob", "BobSecurePassword123!")

    return {
        "alice_private": load_private_key(
            "alice", "AliceSecurePassword123!"
        ),
        "alice_public": load_public_key("alice"),
        "bob_private": load_private_key(
            "bob", "BobSecurePassword123!"
        ),
        "bob_public": load_public_key("bob")
    }


def test_successful_transfer(tmp_path, users):
    original = b"QuantumShield secure file transfer test."

    source = tmp_path / "sample.txt"
    source.write_bytes(original)

    package = create_transfer_package(
        str(source),
        "alice",
        "bob",
        users["bob_public"],
        users["alice_private"]
    )

    package_path = tmp_path / "transfer.json"
    save_transfer_package(package, package_path)

    result = receive_transfer(
        package_path,
        "bob",
        users["bob_private"],
        users["alice_public"],
        tmp_path / "received"
    )

    assert result["signature_verified"] is True
    assert result["integrity_verified"] is True

    recovered = Path(result["output_path"]).read_bytes()

    assert recovered == original


def test_wrong_recipient(tmp_path, users):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"Secret data")

    package = create_transfer_package(
        str(source),
        "alice",
        "bob",
        users["bob_public"],
        users["alice_private"]
    )

    package_path = tmp_path / "transfer.json"
    save_transfer_package(package, package_path)

    with pytest.raises(PermissionError):
        receive_transfer(
            package_path,
            "alice",
            users["alice_private"],
            users["bob_public"],
            tmp_path / "received"
        )


def test_tampered_package(tmp_path, users):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"Secret data")

    package = create_transfer_package(
        str(source),
        "alice",
        "bob",
        users["bob_public"],
        users["alice_private"]
    )

    package["ciphertext"] = "QUJDREVGR0g="

    package_path = tmp_path / "tampered.json"
    save_transfer_package(package, package_path)

    with pytest.raises(InvalidSignature):
        receive_transfer(
            package_path,
            "bob",
            users["bob_private"],
            users["alice_public"],
            tmp_path / "received"
        )


def test_corrupted_gcm_payload(tmp_path, users):
    source = tmp_path / "sample.txt"
    source.write_bytes(b"Secret data")

    package = create_transfer_package(
        str(source),
        "alice",
        "bob",
        users["bob_public"],
        users["alice_private"]
    )

    from quantumshield.transfer.package import decode, encode

    encrypted = bytearray(decode(package["ciphertext"]))
    encrypted[-1] ^= 1
    package["ciphertext"] = encode(bytes(encrypted))

    # Re-sign with Alice's key to simulate a valid sender
    # signature over a malformed encrypted payload.
    from quantumshield.crypto.classical import sign_data

    from quantumshield.transfer.package import canonical_metadata

    package["signature"] = encode(
        sign_data(
            canonical_metadata(package),
            users["alice_private"]
        )
    )

    package_path = tmp_path / "corrupted.json"
    save_transfer_package(package, package_path)

    with pytest.raises(InvalidTag):
        receive_transfer(
            package_path,
            "bob",
            users["bob_private"],
            users["alice_public"],
            tmp_path / "received"
        )

