
"""
QuantumShield - Security Evaluation Tests

Controlled attack simulations against:
    1. Classical RSA + AES file transfer
    2. Post-quantum ML-KEM + ML-DSA file transfer
"""

import pytest

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa

from quantumshield.crypto.classical import sign_data as rsa_sign_data

from quantumshield.crypto.pqc import (
    generate_kem_keypair,
    generate_signature_keys,
    sign_data as mldsa_sign_data
)

from quantumshield.transfer.package import (
    create_transfer_package,
    save_transfer_package,
    canonical_metadata,
    encode,
    decode
)

from quantumshield.transfer.receiver import receive_transfer

from quantumshield.transfer.pqc_package import (
    create_pqc_transfer_package,
    decrypt_pqc_transfer_package,
    canonical_signed_data
)


# =====================================================
# CLASSICAL TEST FIXTURE
# =====================================================

@pytest.fixture
def classical_keys():

    alice_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    bob_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    charlie_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    return {
        "alice_private": alice_private,
        "alice_public": alice_private.public_key(),

        "bob_private": bob_private,
        "bob_public": bob_private.public_key(),

        "charlie_private": charlie_private,
        "charlie_public": charlie_private.public_key()
    }


def create_classical_test_package(tmp_path, keys):

    source = tmp_path / "original.txt"
    source.write_bytes(b"QuantumShield security evaluation.")

    package = create_transfer_package(
        str(source),
        "alice",
        "bob",
        keys["bob_public"],
        keys["alice_private"],
        "a" * 32
    )

    package_path = tmp_path / "classical.qshield"

    save_transfer_package(
        package,
        package_path
    )

    return package, package_path


# =====================================================
# TEST 1: CLASSICAL METADATA TAMPERING
# =====================================================

def test_classical_metadata_tampering(tmp_path, classical_keys):

    package, package_path = create_classical_test_package(
        tmp_path,
        classical_keys
    )

    # Attacker changes the filename.
    package["filename"] = "modified.txt"

    save_transfer_package(package, package_path)

    with pytest.raises(InvalidSignature):

        receive_transfer(
            str(package_path),
            "bob",
            classical_keys["bob_private"],
            classical_keys["alice_public"],
            str(tmp_path / "received")
        )

    assert not (tmp_path / "received").exists()


# =====================================================
# TEST 2: CLASSICAL SIGNATURE TAMPERING
# =====================================================

def test_classical_signature_tampering(tmp_path, classical_keys):

    package, package_path = create_classical_test_package(
        tmp_path,
        classical_keys
    )

    signature = bytearray(
        decode(package["signature"])
    )

    signature[0] ^= 1

    package["signature"] = encode(bytes(signature))

    save_transfer_package(package, package_path)

    with pytest.raises(InvalidSignature):

        receive_transfer(
            str(package_path),
            "bob",
            classical_keys["bob_private"],
            classical_keys["alice_public"],
            str(tmp_path / "received")
        )


# =====================================================
# TEST 3: WRONG CLASSICAL RECIPIENT
# =====================================================

def test_classical_wrong_recipient(tmp_path, classical_keys):

    _, package_path = create_classical_test_package(
        tmp_path,
        classical_keys
    )

    with pytest.raises(PermissionError):

        receive_transfer(
            str(package_path),
            "charlie",
            classical_keys["charlie_private"],
            classical_keys["alice_public"],
            str(tmp_path / "received")
        )


# =====================================================
# TEST 4: WRONG CLASSICAL PRIVATE KEY
# =====================================================

def test_classical_wrong_private_key(tmp_path, classical_keys):

    _, package_path = create_classical_test_package(
        tmp_path,
        classical_keys
    )

    # Charlie attempts to use his private key as Bob.
    with pytest.raises(ValueError):

        receive_transfer(
            str(package_path),
            "bob",
            classical_keys["charlie_private"],
            classical_keys["alice_public"],
            str(tmp_path / "received")
        )


# =====================================================
# TEST 5: CLASSICAL AES-GCM TAMPERING
# WITH A VALID SENDER SIGNATURE
# =====================================================

def test_classical_gcm_tampering_after_resigning(
    tmp_path,
    classical_keys
):

    package, package_path = create_classical_test_package(
        tmp_path,
        classical_keys
    )

    ciphertext = bytearray(
        decode(package["ciphertext"])
    )

    ciphertext[-1] ^= 1

    package["ciphertext"] = encode(bytes(ciphertext))

    # Simulate a malformed payload signed by Alice.
    package["signature"] = encode(
        rsa_sign_data(
            canonical_metadata(package),
            classical_keys["alice_private"]
        )
    )

    save_transfer_package(package, package_path)

    # Signature is valid, but AES-GCM authentication fails.
    with pytest.raises(InvalidTag):

        receive_transfer(
            str(package_path),
            "bob",
            classical_keys["bob_private"],
            classical_keys["alice_public"],
            str(tmp_path / "received")
        )

    assert not (tmp_path / "received").exists()


# =====================================================
# PQC TEST FIXTURE
# =====================================================

@pytest.fixture
def pqc_security_keys():

    alice_sig_public, alice_sig_private = (
        generate_signature_keys()
    )

    bob_kem_public, bob_kem_private = (
        generate_kem_keypair()
    )

    charlie_kem_public, charlie_kem_private = (
        generate_kem_keypair()
    )

    return {
        "alice_sig_public": alice_sig_public,
        "alice_sig_private": alice_sig_private,

        "bob_kem_public": bob_kem_public,
        "bob_kem_private": bob_kem_private,

        "charlie_kem_public": charlie_kem_public,
        "charlie_kem_private": charlie_kem_private
    }


def create_pqc_test_package(keys):

    return create_pqc_transfer_package(
        file_data=b"QuantumShield PQC security evaluation.",
        filename="original.txt",
        sender="alice",
        recipient="bob",
        recipient_kem_public_key=keys["bob_kem_public"],
        sender_signature_secret_key=keys["alice_sig_private"],
        transfer_id="b" * 32
    )


# =====================================================
# TEST 6: PQC METADATA TAMPERING
# =====================================================

def test_pqc_metadata_tampering(pqc_security_keys):

    keys = pqc_security_keys

    package = create_pqc_test_package(keys)

    package["filename"] = "modified.txt"

    with pytest.raises(InvalidSignature):

        decrypt_pqc_transfer_package(
            package,
            "bob",
            keys["bob_kem_private"],
            keys["alice_sig_public"]
        )


# =====================================================
# TEST 7: PQC SIGNATURE TAMPERING
# =====================================================

def test_pqc_signature_tampering(pqc_security_keys):

    keys = pqc_security_keys

    package = create_pqc_test_package(keys)

    signature = bytearray(
        decode(package["signature"])
    )

    signature[0] ^= 1

    package["signature"] = encode(bytes(signature))

    with pytest.raises(InvalidSignature):

        decrypt_pqc_transfer_package(
            package,
            "bob",
            keys["bob_kem_private"],
            keys["alice_sig_public"]
        )


# =====================================================
# TEST 8: WRONG PQC RECIPIENT
# =====================================================

def test_pqc_wrong_recipient(pqc_security_keys):

    keys = pqc_security_keys

    package = create_pqc_test_package(keys)

    with pytest.raises(PermissionError):

        decrypt_pqc_transfer_package(
            package,
            "charlie",
            keys["charlie_kem_private"],
            keys["alice_sig_public"]
        )


# =====================================================
# TEST 9: WRONG PQC PRIVATE KEY
# =====================================================

def test_pqc_wrong_private_key(pqc_security_keys):

    keys = pqc_security_keys

    package = create_pqc_test_package(keys)

    # Use Charlie's valid ML-KEM key instead of Bob's.
    # Decapsulation succeeds, but produces a different secret.
    with pytest.raises(InvalidTag):

        decrypt_pqc_transfer_package(
            package,
            "bob",
            keys["charlie_kem_private"],
            keys["alice_sig_public"]
        )


# =====================================================
# TEST 10: PQC AES-GCM TAMPERING
# WITH A VALID ML-DSA SIGNATURE
# =====================================================

def test_pqc_gcm_tampering_after_resigning(pqc_security_keys):

    keys = pqc_security_keys

    package = create_pqc_test_package(keys)

    ciphertext = bytearray(
        decode(package["ciphertext"])
    )

    ciphertext[-1] ^= 1

    package["ciphertext"] = encode(bytes(ciphertext))

    # Simulate a malformed ciphertext signed by Alice.
    package["signature"] = encode(
        mldsa_sign_data(
            canonical_signed_data(package),
            keys["alice_sig_private"]
        )
    )

    # ML-DSA verification passes, but AES-GCM must reject.
    with pytest.raises(InvalidTag):

        decrypt_pqc_transfer_package(
            package,
            "bob",
            keys["bob_kem_private"],
            keys["alice_sig_public"]
        )

