
import pytest

from quantumshield.crypto.pqc import (
    generate_kem_keypair,
    encapsulate_key,
    decapsulate_key,
    derive_aes_key,
    generate_signature_keys,
    sign_data,
    verify_signature,
    get_pqc_information
)


# =====================================================
# TEST 1: ML-KEM KEY GENERATION
# =====================================================

def test_kem_key_generation():

    public_key, secret_key = generate_kem_keypair()

    assert isinstance(public_key, bytes)
    assert isinstance(secret_key, bytes)

    assert len(public_key) == 1184
    assert len(secret_key) == 2400


# =====================================================
# TEST 2: ML-KEM ENCAPSULATION / DECAPSULATION
# =====================================================

def test_kem_shared_secret():

    public_key, secret_key = generate_kem_keypair()

    ciphertext, sender_secret = encapsulate_key(
        public_key
    )

    receiver_secret = decapsulate_key(
        ciphertext,
        secret_key
    )

    assert sender_secret == receiver_secret

    assert len(sender_secret) == 32
    assert len(ciphertext) == 1088


# =====================================================
# TEST 3: HKDF AES KEY DERIVATION
# =====================================================

def test_aes_key_derivation():

    shared_secret = b"QuantumShieldTestSharedSecret"

    aes_key, salt = derive_aes_key(shared_secret)

    assert len(aes_key) == 32
    assert len(salt) == 16

    # Both parties must derive identical keys.
    recovered_key, _ = derive_aes_key(
        shared_secret,
        salt=salt
    )

    assert aes_key == recovered_key


# =====================================================
# TEST 4: DIFFERENT SALTS PRODUCE DIFFERENT KEYS
# =====================================================

def test_different_salts():

    shared_secret = b"QuantumShieldTestSharedSecret"

    key1, salt1 = derive_aes_key(shared_secret)
    key2, salt2 = derive_aes_key(shared_secret)

    assert salt1 != salt2
    assert key1 != key2


# =====================================================
# TEST 5: ML-DSA KEY GENERATION
# =====================================================

def test_signature_key_generation():

    public_key, secret_key = generate_signature_keys()

    assert isinstance(public_key, bytes)
    assert isinstance(secret_key, bytes)

    assert len(public_key) == 1952
    assert len(secret_key) == 4032


# =====================================================
# TEST 6: ML-DSA SIGNATURE VERIFICATION
# =====================================================

def test_signature_verification():

    public_key, secret_key = generate_signature_keys()

    message = b"QuantumShield secure transfer"

    signature = sign_data(
        message,
        secret_key
    )

    assert verify_signature(
        message,
        signature,
        public_key
    ) is True


# =====================================================
# TEST 7: TAMPERED MESSAGE DETECTION
# =====================================================

def test_tampered_message():

    public_key, secret_key = generate_signature_keys()

    message = b"Original QuantumShield message"

    signature = sign_data(
        message,
        secret_key
    )

    modified_message = b"Modified QuantumShield message"

    assert verify_signature(
        modified_message,
        signature,
        public_key
    ) is False


# =====================================================
# TEST 8: INVALID KEM PUBLIC KEY LENGTH
# =====================================================

def test_invalid_kem_public_key():

    public_key, _ = generate_kem_keypair()

    invalid_key = public_key[:-1]

    with pytest.raises(ValueError):
        encapsulate_key(invalid_key)


# =====================================================
# TEST 9: INVALID KEM CIPHERTEXT LENGTH
# =====================================================

def test_invalid_kem_ciphertext():

    _, secret_key = generate_kem_keypair()

    invalid_ciphertext = b"invalid"

    with pytest.raises(ValueError):
        decapsulate_key(
            invalid_ciphertext,
            secret_key
        )


# =====================================================
# TEST 10: PQC INFORMATION
# =====================================================

def test_pqc_information():

    information = get_pqc_information()

    assert information["kem"]["name"] == "ML-KEM-768"

    assert (
        information["signature"]["name"]
        == "ML-DSA-65"
    )

    assert information["symmetric"]["key_size"] == 32

