
import oqs


KEM_ALGORITHM = "ML-KEM-768"
SIGNATURE_ALGORITHM = "ML-DSA-65"


def main():
    print("=" * 55)
    print("       QUANTUMSHIELD — PQC BACKEND CHECK")
    print("=" * 55)

    print("\nLibrary versions:")
    print("liboqs:", oqs.oqs_version())
    print("liboqs-python:", oqs.oqs_python_version())

    # -------------------------------------------------
    # Check algorithm availability
    # -------------------------------------------------

    enabled_kems = oqs.get_enabled_kem_mechanisms()
    enabled_signatures = oqs.get_enabled_sig_mechanisms()

    print("\nChecking required algorithms...")

    if KEM_ALGORITHM not in enabled_kems:
        raise RuntimeError(
            f"{KEM_ALGORITHM} is not enabled in liboqs."
        )

    if SIGNATURE_ALGORITHM not in enabled_signatures:
        raise RuntimeError(
            f"{SIGNATURE_ALGORITHM} is not enabled in liboqs."
        )

    print(f"[PASS] {KEM_ALGORITHM} available")
    print(f"[PASS] {SIGNATURE_ALGORITHM} available")

    # -------------------------------------------------
    # ML-KEM-768 key encapsulation test
    # -------------------------------------------------

    print("\nTesting ML-KEM-768...")

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as receiver:

        receiver_public_key = receiver.generate_keypair()

        with oqs.KeyEncapsulation(KEM_ALGORITHM) as sender:

            ciphertext, sender_shared_secret = (
                sender.encap_secret(receiver_public_key)
            )

        receiver_shared_secret = receiver.decap_secret(
            ciphertext
        )

        assert sender_shared_secret == receiver_shared_secret

        print("[PASS] ML-KEM key generation")
        print("[PASS] ML-KEM encapsulation")
        print("[PASS] ML-KEM decapsulation")
        print("[PASS] Shared secrets match")

        print(
            "Public key size:",
            len(receiver_public_key),
            "bytes"
        )

        print(
            "KEM ciphertext size:",
            len(ciphertext),
            "bytes"
        )

    # -------------------------------------------------
    # ML-DSA-65 digital signature test
    # -------------------------------------------------

    print("\nTesting ML-DSA-65...")

    message = b"QuantumShield PQC verification test"

    with oqs.Signature(SIGNATURE_ALGORITHM) as signer:

        signature_public_key = signer.generate_keypair()

        signature = signer.sign(message)

    with oqs.Signature(SIGNATURE_ALGORITHM) as verifier:

        valid = verifier.verify(
            message,
            signature,
            signature_public_key
        )

        tampered_valid = verifier.verify(
            message + b" modified",
            signature,
            signature_public_key
        )

        assert valid is True
        assert tampered_valid is False

        print("[PASS] ML-DSA key generation")
        print("[PASS] ML-DSA signing")
        print("[PASS] ML-DSA signature verification")
        print("[PASS] Tampered message rejected")

        print(
            "Public key size:",
            len(signature_public_key),
            "bytes"
        )

        print(
            "Signature size:",
            len(signature),
            "bytes"
        )

    print("\n" + "=" * 55)
    print("ALL PQC BACKEND CHECKS PASSED")
    print("=" * 55)


if __name__ == "__main__":
    main()

