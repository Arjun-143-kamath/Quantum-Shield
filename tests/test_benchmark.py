
from quantumshield.benchmark.crypto_benchmark import (
    run_crypto_benchmark,
    measure_operation
)


def test_measure_operation():

    result = measure_operation(
        lambda: sum(range(1000)),
        repetitions=3
    )

    assert result["mean_ms"] >= 0
    assert result["median_ms"] >= 0
    assert result["min_ms"] >= 0

    assert len(result["samples_ms"]) == 3


def test_complete_benchmark_structure():

    result = run_crypto_benchmark(
        repetitions=1,
        file_sizes=(1024,)
    )

    assert "metadata" in result

    assert "key_generation" in result

    assert "key_establishment" in result

    assert "digital_signatures" in result

    assert "file_encryption" in result

    assert "key_sizes" in result

    assert result["key_generation"]["rsa_2048"]["median_ms"] >= 0

    assert result["key_generation"]["ml_kem_768"]["median_ms"] >= 0

    assert result["key_generation"]["ml_dsa_65"]["median_ms"] >= 0


def test_benchmark_key_sizes():

    result = run_crypto_benchmark(
        repetitions=1,
        file_sizes=(1024,)
    )

    sizes = result["key_sizes"]

    assert sizes["rsa_2048"]["public_key_bytes"] > 0

    assert sizes["ml_kem_768"]["public_key_bytes"] == 1184

    assert sizes["ml_kem_768"]["encapsulated_ciphertext_bytes"] == 1088

    assert sizes["ml_dsa_65"]["public_key_bytes"] == 1952

    assert sizes["ml_dsa_65"]["signature_bytes"] == 3309


def test_aes_file_benchmark():

    result = run_crypto_benchmark(
        repetitions=1,
        file_sizes=(1024,)
    )

    file_result = result["file_encryption"][0]

    assert file_result["size_bytes"] == 1024

    assert file_result["ciphertext_size_bytes"] == 1040

    assert file_result["encryption"]["median_ms"] >= 0

    assert file_result["decryption"]["median_ms"] >= 0

