
"""Run and save QuantumShield cryptographic benchmarks."""

import argparse
import json

from datetime import datetime, timezone
from pathlib import Path

from quantumshield.benchmark.crypto_benchmark import (
    run_crypto_benchmark,
    DEFAULT_FILE_SIZES
)


BASE_DIR = Path(__file__).resolve().parents[1]

RESULTS_DIR = BASE_DIR / "research" / "results"


def main():

    parser = argparse.ArgumentParser(
        description="QuantumShield Cryptographic Benchmark"
    )

    parser.add_argument(
        "--repetitions",
        type=int,
        default=5,
        help="Number of measurement repetitions (default: 5)"
    )

    parser.add_argument(
        "--sizes-kb",
        nargs="+",
        type=int,
        default=[100, 1024, 10240],
        help="File sizes in KB (default: 100 1024 10240)"
    )

    args = parser.parse_args()

    file_sizes = tuple(
        size * 1024
        for size in args.sizes_kb
    )

    print("=" * 60)
    print("       QUANTUMSHIELD PERFORMANCE BENCHMARK")
    print("=" * 60)

    print("\nBenchmark configuration:")
    print("Repetitions:", args.repetitions)
    print("File sizes:", args.sizes_kb, "KB")

    print("\nRunning cryptographic experiments...")
    print("Please avoid running CPU-intensive applications simultaneously.")

    results = run_crypto_benchmark(
        repetitions=args.repetitions,
        file_sizes=file_sizes
    )

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    output_file = (
        RESULTS_DIR /
        f"benchmark_{timestamp}.json"
    )

    output_file.write_text(
        json.dumps(
            results,
            indent=4
        ),
        encoding="utf-8"
    )

    print("\nBenchmark completed successfully.")

    print("\nKey generation (median):")

    for algorithm, metrics in results["key_generation"].items():
        print(
            f"{algorithm}: "
            f"{metrics['median_ms']:.4f} ms"
        )

    print("\nKey establishment (median):")

    for algorithm, metrics in results["key_establishment"].items():

        for operation, values in metrics.items():

            print(
                f"{algorithm} / {operation}: "
                f"{values['median_ms']:.4f} ms"
            )

    print("\nDigital signatures (median):")

    for algorithm, metrics in results["digital_signatures"].items():

        for operation, values in metrics.items():

            print(
                f"{algorithm} / {operation}: "
                f"{values['median_ms']:.4f} ms"
            )

    print("\nFile encryption and decryption (median):")

    for item in results["file_encryption"]:

        print(f"\nFile size: {item['size_bytes']:,} bytes")

        print(
            "Encryption:",
            item["encryption"]["median_ms"],
            "ms"
        )

        print(
            "Decryption:",
            item["decryption"]["median_ms"],
            "ms"
        )

    print("\nKey and signature sizes:")

    print(
        json.dumps(
            results["key_sizes"],
            indent=4
        )
    )

    print("\nResults saved to:")
    print(output_file)

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()

