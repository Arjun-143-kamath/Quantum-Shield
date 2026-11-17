
"""
QuantumShield - Cryptographic Comparison Dashboard

Loads actual benchmark JSON reports and visualizes:
    - Key generation
    - Key establishment
    - Digital signatures
    - AES file encryption/decryption
    - Cryptographic key and signature sizes
"""

import json

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


# =====================================================
# CONFIGURATION
# =====================================================

BASE_DIR = Path(__file__).resolve().parents[3]

RESULTS_DIR = BASE_DIR / "research" / "results"


# =====================================================
# DISCOVER BENCHMARK REPORTS
# =====================================================

def get_benchmark_files():
    """Return available benchmark reports, newest first."""

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    return sorted(
        RESULTS_DIR.glob("benchmark_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True
    )


# =====================================================
# LOAD BENCHMARK REPORT
# =====================================================

def load_benchmark_report(report_path: Path):
    """Load and validate a benchmark JSON report."""

    try:
        report = json.loads(
            report_path.read_text(encoding="utf-8")
        )

    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(
            f"Could not load benchmark report: {error}"
        ) from error

    required_sections = [
        "metadata",
        "key_generation",
        "key_establishment",
        "digital_signatures",
        "file_encryption",
        "key_sizes"
    ]

    for section in required_sections:

        if section not in report:
            raise ValueError(
                f"Benchmark report is missing: {section}"
            )

    return report


# =====================================================
# METADATA
# =====================================================

def render_benchmark_metadata(metadata: dict):

    st.subheader("Experiment Environment")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.write("**Python Version**")
        st.write(metadata.get("python_version", "Unknown"))

    with col2:
        st.write("**Processor**")
        st.write(metadata.get("processor", "Not reported"))

    with col3:
        st.write("**Repetitions**")
        st.write(metadata.get("repetitions", "Unknown"))

    st.caption(
        f"Platform: {metadata.get('platform', 'Unknown')}"
    )

    st.caption(
        f"Experiment timestamp: "
        f"{metadata.get('timestamp_utc', 'Unknown')}"
    )

    versions = metadata.get("library_versions", {})

    if versions:

        with st.expander("Cryptographic library versions"):

            st.json(versions)


# =====================================================
# KEY GENERATION
# =====================================================

def render_key_generation(data: dict):

    st.subheader("1. Key Generation Performance")

    st.write(
        "Comparison of median key-pair generation times "
        "for conventional and post-quantum algorithms."
    )

    rows = []

    labels = {
        "rsa_2048": "RSA-2048",
        "ml_kem_768": "ML-KEM-768",
        "ml_dsa_65": "ML-DSA-65"
    }

    for algorithm, metrics in data.items():

        rows.append({
            "Algorithm": labels.get(algorithm, algorithm),
            "Median time (ms)": metrics["median_ms"],
            "Mean time (ms)": metrics["mean_ms"]
        })

    df = pd.DataFrame(rows)

    fig = px.bar(
        df,
        x="Algorithm",
        y="Median time (ms)",
        color="Algorithm",
        text="Median time (ms)",
        title="Key Generation Time"
    )

    fig.update_traces(
        texttemplate="%{text:.4f} ms",
        textposition="outside"
    )
    
    fig.update_yaxes(
        type="log",
        title="Median time (milliseconds, logarithmic scale)"
    )

    fig.update_layout(
        showlegend=False,
        yaxis_title="Time (milliseconds)",
        xaxis_title="Algorithm"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "RSA key generation and PQC key generation are separate "
        "measurements. The PQC design uses separate KEM and signature keys."
    )


# =====================================================
# KEY ESTABLISHMENT
# =====================================================

def render_key_establishment(data: dict):

    st.subheader("2. Key Establishment Performance")

    st.write(
        "Comparison of RSA-OAEP key transport and "
        "ML-KEM shared-secret establishment."
    )

    rows = []

    labels = {
        "rsa_oaep": {
            "name": "RSA-OAEP",
            "encryption": "Key encryption",
            "decryption": "Key decryption",
            "round_trip": "Complete key transport"
        },

        "ml_kem_768": {
            "name": "ML-KEM-768",
            "encapsulation": "Encapsulation",
            "decapsulation": "Decapsulation",
            "round_trip_with_hkdf": "Encapsulation + HKDF workflow"
        }
    }

    for algorithm, operations in data.items():

        algorithm_labels = labels.get(
            algorithm,
            {}
        )

        for operation, metrics in operations.items():

            rows.append({
                "Algorithm": algorithm_labels.get(
                    "name",
                    algorithm
                ),
                "Operation": algorithm_labels.get(
                    operation,
                    operation
                ),
                "Median time (ms)": metrics["median_ms"]
            })

    df = pd.DataFrame(rows)

    fig = px.bar(
        df,
        x="Operation",
        y="Median time (ms)",
        color="Algorithm",
        barmode="group",
        title="Key Establishment Performance"
    )

    fig.update_layout(
        xaxis_title="Operation",
        yaxis_title="Time (milliseconds)"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "RSA-OAEP transports a randomly generated AES key. "
        "ML-KEM establishes a shared secret, which requires HKDF "
        "to derive the AES key. The complete-workflow measurements "
        "therefore include different processing steps."
    )


# =====================================================
# DIGITAL SIGNATURES
# =====================================================

def render_digital_signatures(data: dict):

    st.subheader("3. Digital Signature Performance")

    st.write(
        "Comparison of RSA-PSS and ML-DSA-65 signing "
        "and verification performance."
    )

    labels = {
        "rsa_pss": "RSA-PSS",
        "ml_dsa_65": "ML-DSA-65"
    }

    for operation in ("signing", "verification"):

        rows = []

        for algorithm, metrics in data.items():

            rows.append({
                "Algorithm": labels.get(
                    algorithm,
                    algorithm
                ),
                "Median time (ms)": metrics[operation]["median_ms"]
            })

        df = pd.DataFrame(rows)

        fig = px.bar(
            df,
            x="Algorithm",
            y="Median time (ms)",
            color="Algorithm",
            text="Median time (ms)",
            title=operation.capitalize()
        )

        fig.update_traces(
            texttemplate="%{text:.4f} ms",
            textposition="outside"
        )

        fig.update_layout(
            showlegend=False,
            yaxis_title="Time (milliseconds)"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


# =====================================================
# FILE ENCRYPTION
# =====================================================

def render_file_encryption(data: list):

    st.subheader("4. AES-256-GCM File Performance")

    st.write(
        "Encryption and decryption performance for different "
        "file sizes. Both modes use the same AES-256-GCM engine."
    )

    rows = []

    for item in data:

        size_mb = item["size_bytes"] / (1024 * 1024)

        rows.append({
            "File size (MB)": size_mb,
            "Operation": "Encryption",
            "Median time (ms)": item["encryption"]["median_ms"]
        })

        rows.append({
            "File size (MB)": size_mb,
            "Operation": "Decryption",
            "Median time (ms)": item["decryption"]["median_ms"]
        })

    df = pd.DataFrame(rows)

    fig = px.line(
        df,
        x="File size (MB)",
        y="Median time (ms)",
        color="Operation",
        markers=True,
        title="AES-256-GCM Execution Time"
    )

    fig.update_layout(
        xaxis_title="File size (MB)",
        yaxis_title="Time (milliseconds)"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "These are in-memory AES measurements. They exclude "
        "file-system, network and application-transfer overhead."
    )


# =====================================================
# CRYPTOGRAPHIC SIZE COMPARISON
# =====================================================

def render_key_sizes(data: dict):

    st.subheader("5. Cryptographic Key and Signature Sizes")

    st.write(
        "The following table compares actual serialized "
        "or exported cryptographic object sizes."
    )

    rsa = data["rsa_2048"]
    kem = data["ml_kem_768"]
    dsa = data["ml_dsa_65"]
    aes = data["aes_256_gcm"]

    rows = [
        {
            "Algorithm": "RSA-2048",
            "Public key (bytes)": rsa["public_key_bytes"],
            "Private key (bytes)": rsa["private_key_bytes_der"],
            "Ciphertext / Encapsulation (bytes)": rsa["encrypted_aes_key_bytes"],
            "Signature (bytes)": rsa["signature_bytes"]
        },
        {
            "Algorithm": "ML-KEM-768",
            "Public key (bytes)": kem["public_key_bytes"],
            "Private key (bytes)": kem["private_key_bytes"],
            "Ciphertext / Encapsulation (bytes)": kem["encapsulated_ciphertext_bytes"],
            "Signature (bytes)": None
        },
        {
            "Algorithm": "ML-DSA-65",
            "Public key (bytes)": dsa["public_key_bytes"],
            "Private key (bytes)": dsa["private_key_bytes"],
            "Ciphertext / Encapsulation (bytes)": None,
            "Signature (bytes)": dsa["signature_bytes"]
        },
        {
            "Algorithm": "AES-256-GCM",
            "Public key (bytes)": None,
            "Private key (bytes)": aes["key_bytes"],
            "Ciphertext / Encapsulation (bytes)": None,
            "Signature (bytes)": aes["authentication_tag_bytes"]
        }
    ]

    df = pd.DataFrame(rows)

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "RSA private keys are serialized as unencrypted PKCS#8 DER; "
        "PQC keys are raw liboqs exports. AES's final column refers "
        "to its authentication tag, not a digital signature."
    )

    st.metric(
        "ML-KEM-768 Shared Secret",
        f"{kem['shared_secret_bytes']} bytes"
    )

    st.metric(
        "AES-GCM Nonce",
        f"{aes['nonce_bytes']} bytes"
    )


# =====================================================
# FULL DASHBOARD
# =====================================================

def render_benchmark_dashboard():

    st.title("📊 Cryptography Comparison")

    st.write(
        "Experimental comparison of conventional and "
        "post-quantum cryptographic algorithms."
    )

    benchmark_files = get_benchmark_files()

    if not benchmark_files:

        st.warning(
            "No benchmark reports found. Run the benchmark "
            "script to generate your first report."
        )

        st.code(
            "PYTHONPATH=src uv run python scripts/run_benchmark.py"
        )

        return

    selected_file = st.selectbox(
        "Select benchmark experiment",
        options=benchmark_files,
        format_func=lambda path: path.name
    )

    try:

        report = load_benchmark_report(selected_file)

    except ValueError as error:

        st.error(str(error))
        return

    # Allow downloading the selected raw report.
    st.download_button(
        "⬇️ Download Benchmark JSON",
        data=selected_file.read_bytes(),
        file_name=selected_file.name,
        mime="application/json"
    )

    st.divider()

    metadata = report["metadata"]

    render_benchmark_metadata(metadata)

    st.divider()

    st.subheader("Performance Overview")

    keygen = report["key_generation"]
    signatures = report["digital_signatures"]

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "RSA-2048 Key Generation",
            f"{keygen['rsa_2048']['median_ms']:.4f} ms"
        )

    with col2:
        st.metric(
            "ML-KEM-768 Key Generation",
            f"{keygen['ml_kem_768']['median_ms']:.4f} ms"
        )

    with col3:
        st.metric(
            "ML-DSA-65 Signing",
            f"{signatures['ml_dsa_65']['signing']['median_ms']:.4f} ms"
        )

    st.divider()

    render_key_generation(report["key_generation"])

    st.divider()

    render_key_establishment(report["key_establishment"])

    st.divider()

    render_digital_signatures(report["digital_signatures"])

    st.divider()

    render_file_encryption(report["file_encryption"])

    st.divider()

    render_key_sizes(report["key_sizes"])

    st.divider()

    st.subheader("Experimental Notes")

    for note in report.get("notes", []):
        st.write(f"- {note}")

    st.success(
        "Benchmark report loaded successfully. "
        "All displayed measurements come from the selected JSON report."
    )

