# QuantumShield

**A local quantum-safe secure file-transfer prototype with quantum attack simulations.**

QuantumShield is an academic cybersecurity project that demonstrates the differences between conventional cryptography and post-quantum cryptography (PQC). It provides a local sender/receiver file-transfer workflow, simulations of selected quantum algorithms, and a benchmarking dashboard for comparing cryptographic operations.

> **Project status:** Academic prototype. QuantumShield is intended for learning, experimentation, and demonstration. It is not a production-ready secure file-transfer product and has not undergone an independent security audit.

## Contents

- [Overview](#overview)
- [Features](#features)
- [Cryptographic design](#cryptographic-design)
- [Application architecture](#application-architecture)
- [Technology stack](#technology-stack)
- [Requirements](#requirements)
- [Run with Docker](#run-with-docker-recommended)
- [Run locally](#run-locally)
- [Run the tests](#run-the-tests)
- [Run benchmarks](#run-benchmarks)
- [Project structure](#project-structure)
- [Data storage](#data-storage)
- [Security considerations and limitations](#security-considerations-and-limitations)
- [References](#references)

## Overview

Quantum computers running sufficiently capable fault-tolerant algorithms could threaten some public-key cryptographic systems in use today. QuantumShield provides a hands-on way to explore this issue by implementing a conventional cryptographic workflow alongside a post-quantum workflow.

The application has three main areas:

1. **Secure file transfer:** Alice can package a file for Bob using either the traditional or PQC cryptographic mode. The recipient verifies the sender's signature and decrypts the file.
2. **Quantum Attack Lab:** Qiskit simulations demonstrate Shor's algorithm on a small factorization example and Grover's algorithm on a small unstructured search space.
3. **Cryptography comparison:** Local benchmarks measure key generation, key establishment, signature operations, AES file encryption/decryption, and key/signature sizes.

The current transfer mechanism is local: encrypted packages are written to an incoming-transfer directory on the machine running QuantumShield. It does **not** implement remote network file transfer between separate machines.

## Features

- Two local identities: **Alice** and **Bob**.
- Traditional cryptographic mode using RSA-2048, RSA-OAEP, RSA-PSS, and AES-256-GCM.
- Post-quantum mode using ML-KEM-768, ML-DSA-65, HKDF-SHA-256, and AES-256-GCM.
- Password-encrypted storage for RSA and PQC private keys.
- Authenticated file encryption and digital-signature verification.
- Shor's algorithm demonstration using a small-number order-finding circuit.
- Grover's algorithm demonstration using a configurable small search space.
- Benchmark reports saved as JSON and visualized in Streamlit.
- SQLite-backed security event and transfer-state storage in the security-hardening implementation.
- Docker configuration for packaging the application and its native PQC dependency.

## Cryptographic design

### Traditional mode

| Purpose | Algorithm |
|---|---|
| Key pair | RSA-2048 |
| AES key protection | RSA-OAEP with SHA-256 |
| File encryption | AES-256-GCM |
| Digital signature | RSA-PSS with SHA-256 |

The sender generates a random AES-256 key, encrypts the file with AES-GCM, and protects the AES key using the recipient's RSA public key. The sender signs the transfer package using RSA-PSS. The recipient verifies the signature, recovers the AES key using their RSA private key, and decrypts/authenticates the file.

### Post-quantum mode

| Purpose | Algorithm |
|---|---|
| Key establishment | ML-KEM-768 |
| Key derivation | HKDF-SHA-256 |
| File encryption | AES-256-GCM |
| Digital signature | ML-DSA-65 |

The sender encapsulates to the recipient's ML-KEM public key to obtain a shared secret and an encapsulated ciphertext. Both parties derive the AES-256 key from the shared secret and the package's HKDF salt. The sender signs the package using ML-DSA-65. The recipient verifies the signature, decapsulates the shared secret, derives the AES key, and authenticates/decrypts the file.

The ML-KEM and ML-DSA parameter sets correspond to NIST's standardized post-quantum algorithms (FIPS 203 and FIPS 204).

## Application architecture

```text
                         QuantumShield
                               |
                         Streamlit UI
                               |
                    Application / transfer layer
                       /          |          \
                      /           |           \
             Classical engine  PQC engine  Quantum Lab
             RSA + AES-GCM     ML-KEM       Shor
             RSA-PSS           ML-DSA       Grover
                               HKDF
                               AES-GCM
                      \           |           /
                       \          |          /
                         Local data storage
                    Keys / transfer packages / SQLite
                    Benchmark JSON reports
```

### Main application pages

| Page | Responsibility |
|---|---|
| Dashboard | Identity and application overview |
| Identity Setup | Generate RSA and PQC identities for Alice and Bob |
| Send File | Select a cryptographic mode and create an encrypted package |
| Receive File | Verify and decrypt an incoming package |
| Quantum Attack Lab | Run Shor and Grover simulations |
| Cryptography Comparison | View benchmark reports and charts |
| Security Reports | Review local security events and audit records |

## Technology stack

- **Language:** Python
- **UI:** Streamlit
- **Classical cryptography:** `cryptography`
- **Post-quantum cryptography:** Open Quantum Safe `liboqs` and `liboqs-python`
- **Quantum circuits and simulation:** Qiskit and Qiskit Aer
- **Data and visualization:** Pandas, Plotly, Matplotlib
- **Local security state:** SQLite
- **Environment/dependency management:** `uv`
- **Containerization:** Docker and Docker Compose

## Requirements

### Recommended: Docker

- Docker Engine
- Docker Compose v2 (`docker compose`)
- A supported CPU architecture for the Python, Qiskit Aer, and native `liboqs` dependencies

Docker is the simplest way to run the application without manually installing Python dependencies or building `liboqs` on the host. The image compiles a minimal `liboqs` build containing the algorithms used by QuantumShield.

### Local development

- Python 3.14 (the development environment used for this project)
- `uv`
- A C/C++ compiler and build tools
- CMake and Ninja
- Git
- OpenSSL development files as required by the local `liboqs` build

On Arch Linux, the system build tools can be installed with:

```bash
sudo pacman -S --needed git uv base-devel cmake ninja openssl
```

## Run with Docker (recommended)

From the repository root, build and start the application:

```bash
docker compose build
docker compose up -d
```

Open the application at:

```text
http://127.0.0.1:8501
```

Useful commands:

```bash
# View container status
docker compose ps

# Follow application logs
docker compose logs -f quantumshield

# Stop the application (persistent volumes are retained)
docker compose down

# Restart the application
docker compose up -d
```

The Compose configuration uses named volumes for application data and benchmark results. These volumes preserve keys, transfer packages, the SQLite database, and benchmark reports when the container is recreated.

> **Warning:** `docker compose down -v` removes the named volumes. This deletes the persisted application data, including generated keys, transfer state, audit records, and benchmark reports. Back up the volumes before doing this.

The provided Docker configuration binds the application to `127.0.0.1` on the host by default. This keeps it local to the machine. Do not expose the Streamlit port to an untrusted network without adding appropriate authentication, transport security, and access controls.

For a different CPU architecture, build the image on that architecture or create a multi-platform image after confirming that all Python wheels and native dependencies are available for the target platform. A Docker image is not automatically portable across incompatible CPU architectures.

## Run locally

### 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd QuantumShield
```

Replace `<YOUR_REPOSITORY_URL>` with the URL of your Git repository.

### 2. Install dependencies

If the repository contains the committed `pyproject.toml` and `uv.lock` files, synchronize the environment:

```bash
uv sync
```

The project uses these core dependencies:

- `streamlit`
- `cryptography`
- `qiskit`
- `qiskit-aer`
- `liboqs-python==0.16.0.2`
- `pandas`
- `matplotlib`
- `plotly`
- `pytest` for development/testing

The Python bindings require the native `liboqs` library. On a first local import, `liboqs-python` may build/install the native library if it cannot find one. The Docker build handles the native library separately.

### 3. Verify the PQC backend

```bash
uv run python scripts/check_pqc.py
```

The check exercises ML-KEM-768 encapsulation/decapsulation and ML-DSA-65 signing/verification.

### 4. Start QuantumShield

```bash
PYTHONPATH=src uv run streamlit run app.py
```

Open:

```text
http://127.0.0.1:8501
```

## Run the tests

Run the complete test suite from the repository root:

```bash
PYTHONPATH=src uv run pytest -v
```

Run an individual test module when debugging:

```bash
PYTHONPATH=src uv run pytest tests/test_classical.py -v
PYTHONPATH=src uv run pytest tests/test_pqc.py -v
PYTHONPATH=src uv run pytest tests/test_pqc_transfer.py -v
PYTHONPATH=src uv run pytest tests/test_quantum.py -v
PYTHONPATH=src uv run pytest tests/test_benchmark.py -v
PYTHONPATH=src uv run pytest tests/test_dashboard.py -v
PYTHONPATH=src uv run pytest tests/test_security.py -v
PYTHONPATH=src uv run pytest tests/test_security_store.py -v
```

Test modules listed above should be run only if they exist in the checked-out revision. Always use the test output from the current revision as the source of truth for the passing test count.

## Run benchmarks

Run the local cryptographic benchmark with the default file sizes and repetition count:

```bash
PYTHONPATH=src uv run python scripts/run_benchmark.py
```

Or specify the repetitions and file sizes in kilobytes:

```bash
PYTHONPATH=src uv run python scripts/run_benchmark.py \
    --repetitions 5 \
    --sizes-kb 100 1024 10240
```

Benchmark JSON reports are written to:

```text
research/results/
```

The Cryptography Comparison page discovers reports in this directory and visualizes the selected run.

### Benchmark methodology and interpretation

The benchmark records local application-level timings for:

- RSA-2048, ML-KEM-768, and ML-DSA-65 key generation
- RSA-OAEP key encryption/decryption and ML-KEM encapsulation/decapsulation
- RSA-PSS and ML-DSA signing/verification
- AES-256-GCM encryption/decryption for selected in-memory payload sizes
- Public-key, private-key, encapsulated-ciphertext, and signature sizes

The timing helper performs a warm-up call and then records repeated measurements. The report includes mean and median values. Results depend on the CPU, operating system, Python version, library versions, build options, and system load; they should not be treated as universal algorithm performance claims.

The RSA private-key size is measured as unencrypted PKCS#8 DER for size comparison only. PQC key sizes are measured as raw exported key bytes. These are not identical serialization formats. AES file measurements are in-memory measurements and exclude disk and network I/O.

## Project structure

```text
QuantumShield/
├── app.py
├── Dockerfile
├── compose.yaml
├── .dockerignore
├── .gitignore
├── pyproject.toml
├── uv.lock
│
├── scripts/
│   ├── check_pqc.py
│   └── run_benchmark.py
│
├── src/
│   └── quantumshield/
│       ├── crypto/
│       │   ├── classical.py
│       │   ├── key_manager.py
│       │   ├── pqc.py
│       │   └── pqc_key_manager.py
│       ├── transfer/
│       │   ├── package.py
│       │   ├── receiver.py
│       │   ├── service.py
│       │   └── pqc_package.py
│       ├── quantum/
│       │   ├── shor.py
│       │   └── grover.py
│       ├── benchmark/
│       │   ├── crypto_benchmark.py
│       │   └── dashboard.py
│       └── storage/
│           └── security_store.py
│
├── tests/
│   ├── test_classical.py
│   ├── test_pqc.py
│   ├── test_pqc_transfer.py
│   ├── test_quantum.py
│   ├── test_benchmark.py
│   ├── test_dashboard.py
│   ├── test_security.py
│   └── test_security_store.py
│
├── data/                  # Runtime data; do not commit
└── research/
    └── results/           # Generated benchmark JSON reports
```

The tree describes the intended project layout. Some test modules or optional files may not exist in every revision; check the repository before running commands that reference them.

## Data storage

In local development, the application writes runtime data beneath `data/` and benchmark reports beneath `research/results/`.

Typical data includes:

- RSA and PQC public/private key files
- Incoming and outgoing encrypted transfer packages
- Recovered files
- SQLite transfer-state and audit-event records
- Benchmark JSON reports

Private keys and user data must not be committed to Git or copied into a container image. The repository's `.gitignore` and `.dockerignore` should exclude runtime data. Keep backups of persistent Docker volumes if the keys or benchmark records matter to you.

## Security considerations and limitations

QuantumShield is a **local academic prototype**, with important limitations:

1. **No remote network transfer:** The current workflow places encrypted packages in a local incoming directory. It is not a networked file-transfer service.
2. **Local identity trust:** Alice's and Bob's identities and public keys are managed locally. There is no certificate authority, external identity verification, or secure public-key distribution protocol.
3. **No production authentication:** The application does not provide a hardened multi-user authentication and authorization system.
4. **Local audit/replay state:** Replay protection depends on the local SQLite database. Removing or restoring the database can remove recorded transfer history.
5. **Key handling:** Private-key files are password-encrypted, but Python process memory, host compromise, password strength, filesystem backups, and operating-system access remain relevant risks.
6. **No independent security audit:** The implementation has not been independently audited or certified for production use.
7. **Quantum demonstrations are educational:** The Shor demonstration factors a small integer (15); it does not factor an actual RSA-2048 modulus. The Grover demonstration searches a small simulated space; it does not recover an AES key.
8. **Benchmark results are environment-specific:** They measure this application's implementations on the machine running the tests, not an abstract comparison of the algorithms under all conditions.
9. **Open Quantum Safe library scope:** `liboqs` is suitable for prototyping and evaluation. Production cryptographic deployments should follow current standards, vetted implementations, platform guidance, and a formal security review.

Do not use QuantumShield to protect sensitive production data or expose it to the public internet in its current form.

## References

- [NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [Open Quantum Safe — liboqs](https://github.com/open-quantum-safe/liboqs)
- [Open Quantum Safe — liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
- [Qiskit documentation](https://docs.quantum.ibm.com/)
- [Qiskit Aer documentation](https://qiskit.github.io/qiskit-aer/)
- [Streamlit documentation](https://docs.streamlit.io/)
- [Astral uv documentation](https://docs.astral.sh/uv/)

---

**QuantumShield** — Exploring the transition from conventional cryptography to post-quantum security.
