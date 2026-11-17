
# QuantumShield

**A local quantum-safe secure file-transfer prototype with quantum attack simulations.**

**GitHub Repository:** [Arjun-143-kamath/Quantum-Shield](https://github.com/Arjun-143-kamath/Quantum-Shield)

QuantumShield is an academic cybersecurity project that demonstrates the differences between conventional cryptography and post-quantum cryptography (PQC). It provides a local sender/receiver file-transfer workflow, simulations of selected quantum algorithms, and a benchmarking dashboard for comparing cryptographic operations.

> **Project Status:** Academic prototype. QuantumShield is intended for learning, experimentation, and demonstration. It is not production-ready and has not undergone an independent security audit.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Cryptographic Design](#cryptographic-design)
- [Application Architecture](#application-architecture)
- [Technology Stack](#technology-stack)
- [Requirements](#requirements)
- [Run with Docker](#run-with-docker-recommended)
  - [Windows](#windows)
  - [macOS](#macos)
  - [Linux](#linux)
  - [Common Docker Commands](#common-docker-commands)
  - [Troubleshooting](#docker-troubleshooting)
- [Run Locally](#run-locally)
- [Run the Tests](#run-the-tests)
- [Run Benchmarks](#run-benchmarks)
- [Project Structure](#project-structure)
- [Data Storage](#data-storage)
- [Security Considerations and Limitations](#security-considerations-and-limitations)
- [References](#references)

---

## Overview

Quantum computers running sufficiently capable fault-tolerant algorithms could threaten some public-key cryptographic systems in use today. QuantumShield provides a hands-on way to explore this issue by implementing a conventional cryptographic workflow alongside a post-quantum workflow.

The application has three main areas:

1. **Secure File Transfer:** Alice can package a file for Bob using either traditional or PQC cryptography.
2. **Quantum Attack Lab:** Qiskit simulations demonstrate Shor's algorithm on a small factorization example and Grover's algorithm on a small search space.
3. **Cryptography Comparison:** Local benchmarks measure key generation, key establishment, signature operations, AES file encryption/decryption, and key/signature sizes.

The current transfer mechanism is local: encrypted packages are written to an incoming-transfer directory on the machine running QuantumShield. It does not implement remote network file transfer between separate machines.

## Features

- Two local identities: **Alice** and **Bob**.
- Traditional cryptographic mode using RSA-2048, RSA-OAEP, RSA-PSS, and AES-256-GCM.
- Post-quantum mode using ML-KEM-768, ML-DSA-65, HKDF-SHA-256, and AES-256-GCM.
- Password-encrypted storage for RSA and PQC private keys.
- Authenticated file encryption and digital-signature verification.
- Shor's algorithm demonstration using a small-number order-finding circuit.
- Grover's algorithm demonstration using a configurable small search space.
- Benchmark reports saved as JSON and visualized in Streamlit.
- SQLite-backed security event and transfer-state storage.
- Docker configuration for packaging the application and its native PQC dependency.

---

## Cryptographic Design

### 1. Traditional Mode

| Purpose | Algorithm |
|---|---|
| Key pair | RSA-2048 |
| AES key protection | RSA-OAEP with SHA-256 |
| File encryption | AES-256-GCM |
| Digital signature | RSA-PSS with SHA-256 |

The sender generates a random AES-256 key, encrypts the file with AES-GCM, and protects the AES key using the recipient's RSA public key. The sender signs the transfer package using RSA-PSS.

The recipient verifies the signature, recovers the AES key using their RSA private key, and decrypts/authenticates the file.

### 2. Post-Quantum Mode

| Purpose | Algorithm |
|---|---|
| Key establishment | ML-KEM-768 |
| Key derivation | HKDF-SHA-256 |
| File encryption | AES-256-GCM |
| Digital signature | ML-DSA-65 |

The sender encapsulates to the recipient's ML-KEM public key to obtain a shared secret and an encapsulated ciphertext. Both parties derive the AES-256 key from the shared secret and the package's HKDF salt.

The sender signs the package using ML-DSA-65. The recipient verifies the signature, decapsulates the shared secret, derives the AES key, and authenticates/decrypts the file.

The ML-KEM and ML-DSA parameter sets correspond to NIST's standardized post-quantum algorithms (FIPS 203 and FIPS 204).

---

## Application Architecture

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

### Main Application Pages

| Page | Responsibility |
|---|---|
| Dashboard | Identity and application overview |
| Identity Setup | Generate RSA and PQC identities for Alice and Bob |
| Send File | Select a cryptographic mode and create an encrypted package |
| Receive File | Verify and decrypt an incoming package |
| Quantum Attack Lab | Run Shor and Grover simulations |
| Cryptography Comparison | View benchmark reports and charts |
| Security Reports | Review local security events and audit records |

---

## Technology Stack

- **Language:** Python
- **UI:** Streamlit
- **Classical cryptography:** `cryptography`
- **Post-quantum cryptography:** Open Quantum Safe `liboqs` and `liboqs-python`
- **Quantum circuits and simulation:** Qiskit and Qiskit Aer
- **Data and visualization:** Pandas, Plotly, Matplotlib
- **Local security state:** SQLite
- **Environment/dependency management:** `uv`
- **Containerization:** Docker and Docker Compose

---

## Requirements

### Recommended: Docker

- Docker Engine
- Docker Compose v2 (`docker compose`)
- A supported CPU architecture for the Python, Qiskit Aer, and native `liboqs` dependencies

Docker is the simplest way to run the application without manually installing Python dependencies or building `liboqs` on the host.

### Local Development

- Python 3.14
- `uv`
- A C/C++ compiler and build tools
- CMake and Ninja
- Git
- OpenSSL development files as required by the local `liboqs` build

On Arch Linux:

```bash
sudo pacman -S --needed git uv base-devel cmake ninja openssl
```

---

# Run with Docker (Recommended)

Docker is the recommended way to run QuantumShield on another computer. You do not need to install Python, Qiskit, `liboqs`, or the project dependencies directly on the host.

The first build can take several minutes because the Dockerfile compiles the native Open Quantum Safe library.

## Windows

The instructions use **Docker Desktop with the WSL 2 backend**.

### Step 1: Check Windows Requirements

Open PowerShell as Administrator:

```powershell
wsl --install
wsl --update
```

Restart Windows if prompted.

### Step 2: Install Docker Desktop

1. Download [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/).
2. Run the installer.
3. Enable the **WSL 2** backend.
4. If using a Linux terminal, enable your distribution under **Settings → Resources → WSL Integration**.
5. Start Docker Desktop and wait until Docker is running.

See the [official Windows installation guide](https://docs.docker.com/desktop/setup/install/windows-install/).

### Step 3: Install Git and Clone the Repository

Install [Git for Windows](https://git-scm.com/download/win).

Open PowerShell:

```powershell
git --version
git clone https://github.com/Arjun-143-kamath/Quantum-Shield.git
cd Quantum-Shield
```

Alternatively, if using WSL, clone the repository inside your Linux home directory, such as `~/projects/Quantum-Shield`.

### Step 4: Build the Docker Image

Run from the repository root:

```powershell
docker version
docker compose version
docker compose build --progress=plain
```

The build compiles `liboqs` and checks that ML-KEM-768 and ML-DSA-65 are available.

### Step 5: Start QuantumShield

```powershell
docker compose up -d
docker compose ps
```

Open the application in your browser:

[http://127.0.0.1:8501](http://127.0.0.1:8501)

### Step 6: View Logs or Stop the Application

```powershell
# Follow application logs
docker compose logs -f quantumshield

# Stop the container; keep saved data
docker compose down

# Start it again
docker compose up -d
```

---

## macOS

These steps apply to both **Apple silicon (M-series)** and **Intel Macs**, provided the required dependencies support the machine's architecture.

### Step 1: Install Docker Desktop

1. Open **Apple menu → About This Mac** to identify your processor.
2. Download the appropriate [Docker Desktop installer](https://www.docker.com/products/docker-desktop/).
3. Open the `.dmg` file and install Docker Desktop.
4. Launch Docker Desktop and approve any requested permissions.
5. Wait until Docker reports that it is running.

See the [official macOS installation guide](https://docs.docker.com/desktop/setup/install/mac-install/).

### Step 2: Install Git and Clone the Repository

Check Git:

```bash
git --version
```

If macOS prompts you to install Command Line Developer Tools, accept the prompt.

Clone the repository:

```bash
git clone https://github.com/Arjun-143-kamath/Quantum-Shield.git
cd Quantum-Shield
```

### Step 3: Build the Docker Image

```bash
docker version
docker compose version
docker compose build --progress=plain
```

The first build compiles the native `liboqs` library for the Mac's architecture.

### Step 4: Start QuantumShield

```bash
docker compose up -d
docker compose ps
```

Open the application:

[http://127.0.0.1:8501](http://127.0.0.1:8501)

### Step 5: View Logs or Stop the Application

```bash
# Follow application logs
docker compose logs -f quantumshield

# Stop the application; keep saved data
docker compose down

# Start it again
docker compose up -d
```

---

## Linux

Install Docker Engine and Docker Compose using [Docker's official installation documentation](https://docs.docker.com/engine/install/).

### Arch Linux

```bash
sudo pacman -S --needed docker docker-compose
sudo systemctl enable --now docker
```

Verify:

```bash
docker --version
docker compose version
```

Clone and run:

```bash
git clone https://github.com/Arjun-143-kamath/Quantum-Shield.git
cd Quantum-Shield
docker compose build --progress=plain
docker compose up -d
docker compose ps
```

Open the application:

[http://127.0.0.1:8501](http://127.0.0.1:8501)

---

## Common Docker Commands

Run these commands from the repository directory:

```bash
# Build or rebuild the image
docker compose build

# Start the application in the background
docker compose up -d

# Show container status and health
docker compose ps

# Follow application logs
docker compose logs -f quantumshield

# Check PQC algorithm availability
docker compose exec quantumshield python -c "import oqs; print('ML-KEM-768:', 'ML-KEM-768' in oqs.get_enabled_kem_mechanisms()); print('ML-DSA-65:', 'ML-DSA-65' in oqs.get_enabled_sig_mechanisms())"

# Stop the application while preserving saved data
docker compose down

# Start it again
docker compose up -d
```

The Compose configuration uses named volumes for application data and benchmark results. These volumes preserve keys, transfer packages, the SQLite database, and benchmark reports when the container is recreated.

> **Warning:** `docker compose down -v` removes the named volumes. This deletes persisted application data, including generated keys, transfer state, audit records, and benchmark reports.

The Docker configuration binds the application to `127.0.0.1` on the host by default. This keeps it local to the computer.

---

## Docker Troubleshooting

### 1. Docker daemon is not running

**Linux:**

```bash
sudo systemctl start docker
sudo systemctl status docker
```

**Windows/macOS:** Start Docker Desktop and wait until its status indicates that the engine is running.

### 2. Docker Compose command is not found

Check the installed version:

```bash
docker compose version
```

Install or update Docker Compose v2 if necessary.

### 3. Port 8501 is already in use

Check which process is using the port.

**Linux:**

```bash
sudo ss -ltnp | grep 8501
```

You can change the host-side port in `compose.yaml`, for example:

```yaml
ports:
  - "127.0.0.1:8502:8501"
```

Then open:

[http://127.0.0.1:8502](http://127.0.0.1:8502)

### 4. PQC algorithms are unavailable

Check the algorithms from inside the container:

```bash
docker compose exec quantumshield python -c "import oqs; print(oqs.get_enabled_kem_mechanisms()); print(oqs.get_enabled_sig_mechanisms())"
```

The output should include `ML-KEM-768` and `ML-DSA-65`.

If not, inspect the build logs:

```bash
docker compose logs quantumshield
docker compose build --no-cache --progress=plain
```

### 5. Application does not load

Check the container status:

```bash
docker compose ps
docker compose logs --tail=100 quantumshield
```

### 6. Docker build fails on Apple silicon or Intel Macs

Confirm that Docker Desktop is running and that the image is being built for the intended architecture. Native dependencies such as `liboqs` and Qiskit Aer must support the selected architecture.

---

# Run Locally

Docker is recommended for deployment. For development, you can run QuantumShield directly using `uv`.

### Step 1: Clone the Repository

```bash
git clone https://github.com/Arjun-143-kamath/Quantum-Shield.git
cd Quantum-Shield
```

### Step 2: Install Dependencies

```bash
uv sync
```

### Step 3: Configure liboqs

QuantumShield requires the native Open Quantum Safe library and the Python bindings.

If you have already installed `liboqs` in a custom directory, configure the environment accordingly.

For example:

```bash
export OQS_INSTALL_PATH="$HOME/_oqs"
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib:$OQS_INSTALL_PATH/lib64:$LD_LIBRARY_PATH"
```

Adjust the path to match your installation.

### Step 4: Verify PQC Support

```bash
uv run python -c "import oqs; print(oqs.get_enabled_kem_mechanisms()); print(oqs.get_enabled_sig_mechanisms())"
```

Ensure that ML-KEM-768 and ML-DSA-65 are available.

### Step 5: Start the Application

```bash
PYTHONPATH=src uv run streamlit run app.py
```

Open:

[http://localhost:8501](http://localhost:8501)

---

## Run the Tests

Run the complete test suite:

```bash
PYTHONPATH=src uv run pytest -v
```

For a concise test summary:

```bash
PYTHONPATH=src uv run pytest -q
```

---

## Run Benchmarks

QuantumShield includes a benchmark script for comparing classical and post-quantum cryptographic operations.

Run:

```bash
PYTHONPATH=src uv run python scripts/run_benchmark.py \
    --repetitions 5 \
    --sizes-kb 100 1024 10240
```

The benchmark measures:

- RSA key generation.
- ML-KEM key generation.
- ML-DSA key generation.
- RSA-OAEP encryption and decryption.
- ML-KEM encapsulation and decapsulation.
- RSA-PSS signing and verification.
- ML-DSA signing and verification.
- AES-256-GCM encryption and decryption for different file sizes.

Benchmark results are saved as JSON files under:

```text
research/results/
```

> Benchmark results are hardware- and environment-dependent. They should not be interpreted as universal performance guarantees.

---

## Project Structure

```text
Quantum-Shield/
│
├── app.py
├── Dockerfile
├── compose.yaml
├── .dockerignore
├── pyproject.toml
├── uv.lock
├── README.md
│
├── src/
│   └── quantumshield/
│       ├── crypto/
│       ├── quantum/
│       ├── services/
│       └── ...
│
├── scripts/
│   └── run_benchmark.py
│
├── tests/
│
├── data/
│   ├── keys/
│   ├── incoming/
│   ├── outgoing/
│   └── received/
│
└── research/
    └── results/
```

The structure above is a high-level overview. Individual modules may be organized differently as the project evolves.

---

## Data Storage

QuantumShield stores its data locally.

| Data | Purpose |
|---|---|
| `data/keys/` | Generated identity keys |
| `data/incoming/` | Incoming encrypted transfer packages |
| `data/outgoing/` | Outgoing encrypted transfer packages |
| `data/received/` | Successfully received and decrypted files |
| SQLite database | Transfer state and security audit events |
| `research/results/` | Benchmark JSON reports |

When using Docker Compose, named volumes preserve application data between container restarts and rebuilds.

---

## Security Considerations and Limitations

QuantumShield is an academic prototype, not a production secure-transfer product.

- The application is designed for local demonstration and does not implement remote network transfer.
- Shor's algorithm is demonstrated using a small factorization example. It does not break RSA-2048.
- Grover's algorithm is demonstrated on a small search space. It does not break AES-256 in this application.
- Quantum simulations are educational and are not demonstrations of attacks on real-world cryptographic key sizes.
- ML-KEM-768 and ML-DSA-65 are standardized post-quantum algorithms, but their use in this prototype does not constitute a formal security certification.
- The implementation has not undergone an independent cryptographic audit or penetration test.
- Do not use the prototype to protect sensitive production data.
- Keep backups of generated private keys and application data.
- Do not commit private keys, passwords, `.env` files, databases, or real transfer data to Git.

---

## References

1. [NIST FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
2. [NIST FIPS 204 - Module-Lattice-Based Digital Signature Standard (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
3. [Open Quantum Safe - liboqs](https://github.com/open-quantum-safe/liboqs)
4. [Open Quantum Safe - liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
5. [Qiskit Documentation](https://docs.quantum.ibm.com/)
6. [Streamlit Documentation](https://docs.streamlit.io/)
7. [Docker Documentation](https://docs.docker.com/)

---

**Repository:** [https://github.com/Arjun-143-kamath/Quantum-Shield](https://github.com/Arjun-143-kamath/Quantum-Shield)
