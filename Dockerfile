
# =====================================================
# STAGE 1: BUILD OPEN QUANTUM SAFE LIBRARY
# =====================================================

FROM python:3.14-slim AS oqs-builder

ARG LIBOQS_VERSION=0.16.0

WORKDIR /build

# Native build dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download the matching liboqs release.
RUN git clone \
    --depth 1 \
    --branch "${LIBOQS_VERSION}" \
    https://github.com/open-quantum-safe/liboqs.git \
    /build/liboqs

# Build only the algorithms QuantumShield requires.
RUN cmake -S /build/liboqs -B /build/liboqs/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=ON \
    -DOQS_USE_OPENSSL=OFF \
    "-DOQS_MINIMAL_BUILD=KEM_ml_kem_768;SIG_ml_dsa_65" \
    && cmake --build /build/liboqs/build --parallel 2 \
    && cmake --install /build/liboqs/build


# =====================================================
# STAGE 2: QUANTUMSHIELD APPLICATION
# =====================================================

FROM python:3.14-slim AS runtime

# Python and uv configuration.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    OQS_INSTALL_PATH=/opt/liboqs \
    PATH="/opt/venv/bin:$PATH" \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Install uv.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Runtime dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgomp1 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy the precompiled liboqs library.
COPY --from=oqs-builder /opt/liboqs /opt/liboqs

# Application directory.
WORKDIR /app

# Create a non-root application user.
RUN useradd \
    --uid 10001 \
    --create-home \
    --shell /usr/sbin/nologin \
    appuser

# Copy dependency manifests first for build caching.
COPY pyproject.toml uv.lock ./

# Install locked runtime dependencies.
# pytest and other development-only packages are excluded.
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source and configuration.
COPY --chown=10001:10001 . /app

# Create persistent-storage directories.
RUN mkdir -p \
    /app/data/keys \
    /app/data/incoming \
    /app/data/outgoing \
    /app/data/received \
    /app/research/results \
    && chown -R appuser:appuser \
        /app/data \
        /app/research/results

# Verify native PQC algorithms are available.
RUN python -c "\
import oqs; \
assert 'ML-KEM-768' in oqs.get_enabled_kem_mechanisms(); \
assert 'ML-DSA-65' in oqs.get_enabled_sig_mechanisms(); \
print('PQC algorithms successfully loaded')"

# Run without root privileges.
USER appuser

# Streamlit port.
EXPOSE 8501

# Container health check.
HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=60s \
    --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4)" || exit 1

# Start QuantumShield.
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]

