# PQC tools image: liboqs (ML-DSA-44, FIPS 204) + liboqs-python + the pqcdns package.
# Used by the `signer` (offline zone signing) and `client` (dig + validator + benchmarks).
FROM python:3.12-slim-bookworm

ARG LIBOQS_VERSION=0.16.0
ARG LIBOQS_PYTHON_VERSION=0.16.0.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git ca-certificates \
        dnsutils curl iproute2 iputils-ping procps jq util-linux \
    && rm -rf /var/lib/apt/lists/*

# liboqs: shared lib, only what we need (ML-DSA-44), no OpenSSL dependency -> reproducible
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_USE_OPENSSL=OFF -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44" -DCMAKE_INSTALL_PREFIX=/usr/local \
 && ninja -C /tmp/liboqs/build install && ldconfig && rm -rf /tmp/liboqs

ENV OQS_INSTALL_PATH=/usr/local
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && pip install --no-cache-dir "git+https://github.com/open-quantum-safe/liboqs-python@${LIBOQS_PYTHON_VERSION}" \
 && python -c "import oqs; s=oqs.Signature('ML-DSA-44'); print('liboqs', oqs.oqs_version(), 'ML-DSA-44 OK', len(s.generate_keypair()))"

COPY pqcdns /opt/pqcdns/pqcdns
ENV PYTHONPATH=/opt/pqcdns PYTHONUNBUFFERED=1 MPLCONFIGDIR=/tmp
WORKDIR /work
CMD ["sleep", "infinity"]
