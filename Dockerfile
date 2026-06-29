# ─── Stage 1: Build liboqs C library ───────────────────────────────────────
FROM ubuntu:24.04 AS liboqs-builder

RUN apt-get update && apt-get install -y \
    cmake ninja-build libssl-dev git build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /liboqs \
    && cd /liboqs && mkdir build && cd build \
    && cmake -GNinja -DBUILD_SHARED_LIBS=ON .. \
    && ninja && ninja install

# ─── Stage 2: Final image ──────────────────────────────────────────────────
FROM ubuntu:24.04

# Copy compiled liboqs from builder
COPY --from=liboqs-builder /usr/local/lib /usr/local/lib
COPY --from=liboqs-builder /usr/local/include /usr/local/include

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv python3-dev \
    libdmtx-dev libdmtx0b libssl-dev \
    build-essential cmake git \
    && ldconfig \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy everything including the liboqs-python submodule
COPY . .

# ── KEY FIX: install liboqs-python from the submodule first ─────────────────
# The submodule lives at ./liboqs-python (check your repo structure)
# It must be built against the already-installed liboqs C library
RUN python3 -m venv venv \
    && ./venv/bin/pip install --upgrade pip

# Install liboqs-python from submodule (it's not on PyPI, it's in your repo)
RUN ./venv/bin/pip install ./liboqs-python

# Install the rest of the requirements
RUN ./venv/bin/pip install -r requirements.txt

# Generate keys
RUN ./venv/bin/python scripts/keygen.py

EXPOSE 8000 8001 8002 8003

CMD ["./venv/bin/honcho", "start"]