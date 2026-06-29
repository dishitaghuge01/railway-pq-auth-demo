# Stage 1: Build liboqs from source
FROM ubuntu:24.04 AS liboqs-builder

RUN apt-get update && apt-get install -y \
    cmake ninja-build libssl-dev git build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /liboqs \
    && cd /liboqs && mkdir build && cd build \
    && cmake -GNinja -DBUILD_SHARED_LIBS=ON .. \
    && ninja && ninja install

# Stage 2: Final image
FROM ubuntu:24.04

# Copy compiled liboqs from builder
COPY --from=liboqs-builder /usr/local/lib /usr/local/lib
COPY --from=liboqs-builder /usr/local/include /usr/local/include

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    libdmtx-dev libdmtx0b libssl-dev \
    && ldconfig \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Install Python deps including liboqs-python submodule
RUN python3 -m venv venv \
    && ./venv/bin/pip install --upgrade pip \
    && ./venv/bin/pip install -r requirements.txt

# Generate keys at build time
RUN ./venv/bin/python scripts/keygen.py

EXPOSE 8000 8001 8002 8003

CMD ["./venv/bin/honcho", "start"]