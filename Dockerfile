# ─── Stage 1: Build liboqs C library ────────────────────────────────────────
FROM ubuntu:24.04 AS liboqs-builder
RUN apt-get update && apt-get install -y \
    cmake ninja-build libssl-dev git build-essential \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /liboqs \
    && cd /liboqs && mkdir build && cd build \
    && cmake -GNinja -DBUILD_SHARED_LIBS=ON .. \
    && ninja && ninja install

# ─── Stage 2: Build frontend ─────────────────────────────────────────────────
FROM node:22 AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# ─── Stage 3: Final image ────────────────────────────────────────────────────
FROM ubuntu:24.04

COPY --from=liboqs-builder /usr/local/lib /usr/local/lib
COPY --from=liboqs-builder /usr/local/include /usr/local/include

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv python3-dev \
    libdmtx-dev libdmtx0b libssl-dev \
    build-essential cmake git \
    nodejs npm nginx \
    && ldconfig \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

RUN python3 -m venv venv \
    && ./venv/bin/pip install --upgrade pip setuptools
RUN ./venv/bin/pip install ./liboqs-python
RUN ./venv/bin/pip install -r requirements.txt
RUN echo "y" | ./venv/bin/python scripts/keygen.py

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 8000 8001 8002 8003

CMD ["/bin/bash", "/app/start.sh"]
