# A3-PS022-TC177: Containerized Testbed & Build Environment
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install LLVM/Clang compiler toolchain, libbpf, and network benchmark utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    pkg-config \
    iproute2 \
    iputils-ping \
    ethtool \
    nftables \
    tmux \
    python3 \
    python3-matplotlib \
    python3-numpy \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy codebase
COPY . /workspace

# Precompile all kernel objects and user utilities, then run unprivileged test suite
RUN make all && make test

CMD ["/bin/bash"]
