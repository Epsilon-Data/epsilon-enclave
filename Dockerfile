# Epsilon Enclave - AWS Nitro Enclave Docker Image with KMS Support
# Builds kmstool_enclave_cli and all AWS dependencies from source

# =============================================================================
# Stage 1: Build all AWS libraries and kmstool
# =============================================================================
FROM amazonlinux:2 AS builder

# Install build dependencies
RUN amazon-linux-extras enable epel && \
    yum install -y epel-release && \
    yum install -y \
        gcc \
        gcc-c++ \
        cmake3 \
        git \
        tar \
        make \
        go \
        ninja-build \
        openssl-devel \
        curl-devel \
        ca-certificates \
    && yum clean all && \
    ln -sf /usr/bin/ninja-build /usr/bin/ninja

# Install Rust (required for NSM library)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Build aws-lc (AWS crypto library) - use latest stable
RUN git clone --depth 1 --branch v1.21.0 https://github.com/aws/aws-lc.git && \
    cd aws-lc && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON . && \
    cmake3 --build . --target install && \
    cd .. && rm -rf aws-lc

# Build s2n-tls
RUN git clone --depth 1 --branch v1.5.10 https://github.com/aws/s2n-tls.git && \
    cd s2n-tls && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -S . -B build \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON && \
    cmake3 --build build --target install && \
    cd .. && rm -rf s2n-tls

# Build aws-c-common (newer version with utf8_decoder support)
RUN git clone --depth 1 --branch v0.9.27 https://github.com/awslabs/aws-c-common.git && \
    cd aws-c-common && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON . && \
    cmake3 --build . --target install && \
    cd .. && rm -rf aws-c-common

# Build aws-c-sdkutils
RUN git clone --depth 1 --branch v0.1.19 https://github.com/awslabs/aws-c-sdkutils.git && \
    cd aws-c-sdkutils && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON . && \
    cmake3 --build . --target install && \
    cd .. && rm -rf aws-c-sdkutils

# Build aws-c-cal
RUN git clone --depth 1 --branch v0.7.4 https://github.com/awslabs/aws-c-cal.git && \
    cd aws-c-cal && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON . && \
    cmake3 --build . --target install && \
    cd .. && rm -rf aws-c-cal

# Build aws-c-io (with vsock support for enclaves)
RUN git clone --depth 1 --branch v0.14.18 https://github.com/awslabs/aws-c-io.git && \
    cd aws-c-io && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON -DUSE_VSOCK=ON . && \
    cmake3 --build . --target install && \
    cd .. && rm -rf aws-c-io

# Build aws-c-compression
RUN git clone --depth 1 --branch v0.2.19 https://github.com/awslabs/aws-c-compression.git && \
    cd aws-c-compression && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON . && \
    cmake3 --build . --target install && \
    cd .. && rm -rf aws-c-compression

# Build aws-c-http
RUN git clone --depth 1 --branch v0.8.10 https://github.com/awslabs/aws-c-http.git && \
    cd aws-c-http && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON . && \
    cmake3 --build . --target install && \
    cd .. && rm -rf aws-c-http

# Build aws-c-auth
RUN git clone --depth 1 --branch v0.7.31 https://github.com/awslabs/aws-c-auth.git && \
    cd aws-c-auth && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON . && \
    cmake3 --build . --target install && \
    cd .. && rm -rf aws-c-auth

# Build json-c
RUN git clone --depth 1 --branch json-c-0.18-20240915 https://github.com/json-c/json-c.git && \
    cd json-c && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON . && \
    cmake3 --build . --target install && \
    cd .. && rm -rf json-c

# Build NSM library (Rust)
RUN git clone --depth 1 --branch v0.4.0 https://github.com/aws/aws-nitro-enclaves-nsm-api.git && \
    cd aws-nitro-enclaves-nsm-api && \
    cargo build --release -p nsm-lib && \
    cp target/release/libnsm.so /usr/lib64/ && \
    cp target/release/nsm.h /usr/include/ && \
    cd .. && rm -rf aws-nitro-enclaves-nsm-api

# Build aws-nitro-enclaves-sdk-c and kmstool_enclave_cli
RUN git clone --depth 1 --branch v0.4.4 https://github.com/aws/aws-nitro-enclaves-sdk-c.git && \
    cd aws-nitro-enclaves-sdk-c && \
    cmake3 -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON . && \
    cmake3 --build . --target install && \
    cmake3 --build . --target kmstool_enclave_cli

# =============================================================================
# Stage 2: Runtime image
# =============================================================================
FROM amazonlinux:2

# Install Python 3 and runtime dependencies (gcc needed for psutil)
RUN amazon-linux-extras install python3.8 -y && \
    yum install -y \
        python38 \
        python38-pip \
        python38-devel \
        gcc \
        openssl \
        json-c \
        ca-certificates \
    && update-ca-trust && \
    yum clean all && \
    alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1 && \
    alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.8 1

# Create app directory
WORKDIR /app

# Copy KMS tools and libraries from builder
COPY --from=builder /usr/lib64/libnsm.so /usr/lib64/
COPY --from=builder /usr/lib64/libaws*.so* /usr/lib64/
COPY --from=builder /usr/lib64/libs2n.so /usr/lib64/
COPY --from=builder /usr/lib64/libcrypto.so* /usr/lib64/
COPY --from=builder /usr/lib64/libjson-c.so* /usr/lib64/
COPY --from=builder /build/aws-nitro-enclaves-sdk-c/bin/kmstool-enclave-cli/kmstool_enclave_cli /app/
RUN chmod +x /app/kmstool_enclave_cli && ldconfig

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the enclave application modules
COPY *.py /app/
COPY interfaces/ /app/interfaces/
COPY implementations/ /app/implementations/
COPY server/ /app/server/

# Environment configuration
ENV LD_LIBRARY_PATH=/usr/lib64
ENV PYTHONUNBUFFERED=1
ENV VSOCK_PORT=5005
ENV LOG_LEVEL=INFO
ENV ENABLE_KMS_ATTESTATION=true
ENV KMSTOOL_PATH=/app/kmstool_enclave_cli

# Run the enclave application
CMD ["python3", "/app/main.py"]
