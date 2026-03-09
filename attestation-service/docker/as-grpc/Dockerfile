# Copyright (c) 2023 by Alibaba.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# rust:1.90.0
FROM --platform=${BUILDPLATFORM:-linux/amd64} \
    docker.io/library/rust@sha256:e227f20ec42af3ea9a3c9c1dd1b2012aa15f12279b5e9d5fb890ca1c2bb5726c \
    AS builder
ARG ARCH=x86_64
ARG VERIFIER=all-verifier

WORKDIR /usr/src/attestation-service
COPY . .

# Install TPM Build Dependencies
RUN apt-get update && apt-get install --no-install-recommends -y protobuf-compiler clang libtss2-dev cmake

# Install TDX Build Dependencies
ARG DCAP_VERSION=1_24_100
RUN if [ "${ARCH}" = "x86_64" ]; then curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    curl -sSLf https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg | \
    tee -a /etc/apt/preferences.d/99dcap && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install --no-install-recommends -y libsgx-dcap-quote-verify-dev; fi

# Install NVAT Dependencies
RUN if [ "${ARCH}" = "x86_64" ] && ( [ "${VERIFIER}" = "all-verifier" ] || [ "${VERIFIER}" = "nvidia-verifier" ] ); \
    then set -ex && apt-get update && apt-get install -y git cmake build-essential libxml2-dev && \
    tmpdir=$(mktemp -d) && cd "$tmpdir" && git clone https://github.com/NVIDIA/attestation-sdk && \
    cd attestation-sdk/nv-attestation-sdk-cpp && cmake . && make install && \
    ln -s /usr/local/include/nvat.h /usr/include/nvat.h && ldconfig; fi

# Build and Install gRPC attestation-service
RUN if [ "$(uname -m)" != "${ARCH}" ]; then \
    export GCC_PACKAGE="gcc-${ARCH}-linux-gnu"; \
    export GCC_COMPILER="${ARCH}-linux-gnu-gcc"; \
    export RUSTC_TARGET="${ARCH}-unknown-linux-gnu"; \
    export TARGET_FLAG="--target ${RUSTC_TARGET}"; \
    export RUSTFLAGS_ARGS=" -C linker=${GCC_COMPILER}"; \
    export RUSTFLAGS="${RUSTFLAGS_ARGS}"; \
    apt-get install -y ${GCC_PACKAGE}; \
    rustup target add ${RUSTC_TARGET}; fi; \
    export NVAT_USE_SYSTEM_LIB=1; \
    export CFLAGS="-I/usr/local/include"; \
    export RUSTFLAGS="-L /usr/local/lib"; \
    export LD_LIBRARY_PATH="/usr/local/lib"; \
    cargo install --path attestation-service --bin grpc-as --features grpc-bin,${VERIFIER} --locked ${TARGET_FLAG}

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9
ARG ARCH=x86_64
ARG VERIFIER=all-verifier

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/tree/main/attestation-service"

# Install Openssl Suites
RUN apt-get update && apt-get install openssl -y && \
    apt install --reinstall ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Install TDX Runtime Dependencies
ARG DCAP_VERSION=1_24_100
RUN if [ "${ARCH}" = "x86_64" ] && ( [ "${VERIFIER}" = "all-verifier" ] || [ "${VERIFIER}" = "tdx-verifier" ] ); \
    then apt-get update && apt-get install curl gnupg -y && \
    curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    curl -sSLf https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg | \
    tee -a /etc/apt/preferences.d/99dcap && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install --no-install-recommends -y libsgx-dcap-default-qpl libsgx-dcap-quote-verify && \
    apt-get remove curl gnupg -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

# Install TPM Runtime Dependencies
RUN if [ "${VERIFIER}" = "all-verifier" ] || [ "${VERIFIER}" = "az-snp-vtpm-verifier" ] || [ "${VERIFIER}" = "az-tdx-vtpm-verifier" ]; \
    then apt-get update && apt-get install libtss2-dev -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

COPY --from=builder /usr/local/cargo/bin/grpc-as /usr/local/bin/grpc-as
COPY --from=builder /usr/local/lib/libnvat.so.1.2.0 /usr/local/lib/
RUN ln -s /usr/local/lib/libnvat.so.1.2.0 /usr/local/lib/libnvat.so.1
RUN ln -s /usr/local/lib/libnvat.so.1.2.0 /usr/local/lib/libnvat.so
RUN ls -l /usr/local/lib

VOLUME /opt/confidential-containers/attestation-service
ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

CMD ["grpc-as", "--socket", "0.0.0.0:50004"]

EXPOSE 50004
