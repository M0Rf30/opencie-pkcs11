# Build container for distro-independent libopencie-pkcs11.so
#
# Builds on Ubuntu 22.04 (glibc 2.35) for maximum compatibility:
#   Ubuntu 22.04+, Debian 12+, Fedora 37+, RHEL 9+, Arch, etc.
#
# All dependencies except glibc are statically linked.
# The output binary only requires: libc.so.6, libm.so.6, ld-linux-*.so.*
#
# Usage:
#   podman build -t libopencie-builder -f Containerfile .
#   podman run --rm -v $(pwd)/output:/output libopencie-builder
#
# For aarch64 cross-compilation:
#   podman run --rm -v $(pwd)/output:/output libopencie-builder aarch64

FROM docker.io/library/ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV VCPKG_FORCE_SYSTEM_BINARIES=1

# Build tools + aarch64 cross-compiler
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    autoconf-archive \
    automake \
    libtool \
    ca-certificates \
    curl \
    git \
    ninja-build \
    pkg-config \
    python3 \
    python3-pip \
    tar \
    unzip \
    zip \
    # System libs that must stay dynamic (x86_64 native builds)
    libpcsclite-dev \
    # aarch64 cross-compilation toolchain
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

# Install newer meson and cmake via pip (Ubuntu 22.04 versions are too old for vcpkg)
RUN pip3 install --no-cache-dir meson cmake

# Install vcpkg
RUN git clone --depth 1 https://github.com/microsoft/vcpkg.git /opt/vcpkg && \
    /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics

ENV VCPKG_ROOT=/opt/vcpkg
ENV PATH="${VCPKG_ROOT}:${PATH}"

# Install x86_64 static dependencies via vcpkg
RUN vcpkg install --triplet x64-linux \
    cryptopp \
    curl \
    fontconfig \
    freetype \
    libpng \
    libxml2 \
    openssl \
    podofo \
    zlib

# Install aarch64 static dependencies via vcpkg
# vcpkg auto-detects aarch64-linux-gnu-gcc from the cross-compiler package
RUN vcpkg install --triplet arm64-linux \
    cryptopp \
    curl \
    fontconfig \
    freetype \
    libpng \
    libxml2 \
    openssl \
    podofo \
    zlib

COPY . /src
WORKDIR /src

# Build script
RUN cat > /build.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail

ARCH="${1:-x86_64}"
BUILDDIR="builddir-portable-${ARCH}"

case "$ARCH" in
    x86_64)
        VCPKG_TRIPLET="x64-linux"
        CROSS_ARGS=""
        ;;
    aarch64)
        VCPKG_TRIPLET="arm64-linux"
        CROSS_ARGS="--cross-file cross-aarch64.ini"
        ;;
    *)
        echo "Unsupported architecture: ${ARCH}"
        echo "Supported: x86_64, aarch64"
        exit 1
        ;;
esac

echo "=== Building libopencie-pkcs11.so (portable, ${ARCH}) ==="

rm -rf "${BUILDDIR}"
PKG_CONFIG_LIBDIR="${VCPKG_ROOT}/installed/${VCPKG_TRIPLET}/lib/pkgconfig" \
    meson setup "${BUILDDIR}" \
    -Dportable=true \
    -Dprefer_static=true \
    -Dbuildtype=release \
    -Dstrip=true \
    ${CROSS_ARGS}

meson compile -C "${BUILDDIR}"

echo ""
echo "=== Build complete ==="
echo ""
echo "--- Dynamic dependencies ---"
readelf -d "${BUILDDIR}/libopencie-pkcs11.so" | grep NEEDED || true
echo ""
echo "--- Exported symbols ---"
nm -D "${BUILDDIR}/libopencie-pkcs11.so" | grep -c ' T ' || true
echo ""
echo "--- glibc version requirement ---"
readelf -V "${BUILDDIR}/libopencie-pkcs11.so" 2>/dev/null | grep -oP 'GLIBC_\S+' | sort -V | tail -1 || true
echo ""
echo "--- File info ---"
file "${BUILDDIR}/libopencie-pkcs11.so"
ls -lh "${BUILDDIR}/libopencie-pkcs11.so"

# Copy to output if mounted
if [ -d /output ]; then
    cp "${BUILDDIR}/libopencie-pkcs11.so" "/output/libopencie-pkcs11-${ARCH}.so"
    echo ""
    echo "Output copied to /output/libopencie-pkcs11-${ARCH}.so"
fi
SCRIPT
RUN chmod +x /build.sh

ENTRYPOINT ["/build.sh"]
CMD ["x86_64"]
