# Multi-arch Dockerfile for patch library testing
# Build for multiple architectures:
#   docker buildx build --platform linux/amd64,linux/arm64 -t patch-test .
#
# Or build for current architecture:
#   docker build -t patch-test .
#
# Run tests:
#   docker run --rm patch-test

FROM ubuntu:24.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    lld \
    ninja-build \
    pkg-config \
    python3-pip \
    pipx \
    && rm -rf /var/lib/apt/lists/*

# Install latest meson via pipx (has C23 support)
ENV PATH="/root/.local/bin:$PATH"
RUN pipx install meson

# Check versions
RUN clang --version && meson --version

WORKDIR /src

# Copy source
COPY . .

# Build
RUN CC=clang meson setup build \
    -Dc_std=gnu23 \
    -Dwarning_level=3 \
    -Dwerror=true \
    && meson compile -C build

# Test stage
FROM builder AS test

# Run tests
CMD ["meson", "test", "-C", "build", "-v"]

# Interactive stage for debugging
FROM builder AS interactive

CMD ["/bin/bash"]
