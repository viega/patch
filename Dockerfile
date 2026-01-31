# Multi-arch Dockerfile for patch library testing
# Build for multiple architectures:
#   docker buildx build --platform linux/amd64,linux/arm64 -t patch-test .
#
# Or build for current architecture:
#   docker build -t patch-test .
#
# Run tests (basic):
#   docker run --rm patch-test
#
# Run tests with hardware watchpoint support (requires host perf access):
#   docker run --rm --privileged \
#     --cap-add=SYS_PTRACE \
#     --cap-add=CAP_PERFMON \
#     --security-opt seccomp=unconfined \
#     patch-test
#
# Note: Hardware watchpoints use perf_event_open() which requires either:
# - kernel.perf_event_paranoid <= 1 on the host
# - CAP_PERFMON capability (Linux 5.8+)
# - Running with --privileged

FROM ubuntu:24.04 AS builder

# Install build dependencies including libffi for FFI support
RUN apt-get update && apt-get install -y \
    clang \
    lld \
    ninja-build \
    pkg-config \
    python3-pip \
    pipx \
    libffi-dev \
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

# Script to check perf_event access and run tests
COPY <<'EOF' /run-tests.sh
#!/bin/bash
set -e

echo "=== Environment Diagnostics ==="
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"

# Check perf_event_paranoid
if [ -f /proc/sys/kernel/perf_event_paranoid ]; then
    PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid)
    echo "perf_event_paranoid: $PARANOID"
    if [ "$PARANOID" -gt 1 ]; then
        echo "Warning: perf_event_paranoid > 1 - hardware watchpoints may not work"
        echo "To enable: sudo sysctl kernel.perf_event_paranoid=-1"
    fi
else
    echo "Warning: /proc/sys/kernel/perf_event_paranoid not found"
fi

# Check capabilities
echo ""
echo "=== Running Tests ==="
exec meson test -C build -v
EOF
RUN chmod +x /run-tests.sh

CMD ["/run-tests.sh"]

# Interactive stage for debugging
FROM builder AS interactive

CMD ["/bin/bash"]
