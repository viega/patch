#!/bin/bash
# Test the patch library in Docker containers
#
# Usage:
#   ./scripts/test-docker.sh          # Test on both architectures
#   ./scripts/test-docker.sh amd64    # Test on x86-64 only
#   ./scripts/test-docker.sh arm64    # Test on ARM64 only

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Detect host OS for capability support
# Hardware watchpoints (perf_event_open) only work on native Linux hosts
HOST_OS="$(uname -s)"
EXTRA_RUN_ARGS=""

if [[ "$HOST_OS" == "Linux" ]]; then
    # Add capabilities for hardware watchpoints via perf_event_open
    # CAP_PERFMON: allows perf_event_open (Linux 5.8+)
    # seccomp=unconfined: allows perf syscalls that may be blocked by default
    EXTRA_RUN_ARGS="--cap-add=CAP_PERFMON --cap-add=CAP_SYS_PTRACE --security-opt seccomp=unconfined"
    echo "Linux host detected: enabling watchpoint capabilities"
fi

# Check if docker/podman is available
if command -v docker &> /dev/null; then
    CONTAINER_CMD="docker"
elif command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
else
    echo "Error: docker or podman is required"
    exit 1
fi

# Check for buildx support (needed for cross-arch builds)
if ! $CONTAINER_CMD buildx version &> /dev/null; then
    echo "Warning: docker buildx not available, using native builds only"
    NATIVE_ONLY=1
fi

run_test() {
    local arch=$1
    local platform="linux/$arch"

    echo "========================================"
    echo "Testing on $platform"
    echo "========================================"

    if [[ -n "$NATIVE_ONLY" ]]; then
        $CONTAINER_CMD build -t "patch-test-$arch" --target test .
        # shellcheck disable=SC2086
        $CONTAINER_CMD run --rm $EXTRA_RUN_ARGS "patch-test-$arch"
    else
        $CONTAINER_CMD buildx build \
            --platform "$platform" \
            --target test \
            -t "patch-test-$arch" \
            --load \
            .
        # shellcheck disable=SC2086
        $CONTAINER_CMD run --rm --platform "$platform" $EXTRA_RUN_ARGS "patch-test-$arch"
    fi

    echo ""
}

case "${1:-all}" in
    amd64|x86_64|x64)
        run_test amd64
        ;;
    arm64|aarch64)
        run_test arm64
        ;;
    all)
        run_test arm64
        run_test amd64
        ;;
    *)
        echo "Usage: $0 [amd64|arm64|all]"
        exit 1
        ;;
esac

echo "========================================"
echo "All tests completed successfully!"
echo "========================================"
