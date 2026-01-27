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
        $CONTAINER_CMD run --rm "patch-test-$arch"
    else
        $CONTAINER_CMD buildx build \
            --platform "$platform" \
            --target test \
            -t "patch-test-$arch" \
            --load \
            .
        $CONTAINER_CMD run --rm --platform "$platform" "patch-test-$arch"
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
