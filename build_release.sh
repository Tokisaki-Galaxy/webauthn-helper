#!/bin/bash
set -e

# Define project name and version
PROJECT_NAME="rust-template"
VERSION=$(grep "^version" Cargo.toml | cut -d '"' -f2)
echo "Build version: $VERSION"

# Check if cross is installed
if ! command -v cross &> /dev/null; then
  echo "Error: cross is not installed. Install it with: cargo install cross --locked"
  exit 1
fi

# Ensure release directory exists
RELEASE_DIR="release"
mkdir -p $RELEASE_DIR

# Build target platform lists
DEFAULT_TARGETS=(
  # x86_64 architecture
  "x86_64-unknown-linux-musl"

  # AArch64 (ARM64) architecture
  "aarch64-unknown-linux-musl"

  # ARM 32-bit architecture
  "armv7-unknown-linux-musleabihf"
  "armv7-unknown-linux-musleabi"
  "armv5te-unknown-linux-musleabi"
  "arm-unknown-linux-musleabi"
  "arm-unknown-linux-musleabihf"

  # RISC-V architecture (emerging open source architecture)
  "riscv64gc-unknown-linux-musl"

  # PowerPC architecture (some high-end routers)
  "powerpc64le-unknown-linux-musl"
)

NIGHTLY_TARGETS=(
  # MIPS 32-bit architectures (built with nightly + build-std)
  "mips-unknown-linux-musl"
  "mipsel-unknown-linux-musl"
)

# Helper to package build artifacts
package_target() {
  local TARGET="$1"
  local TARGET_DIR="$RELEASE_DIR/$PROJECT_NAME-$VERSION-$TARGET"
  local BINARY_PATH="target/$TARGET/release/$PROJECT_NAME"

  if [ -f "$BINARY_PATH" ]; then
    mkdir -p "$TARGET_DIR"
    cp "$BINARY_PATH" "$TARGET_DIR/"
    cp LICENSE "$TARGET_DIR/" 2>/dev/null || echo "⚠ Warning: LICENSE file does not exist"
    cp README.md "$TARGET_DIR/" 2>/dev/null || echo "⚠ Warning: README.md file does not exist"

    echo "Creating compressed package..."
    tar -czvf "$RELEASE_DIR/$PROJECT_NAME-$VERSION-$TARGET.tar.gz" -C "$RELEASE_DIR" "$PROJECT_NAME-$VERSION-$TARGET" > /dev/null
    rm -rf "$TARGET_DIR"

    echo "✓ Completed $TARGET build and packaging"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    return 0
  else
    echo "✗ Binary file does not exist: $BINARY_PATH"
    FAILED_COUNT=$((FAILED_COUNT + 1))
    FAILED_TARGETS+=("$TARGET")
    return 1
  fi
}

# Build statistics
SUCCESS_COUNT=0
FAILED_COUNT=0
FAILED_TARGETS=()

echo "Starting build for all target platforms..."
echo "========================================"

# Build for each default target platform using cross
for TARGET in "${DEFAULT_TARGETS[@]}"; do
  echo ""
  echo "Starting build for $TARGET..."

  if cross build -q --release --target "$TARGET"; then
    echo "✓ Build successful: $TARGET"
    package_target "$TARGET"
  else
    echo "✗ cross build failed: $TARGET"
    FAILED_COUNT=$((FAILED_COUNT + 1))
    FAILED_TARGETS+=("$TARGET")
  fi

  echo "----------------------------------------"
done

# Build for each nightly target platform (nightly + build-std) using cross
for TARGET in "${NIGHTLY_TARGETS[@]}"; do
  echo ""
  echo "Starting build for $TARGET (nightly + build-std)..."

  if cross +nightly build -q -Z build-std=std,panic_abort --release --target "$TARGET"; then
    echo "✓ Build successful (nightly build-std): $TARGET"
    package_target "$TARGET"
  else
    echo "✗ cross +nightly -Z build-std failed: $TARGET"
    FAILED_COUNT=$((FAILED_COUNT + 1))
    FAILED_TARGETS+=("$TARGET")
  fi

  echo "----------------------------------------"
done

echo ""
echo "Build completion summary:"
echo "========================================"
echo "✓ Successfully built: $SUCCESS_COUNT targets"
if [ $FAILED_COUNT -gt 0 ]; then
  echo "✗ Failed builds: $FAILED_COUNT targets"
  echo "Failed targets:"
  for target in "${FAILED_TARGETS[@]}"; do
    echo "  - $target"
  done
fi

echo ""
echo "Release packages located in $RELEASE_DIR directory"
if [ $SUCCESS_COUNT -gt 0 ]; then
  echo "Generated files:"
  ls -la $RELEASE_DIR/*.tar.gz 2>/dev/null | sed 's/^/  /' || echo "  No compressed packages generated"
fi

# Display disk usage
echo "Disk usage:"
du -sh $RELEASE_DIR 2>/dev/null | sed 's/^/  Total size: /'

if [ $FAILED_COUNT -eq 0 ]; then
  echo "🎉 All platforms built successfully!"
  exit 0
else
  echo "⚠ Some platforms failed to build, please check error messages"
  exit 1
fi
