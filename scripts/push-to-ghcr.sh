#!/bin/bash
# Build and push Epsilon Enclave Docker image to GitHub Container Registry (GHCR)
# Multi-architecture build (amd64 + arm64)

# Variables - EDIT THESE
GITHUB_USERNAME="${GITHUB_USERNAME:-khajievn}"
GITHUB_TOKEN="${GITHUB_TOKEN:?ERROR: Set GITHUB_TOKEN env var (GitHub PAT with packages:write scope)}"
GITHUB_ORG="epsilon-data"
IMAGE_NAME="epsilon-enclave"
IMAGE_TAG="${1:-1.1.0}"  # Pass version as argument, default 1.1.0

# Full image path
GHCR_IMAGE="ghcr.io/${GITHUB_ORG}/${IMAGE_NAME}"

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=============================================="
echo "Epsilon Enclave - Build and Push to GHCR"
echo "=============================================="
echo ""
echo "Image: ${GHCR_IMAGE}:${IMAGE_TAG}"
echo "Platforms: linux/amd64, linux/arm64"
echo ""

# Validate credentials
if [ -z "$GITHUB_USERNAME" ] || [ -z "$GITHUB_TOKEN" ]; then
    echo "ERROR: Please edit this script and set GITHUB_USERNAME and GITHUB_TOKEN"
    exit 1
fi

# Change to project directory
cd "$PROJECT_DIR"

echo "Setting up Docker buildx for multi-platform builds..."
docker buildx create --name multiarch --use 2>/dev/null || docker buildx use multiarch

echo "Logging in to GitHub Container Registry..."
echo "${GITHUB_TOKEN}" | docker login ghcr.io -u "${GITHUB_USERNAME}" --password-stdin

echo "Building and pushing multi-architecture image..."
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ${GHCR_IMAGE}:${IMAGE_TAG} \
  -t ${GHCR_IMAGE}:latest \
  --push \
  .

echo ""
echo "=============================================="
echo "Multi-architecture image pushed successfully!"
echo "=============================================="
echo ""
echo "Image URL: ${GHCR_IMAGE}:${IMAGE_TAG}"
echo "Platforms: linux/amd64, linux/arm64"
echo ""
echo "To pull on EC2 (Nitro instance):"
echo "  echo \$GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_USERNAME --password-stdin"
echo "  docker pull ${GHCR_IMAGE}:${IMAGE_TAG}"
echo ""
echo "To build EIF:"
echo "  nitro-cli build-enclave --docker-uri ${GHCR_IMAGE}:${IMAGE_TAG} --output-file epsilon-enclave.eif"
