#!/bin/bash
# Deploy new enclave version on EC2
# Usage: ./deploy-ec2.sh [version]
# Pulls image, builds EIF, extracts PCRs, registers in DB
set -e

VERSION="${1:-latest}"
GHCR_IMAGE="ghcr.io/epsilon-data/epsilon-enclave"
EIF_PATH="/home/ec2-user/epsilon-enclave.eif"
DB_URL="${COORDINATOR_DATABASE_URL}"

echo "=============================================="
echo "Epsilon Enclave Deploy - v${VERSION}"
echo "=============================================="

# Step 1: Pull image
echo ""
echo "[1/5] Pulling image ${GHCR_IMAGE}:${VERSION}..."
docker pull "${GHCR_IMAGE}:${VERSION}"

# Step 2: Stop current enclave
echo ""
echo "[2/5] Stopping current enclave..."
nitro-cli terminate-enclave --all 2>/dev/null || true

# Step 3: Build EIF
echo ""
echo "[3/5] Building EIF..."
BUILD_OUTPUT=$(nitro-cli build-enclave \
    --docker-uri "${GHCR_IMAGE}:${VERSION}" \
    --output-file "${EIF_PATH}" 2>&1)

echo "$BUILD_OUTPUT"

# Extract PCR values from build output
PCR0=$(echo "$BUILD_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['Measurements']['PCR0'])" 2>/dev/null || echo "")
PCR1=$(echo "$BUILD_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['Measurements']['PCR1'])" 2>/dev/null || echo "")
PCR2=$(echo "$BUILD_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['Measurements']['PCR2'])" 2>/dev/null || echo "")

echo ""
echo "PCR Values for v${VERSION}:"
echo "  PCR0: ${PCR0}"
echo "  PCR1: ${PCR1}"
echo "  PCR2: ${PCR2}"

# Step 4: Start new enclave
echo ""
echo "[4/4] Starting enclave..."
nitro-cli run-enclave \
    --eif-path "${EIF_PATH}" \
    --memory 4096 \
    --cpu-count 2 \
    --enclave-cid 18

echo ""
echo "=============================================="
echo "Enclave v${VERSION} deployed successfully!"
echo "=============================================="
echo ""
echo "PCR0: ${PCR0}"
echo "PCR1: ${PCR1}"
echo "PCR2: ${PCR2}"
echo ""

# Save PCRs to a local file for reference
echo "{\"version\": \"${VERSION}\", \"pcr0\": \"${PCR0}\", \"pcr1\": \"${PCR1}\", \"pcr2\": \"${PCR2}\", \"deployed_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > /home/ec2-user/enclave-pcrs.json
echo "PCRs saved to /home/ec2-user/enclave-pcrs.json"
