#!/bin/bash

# Clean Enclave VSock Server Startup Script

set -e

echo "🚀 Starting Clean Enclave VSock Server..."

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:/app"
export LD_LIBRARY_PATH="/app:${LD_LIBRARY_PATH}"

# Create logs directory
mkdir -p /app/logs

# VSock configuration (must match coordinator's settings)
export VSOCK_PORT="${VSOCK_PORT:-5005}"
export KMS_REGION="${KMS_REGION:-ap-southeast-2}"
export KMS_PROXY_PORT="${KMS_PROXY_PORT:-8000}"
export LOG_LEVEL="${LOG_LEVEL:-INFO}"

echo "🔧 Configuration:"
echo "  VSock Port: $VSOCK_PORT"
echo "  KMS Region: $KMS_REGION"
echo "  KMS Proxy Port: $KMS_PROXY_PORT"
echo "  Log Level: $LOG_LEVEL"

# Check if KMS tools exist
if [ -f "/app/kmstool_enclave_cli" ]; then
    echo "✅ KMS tool found: /app/kmstool_enclave_cli"
else
    echo "⚠️  KMS tool not found - attestation will be disabled"
    export ENABLE_KMS_ATTESTATION=false
fi

if [ -f "/app/libnsm.so" ]; then
    echo "✅ NSM library found: /app/libnsm.so"
else
    echo "⚠️  NSM library not found"
fi

echo "🔒 Starting Clean Enclave with VSock communication..."
python3 /app/main.py