"""
Clean Enclave Configuration
Configuration settings for the clean enclave application
"""
import os

# VSock configuration (must match coordinator's settings)
VSOCK_PORT = int(os.getenv('VSOCK_PORT', '5005'))

# Request limits
MAX_REQUEST_SIZE = int(os.getenv('MAX_REQUEST_SIZE', '10485760'))  # 10MB

# Logging configuration
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FORMAT = os.getenv('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# KMS configuration
KMS_REGION = os.getenv('KMS_REGION', 'ap-southeast-2')
KMS_PROXY_PORT = int(os.getenv('KMS_PROXY_PORT', '8000'))
KMSTOOL_PATH = os.getenv('KMSTOOL_PATH', '/app/kmstool_enclave_cli')

# Execution limits
EXECUTION_TIMEOUT = int(os.getenv('EXECUTION_TIMEOUT', '300'))  # 5 minutes
MAX_MEMORY_MB = int(os.getenv('MAX_MEMORY_MB', '512'))
MAX_OUTPUT_SIZE_MB = int(os.getenv('MAX_OUTPUT_SIZE_MB', '50'))

# Session management
SESSION_TTL = int(os.getenv('SESSION_TTL', '3600'))  # 1 hour
CLEANUP_INTERVAL = int(os.getenv('CLEANUP_INTERVAL', '300'))  # 5 minutes

# Server socket timeouts
CLIENT_RECV_TIMEOUT = int(os.getenv('CLIENT_RECV_TIMEOUT', '300'))  # seconds
CLIENT_SEND_TIMEOUT = int(os.getenv('CLIENT_SEND_TIMEOUT', '60'))  # seconds

# ZIP extraction safety limits
MAX_ZIP_ENTRIES = int(os.getenv('MAX_ZIP_ENTRIES', '500'))
MAX_ZIP_TOTAL_SIZE = int(os.getenv('MAX_ZIP_TOTAL_SIZE', str(200 * 1024 * 1024)))  # 200 MB

# Security settings
DEFAULT_KEY_SIZE = int(os.getenv('DEFAULT_KEY_SIZE', '2048'))
ALLOWED_KEY_SIZES = [2048, 3072, 4096]

# Feature flags
ALLOW_LOCAL_ATTESTATION = os.getenv('ALLOW_LOCAL_ATTESTATION', 'false').lower() == 'true'
ENABLE_KMS_ATTESTATION = os.getenv('ENABLE_KMS_ATTESTATION', 'true').lower() == 'true'
ENABLE_SCRIPT_VALIDATION = os.getenv('ENABLE_SCRIPT_VALIDATION', 'true').lower() == 'true'
ENABLE_RESOURCE_MONITORING = os.getenv('ENABLE_RESOURCE_MONITORING', 'false').lower() == 'true'