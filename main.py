#!/usr/bin/env python3
"""
Main entry point for the Epsilon Enclave server application.

This is a standalone enclave service that handles:
- RSA keypair generation and management
- Hybrid encryption/decryption (AES-256-CBC + RSA-OAEP)
- Secure script execution in isolated environment
- KMS attestation for AWS Nitro Enclaves
"""
import logging
import os
import sys

from server.server import EnclaveServer
from config import LOG_LEVEL, LOG_FORMAT, ENABLE_KMS_ATTESTATION
from implementations.kms_attestation_impl import KMSAttestationService

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


def create_kms_attestation():
    """Create KMS attestation service if enabled and available"""
    if not ENABLE_KMS_ATTESTATION:
        logger.info("[KMS] KMS attestation disabled via configuration")
        return None

    kms_key_arn = os.getenv('AWS_KMS_KEY_ARN')
    if not kms_key_arn:
        logger.warning("[KMS] AWS_KMS_KEY_ARN not set, KMS attestation disabled")
        return None

    kms_service = KMSAttestationService(kms_key_id=kms_key_arn)

    if kms_service.is_enabled:
        logger.info("[KMS] KMS attestation service initialized successfully")
        return kms_service
    else:
        logger.warning("[KMS] KMS attestation service not available")
        return None


def main():
    """Main entry point"""
    logger.info("[START] Starting Epsilon Executor Nitro Enclave")
    logger.info("=" * 60)
    logger.info("[ARCHITECTURE] Using clean interfaces:")
    logger.info("  - IRequestHandler (request routing)")
    logger.info("  - IDecryptService (RSA-OAEP + AES-256-CBC decryption)")
    logger.info("  - IExecuteService (secure script execution)")
    logger.info("  - IKeyPairManager (RSA key management)")
    logger.info("=" * 60)

    # Initialize KMS attestation if available
    kms_attestation = create_kms_attestation()

    # Start server with optional KMS attestation
    server = EnclaveServer(kms_attestation=kms_attestation)
    server.start()


if __name__ == "__main__":
    main()