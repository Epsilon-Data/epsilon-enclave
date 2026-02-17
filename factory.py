"""
Factory for creating and wiring enclave service implementations
"""
import logging

from interfaces import (
    IRequestHandler,
    IDecryptService,
    IExecuteService,
    IKeyPairManager,
    IAttestationService,
    IKMSAttestationService,
)
from implementations import (
    RequestHandlerImpl,
    DecryptServiceImpl,
    ExecuteServiceImpl,
    KeyPairManagerImpl,
    AttestationService,
)

logger = logging.getLogger(__name__)


class EnclaveServiceFactory:
    """
    Factory for creating and wiring enclave services with clean dependency injection
    """

    @staticmethod
    def create_enclave_services(kms_attestation: IKMSAttestationService = None) -> IRequestHandler:
        """
        Create a fully wired enclave service stack

        Args:
            kms_attestation: Optional KMS attestation service

        Returns:
            Configured request handler with all dependencies
        """
        logger.info("[FACTORY] Creating enclave service stack...")

        # Create core services
        keypair_manager = KeyPairManagerImpl()
        decrypt_service = DecryptServiceImpl(keypair_manager)
        execute_service = ExecuteServiceImpl(decrypt_service)
        attestation_service = AttestationService()

        # Create request handler with all dependencies
        request_handler = RequestHandlerImpl(
            decrypt_service=decrypt_service,
            execute_service=execute_service,
            keypair_manager=keypair_manager,
            attestation_service=attestation_service,
            kms_attestation=kms_attestation,
        )

        logger.info("[FACTORY] Enclave service stack created successfully")
        logger.info("[FACTORY] Services: RequestHandler, DecryptService, ExecuteService, KeyPairManager, AttestationService")

        return request_handler

    @staticmethod
    def create_keypair_manager() -> IKeyPairManager:
        """Create standalone keypair manager"""
        return KeyPairManagerImpl()

    @staticmethod
    def create_decrypt_service(keypair_manager: IKeyPairManager) -> IDecryptService:
        """Create decrypt service with keypair manager dependency"""
        return DecryptServiceImpl(keypair_manager)

    @staticmethod
    def create_execute_service(decrypt_service: IDecryptService) -> IExecuteService:
        """Create execute service with decrypt service dependency"""
        return ExecuteServiceImpl(decrypt_service)

    @staticmethod
    def create_attestation_service() -> IAttestationService:
        """Create attestation service"""
        return AttestationService()

    @staticmethod
    def create_request_handler(
        decrypt_service: IDecryptService,
        execute_service: IExecuteService,
        keypair_manager: IKeyPairManager,
        attestation_service: IAttestationService,
        kms_attestation: IKMSAttestationService = None,
    ) -> IRequestHandler:
        """
        Create request handler with all dependencies

        Args:
            decrypt_service: Decrypt service instance
            execute_service: Execute service instance
            keypair_manager: Keypair manager instance
            attestation_service: Attestation service instance
            kms_attestation: Optional KMS attestation service

        Returns:
            Configured request handler
        """
        return RequestHandlerImpl(
            decrypt_service=decrypt_service,
            execute_service=execute_service,
            keypair_manager=keypair_manager,
            attestation_service=attestation_service,
            kms_attestation=kms_attestation,
        )
