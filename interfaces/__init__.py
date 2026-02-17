"""
Clean interfaces for enclave operations
Provides abstract base classes for request handling, decryption, execution, and key management
"""
from interfaces.request_handler_interface import IRequestHandler
from interfaces.decrypt_interface import IDecryptService
from interfaces.execute_interface import IExecuteService
from interfaces.keypair_interface import IKeyPairManager
from interfaces.attestation_interface import IAttestationService
from interfaces.kms_attestation_interface import IKMSAttestationService

__all__ = [
    'IRequestHandler',
    'IDecryptService',
    'IExecuteService',
    'IKeyPairManager',
    'IAttestationService',
    'IKMSAttestationService',
]
