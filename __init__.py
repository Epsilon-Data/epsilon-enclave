"""
Epsilon Enclave - Secure Execution Environment

A standalone enclave service providing:
- RSA keypair generation and management
- Hybrid encryption/decryption (AES-256 + RSA)
- Secure script execution in isolated environment
- KMS attestation for AWS Nitro Enclaves
"""
from .interfaces import (
    IRequestHandler,
    IDecryptService,
    IExecuteService,
    IKeyPairManager
)
from .implementations import (
    RequestHandlerImpl,
    DecryptServiceImpl,
    ExecuteServiceImpl,
    KeyPairManagerImpl
)
from .factory import EnclaveServiceFactory

__version__ = '1.0.0'

__all__ = [
    # Interfaces
    'IRequestHandler',
    'IDecryptService',
    'IExecuteService',
    'IKeyPairManager',
    # Implementations
    'RequestHandlerImpl',
    'DecryptServiceImpl',
    'ExecuteServiceImpl',
    'KeyPairManagerImpl',
    # Factory
    'EnclaveServiceFactory',
]
