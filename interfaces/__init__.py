"""
Clean interfaces for enclave operations
Provides abstract base classes for request handling, decryption, execution, and key management
"""
try:
    from .request_handler_interface import IRequestHandler
    from .decrypt_interface import IDecryptService
    from .execute_interface import IExecuteService
    from .keypair_interface import IKeyPairManager
except ImportError:
    from request_handler_interface import IRequestHandler
    from decrypt_interface import IDecryptService
    from execute_interface import IExecuteService
    from keypair_interface import IKeyPairManager

__all__ = [
    'IRequestHandler',
    'IDecryptService',
    'IExecuteService',
    'IKeyPairManager'
]