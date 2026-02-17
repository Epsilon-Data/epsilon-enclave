"""
KMS Attestation Service Interface
Abstract interface for AWS KMS operations with Nitro attestation
"""
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional


class IKMSAttestationService(ABC):
    """
    Abstract interface for KMS attestation operations.
    Uses kmstool_enclave_cli for KMS operations with Nitro attestation.
    """

    @property
    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if KMS attestation is enabled and available."""
        pass

    @abstractmethod
    def decrypt_data_key(
        self,
        encrypted_data_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, bytes]:
        """
        Decrypt a data key using KMS with Nitro attestation.

        Args:
            encrypted_data_key: Encrypted data key bytes
            encryption_context: Optional encryption context for additional auth

        Returns:
            Tuple of (success, decrypted_key or error_message)
        """
        pass

    @abstractmethod
    def encrypt_data_key(
        self,
        plaintext_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, bytes]:
        """
        Encrypt a data key using KMS with Nitro attestation.

        Args:
            plaintext_key: Plain data key to encrypt
            encryption_context: Optional encryption context for additional auth

        Returns:
            Tuple of (success, encrypted_key or error_message)
        """
        pass

    @abstractmethod
    def generate_data_key(
        self,
        key_spec: str = "AES_256",
        encryption_context: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, Dict[str, bytes]]:
        """
        Generate a new data key using KMS with Nitro attestation.

        Args:
            key_spec: Key specification (AES_256 or AES_128)
            encryption_context: Optional encryption context

        Returns:
            Tuple of (success, key_dict or error_dict)
        """
        pass

    @abstractmethod
    def get_attestation_document(self) -> Tuple[bool, bytes]:
        """
        Get a Nitro attestation document.

        Returns:
            Tuple of (success, attestation_document or error_message)
        """
        pass

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """
        Get KMS attestation service status.

        Returns:
            Dictionary with status information
        """
        pass
