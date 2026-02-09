"""
KeyPair Manager Interface
Abstract interface for managing RSA key pairs in the enclave
"""
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional


class IKeyPairManager(ABC):
    """
    Abstract interface for RSA key pair management
    Handles creation, storage, and retrieval of public/private key pairs per job
    """

    @abstractmethod
    def generate_keypair(
        self,
        job_id: str,
        key_size: int = 2048
    ) -> Tuple[bool, str]:
        """
        Generate a new RSA key pair for a job

        Args:
            job_id: Unique job identifier
            key_size: RSA key size in bits (default: 2048)

        Returns:
            Tuple of (success, session_id or error_message)
        """
        pass

    @abstractmethod
    def get_public_key(
        self,
        session_id: str,
        format: str = "PEM"
    ) -> Optional[str]:
        """
        Get the public key for a session

        Args:
            session_id: Session identifier
            format: Key format (PEM, DER, base64)

        Returns:
            Base64 encoded public key if found, None otherwise
        """
        pass

    @abstractmethod
    def get_private_key(
        self,
        session_id: str
    ) -> Optional[bytes]:
        """
        Get the private key for a session (internal use only)

        Args:
            session_id: Session identifier

        Returns:
            Private key bytes if found, None otherwise
        """
        pass

    @abstractmethod
    def delete_keypair(
        self,
        session_id: str
    ) -> bool:
        """
        Securely delete a key pair

        Args:
            session_id: Session identifier

        Returns:
            True if deletion was successful
        """
        pass

