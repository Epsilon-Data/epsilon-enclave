"""
Decrypt Service Interface
Abstract interface for handling decryption operations in the enclave
"""
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional


class IDecryptService(ABC):
    """
    Abstract interface for decryption services
    Handles RSA hybrid decryption and data processing
    """

    @abstractmethod
    def decrypt_combined_hybrid_data(
        self,
        combined_encrypted_data: str,
        session_id: str
    ) -> Tuple[bool, bytes]:
        """
        Decrypt data using RSA hybrid encryption (RSA-OAEP + AES-256-CBC)
        with combined format used by the coordinator.

        Format: Base64([encrypted_key (RSA_size/8 bytes)][iv (16 bytes)][ciphertext])

        Args:
            combined_encrypted_data: Base64 encoded combined encrypted data
            session_id: Session ID containing the RSA private key

        Returns:
            Tuple of (success, decrypted_data or error_message)
        """
        pass

    @abstractmethod
    def decrypt_hybrid_data(
        self,
        encrypted_data: str,
        encrypted_key: str,
        session_id: str
    ) -> Tuple[bool, bytes]:
        """
        Decrypt data using RSA hybrid encryption (RSA + AES) - LEGACY

        Args:
            encrypted_data: Base64 encoded AES encrypted data
            encrypted_key: Base64 encoded RSA encrypted AES key
            session_id: Session ID containing the RSA private key

        Returns:
            Tuple of (success, decrypted_data or error_message)
        """
        pass

    @abstractmethod
    def decrypt_rsa_data(
        self,
        encrypted_data: str,
        session_id: str
    ) -> Tuple[bool, bytes]:
        """
        Decrypt data using pure RSA encryption

        Args:
            encrypted_data: Base64 encoded RSA encrypted data
            session_id: Session ID containing the RSA private key

        Returns:
            Tuple of (success, decrypted_data or error_message)
        """
        pass

    @abstractmethod
    def decrypt_csv_file(
        self,
        file_path: str,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Decrypt a CSV file using session-based decryption

        Args:
            file_path: Path to the encrypted CSV file
            session_id: Session ID for decryption keys
            metadata: Optional metadata for decryption process

        Returns:
            Tuple of (success, output_file_path or error_message)
        """
        pass

    @abstractmethod
    def decrypt_bundle(
        self,
        bundle_data: bytes,
        session_id: str
    ) -> Tuple[bool, bytes]:
        """
        Decrypt a data bundle (zip or other archive format)

        Args:
            bundle_data: Encrypted bundle data
            session_id: Session ID for decryption

        Returns:
            Tuple of (success, decrypted_bundle or error_message)
        """
        pass

    @abstractmethod
    def validate_encryption_metadata(
        self,
        metadata: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Validate encryption metadata format and content

        Args:
            metadata: Encryption metadata dictionary

        Returns:
            Tuple of (is_valid, error_message or success_message)
        """
        pass

    @abstractmethod
    def get_supported_algorithms(self) -> Dict[str, Any]:
        """
        Get list of supported encryption algorithms

        Returns:
            Dictionary containing supported algorithms and their parameters
        """
        pass

    @abstractmethod
    def verify_data_integrity(
        self,
        data: bytes,
        expected_hash: Optional[str] = None
    ) -> bool:
        """
        Verify the integrity of decrypted data

        Args:
            data: Decrypted data to verify
            expected_hash: Optional expected hash for verification

        Returns:
            True if data integrity is verified
        """
        pass

    @abstractmethod
    def get_decryption_stats(self) -> Dict[str, Any]:
        """
        Get statistics about decryption operations

        Returns:
            Dictionary containing decryption statistics
        """
        pass