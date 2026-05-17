"""
Attestation Service Interface
Abstract interface for generating cryptographic attestation documents
"""
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional


class IAttestationService(ABC):
    """
    Abstract interface for attestation document generation.
    Provides cryptographic proof that code ran inside a Nitro Enclave.
    """

    @abstractmethod
    def generate_attestation(
        self,
        user_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        public_key: Optional[bytes] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Generate an attestation document from the Nitro Secure Module.

        Args:
            user_data: Custom data to include (e.g., hash of output) - max 1024 bytes
            nonce: Random value to prevent replay attacks - max 1024 bytes
            public_key: Public key for encrypted response - max 1024 bytes

        Returns:
            Tuple of (success, attestation_data or error_dict)
        """
        pass

    @abstractmethod
    def create_execution_attestation(
        self,
        job_id: str,
        output: str,
        script_bytes: Optional[bytes] = None,
        dataset_bytes: Optional[bytes] = None,
        external_nonce: Optional[bytes] = None,
        context_hash: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Create an attestation for a specific execution.

        Args:
            job_id: Job or session identifier
            output: Execution output to attest
            script_bytes: Raw code bundle bytes (for script_hash)
            dataset_bytes: Raw dataset bytes (for dataset_hash)
            external_nonce: Researcher-supplied nonce = H(STH_current)
            context_hash: H(job_id || commit_sha || archetype_id || dataset_id)

        Returns:
            Tuple of (success, attestation_result or error_dict)
        """
        pass

    @property
    @abstractmethod
    def is_real_enclave(self) -> bool:
        """Check if running in a real Nitro Enclave."""
        pass
