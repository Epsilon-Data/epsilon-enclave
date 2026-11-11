"""
Attestation Service Interface
Abstract interface for generating cryptographic attestation documents
"""
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional


def execution_fields(
    outcome: Optional[str],
    exit_code: Optional[int],
    error_hash: Optional[str],
    platform_job_id: Optional[str],
    attempt_id: Optional[str],
) -> Dict[str, Any]:
    """The outcome and job/attempt fields that were supplied, for the signed proof."""
    fields = {
        'outcome': outcome,
        'exit_code': exit_code,
        'error_hash': error_hash,
        'platform_job_id': platform_job_id,
        'attempt_id': attempt_id,
    }
    return {name: value for name, value in fields.items() if value is not None}


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
        files_manifest_sha256: Optional[str] = None,
        outcome: Optional[str] = None,
        exit_code: Optional[int] = None,
        error_hash: Optional[str] = None,
        platform_job_id: Optional[str] = None,
        attempt_id: Optional[str] = None,
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
            files_manifest_sha256: SHA-256 of the canonical output-files manifest
            outcome: What happened to the script (see execute_interface.OUTCOME_*)
            exit_code: Exit code of the script, when it ran to an exit
            error_hash: SHA-256 of the error text returned for a run that did not succeed
            platform_job_id: The platform's job identifier, as supplied by the coordinator
            attempt_id: The platform's identifier for this execution attempt

        Returns:
            Tuple of (success, attestation_result or error_dict)
        """
        pass

    @property
    @abstractmethod
    def is_real_enclave(self) -> bool:
        """Check if running in a real Nitro Enclave."""
        pass
