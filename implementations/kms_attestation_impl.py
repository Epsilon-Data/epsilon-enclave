"""
KMS Attestation Implementation
AWS Nitro Enclave KMS attestation for secure key access
"""
import base64
import json
import logging
import os
import subprocess
from typing import Tuple, Dict, Any, Optional

from interfaces.kms_attestation_interface import IKMSAttestationService
from config import KMSTOOL_PATH, KMS_PROXY_PORT, KMS_REGION

logger = logging.getLogger(__name__)


class KMSAttestationService(IKMSAttestationService):
    """
    AWS Nitro Enclave KMS Attestation Service

    This service uses the kmstool_enclave_cli to:
    1. Generate attestation documents
    2. Decrypt data keys using KMS with attestation
    3. Encrypt data keys using KMS with attestation

    The kmstool connects to a vsock-proxy running on the parent instance,
    which forwards requests to AWS KMS with the attestation document.
    """

    def __init__(self, kms_key_id: Optional[str] = None):
        """
        Initialize KMS attestation service

        Args:
            kms_key_id: AWS KMS key ID or ARN for encryption/decryption
        """
        self.kms_key_id = kms_key_id or os.getenv('AWS_KMS_KEY_ARN', '')
        self.kms_region = KMS_REGION
        self.proxy_port = KMS_PROXY_PORT
        self.kmstool_path = KMSTOOL_PATH
        self._enabled = self._check_availability()

        logger.info(f"[KMS-ATTESTATION] Initialized:")
        logger.info(f"[KMS-ATTESTATION]   Key ID: {self.kms_key_id[:20]}..." if self.kms_key_id else "[KMS-ATTESTATION]   Key ID: (not set)")
        logger.info(f"[KMS-ATTESTATION]   Region: {self.kms_region}")
        logger.info(f"[KMS-ATTESTATION]   Proxy Port: {self.proxy_port}")
        logger.info(f"[KMS-ATTESTATION]   Enabled: {self._enabled}")

    def _check_availability(self) -> bool:
        """Check if KMS attestation is available"""
        if not os.path.exists(self.kmstool_path):
            logger.warning(f"[KMS-ATTESTATION] kmstool not found at {self.kmstool_path}")
            return False

        if not self.kms_key_id:
            logger.warning("[KMS-ATTESTATION] No KMS key ID configured")
            return False

        return True

    @property
    def is_enabled(self) -> bool:
        """Check if KMS attestation is enabled and available"""
        return self._enabled

    def decrypt_data_key(
        self,
        encrypted_data_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, bytes]:
        """
        Decrypt a data key using KMS with Nitro attestation

        Args:
            encrypted_data_key: Base64 encoded encrypted data key
            encryption_context: Optional encryption context for additional auth

        Returns:
            Tuple of (success, decrypted_key or error_message)
        """
        if not self._enabled:
            return False, b"KMS attestation not enabled"

        try:
            logger.info("[KMS-ATTESTATION] Decrypting data key with attestation")

            cmd = [
                self.kmstool_path,
                'decrypt',
                '--region', self.kms_region,
                '--proxy-port', str(self.proxy_port),
                '--ciphertext', base64.b64encode(encrypted_data_key).decode()
            ]

            if encryption_context:
                for key, value in encryption_context.items():
                    cmd.extend(['--encryption-context', f'{key}={value}'])

            logger.debug(f"[KMS-ATTESTATION] Running: {cmd[0]} decrypt ...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30
            )

            if result.returncode != 0:
                error_msg = result.stderr.decode() if result.stderr else "Unknown error"
                logger.error(f"[KMS-ATTESTATION] Decrypt failed: {error_msg}")
                return False, error_msg.encode()

            plaintext_b64 = result.stdout.decode().strip()
            plaintext = base64.b64decode(plaintext_b64)

            logger.info(f"[KMS-ATTESTATION] Successfully decrypted data key ({len(plaintext)} bytes)")
            return True, plaintext

        except subprocess.TimeoutExpired:
            logger.error("[KMS-ATTESTATION] Decrypt timed out")
            return False, b"KMS decrypt timeout"
        except Exception as e:
            logger.error(f"[KMS-ATTESTATION] Decrypt error: {str(e)}")
            return False, str(e).encode()

    def encrypt_data_key(
        self,
        plaintext_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, bytes]:
        """
        Encrypt a data key using KMS with Nitro attestation

        Args:
            plaintext_key: Plain data key to encrypt
            encryption_context: Optional encryption context for additional auth

        Returns:
            Tuple of (success, encrypted_key or error_message)
        """
        if not self._enabled:
            return False, b"KMS attestation not enabled"

        try:
            logger.info("[KMS-ATTESTATION] Encrypting data key with attestation")

            cmd = [
                self.kmstool_path,
                'encrypt',
                '--region', self.kms_region,
                '--proxy-port', str(self.proxy_port),
                '--key-id', self.kms_key_id,
                '--plaintext', base64.b64encode(plaintext_key).decode()
            ]

            if encryption_context:
                for key, value in encryption_context.items():
                    cmd.extend(['--encryption-context', f'{key}={value}'])

            logger.debug(f"[KMS-ATTESTATION] Running: {cmd[0]} encrypt ...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30
            )

            if result.returncode != 0:
                error_msg = result.stderr.decode() if result.stderr else "Unknown error"
                logger.error(f"[KMS-ATTESTATION] Encrypt failed: {error_msg}")
                return False, error_msg.encode()

            ciphertext_b64 = result.stdout.decode().strip()
            ciphertext = base64.b64decode(ciphertext_b64)

            logger.info(f"[KMS-ATTESTATION] Successfully encrypted data key ({len(ciphertext)} bytes)")
            return True, ciphertext

        except subprocess.TimeoutExpired:
            logger.error("[KMS-ATTESTATION] Encrypt timed out")
            return False, b"KMS encrypt timeout"
        except Exception as e:
            logger.error(f"[KMS-ATTESTATION] Encrypt error: {str(e)}")
            return False, str(e).encode()

    def generate_data_key(
        self,
        key_spec: str = "AES_256",
        encryption_context: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, Dict[str, bytes]]:
        """
        Generate a new data key using KMS with Nitro attestation

        Args:
            key_spec: Key specification (AES_256 or AES_128)
            encryption_context: Optional encryption context

        Returns:
            Tuple of (success, {"plaintext": bytes, "ciphertext": bytes} or error_dict)
        """
        if not self._enabled:
            return False, {"error": b"KMS attestation not enabled"}

        try:
            logger.info(f"[KMS-ATTESTATION] Generating {key_spec} data key with attestation")

            cmd = [
                self.kmstool_path,
                'genkey',
                '--region', self.kms_region,
                '--proxy-port', str(self.proxy_port),
                '--key-id', self.kms_key_id,
                '--key-spec', key_spec
            ]

            if encryption_context:
                for key, value in encryption_context.items():
                    cmd.extend(['--encryption-context', f'{key}={value}'])

            logger.debug(f"[KMS-ATTESTATION] Running: {cmd[0]} genkey ...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30
            )

            if result.returncode != 0:
                error_msg = result.stderr.decode() if result.stderr else "Unknown error"
                logger.error(f"[KMS-ATTESTATION] Generate key failed: {error_msg}")
                return False, {"error": error_msg.encode()}

            output = json.loads(result.stdout.decode())

            plaintext = base64.b64decode(output['Plaintext'])
            ciphertext = base64.b64decode(output['CiphertextBlob'])

            logger.info(f"[KMS-ATTESTATION] Successfully generated data key")
            return True, {
                "plaintext": plaintext,
                "ciphertext": ciphertext
            }

        except subprocess.TimeoutExpired:
            logger.error("[KMS-ATTESTATION] Generate key timed out")
            return False, {"error": b"KMS generate key timeout"}
        except json.JSONDecodeError as e:
            logger.error(f"[KMS-ATTESTATION] Failed to parse kmstool output: {e}")
            return False, {"error": str(e).encode()}
        except Exception as e:
            logger.error(f"[KMS-ATTESTATION] Generate key error: {str(e)}")
            return False, {"error": str(e).encode()}

    def get_attestation_document(self) -> Tuple[bool, bytes]:
        """
        Get a Nitro attestation document

        Returns:
            Tuple of (success, attestation_document or error_message)
        """
        if not self._enabled:
            return False, b"KMS attestation not enabled"

        try:
            logger.info("[KMS-ATTESTATION] Generating attestation document")

            cmd = [
                self.kmstool_path,
                'attestation-document'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30
            )

            if result.returncode != 0:
                error_msg = result.stderr.decode() if result.stderr else "Unknown error"
                logger.error(f"[KMS-ATTESTATION] Attestation document failed: {error_msg}")
                return False, error_msg.encode()

            attestation_doc = result.stdout

            logger.info(f"[KMS-ATTESTATION] Generated attestation document ({len(attestation_doc)} bytes)")
            return True, attestation_doc

        except subprocess.TimeoutExpired:
            logger.error("[KMS-ATTESTATION] Attestation document timed out")
            return False, b"Attestation timeout"
        except Exception as e:
            logger.error(f"[KMS-ATTESTATION] Attestation error: {str(e)}")
            return False, str(e).encode()

    def get_status(self) -> Dict[str, Any]:
        """
        Get KMS attestation service status

        Returns:
            Dictionary with status information
        """
        return {
            "enabled": self._enabled,
            "kms_key_id": self.kms_key_id[:20] + "..." if self.kms_key_id else None,
            "region": self.kms_region,
            "proxy_port": self.proxy_port,
            "kmstool_path": self.kmstool_path,
            "kmstool_exists": os.path.exists(self.kmstool_path)
        }
