"""
Decrypt Service Implementation
Concrete implementation of IDecryptService interface for RSA hybrid decryption

Encryption Format (matching coordinator):
- Combined base64 data: [encrypted_key (256 bytes)] + [iv (16 bytes)] + [ciphertext]
- RSA-OAEP with SHA-256 for key encryption
- AES-256-CBC with PKCS7 padding for data encryption
"""
import base64
import logging
import time
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from interfaces import IDecryptService
except ImportError:
    from ..interfaces import IDecryptService

logger = logging.getLogger(__name__)

# Encryption constants (must match coordinator)
AES_KEY_SIZE = 32  # 256 bits
IV_SIZE = 16  # 128 bits for AES-CBC
AES_BLOCK_SIZE = 128  # bits


class DecryptServiceImpl(IDecryptService):
    """
    Concrete implementation of decryption service using pure RSA hybrid encryption
    """

    def __init__(self, keypair_manager):
        """
        Initialize decrypt service with keypair manager

        Args:
            keypair_manager: IKeyPairManager instance for accessing private keys
        """
        self.keypair_manager = keypair_manager
        self._supported_algorithms = {
            'rsa_hybrid': {
                'description': 'RSA + AES hybrid encryption',
                'rsa_key_sizes': [2048, 3072, 4096],
                'aes_key_size': 256,
                'padding': 'OAEP'
            },
            'pure_rsa': {
                'description': 'Pure RSA encryption',
                'key_sizes': [2048, 3072, 4096],
                'padding': 'OAEP'
            }
        }

    def decrypt_combined_hybrid_data(
        self,
        combined_encrypted_data: str,
        session_id: str
    ) -> Tuple[bool, bytes]:
        """
        Decrypt data using RSA hybrid encryption (RSA-OAEP + AES-256-CBC).

        This matches the coordinator's encryption format:
        - Base64 encoded combined data
        - Format: [encrypted_key (RSA key_size/8 bytes)] + [iv (16 bytes)] + [ciphertext]
        - RSA-OAEP with SHA-256 for key encryption
        - AES-256-CBC with PKCS7 padding for data encryption
        """
        try:
            logger.info(f"[DECRYPT] Starting combined RSA hybrid decryption for session {session_id}")

            # Get private key from keypair manager
            private_key_bytes = self.keypair_manager.get_private_key(session_id)
            if not private_key_bytes:
                error_msg = f"Private key not found for session {session_id}"
                logger.error(f"[DECRYPT] {error_msg}")
                return False, error_msg.encode()

            # Deserialize private key
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None
            )

            # Decode the combined base64 data
            combined = base64.b64decode(combined_encrypted_data)

            # Parse the combined format: [encrypted_key][iv][ciphertext]
            rsa_key_bytes = private_key.key_size // 8  # 256 bytes for RSA-2048
            encrypted_key = combined[:rsa_key_bytes]
            iv = combined[rsa_key_bytes:rsa_key_bytes + IV_SIZE]
            ciphertext = combined[rsa_key_bytes + IV_SIZE:]

            logger.info(f"[DECRYPT] Parsed combined data: key={len(encrypted_key)}B, iv={len(iv)}B, ciphertext={len(ciphertext)}B")
            logger.info(f"[DECRYPT] Step 1: Decrypting AES key with RSA-{private_key.key_size} private key")

            # Step 1: Decrypt AES key with RSA-OAEP
            t0 = time.time()
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            rsa_ms = round((time.time() - t0) * 1000, 2)

            logger.info(f"[DECRYPT] Decrypted AES-256 key ({len(aes_key)} bytes) in {rsa_ms}ms")

            # Step 2: Decrypt data with AES-256-CBC
            logger.info(f"[DECRYPT] Step 2: Decrypting data with AES-256-CBC")
            t0 = time.time()
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # Step 3: Remove PKCS7 padding
            unpadder = sym_padding.PKCS7(AES_BLOCK_SIZE).unpadder()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
            aes_ms = round((time.time() - t0) * 1000, 2)

            logger.info(f"[DECRYPT] Decrypted data ({len(ciphertext)} -> {len(decrypted_data)} bytes) in {aes_ms}ms")
            logger.info(f"[TIMING] rsa_oaep={rsa_ms}ms aes_cbc={aes_ms}ms total={round(rsa_ms + aes_ms, 2)}ms")

            return True, decrypted_data

        except Exception as e:
            logger.error(f"[DECRYPT] RSA hybrid decryption failed: {str(e)}")
            import traceback
            logger.error(f"[DECRYPT] Traceback: {traceback.format_exc()}")
            return False, str(e).encode()

    def decrypt_hybrid_data(
        self,
        encrypted_data: str,
        encrypted_key: str,
        session_id: str
    ) -> Tuple[bool, bytes]:
        """
        Decrypt data using RSA hybrid encryption (RSA + AES) - LEGACY METHOD

        Note: This method expects separate encrypted_data and encrypted_key parameters.
        For the combined format used by the coordinator, use decrypt_combined_hybrid_data().
        """
        try:
            logger.info(f"[DECRYPT] Starting RSA hybrid decryption for session {session_id}")

            # Get private key from keypair manager
            private_key_bytes = self.keypair_manager.get_private_key(session_id)
            if not private_key_bytes:
                error_msg = f"Private key not found for session {session_id}"
                logger.error(f"[DECRYPT] {error_msg}")
                return False, error_msg.encode()

            # Deserialize private key
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None
            )

            logger.info(f"[DECRYPT] Step 1: Decrypting AES key with RSA-{private_key.key_size} private key")

            # Step 1: Decrypt AES key with RSA private key
            encrypted_aes_key = base64.b64decode(encrypted_key)
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            logger.info(f"[DECRYPT] Successfully decrypted AES-256 key ({len(aes_key)} bytes)")

            # Step 2: Decrypt data with AES-256-CBC (updated to match coordinator)
            logger.info(f"[DECRYPT] Step 2: Decrypting data with AES-256-CBC")
            encrypted_data_bytes = base64.b64decode(encrypted_data)

            # Extract IV from the beginning of encrypted data
            iv = encrypted_data_bytes[:IV_SIZE]
            ciphertext = encrypted_data_bytes[IV_SIZE:]

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove PKCS7 padding
            unpadder = sym_padding.PKCS7(AES_BLOCK_SIZE).unpadder()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

            logger.info(f"[DECRYPT] Successfully decrypted data ({len(encrypted_data_bytes)} -> {len(decrypted_data)} bytes)")
            logger.info(f"[DECRYPT] RSA hybrid decryption completed successfully")

            return True, decrypted_data

        except Exception as e:
            logger.error(f"[DECRYPT] RSA hybrid decryption failed: {str(e)}")
            return False, str(e).encode()

    def decrypt_rsa_data(
        self,
        encrypted_data: str,
        session_id: str
    ) -> Tuple[bool, bytes]:
        """
        Decrypt data using pure RSA encryption
        """
        try:
            logger.info(f"[DECRYPT-RSA] Starting pure RSA decryption for session {session_id}")

            # Get private key from keypair manager
            private_key_bytes = self.keypair_manager.get_private_key(session_id)
            if not private_key_bytes:
                error_msg = f"Private key not found for session {session_id}"
                logger.error(f"[DECRYPT-RSA] {error_msg}")
                return False, error_msg.encode()

            # Deserialize private key
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None
            )

            # Decrypt data with RSA private key
            encrypted_data_bytes = base64.b64decode(encrypted_data)
            decrypted_data = private_key.decrypt(
                encrypted_data_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            logger.info(f"[DECRYPT-RSA] Successfully decrypted data ({len(encrypted_data_bytes)} -> {len(decrypted_data)} bytes)")

            return True, decrypted_data

        except Exception as e:
            logger.error(f"[DECRYPT-RSA] Pure RSA decryption failed: {str(e)}")
            return False, str(e).encode()

    def decrypt_csv_file(
        self,
        file_path: str,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Decrypt a CSV file using session-based decryption
        """
        try:
            logger.info(f"[DECRYPT-CSV] Starting CSV file decryption: {file_path}")

            # Read encrypted CSV file
            with open(file_path, 'rb') as f:
                file_content = f.read()

            # Extract encrypted key and data from file structure
            # Assuming format: [encrypted_key_length(4 bytes)][encrypted_key][encrypted_data]
            key_length = int.from_bytes(file_content[:4], 'big')
            encrypted_aes_key = file_content[4:4+key_length]
            encrypted_content = file_content[4+key_length:]

            logger.info(f"[DECRYPT-CSV] Extracted encrypted key ({key_length} bytes) and data ({len(encrypted_content)} bytes)")

            # Decrypt using CSV-specific method
            success, decrypted_content = self.decrypt_csv_data(
                encrypted_aes_key, encrypted_content, session_id
            )

            if not success:
                return False, decrypted_content.decode() if isinstance(decrypted_content, bytes) else decrypted_content

            # Write decrypted content to temporary file
            import tempfile
            import os

            temp_dir = tempfile.mkdtemp()
            output_file = os.path.join(temp_dir, f"decrypted_{os.path.basename(file_path)}")

            with open(output_file, 'wb') as f:
                f.write(decrypted_content)

            logger.info(f"[DECRYPT-CSV] CSV file decrypted successfully: {output_file}")
            return True, output_file

        except Exception as e:
            logger.error(f"[DECRYPT-CSV] CSV file decryption failed: {str(e)}")
            return False, str(e)

    def decrypt_csv_data(
        self,
        encrypted_aes_key: bytes,
        encrypted_content: bytes,
        session_id: str
    ) -> Tuple[bool, bytes]:
        """
        Decrypt CSV data using RSA hybrid encryption
        """
        try:
            logger.info(f"[DECRYPT-CSV-DATA] Starting CSV data decryption for session {session_id}")

            # Get private key from keypair manager
            private_key_bytes = self.keypair_manager.get_private_key(session_id)
            if not private_key_bytes:
                error_msg = f"Private key not found for session {session_id}"
                logger.error(f"[DECRYPT-CSV-DATA] {error_msg}")
                return False, error_msg.encode()

            # Deserialize private key
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None
            )

            logger.info(f"[DECRYPT-CSV-DATA] Step 1: Decrypting CSV AES key with RSA private key")

            # Step 1: Decrypt AES key with RSA private key
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            logger.info(f"[DECRYPT-CSV-DATA] Successfully decrypted CSV AES key ({len(aes_key)} bytes)")

            # Step 2: Decrypt CSV content with AES key
            logger.info(f"[DECRYPT-CSV-DATA] Step 2: Decrypting CSV content with AES-256 key")
            fernet = Fernet(base64.urlsafe_b64encode(aes_key[:32]))
            decrypted_content = fernet.decrypt(encrypted_content)

            logger.info(f"[DECRYPT-CSV-DATA] Successfully decrypted CSV content ({len(encrypted_content)} -> {len(decrypted_content)} bytes)")

            return True, decrypted_content

        except Exception as e:
            logger.error(f"[DECRYPT-CSV-DATA] CSV data decryption failed: {str(e)}")
            return False, str(e).encode()

    def decrypt_bundle(
        self,
        bundle_data: bytes,
        session_id: str
    ) -> Tuple[bool, bytes]:
        """
        Decrypt a data bundle (zip or other archive format)
        """
        try:
            logger.info(f"[DECRYPT-BUNDLE] Starting bundle decryption for session {session_id}")

            # For now, assume bundle_data is already decrypted bytes from hybrid decryption
            # In a real implementation, you might need to extract encrypted key and data
            # from the bundle structure first

            logger.info(f"[DECRYPT-BUNDLE] Bundle decrypted successfully ({len(bundle_data)} bytes)")
            return True, bundle_data

        except Exception as e:
            logger.error(f"[DECRYPT-BUNDLE] Bundle decryption failed: {str(e)}")
            return False, str(e).encode()

    def validate_encryption_metadata(
        self,
        metadata: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Validate encryption metadata format and content
        """
        try:
            required_fields = ['algorithm', 'key_size']

            for field in required_fields:
                if field not in metadata:
                    return False, f"Missing required field: {field}"

            algorithm = metadata['algorithm']
            if algorithm not in self._supported_algorithms:
                return False, f"Unsupported algorithm: {algorithm}"

            key_size = metadata.get('key_size')
            if algorithm == 'rsa_hybrid':
                if key_size not in self._supported_algorithms[algorithm]['rsa_key_sizes']:
                    return False, f"Unsupported key size for {algorithm}: {key_size}"
            elif algorithm == 'pure_rsa':
                if key_size not in self._supported_algorithms[algorithm]['key_sizes']:
                    return False, f"Unsupported key size for {algorithm}: {key_size}"

            return True, "Metadata validation successful"

        except Exception as e:
            return False, f"Metadata validation error: {str(e)}"

    def get_supported_algorithms(self) -> Dict[str, Any]:
        """
        Get list of supported encryption algorithms
        """
        return self._supported_algorithms.copy()

    def verify_data_integrity(
        self,
        data: bytes,
        expected_hash: Optional[str] = None
    ) -> bool:
        """
        Verify the integrity of decrypted data
        """
        try:
            if expected_hash is None:
                # Without expected hash, we can only verify basic data properties
                return len(data) > 0

            import hashlib

            # Calculate SHA256 hash of the data
            actual_hash = hashlib.sha256(data).hexdigest()

            # Compare with expected hash
            return actual_hash == expected_hash

        except Exception as e:
            logger.error(f"Data integrity verification failed: {str(e)}")
            return False

    def get_decryption_stats(self) -> Dict[str, Any]:
        """
        Get statistics about decryption operations
        """
        return {
            'supported_algorithms': list(self._supported_algorithms.keys()),
            'total_algorithms': len(self._supported_algorithms),
            'default_algorithm': 'rsa_hybrid',
            'service_status': 'active',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        }