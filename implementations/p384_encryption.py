"""
P-384 ECDH + AES-256-GCM Encryption Service
Copied pattern from enclaver-sparsity (Rust) -> Python

Security improvements over RSA-2048:
- P-384 ECDH: 192-bit security (vs 112-bit for RSA-2048)
- Forward secrecy: Each session has unique keys
- AES-GCM: Authenticated encryption (vs CBC which needs separate MAC)
"""
import os
import base64
import hashlib
import logging
from typing import Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# Constants (matching enclaver-sparsity)
CURVE = ec.SECP384R1()  # P-384 curve
AES_KEY_SIZE = 32       # 256 bits
NONCE_SIZE = 12         # 96 bits for GCM
HKDF_INFO = b"enclaver-p384-ecdh-aes256gcm"


class P384EncryptionService:
    """
    P-384 ECDH key exchange + AES-256-GCM encryption.

    Flow:
    1. Enclave generates P-384 keypair
    2. Client gets enclave's public key
    3. Client generates own P-384 keypair
    4. Client computes shared secret via ECDH
    5. Client derives AES key via HKDF
    6. Client encrypts data with AES-256-GCM
    7. Client sends: client_public_key + nonce + ciphertext + tag
    8. Enclave computes same shared secret and AES key
    9. Enclave decrypts data
    """

    def __init__(self):
        self._private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self._public_key: Optional[ec.EllipticCurvePublicKey] = None
        self._session_id: Optional[str] = None

    def generate_keypair(self) -> Tuple[str, str]:
        """
        Generate P-384 keypair for this session.

        Returns:
            Tuple of (public_key_pem, session_id)
        """
        self._private_key = ec.generate_private_key(CURVE, default_backend())
        self._public_key = self._private_key.public_key()
        self._session_id = f"p384-{os.urandom(8).hex()}"

        # Export public key as PEM
        public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        logger.info(f"[P384] Generated keypair, session: {self._session_id}")
        return public_key_pem, self._session_id

    def get_public_key_bytes(self) -> bytes:
        """Get public key as uncompressed point (for compact transmission)."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def decrypt(self, encrypted_data: bytes, client_public_key_bytes: bytes) -> bytes:
        """
        Decrypt data from client using ECDH + AES-256-GCM.

        Args:
            encrypted_data: nonce (12 bytes) + ciphertext + tag (16 bytes)
            client_public_key_bytes: Client's P-384 public key (uncompressed point)

        Returns:
            Decrypted plaintext
        """
        if not self._private_key:
            raise ValueError("No keypair generated")

        # Load client's public key
        client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            CURVE, client_public_key_bytes
        )

        # ECDH: Compute shared secret
        shared_secret = self._private_key.exchange(ec.ECDH(), client_public_key)
        logger.debug(f"[P384] ECDH shared secret: {len(shared_secret)} bytes")

        # HKDF: Derive AES key from shared secret
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=None,
            info=HKDF_INFO,
            backend=default_backend()
        ).derive(shared_secret)
        logger.debug(f"[P384] Derived AES-256 key via HKDF")

        # Parse encrypted data: nonce + ciphertext_with_tag
        if len(encrypted_data) < NONCE_SIZE + 16:  # At least nonce + tag
            raise ValueError("Encrypted data too short")

        nonce = encrypted_data[:NONCE_SIZE]
        ciphertext_with_tag = encrypted_data[NONCE_SIZE:]

        # AES-256-GCM decrypt
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

        logger.info(f"[P384] Decrypted {len(ciphertext_with_tag)} -> {len(plaintext)} bytes")
        return plaintext

    def decrypt_combined(self, combined_data: str) -> bytes:
        """
        Decrypt combined format: base64(client_pubkey + nonce + ciphertext + tag)

        Format:
        - Client public key: 97 bytes (uncompressed P-384 point)
        - Nonce: 12 bytes
        - Ciphertext + Tag: variable
        """
        raw_data = base64.b64decode(combined_data)

        # P-384 uncompressed point is 97 bytes (1 + 48 + 48)
        CLIENT_PUBKEY_SIZE = 97

        if len(raw_data) < CLIENT_PUBKEY_SIZE + NONCE_SIZE + 16:
            raise ValueError("Combined data too short")

        client_public_key = raw_data[:CLIENT_PUBKEY_SIZE]
        encrypted_data = raw_data[CLIENT_PUBKEY_SIZE:]

        return self.decrypt(encrypted_data, client_public_key)

    def clear_keys(self):
        """Clear private key from memory."""
        self._private_key = None
        self._public_key = None
        self._session_id = None
        logger.info("[P384] Keys cleared from memory")


class P384ClientEncryption:
    """
    Client-side encryption using P-384 ECDH.
    Use this in the executor/coordinator.
    """

    @staticmethod
    def encrypt(plaintext: bytes, enclave_public_key_pem: str) -> str:
        """
        Encrypt data for the enclave.

        Args:
            plaintext: Data to encrypt
            enclave_public_key_pem: Enclave's P-384 public key (PEM format)

        Returns:
            Base64 encoded: client_pubkey + nonce + ciphertext + tag
        """
        # Load enclave's public key
        enclave_public_key = serialization.load_pem_public_key(
            enclave_public_key_pem.encode(),
            backend=default_backend()
        )

        # Generate ephemeral client keypair
        client_private_key = ec.generate_private_key(CURVE, default_backend())
        client_public_key = client_private_key.public_key()

        # ECDH: Compute shared secret
        shared_secret = client_private_key.exchange(ec.ECDH(), enclave_public_key)

        # HKDF: Derive AES key
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=None,
            info=HKDF_INFO,
            backend=default_backend()
        ).derive(shared_secret)

        # Generate random nonce
        nonce = os.urandom(NONCE_SIZE)

        # AES-256-GCM encrypt
        aesgcm = AESGCM(aes_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

        # Get client public key as uncompressed point
        client_public_key_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        # Combine: client_pubkey + nonce + ciphertext_with_tag
        combined = client_public_key_bytes + nonce + ciphertext_with_tag

        return base64.b64encode(combined).decode()
