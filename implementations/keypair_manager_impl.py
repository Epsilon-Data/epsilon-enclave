"""
KeyPair Manager Implementation
Concrete implementation of IKeyPairManager interface for RSA key management
"""
import logging
import time
import uuid
import base64
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

try:
    from interfaces import IKeyPairManager
except ImportError:
    from ..interfaces import IKeyPairManager

logger = logging.getLogger(__name__)


class KeyPairManagerImpl(IKeyPairManager):
    """
    Concrete implementation of RSA key pair management
    """

    def __init__(self):
        """
        Initialize keypair manager with in-memory storage
        """
        self.active_sessions = {}  # {session_id: {job_id, private_key, public_key, metadata, created_at, ttl}}
        self._supported_formats = {
            'PEM': 'Privacy-Enhanced Mail format',
            'DER': 'Distinguished Encoding Rules format',
            'base64': 'Base64 encoded PEM',
            'SSH': 'SSH public key format',
            'JWK': 'JSON Web Key format'
        }
        self._default_ttl = 3600  # 1 hour

    def generate_keypair(
        self,
        job_id: str,
        key_size: int = 2048
    ) -> Tuple[bool, str]:
        """
        Generate a new RSA key pair for a job
        """
        try:
            logger.info(f"[KEYPAIR] Generating RSA-{key_size} key pair for job {job_id}")

            # Validate key size
            if key_size not in [2048, 3072, 4096]:
                return False, f"Unsupported key size: {key_size}. Supported: 2048, 3072, 4096"

            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            public_key = private_key.public_key()

            # Create session ID
            session_id = f"rsa-session-{uuid.uuid4().hex[:8]}"

            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            # Store keypair with metadata
            session_data = {
                'job_id': job_id,
                'private_key': private_pem,
                'public_key': public_pem,
                'key_size': key_size,
                'created_at': time.time(),
                'ttl': self._default_ttl,
                'metadata': {
                    'algorithm': 'RSA',
                    'key_size': key_size,
                    'public_exponent': 65537,
                    'created_at': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                    'encryption_method': 'rsa_hybrid'
                }
            }

            self.active_sessions[session_id] = session_data

            logger.info(f"[KEYPAIR] Generated RSA-{key_size} key pair for job {job_id}")
            logger.info(f"[KEYPAIR] Private key stored in memory (session {session_id})")
            logger.info(f"[KEYPAIR] Public key ready for client encryption")

            return True, session_id

        except Exception as e:
            logger.error(f"[KEYPAIR] Key generation failed: {str(e)}")
            return False, str(e)

    def get_public_key(
        self,
        session_id: str,
        format: str = "PEM"
    ) -> Optional[str]:
        """
        Get the public key for a session
        """
        try:
            session = self._get_valid_session(session_id)
            if not session:
                return None

            public_key_pem = session['public_key']

            if format == "PEM":
                return public_key_pem
            elif format == "base64":
                return base64.b64encode(public_key_pem.encode()).decode()
            elif format == "DER":
                # Convert PEM to DER
                public_key = serialization.load_pem_public_key(public_key_pem.encode())
                der_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return base64.b64encode(der_bytes).decode()
            elif format == "SSH":
                # Convert to SSH format (simplified)
                return f"ssh-rsa {base64.b64encode(public_key_pem.encode()).decode()}"
            else:
                logger.error(f"[KEYPAIR] Unsupported format: {format}")
                return None

        except Exception as e:
            logger.error(f"[KEYPAIR] Failed to get public key: {str(e)}")
            return None

    def get_private_key(
        self,
        session_id: str
    ) -> Optional[bytes]:
        """
        Get the private key for a session (internal use only)
        """
        try:
            session = self._get_valid_session(session_id)
            if not session:
                return None

            return session['private_key']

        except Exception as e:
            logger.error(f"[KEYPAIR] Failed to get private key: {str(e)}")
            return None

    def delete_keypair(
        self,
        session_id: str
    ) -> bool:
        """
        Securely delete a key pair
        """
        try:
            if session_id in self.active_sessions:
                job_id = self.active_sessions[session_id].get('job_id', 'unknown')
                del self.active_sessions[session_id]
                logger.info(f"[KEYPAIR] Keypair deleted for session {session_id} (job {job_id})")
                logger.info(f"[KEYPAIR] Private key removed from memory")
                return True
            else:
                logger.warning(f"[KEYPAIR] Session {session_id} not found for deletion")
                return False

        except Exception as e:
            logger.error(f"[KEYPAIR] Failed to delete keypair: {str(e)}")
            return False

    def _get_valid_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session if it exists and is valid (not expired)
        """
        if session_id not in self.active_sessions:
            logger.error(f"[KEYPAIR] Session {session_id} not found")
            return None

        session = self.active_sessions[session_id]

        if not self._is_session_valid(session):
            logger.warning(f"[KEYPAIR] Session {session_id} expired, cleaning up")
            del self.active_sessions[session_id]
            return None

        return session

    def _is_session_valid(self, session_data: Dict[str, Any]) -> bool:
        """
        Check if a session is still valid (not expired)
        """
        created_at = session_data.get('created_at', 0)
        ttl = session_data.get('ttl', self._default_ttl)

        return (time.time() - created_at) < ttl