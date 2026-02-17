"""
KeyPair Manager Implementation
Concrete implementation of IKeyPairManager interface for RSA key management
"""
import logging
import threading
import time
import uuid
import base64
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from interfaces import IKeyPairManager
from config import SESSION_TTL, CLEANUP_INTERVAL, ALLOWED_KEY_SIZES

logger = logging.getLogger(__name__)


class KeyPairManagerImpl(IKeyPairManager):
    """
    Concrete implementation of RSA key pair management
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self._default_ttl = SESSION_TTL

        # Start background cleanup thread
        self._cleanup_interval = CLEANUP_INTERVAL
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
        )
        self._cleanup_thread.start()
        logger.info(f"[KEYPAIR] Session cleanup thread started (interval={self._cleanup_interval}s, ttl={self._default_ttl}s)")

    def _cleanup_loop(self):
        """Periodically remove expired sessions."""
        while True:
            time.sleep(self._cleanup_interval)
            self._purge_expired_sessions()

    def _purge_expired_sessions(self):
        """Remove all expired sessions."""
        now = time.time()
        with self._lock:
            expired = [
                sid for sid, data in self.active_sessions.items()
                if (now - data.get('created_at', 0)) >= data.get('ttl', self._default_ttl)
            ]
            for sid in expired:
                del self.active_sessions[sid]
            if expired:
                logger.info(f"[KEYPAIR] Purged {len(expired)} expired sessions")

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

            if key_size not in ALLOWED_KEY_SIZES:
                return False, f"Unsupported key size: {key_size}. Supported: {ALLOWED_KEY_SIZES}"

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            public_key = private_key.public_key()

            session_id = f"rsa-session-{uuid.uuid4().hex[:8]}"

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

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

            with self._lock:
                self.active_sessions[session_id] = session_data

            logger.info(f"[KEYPAIR] Generated RSA-{key_size} key pair for job {job_id}, session {session_id}")

            return True, session_id

        except Exception as e:
            logger.error(f"[KEYPAIR] Key generation failed: {str(e)}")
            return False, str(e)

    def get_public_key(
        self,
        session_id: str,
        key_format: str = "PEM"
    ) -> Optional[str]:
        """
        Get the public key for a session
        """
        try:
            session = self._get_valid_session(session_id)
            if not session:
                return None

            public_key_pem = session['public_key']

            if key_format == "PEM":
                return public_key_pem
            elif key_format == "base64":
                return base64.b64encode(public_key_pem.encode()).decode()
            elif key_format == "DER":
                public_key = serialization.load_pem_public_key(public_key_pem.encode())
                der_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return base64.b64encode(der_bytes).decode()
            else:
                logger.error(f"[KEYPAIR] Unsupported format: {key_format}")
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
            with self._lock:
                if session_id in self.active_sessions:
                    job_id = self.active_sessions[session_id].get('job_id', 'unknown')
                    del self.active_sessions[session_id]
                    logger.info(f"[KEYPAIR] Keypair deleted for session {session_id} (job {job_id})")
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
        with self._lock:
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
