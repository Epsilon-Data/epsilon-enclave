"""
Attestation Service Implementation
Generates cryptographic proof that code ran inside AWS Nitro Enclave

Uses direct /dev/nsm ioctl interface following AWS NSM API specification
Reference: https://github.com/aws/aws-nitro-enclaves-nsm-api
"""
import base64
import hashlib
import json
import logging
import os
import struct
import fcntl
import ctypes
from typing import Tuple, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Check if running in real Nitro Enclave
RUNNING_IN_ENCLAVE = os.path.exists('/dev/nsm')

# NSM ioctl calculation:
# _IOWR(type, nr, size) = ((3 << 30) | (type << 8) | nr | (size << 16))
# type = 0x0A (NSM_IOCTL_MAGIC), nr = 0, size = 32 (sizeof NsmMessage = 2 * iovec)
# = 0xC0000000 | 0x00000A00 | 0 | 0x00200000 = 0xC0200A00
NSM_IOCTL_REQUEST = 0xC0200A00


class NSMError(Exception):
    """NSM operation error"""
    pass


class AttestationService:
    """
    Service for generating Nitro Enclave attestation documents.

    Uses direct /dev/nsm ioctl for reliability.

    Attestation documents prove:
    1. Code is running in a genuine AWS Nitro Enclave
    2. The exact code that ran (via PCR values)
    3. Custom user_data (e.g., hash of execution output)

    The document is signed by AWS and can be verified by anyone.
    """

    def __init__(self):
        self._nsm_available = RUNNING_IN_ENCLAVE
        self._nsm_fd = None

        if self._nsm_available:
            self._open_nsm_device()

        logger.info(f"[ATTESTATION] Initialized, NSM available: {self._nsm_available}, NSM fd: {self._nsm_fd}")

    def _open_nsm_device(self):
        """Open the NSM device using os.open() to avoid seek issues."""
        try:
            self._nsm_fd = os.open('/dev/nsm', os.O_RDWR)
            logger.info(f"[ATTESTATION] Opened /dev/nsm, fd: {self._nsm_fd}")
        except OSError as e:
            logger.error(f"[ATTESTATION] Failed to open /dev/nsm: {e}")
            self._nsm_fd = None

    def _build_attestation_request(
        self,
        user_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        public_key: Optional[bytes] = None
    ) -> bytes:
        """Build CBOR-encoded attestation request."""
        try:
            import cbor2
        except ImportError:
            raise NSMError("cbor2 library required for attestation")

        # Build the request map per NSM API spec
        attestation_params = {}
        if user_data:
            attestation_params["user_data"] = user_data
        if nonce:
            attestation_params["nonce"] = nonce
        if public_key:
            attestation_params["public_key"] = public_key

        request = {"Attestation": attestation_params}
        return cbor2.dumps(request)

    def _parse_attestation_response(self, response_data: bytes) -> Tuple[bool, Any]:
        """Parse CBOR-encoded attestation response."""
        try:
            import cbor2
        except ImportError:
            raise NSMError("cbor2 library required for attestation")

        response = cbor2.loads(response_data)
        logger.info(f"[ATTESTATION] Parsed response keys: {list(response.keys()) if isinstance(response, dict) else type(response)}")

        if isinstance(response, dict):
            if "Attestation" in response:
                attestation = response["Attestation"]
                if isinstance(attestation, dict) and "document" in attestation:
                    return True, attestation["document"]
            if "Error" in response:
                return False, response["Error"]

        return False, f"Unexpected response format: {response}"

    def _nsm_ioctl(self, request_data: bytes) -> bytes:
        """
        Send request to NSM via ioctl and get response.

        NsmMessage structure (32 bytes on 64-bit):
        struct iovec {
            void *iov_base;   // 8 bytes - pointer to buffer
            size_t iov_len;   // 8 bytes - length of buffer
        };
        struct NsmMessage {
            struct iovec request;   // 16 bytes
            struct iovec response;  // 16 bytes
        };
        """
        if self._nsm_fd is None:
            raise NSMError("NSM device not open")

        # Allocate response buffer (0x3000 = 12288 bytes as per NSM spec)
        response_capacity = 0x3000
        response_buf = ctypes.create_string_buffer(response_capacity)

        # Create request buffer
        request_buf = ctypes.create_string_buffer(request_data)

        # Get buffer addresses
        request_addr = ctypes.addressof(request_buf)
        response_addr = ctypes.addressof(response_buf)

        # Pack NsmMessage: request iovec (ptr, len) + response iovec (ptr, len)
        # Format: Q = unsigned long long (8 bytes), matches pointer and size_t on 64-bit
        nsm_message = struct.pack(
            'QQQQ',
            request_addr, len(request_data),      # request iovec
            response_addr, response_capacity      # response iovec
        )

        # Make it mutable for ioctl to update
        nsm_message_buf = bytearray(nsm_message)

        try:
            fcntl.ioctl(self._nsm_fd, NSM_IOCTL_REQUEST, nsm_message_buf)
        except OSError as e:
            raise NSMError(f"ioctl failed: {e}")

        # After ioctl, the response iov_len field is updated with actual response size
        # Unpack to get response length
        _, _, _, response_len = struct.unpack('QQQQ', bytes(nsm_message_buf))

        if response_len == 0:
            raise NSMError("Empty response from NSM")

        logger.info(f"[ATTESTATION] ioctl returned response_len: {response_len}")

        return response_buf.raw[:response_len]

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
            Tuple of (success, attestation_data)
        """
        if not self._nsm_available:
            logger.error("[ATTESTATION] Not running in Nitro Enclave - attestation not available")
            return False, {
                'error': 'NOT_IN_ENCLAVE',
                'message': 'Attestation requires AWS Nitro Enclave. /dev/nsm not found.',
                'is_real_enclave': False
            }

        if self._nsm_fd is None:
            logger.error("[ATTESTATION] NSM device not open - attestation failed")
            return False, {
                'error': 'NSM_UNAVAILABLE',
                'message': 'Failed to open /dev/nsm device.',
                'is_real_enclave': True
            }

        return self._generate_nsm_attestation(user_data, nonce, public_key)

    def _generate_nsm_attestation(
        self,
        user_data: Optional[bytes],
        nonce: Optional[bytes],
        public_key: Optional[bytes]
    ) -> Tuple[bool, Dict[str, Any]]:
        """Generate attestation using direct ioctl to /dev/nsm."""
        try:
            import time as _time

            # Build CBOR request
            t0 = _time.time()
            request_data = self._build_attestation_request(user_data, nonce, public_key)
            cbor_build_ms = round((_time.time() - t0) * 1000, 2)

            logger.info(f"[ATTESTATION] Sending ioctl, request={len(request_data)}B, user_data={len(user_data) if user_data else 0}B, nonce={len(nonce) if nonce else 0}B")

            # Send to NSM via ioctl
            t0 = _time.time()
            response_data = self._nsm_ioctl(request_data)
            nsm_ioctl_ms = round((_time.time() - t0) * 1000, 2)

            logger.info(f"[ATTESTATION] Received response: {len(response_data)} bytes (ioctl={nsm_ioctl_ms}ms)")

            # Parse CBOR response
            t0 = _time.time()
            success, result = self._parse_attestation_response(response_data)
            cbor_parse_ms = round((_time.time() - t0) * 1000, 2)

            logger.info(f"[TIMING] nsm_cbor_build={cbor_build_ms}ms nsm_ioctl={nsm_ioctl_ms}ms nsm_cbor_parse={cbor_parse_ms}ms")

            if not success:
                logger.error(f"[ATTESTATION] NSM returned error: {result}")
                return False, {
                    'error': 'NSM_ERROR',
                    'message': str(result),
                    'is_real_enclave': True
                }

            # result is the attestation document (bytes)
            attestation_doc_b64 = base64.b64encode(result).decode()

            logger.info(f"[ATTESTATION] Generated attestation document: {len(result)} bytes")

            return True, {
                'attestation_document': attestation_doc_b64,
                'attestation_document_length': len(result),
                'format': 'CBOR',
                'signed_by': 'AWS Nitro Attestation PKI',
                'user_data_included': user_data is not None,
                'user_data_hash': hashlib.sha256(user_data).hexdigest() if user_data else None,
                'nonce_included': nonce is not None,
                'how_to_verify': [
                    '1. Base64 decode the attestation_document',
                    '2. Parse as CBOR (RFC 8949)',
                    '3. Extract certificate chain (cabundle)',
                    '4. Verify chain against AWS Nitro root cert',
                    '5. Verify COSE signature on document',
                    '6. Extract and compare PCR values',
                    '7. Verify user_data matches expected hash'
                ],
                'aws_root_cert_url': 'https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip'
            }

        except NSMError as e:
            logger.error(f"[ATTESTATION] NSM error: {e}")
            return False, {
                'error': 'NSM_ERROR',
                'message': str(e),
                'is_real_enclave': True
            }
        except Exception as e:
            logger.error(f"[ATTESTATION] Attestation failed: {e}")
            import traceback
            logger.error(f"[ATTESTATION] Traceback: {traceback.format_exc()}")
            return False, {
                'error': 'NSM_EXCEPTION',
                'message': str(e),
                'is_real_enclave': True
            }

    def create_execution_attestation(
        self,
        job_id: str,
        output: str,
        execution_metadata: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Create an attestation for a specific execution.

        This is what users receive as proof their code ran in the enclave.
        """
        try:
            import time

            # Create user_data containing execution proof
            proof_data = {
                'job_id': job_id,
                'output_hash': hashlib.sha256(output.encode()).hexdigest(),
                'output_length': len(output),
                'timestamp': int(time.time()),
                'metadata': execution_metadata
            }

            proof_bytes = json.dumps(proof_data, sort_keys=True).encode()

            # Generate random nonce for replay protection
            nonce = os.urandom(32)

            # Generate attestation with proof data
            success, attestation = self.generate_attestation(
                user_data=proof_bytes,
                nonce=nonce
            )

            if success:
                return True, {
                    'attestation': attestation,
                    'proof': {
                        'job_id': job_id,
                        'output_hash': proof_data['output_hash'],
                        'timestamp': proof_data['timestamp'],
                        'nonce': base64.b64encode(nonce).decode()
                    },
                    'verification_guide': {
                        'step_1': 'Download AWS Nitro root certificate from aws_root_cert_url',
                        'step_2': 'Base64 decode attestation_document',
                        'step_3': 'Parse CBOR structure',
                        'step_4': 'Verify certificate chain against AWS root',
                        'step_5': 'Verify COSE_Sign1 signature',
                        'step_6': 'Extract PCR0 and compare with published enclave image hash',
                        'step_7': 'Extract user_data and verify output_hash matches SHA256(output)',
                        'conclusion': 'If all steps pass, the output was generated inside the verified enclave'
                    }
                }
            else:
                return False, attestation

        except Exception as e:
            logger.error(f"[ATTESTATION] Execution attestation failed: {e}")
            return False, {'error': str(e)}

    @property
    def is_real_enclave(self) -> bool:
        """Check if running in a real Nitro Enclave."""
        return self._nsm_available

    def __del__(self):
        """Cleanup NSM device."""
        if self._nsm_fd is not None:
            try:
                os.close(self._nsm_fd)
                logger.info("[ATTESTATION] NSM device closed")
            except:
                pass
