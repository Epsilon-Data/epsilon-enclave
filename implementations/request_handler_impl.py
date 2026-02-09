"""
Request Handler Implementation
Simple logic: encrypted_data + session_id -> decrypt with private key -> execute
"""
import json
import logging
import time
from typing import Dict, Any, Optional

try:
    from interfaces import IRequestHandler, IDecryptService, IExecuteService, IKeyPairManager
    from implementations.attestation_service_impl import AttestationService
except ImportError:
    from ..interfaces import IRequestHandler, IDecryptService, IExecuteService, IKeyPairManager
    from .attestation_service_impl import AttestationService

logger = logging.getLogger(__name__)


class RequestHandlerImpl(IRequestHandler):
    """
    Simple request handler: get encrypted_data + session_id, decrypt with private key, execute
    """

    def __init__(
        self,
        decrypt_service: IDecryptService,
        execute_service: IExecuteService,
        keypair_manager: IKeyPairManager,
        kms_attestation=None
    ):
        self.decrypt_service = decrypt_service
        self.execute_service = execute_service
        self.keypair_manager = keypair_manager
        self.kms_attestation = kms_attestation
        self.attestation_service = AttestationService()

    def handle_request(self, request_data: str) -> Dict[str, Any]:
        """
        Simple logic: Parse request -> Get encrypted_data + session_id -> Decrypt -> Execute
        """
        try:
            request = self._parse_request(request_data)
            if request is None:
                return self._error_response("Invalid JSON request")

            operation = request['operation']
            logger.info(f"[REQUEST] Operation: {operation}")

            if operation == 'generate_rsa_keypair':
                return self._generate_keypair(request)
            elif operation == 'execute_script_rsa_hybrid':
                return self._execute_encrypted_script(request)
            elif operation == 'health_check':
                return {'success': True, 'message': 'Enclave healthy'}
            elif operation == 'get_attestation':
                return self._get_attestation(request)
            elif operation == 'get_enclave_info':
                return self._get_enclave_info()
            else:
                return self._error_response(f"Unknown operation: {operation}")

        except Exception as e:
            logger.error(f"Request handling error: {str(e)}")
            return self._error_response(f"Server error: {str(e)}")

    def _generate_keypair(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Generate RSA keypair for a job"""
        try:
            job_id = request['job_id']
            key_size = request.get('key_size', 2048)

            # Generate keypair using keypair manager
            success, session_id = self.keypair_manager.generate_keypair(job_id, key_size)

            if not success:
                return self._error_response(f"Keypair generation failed: {session_id}")

            # Get public key for client
            public_key = self.keypair_manager.get_public_key(session_id)

            logger.info(f"[KEYPAIR] Generated for job {job_id}, session {session_id}")

            return {
                'success': True,
                'session_id': session_id,
                'public_key': public_key,
                'job_id': job_id,
                'key_size': key_size
            }

        except Exception as e:
            logger.error(f"Keypair generation error: {str(e)}")
            return self._error_response(f"Keypair generation error: {str(e)}")

    def _execute_encrypted_script(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        RSA Hybrid logic: encrypted_data + session_id -> decrypt with private key -> execute

        The coordinator sends data in combined hybrid format:
        - encrypted_data: Base64([encrypted_key][iv][ciphertext]) - the ZIP bundle
        - encrypted_csv (optional): Base64([encrypted_key][iv][ciphertext]) - the CSV data
        """
        try:
            # Extract request data
            session_id = request['session_id']
            encrypted_data = request['encrypted_data']  # RSA hybrid encrypted zip bundle
            encrypted_csv = request.get('encrypted_csv')  # Optional: RSA hybrid encrypted CSV
            timing = {}

            logger.info(f"[EXECUTE] Starting execution for session {session_id}")
            logger.info(f"[EXECUTE] Encrypted ZIP data length: {len(encrypted_data)} chars")
            if encrypted_csv:
                logger.info(f"[EXECUTE] Encrypted CSV data length: {len(encrypted_csv)} chars")

            # Step 1: Decrypt ZIP bundle using session's private key (RSA hybrid)
            t0 = time.time()
            success, decrypted_zip = self.decrypt_service.decrypt_combined_hybrid_data(
                encrypted_data, session_id
            )
            timing['decrypt_zip_ms'] = round((time.time() - t0) * 1000, 2)

            if not success:
                error_msg = decrypted_zip.decode() if isinstance(decrypted_zip, bytes) else str(decrypted_zip)
                return self._error_response(f"ZIP decryption failed: {error_msg}")

            logger.info(f"[EXECUTE] Decrypted ZIP bundle: {len(decrypted_zip)} bytes ({timing['decrypt_zip_ms']}ms)")

            # Step 2: Decrypt CSV data if provided
            decrypted_csv = None
            if encrypted_csv:
                t0 = time.time()
                success, decrypted_csv = self.decrypt_service.decrypt_combined_hybrid_data(
                    encrypted_csv, session_id
                )
                timing['decrypt_csv_ms'] = round((time.time() - t0) * 1000, 2)

                if not success:
                    error_msg = decrypted_csv.decode() if isinstance(decrypted_csv, bytes) else str(decrypted_csv)
                    return self._error_response(f"CSV decryption failed: {error_msg}")

                logger.info(f"[EXECUTE] Decrypted CSV data: {len(decrypted_csv)} bytes ({timing['decrypt_csv_ms']}ms)")

            # Step 3: Execute the decrypted bundle with optional CSV data
            t0 = time.time()
            success, output = self.execute_service.execute_bundle(
                decrypted_zip, session_id, csv_data=decrypted_csv
            )
            timing['script_execution_ms'] = round((time.time() - t0) * 1000, 2)

            # Step 4: Clean up session (remove private key from memory)
            self.cleanup_session(session_id)

            if success:
                logger.info(f"[EXECUTE] Execution successful ({timing['script_execution_ms']}ms)")

                # Generate attestation proof for user
                t0 = time.time()
                attestation_success, attestation_result = self.attestation_service.create_execution_attestation(
                    job_id=session_id,
                    output=output,
                    execution_metadata={
                        'encrypted_zip_size': len(encrypted_data),
                        'encrypted_csv_size': len(encrypted_csv) if encrypted_csv else 0,
                        'decrypted_zip_size': len(decrypted_zip),
                        'decrypted_csv_size': len(decrypted_csv) if decrypted_csv else 0
                    }
                )
                timing['attestation_generation_ms'] = round((time.time() - t0) * 1000, 2)

                logger.info(f"[TIMING] session={session_id} decrypt_zip={timing.get('decrypt_zip_ms')}ms "
                            f"decrypt_csv={timing.get('decrypt_csv_ms', 'N/A')}ms "
                            f"script_exec={timing['script_execution_ms']}ms "
                            f"attestation_gen={timing['attestation_generation_ms']}ms")

                response = {
                    'success': True,
                    'output': output,
                    'session_id': session_id,
                    'enclave_proof': {
                        'ran_in_enclave': self.attestation_service.is_real_enclave,
                        'attestation_available': attestation_success
                    },
                    'timing': timing
                }

                if attestation_success:
                    response['attestation'] = attestation_result
                    logger.info(f"[EXECUTE] Attestation generated for session {session_id}")
                else:
                    logger.warning(f"[EXECUTE] Attestation generation failed: {attestation_result}")

                return response
            else:
                logger.error(f"[EXECUTE] Execution failed: {output}")
                return self._error_response(f"Execution failed: {output}")

        except Exception as e:
            logger.error(f"Execution error: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return self._error_response(f"Execution error: {str(e)}")

    def validate_request(self, request: Dict[str, Any]) -> Optional[str]:
        """Validate request has required fields"""
        operation = request.get('operation')
        if not operation:
            return "Missing required field: operation"

        if operation == 'generate_rsa_keypair':
            if 'job_id' not in request:
                return "Missing required field: job_id"
        elif operation == 'execute_script_rsa_hybrid':
            required = ['session_id', 'encrypted_data']
            for field in required:
                if field not in request:
                    return f"Missing required field: {field}"

        return None

    def create_session(self, job_id: str) -> Dict[str, Any]:
        """Create a new session (same as generate keypair)"""
        return self._generate_keypair({'job_id': job_id})

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session metadata"""
        metadata = self.keypair_manager.get_keypair_metadata(session_id)
        return metadata

    def cleanup_session(self, session_id: str) -> bool:
        """Clean up session and remove private key"""
        return self.keypair_manager.delete_keypair(session_id)

    def get_public_key(self, session_id: str) -> Optional[str]:
        """Get public key for session"""
        return self.keypair_manager.get_public_key(session_id)

    def handle_attestation(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle KMS attestation if available"""
        if not self.kms_attestation:
            return self._error_response("KMS attestation not available")

        try:
            credentials = request['credentials']
            success, result = self.kms_attestation.attest_enclave(credentials)

            return {
                'success': success,
                'data': result if success else None,
                'error': result if not success else None
            }

        except Exception as e:
            logger.error(f"Attestation error: {str(e)}")
            return self._error_response(f"Attestation error: {str(e)}")

    def handle_execution(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle execution request (same as execute_script_rsa_hybrid)"""
        return self._execute_encrypted_script(request)

    def get_health_status(self) -> Dict[str, Any]:
        """Get health status"""
        return {
            'success': True,
            'data': {
                'status': 'healthy',
                'services': {
                    'decrypt_service': 'active',
                    'execute_service': 'active',
                    'keypair_manager': 'active',
                    'kms_attestation': 'active' if self.kms_attestation else 'disabled'
                }
            }
        }

    def _get_attestation(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Get attestation document with optional user data."""
        try:
            user_data = request.get('user_data')
            if user_data:
                user_data = user_data.encode() if isinstance(user_data, str) else user_data

            nonce = request.get('nonce')
            if nonce:
                nonce = nonce.encode() if isinstance(nonce, str) else nonce

            success, attestation = self.attestation_service.generate_attestation(
                user_data=user_data,
                nonce=nonce
            )

            return {
                'success': success,
                'attestation': attestation if success else None,
                'error': attestation.get('error') if not success else None,
                'is_real_enclave': self.attestation_service.is_real_enclave
            }

        except Exception as e:
            logger.error(f"Get attestation error: {str(e)}")
            return self._error_response(f"Attestation error: {str(e)}")

    def _get_enclave_info(self) -> Dict[str, Any]:
        """Get information about the enclave environment."""
        import os
        import hashlib

        return {
            'success': True,
            'enclave_info': {
                'is_nitro_enclave': self.attestation_service.is_real_enclave,
                'nsm_available': os.path.exists('/dev/nsm'),
                'attestation_supported': self.attestation_service.is_real_enclave,
                'services': {
                    'decrypt_service': 'active',
                    'execute_service': 'active',
                    'keypair_manager': 'active',
                    'attestation_service': 'active',
                    'kms_attestation': 'active' if self.kms_attestation else 'disabled'
                },
                'pcr_info': 'PCR values are included in attestation documents. Compare with published enclave image hash to verify code integrity.'
            }
        }

    def _parse_request(self, request_data: str) -> Optional[Dict[str, Any]]:
        """Parse JSON request"""
        try:
            return json.loads(request_data)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            return None

    def _error_response(self, message: str) -> Dict[str, Any]:
        """Create error response"""
        return {
            'success': False,
            'error': message
        }