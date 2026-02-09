import json
import socket
import logging
from typing import Optional

from config import VSOCK_PORT, MAX_REQUEST_SIZE, LOG_FORMAT, LOG_LEVEL
from factory import EnclaveServiceFactory

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT
)
logger = logging.getLogger(__name__)


class EnclaveServer:
    """ VSock server for handling enclave requests using interfaces"""

    def __init__(self, kms_attestation=None):
        self.socket: Optional[socket.socket] = None
        # Use  interface-based request handler
        self.request_handler = EnclaveServiceFactory.create_enclave_services(kms_attestation)

    def start(self):
        """Start the vsock server and listen for connections"""
        try:
            # Create vsock socket
            self.socket = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

            # CID_ANY allows connections from any CID
            self.socket.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
            self.socket.listen(5)

            logger.info(f"[SERVER] enclave server started with interfaces")
            logger.info(f"[LISTENING] Listening on vsock port {VSOCK_PORT}")
            logger.info(f"[INTERFACES] Using: RequestHandler, DecryptService, ExecuteService, KeyPairManager")

            # Main server loop
            while True:
                try:
                    # Accept connections
                    client_socket, client_addr = self.socket.accept()
                    logger.info(f"[CONNECTION] Connection from CID: {client_addr}")

                    # Handle client in same thread (for simplicity)
                    self.handle_client(client_socket)

                except Exception as e:
                    logger.error(f"Error accepting connection: {str(e)}")
                    continue

        except KeyboardInterrupt:
            logger.info("[SHUTDOWN]  server shutdown requested")
        except Exception as e:
            logger.error(f"[ERROR]  server error: {str(e)}")
        finally:
            self.cleanup()

    def handle_client(self, client_socket: socket.socket):
        """Handle a single client connection"""
        try:
            # Receive request data in chunks
            chunks = []
            total_received = 0

            while total_received < MAX_REQUEST_SIZE:
                chunk = client_socket.recv(min(65536, MAX_REQUEST_SIZE - total_received))
                if not chunk:
                    break
                chunks.append(chunk)
                total_received += len(chunk)

                # Check if we have a complete JSON by looking for closing brace
                if chunk.endswith(b'}'):
                    try:
                        # Try to decode to verify we have complete JSON
                        data = b''.join(chunks).decode('utf-8')
                        json.loads(data)  # Validate JSON
                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        # Not complete yet, continue receiving
                        continue

            if not chunks:
                logger.warning("Empty request received")
                return

            data = b''.join(chunks).decode('utf-8')
            logger.info(f"[REQUEST] Received request: {len(data)} bytes")

            # Process request using clean interface
            response = self.request_handler.handle_request(data)

            # Send response
            response_json = json.dumps(response)
            client_socket.send(response_json.encode())

            status_emoji = "[SUCCESS]" if response.get('success') else "[ERROR]"
            logger.info(f"{status_emoji} Sent response via clean interfaces")

        except socket.timeout:
            logger.error("Client connection timed out")
            self._send_error(client_socket, "Request timeout")
        except Exception as e:
            logger.error(f"Error handling client: {str(e)}")
            self._send_error(client_socket, f"Server error: {str(e)}")
        finally:
            client_socket.close()

    def _send_error(self, client_socket: socket.socket, error_msg: str):
        """Send error response to client"""
        try:
            error_response = {
                "success": False,
                "error": error_msg
            }
            client_socket.send(json.dumps(error_response).encode())
        except (socket.error, OSError) as e:
            # Best effort - log but don't raise when sending error response
            logger.debug(f"Could not send error response: {e}")

    def cleanup(self):
        """Clean up server resources"""
        if self.socket:
            try:
                self.socket.close()
                logger.info("[CLEANUP]  server socket closed")
            except (socket.error, OSError) as e:
                logger.debug(f"Error closing socket: {e}")