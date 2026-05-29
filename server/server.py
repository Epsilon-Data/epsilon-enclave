import json
import socket
import struct
import logging
import threading
from typing import Optional

from config import VSOCK_PORT, MAX_REQUEST_SIZE, CLIENT_RECV_TIMEOUT, CLIENT_SEND_TIMEOUT
from factory import EnclaveServiceFactory

logger = logging.getLogger(__name__)

# Length-prefix header: 4-byte big-endian unsigned int
HEADER_SIZE = 4
MAX_HEADER_VALUE = MAX_REQUEST_SIZE


class EnclaveServer:
    """VSock server for handling enclave requests using interfaces"""

    def __init__(self, kms_attestation=None, backend: Optional[str] = None):
        self.socket: Optional[socket.socket] = None
        self.request_handler = EnclaveServiceFactory.create_enclave_services(
            kms_attestation, backend=backend
        )

    def _bind_listening_socket(self) -> socket.socket:
        """Create, bind and listen on the transport socket.

        Template method: the base server listens on VSock; transport-specific
        subclasses (e.g. TcpEnclaveServer for TDX VMs) override only this.
        """
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
        sock.listen(5)
        logger.info(f"[LISTENING] Listening on vsock port {VSOCK_PORT}")
        return sock

    def start(self):
        """Accept connections and dispatch each one in its own thread."""
        try:
            self.socket = self._bind_listening_socket()
            logger.info("[SERVER] Enclave server started")

            while True:
                try:
                    client_socket, client_addr = self.socket.accept()
                    logger.info(f"[CONNECTION] Connection from: {client_addr}")
                    t = threading.Thread(
                        target=self._handle_client_safe,
                        args=(client_socket,),
                        daemon=True,
                    )
                    t.start()
                except Exception as e:
                    logger.error(f"Error accepting connection: {str(e)}")
                    continue

        except KeyboardInterrupt:
            logger.info("[SHUTDOWN] Server shutdown requested")
        except Exception as e:
            logger.error(f"[ERROR] Server error: {str(e)}")
        finally:
            self.cleanup()

    # ------------------------------------------------------------------
    # Client handling
    # ------------------------------------------------------------------

    def _handle_client_safe(self, client_socket: socket.socket):
        """Wrapper that guarantees the socket is closed."""
        try:
            self.handle_client(client_socket)
        except Exception as e:
            logger.error(f"Unhandled error in client thread: {e}")
        finally:
            try:
                client_socket.close()
            except OSError:
                pass

    def handle_client(self, client_socket: socket.socket):
        """Handle a single client connection using length-prefix framing."""
        client_socket.settimeout(CLIENT_RECV_TIMEOUT)

        # ---- receive ----
        data, use_framing = self._recv_request(client_socket)
        if data is None:
            return

        logger.info(f"[REQUEST] Received request: {len(data)} bytes (framed={use_framing})")

        # Process request
        response = self.request_handler.handle_request(data)

        # ---- send ----
        client_socket.settimeout(CLIENT_SEND_TIMEOUT)
        if use_framing:
            self._send_response(client_socket, response)
        else:
            self._send_response_raw(client_socket, response)

        status = "[SUCCESS]" if response.get('success') else "[ERROR]"
        logger.info(f"{status} Response sent")

    # ------------------------------------------------------------------
    # Framing helpers – support both length-prefixed and legacy raw JSON
    # ------------------------------------------------------------------

    def _recv_request(self, client_socket: socket.socket) -> tuple:
        """Receive a request, auto-detecting length-prefix vs raw JSON.
        Returns (data, use_framing) where use_framing indicates length-prefix mode."""
        try:
            # Peek at first 4 bytes to decide framing mode
            first_bytes = self._recv_exact(client_socket, HEADER_SIZE)
            if first_bytes is None:
                logger.warning("Empty request received")
                return None, False

            # Detect framing: if the first byte is '{' (0x7B) it's raw JSON
            if first_bytes[0:1] == b'{':
                return self._recv_raw_json(client_socket, first_bytes), False

            # Length-prefixed framing
            msg_len = struct.unpack('!I', first_bytes)[0]
            if msg_len == 0 or msg_len > MAX_HEADER_VALUE:
                logger.error(f"Invalid message length: {msg_len}")
                self._send_error(client_socket, "Invalid message length")
                return None, True

            body = self._recv_exact(client_socket, msg_len)
            if body is None:
                logger.error("Connection closed before full message received")
                self._send_error(client_socket, "Incomplete message")
                return None, True

            return body.decode('utf-8'), True

        except socket.timeout:
            logger.error("Client connection timed out during receive")
            self._send_error(client_socket, "Request timeout")
            return None, False
        except Exception as e:
            logger.error(f"Error receiving request: {e}")
            self._send_error(client_socket, "Server error")
            return None, False

    def _recv_raw_json(self, client_socket: socket.socket, initial: bytes) -> Optional[str]:
        """Fallback: receive raw JSON without length prefix (legacy compat)."""
        chunks = [initial]
        total = len(initial)

        while total < MAX_REQUEST_SIZE:
            chunk = client_socket.recv(min(65536, MAX_REQUEST_SIZE - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)

            # Try to parse complete JSON
            if chunk.endswith(b'}'):
                try:
                    data = b''.join(chunks).decode('utf-8')
                    json.loads(data)
                    return data
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

        if not chunks:
            return None
        return b''.join(chunks).decode('utf-8')

    def _recv_exact(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly n bytes."""
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _send_response(self, client_socket: socket.socket, response: dict):
        """Send response with length-prefix framing."""
        try:
            payload = json.dumps(response).encode('utf-8')
            header = struct.pack('!I', len(payload))
            client_socket.sendall(header + payload)
        except (socket.error, OSError) as e:
            logger.error(f"Error sending response: {e}")

    def _send_response_raw(self, client_socket: socket.socket, response: dict):
        """Send response as raw JSON without length prefix (legacy compat)."""
        try:
            payload = json.dumps(response).encode('utf-8')
            client_socket.sendall(payload)
        except (socket.error, OSError) as e:
            logger.error(f"Error sending response: {e}")

    def _send_error(self, client_socket: socket.socket, error_msg: str):
        """Send error response to client"""
        try:
            response = {"success": False, "error": error_msg}
            payload = json.dumps(response).encode('utf-8')
            header = struct.pack('!I', len(payload))
            client_socket.sendall(header + payload)
        except (socket.error, OSError) as e:
            logger.debug(f"Could not send error response: {e}")

    def cleanup(self):
        """Clean up server resources"""
        if self.socket:
            try:
                self.socket.close()
                logger.info("[CLEANUP] Server socket closed")
            except (socket.error, OSError) as e:
                logger.debug(f"Error closing socket: {e}")