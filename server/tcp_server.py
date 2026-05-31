"""
TCP transport for the Epsilon enclave server.

A GCP Intel TDX Confidential VM is a whole trust domain, not a Nitro-style
sidecar enclave, so there is no host<->enclave VSock channel; the coordinator
reaches the in-TD agent over TCP. ``TcpEnclaveServer`` reuses ``EnclaveServer``'s
framing, dispatch and accept loop verbatim and overrides only the listening
socket (Template Method).

Transport and attestation backend are independent concerns: pass
``backend="tdx"`` to attest with an Intel TDX quote. For the reference demo the
coordinator and the agent run on the same TDX VM over loopback; the same agent
is reachable over the TD's network endpoint in a split deployment.
"""
import logging
import socket
from typing import Optional

from server.server import EnclaveServer

logger = logging.getLogger(__name__)


class TcpEnclaveServer(EnclaveServer):
    """``EnclaveServer`` that listens on TCP instead of VSock."""

    def __init__(
        self,
        host: str,
        port: int,
        kms_attestation=None,
        backend: Optional[str] = None,
    ):
        super().__init__(kms_attestation=kms_attestation, backend=backend)
        self._host = host
        self._port = port

    def _bind_listening_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._host, self._port))
        sock.listen(5)
        logger.info(f"[LISTENING] Listening on tcp://{self._host}:{self._port}")
        return sock
