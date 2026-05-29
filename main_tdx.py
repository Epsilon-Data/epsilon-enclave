#!/usr/bin/env python3
"""
Entry point for the Epsilon enclave agent on an Intel TDX Confidential VM.

Same service stack as ``main.py`` (decrypt / execute / keypair / request
handler), but attestation is produced as an Intel TDX quote and the agent
listens on TCP instead of VSock (a TDX CVM has no host<->enclave VSock channel).
KMS attestation is Nitro-specific and is not used here.

Run on the TDX VM as root (the TDX quote device is root-only):

    sudo env \\
        TDQUOTE_BIN=/path/to/epsilon-enclave/tdx/tdquote/tdquote \\
        TDX_AGENT_HOST=127.0.0.1 TDX_AGENT_PORT=5005 \\
        python3 main_tdx.py
"""
import logging
import os
import sys

from config import LOG_LEVEL, LOG_FORMAT
from factory import TDX_BACKEND
from server.tcp_server import TcpEnclaveServer

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

TDX_AGENT_HOST = os.getenv("TDX_AGENT_HOST", "127.0.0.1")
TDX_AGENT_PORT = int(os.getenv("TDX_AGENT_PORT", "5005"))


def main():
    """Start the TDX enclave agent (TCP transport, TDX attestation backend)."""
    logger.info("[START] Starting Epsilon Executor -- Intel TDX backend (TCP transport)")
    logger.info("=" * 60)
    logger.info("[ARCHITECTURE] TDX agent:")
    logger.info("  - IRequestHandler (request routing, reused verbatim)")
    logger.info("  - IDecryptService (RSA-OAEP + AES-256-CBC decryption)")
    logger.info("  - IExecuteService (secure script execution)")
    logger.info("  - IKeyPairManager (RSA key management)")
    logger.info("  - TdxAttestationService (TDX quote, REPORTDATA = SHA-512(proof))")
    logger.info("=" * 60)

    # KMS attestation is Nitro-specific and intentionally omitted on TDX.
    server = TcpEnclaveServer(
        host=TDX_AGENT_HOST,
        port=TDX_AGENT_PORT,
        backend=TDX_BACKEND,
    )
    server.start()


if __name__ == "__main__":
    main()
