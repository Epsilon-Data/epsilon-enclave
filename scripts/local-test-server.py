#!/usr/bin/env python3
"""
Local Test Server for Epsilon Enclave

This script simulates the enclave server using TCP sockets instead of VSock,
allowing you to test the enclave logic on any machine without Nitro.

Usage:
    cd epsilon-enclave
    python3 -m scripts.local_test_server

    OR

    python3 scripts/local-test-server.py

Then configure coordinator with:
    USE_LOCAL_ENCLAVE=false
    ENCLAVE_HOST=localhost  # (need to modify EnclaveClient for TCP testing)
"""
import json
import socket
import sys
import os
import logging

# Add parent directory to path for direct script execution
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PROJECT_DIR)

# Now import with absolute imports
from interfaces import IRequestHandler
from implementations import (
    RequestHandlerImpl,
    DecryptServiceImpl,
    ExecuteServiceImpl,
    KeyPairManagerImpl
)
from config import VSOCK_PORT, LOG_LEVEL, LOG_FORMAT


def create_request_handler() -> IRequestHandler:
    """Create request handler with all dependencies (inline factory)"""
    keypair_manager = KeyPairManagerImpl()
    decrypt_service = DecryptServiceImpl(keypair_manager)
    execute_service = ExecuteServiceImpl(decrypt_service)
    return RequestHandlerImpl(
        decrypt_service=decrypt_service,
        execute_service=execute_service,
        keypair_manager=keypair_manager,
        kms_attestation=None
    )

# Configure logging
logging.basicConfig(level=getattr(logging, LOG_LEVEL), format=LOG_FORMAT)
logger = logging.getLogger(__name__)


def run_tcp_server(host='127.0.0.1', port=5005):
    """Run enclave as TCP server for local testing"""

    # Create request handler
    handler = create_request_handler()

    # Create TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)

    logger.info("=" * 60)
    logger.info("Epsilon Enclave LOCAL TEST SERVER")
    logger.info("=" * 60)
    logger.info(f"Listening on {host}:{port}")
    logger.info("This simulates the Nitro enclave for local testing")
    logger.info("")
    logger.info("To test, you can use the test client or modify EnclaveClient")
    logger.info("=" * 60)

    while True:
        try:
            conn, addr = sock.accept()
            logger.info(f"[CONNECTION] Client connected from {addr}")

            # Receive data
            chunks = []
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                # Check for complete JSON
                if chunk.endswith(b'}'):
                    try:
                        data = b''.join(chunks).decode('utf-8')
                        json.loads(data)  # Validate
                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue

            if not chunks:
                logger.warning("[EMPTY] Empty request received")
                conn.close()
                continue

            data = b''.join(chunks).decode('utf-8')
            logger.info(f"[REQUEST] Received {len(data)} bytes")

            # Parse and log operation
            try:
                request = json.loads(data)
                operation = request.get('operation', 'unknown')
                logger.info(f"[OPERATION] {operation}")
            except:
                pass

            # Process request
            response = handler.handle_request(data)

            # Send response
            response_json = json.dumps(response)
            conn.sendall(response_json.encode())

            status = "SUCCESS" if response.get('success') else "ERROR"
            logger.info(f"[{status}] Sent response ({len(response_json)} bytes)")

            conn.close()

        except KeyboardInterrupt:
            logger.info("[SHUTDOWN] Server shutting down")
            break
        except Exception as e:
            logger.error(f"[ERROR] {str(e)}")
            try:
                conn.close()
            except:
                pass

    sock.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Epsilon Enclave Local Test Server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5005, help='Port to listen on')
    args = parser.parse_args()

    run_tcp_server(args.host, args.port)
