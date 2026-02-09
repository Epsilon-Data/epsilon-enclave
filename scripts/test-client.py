#!/usr/bin/env python3
"""
Test Client for Epsilon Enclave

This script tests the enclave server by:
1. Requesting a keypair (simulates coordinator)
2. Encrypting a test ZIP bundle
3. Sending for execution
4. Verifying the response

Usage:
    # Start the local test server first:
    python3 scripts/local-test-server.py

    # Then run this test client:
    python3 scripts/test-client.py
"""
import base64
import json
import os
import socket
import sys
import zipfile
from io import BytesIO

# Cryptography imports
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Constants (must match coordinator)
AES_KEY_SIZE = 32
IV_SIZE = 16
AES_BLOCK_SIZE = 128


def send_request(host, port, request):
    """Send request to enclave and get response"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(60)
    sock.connect((host, port))

    request_json = json.dumps(request)
    sock.sendall(request_json.encode())

    # Receive response
    chunks = []
    while True:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        except socket.timeout:
            if chunks:
                break
            raise

    sock.close()
    response_data = b''.join(chunks).decode('utf-8')
    return json.loads(response_data)


def encrypt_data(data: bytes, public_key_pem: str) -> str:
    """
    Encrypt data using hybrid encryption (AES-256-CBC + RSA-OAEP)
    This mimics exactly what the coordinator does
    """
    # Load public key
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    # Generate random AES key and IV
    aes_key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(IV_SIZE)

    # Encrypt data with AES-256-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # PKCS7 padding
    padder = sym_padding.PKCS7(AES_BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt AES key with RSA-OAEP
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Combine: [encrypted_key][iv][ciphertext]
    combined = encrypted_key + iv + ciphertext

    return base64.b64encode(combined).decode('utf-8')


def create_test_bundle():
    """Create a test ZIP bundle with a simple script"""
    buffer = BytesIO()

    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add main.py
        script_content = '''
def main():
    print("Hello from Epsilon Enclave!")
    print("Script execution successful!")

    # Try to read CSV if it exists
    import os
    csv_path = "generated/data.csv"
    if os.path.exists(csv_path):
        with open(csv_path, 'r') as f:
            lines = f.readlines()
            print(f"CSV has {len(lines)} lines")
            if lines:
                print(f"Header: {lines[0].strip()}")
    else:
        print("No CSV data provided")

    return {"result": "success"}

if __name__ == "__main__":
    result = main()
    print(result)
'''
        zf.writestr('main.py', script_content)

        # Add build.yml
        build_yml = '''version: '1.0'
analysis:
  name: Test
  description: Test script
  script_file: main.py
'''
        zf.writestr('build.yml', build_yml)

        # Add empty generated folder marker
        zf.writestr('generated/.gitkeep', '')

    return buffer.getvalue()


def create_test_csv():
    """Create test CSV data"""
    csv_content = """personal_info.first_name,personal_info.last_name,personal_info.email
John,Doe,john@example.com
Jane,Smith,jane@example.com
Bob,Johnson,bob@example.com
"""
    return csv_content.encode('utf-8')


def main():
    host = '127.0.0.1'
    port = 5005

    print("=" * 60)
    print("Epsilon Enclave Test Client")
    print("=" * 60)
    print(f"Connecting to {host}:{port}")
    print()

    # Step 1: Request keypair
    print("[1/4] Requesting RSA keypair...")
    keypair_response = send_request(host, port, {
        'operation': 'generate_rsa_keypair',
        'job_id': 'test-job-001',
        'key_size': 2048
    })

    if not keypair_response.get('success'):
        print(f"FAILED: {keypair_response.get('error')}")
        return 1

    session_id = keypair_response['session_id']
    public_key = keypair_response['public_key']
    print(f"  Session ID: {session_id}")
    print(f"  Public key received ({len(public_key)} chars)")
    print()

    # Step 2: Create and encrypt test bundle
    print("[2/4] Creating and encrypting test bundle...")
    zip_data = create_test_bundle()
    print(f"  ZIP bundle size: {len(zip_data)} bytes")

    encrypted_zip = encrypt_data(zip_data, public_key)
    print(f"  Encrypted ZIP size: {len(encrypted_zip)} chars")
    print()

    # Step 3: Create and encrypt test CSV
    print("[3/4] Creating and encrypting test CSV...")
    csv_data = create_test_csv()
    print(f"  CSV size: {len(csv_data)} bytes")

    encrypted_csv = encrypt_data(csv_data, public_key)
    print(f"  Encrypted CSV size: {len(encrypted_csv)} chars")
    print()

    # Step 4: Send for execution
    print("[4/4] Sending encrypted data for execution...")
    execute_response = send_request(host, port, {
        'operation': 'execute_script_rsa_hybrid',
        'session_id': session_id,
        'encrypted_data': encrypted_zip,
        'encrypted_csv': encrypted_csv
    })

    print()
    print("=" * 60)
    if execute_response.get('success'):
        print("SUCCESS!")
        print("=" * 60)
        print("Output:")
        print(execute_response.get('output', '(no output)'))
    else:
        print("FAILED!")
        print("=" * 60)
        print(f"Error: {execute_response.get('error')}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
