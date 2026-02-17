# Epsilon Enclave

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Secure execution environment running inside an AWS Nitro Enclave. Handles encrypted data ingestion, script execution, and attestation document generation.

## Architecture

```
epsilon-enclave/
├── interfaces/           # Abstract interfaces (contracts)
│   ├── request_handler_interface.py
│   ├── decrypt_interface.py
│   ├── execute_interface.py
│   ├── keypair_interface.py
│   ├── attestation_interface.py
│   └── kms_attestation_interface.py
├── implementations/      # Concrete implementations
│   ├── request_handler_impl.py
│   ├── decrypt_service_impl.py
│   ├── execute_service_impl.py
│   ├── keypair_manager_impl.py
│   ├── attestation_service_impl.py
│   └── kms_attestation_impl.py
├── server/              # VSock server
│   └── server.py
├── .github/workflows/   # CI/CD
│   ├── release-please.yml  # Automated versioning & changelog
│   ├── pr-title.yml        # Conventional commit PR title check
│   └── build-enclave.yml   # Build & push image on release
├── config.py            # Configuration with env var overrides
├── factory.py           # Dependency injection factory
├── main.py              # Entry point
├── Dockerfile           # Multi-stage build (amazonlinux:2)
└── requirements.txt     # Python dependencies
```

## Execution Flow

```
1. Coordinator requests public key from enclave (VSock CID 18, port 5005)
2. Enclave generates RSA-2048 keypair, returns public key
3. Coordinator encrypts data with public key (hybrid: AES-256-CBC + RSA-OAEP)
4. Coordinator sends encrypted bundle + encrypted CSV to enclave
5. Enclave decrypts, executes script, generates attestation document
6. Enclave returns result + AWS Nitro attestation (COSE_Sign1)
7. Enclave deletes private key from memory (single-use session)
```

## Per-Operation Timing

All operations are instrumented and returned in the response `timing` field:

| Operation | Typical | Description |
|-----------|---------|-------------|
| `decrypt_zip_ms` | ~49ms | RSA-OAEP key + AES-CBC data decryption |
| `decrypt_csv_ms` | ~48ms | CSV payload decryption |
| `script_execution_ms` | ~158ms | Python subprocess execution |
| `attestation_generation_ms` | ~9ms | NSM ioctl + CBOR serialization |

## API Operations

Communication uses VSock with auto-detected framing (length-prefix or raw JSON).

### Generate RSA Keypair
```json
{"operation": "generate_rsa_keypair", "job_id": "job-123"}
```

### Execute Script (RSA Hybrid)
```json
{"operation": "execute_script_rsa_hybrid", "session_id": "rsa-session-...", "encrypted_data": "base64...", "encrypted_csv": "base64..."}
```

### Health Check
```json
{"operation": "health_check"}
```

### Get Attestation
```json
{"operation": "get_attestation", "user_data": "optional", "nonce": "optional"}
```

### Get Enclave Info
```json
{"operation": "get_enclave_info"}
```

## Configuration

All settings can be overridden via environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `VSOCK_PORT` | 5005 | VSock port for communication |
| `MAX_REQUEST_SIZE` | 10MB | Maximum request size |
| `LOG_LEVEL` | INFO | Logging level |
| `EXECUTION_TIMEOUT` | 300 | Script execution timeout (seconds) |
| `SESSION_TTL` | 3600 | Session time-to-live (seconds) |
| `CLEANUP_INTERVAL` | 300 | Session cleanup interval (seconds) |
| `DEFAULT_KEY_SIZE` | 2048 | Default RSA key size |
| `MAX_MEMORY_MB` | 512 | Max memory for script execution |
| `MAX_OUTPUT_SIZE_MB` | 50 | Max script output size |
| `CLIENT_RECV_TIMEOUT` | 300 | Socket receive timeout (seconds) |
| `CLIENT_SEND_TIMEOUT` | 60 | Socket send timeout (seconds) |
| `MAX_ZIP_ENTRIES` | 500 | Max files in ZIP bundle |
| `MAX_ZIP_TOTAL_SIZE` | 200MB | Max extracted ZIP size |

## Versioning

This project uses [release-please](https://github.com/googleapis/release-please) for automated versioning and changelog generation:

1. PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/) (enforced by CI)
2. PRs are squash-merged into `main`
3. `release-please` opens a release PR that bumps the version and updates `CHANGELOG.md`
4. Merging the release PR creates a GitHub release, which triggers the image build and push to GHCR

Image: `ghcr.io/epsilon-data/epsilon-enclave:<version>`

## PCR Verification

Each version produces deterministic PCR values (SHA-384 hashes). Same Docker image always produces the same PCR values on any machine.

| PCR | What it measures |
|-----|-----------------|
| PCR0 | Hash of the enclave image (EIF) |
| PCR1 | Hash of the Linux kernel and boot ramfs |
| PCR2 | Hash of the application code and dependencies |

To verify an enclave is running the expected code, compare the PCR values in the attestation document against the published values for that version.

## Deploy on EC2

```bash
# Pull image
docker pull ghcr.io/epsilon-data/epsilon-enclave:1.0.0

# Build EIF (outputs PCR values)
nitro-cli build-enclave --docker-uri ghcr.io/epsilon-data/epsilon-enclave:1.0.0 --output-file epsilon-enclave.eif

# Start enclave
nitro-cli run-enclave --eif-path epsilon-enclave.eif --memory 4096 --cpu-count 2 --enclave-cid 18

# Verify it's running
nitro-cli describe-enclaves
```

## Local Development

```bash
pip install -r requirements.txt
python scripts/local-test-server.py
```

The local test server binds to `127.0.0.1:5005` using TCP instead of VSock, so you can develop and test without an EC2 instance.

To run the end-to-end test:

```bash
# Terminal 1: start the server
python scripts/local-test-server.py

# Terminal 2: run the test client
python scripts/test-client.py
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, commit conventions, and PR process.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

[Apache License 2.0](LICENSE)
