# Epsilon Enclave

Secure execution environment running inside an AWS Nitro Enclave. Handles encrypted data ingestion, script execution, and attestation document generation.

## Architecture

```
epsilon-enclave/
├── interfaces/           # Abstract interfaces (contracts)
│   ├── request_handler_interface.py
│   ├── decrypt_interface.py
│   ├── execute_interface.py
│   └── keypair_interface.py
├── implementations/      # Concrete implementations
│   ├── request_handler_impl.py
│   ├── decrypt_service_impl.py
│   ├── execute_service_impl.py
│   ├── attestation_service_impl.py
│   └── keypair_manager_impl.py
├── server/              # VSock server
│   └── server.py
├── scripts/             # Build & deploy scripts
│   ├── deploy-ec2.sh    # Pull, build EIF, register PCRs, start
│   ├── push-to-ghcr.sh  # Build & push multi-arch image
│   ├── build-enclave.sh
│   └── run-enclave.sh
├── .github/workflows/   # CI/CD
│   └── build-enclave.yml # Auto-version, build, push to GHCR
├── VERSION              # Current version (auto-bumped by CI)
├── config.py            # Configuration
├── factory.py           # Dependency injection factory
├── main.py              # Entry point
├── Dockerfile           # Container definition
└── requirements.txt     # Python dependencies
```

## Execution Flow

```
1. Coordinator requests public key from enclave (VSock CID 18)
2. Enclave generates RSA keypair, returns public key
3. Coordinator encrypts data with public key (hybrid: AES-256-CBC + RSA-OAEP)
4. Coordinator sends encrypted bundle to enclave
5. Enclave decrypts, executes script, generates attestation document
6. Enclave returns result + AWS Nitro attestation (COSE_Sign1)
```

## Per-Operation Timing

All operations are instrumented and returned in the response `timing` field:

| Operation | Typical | Description |
|-----------|---------|-------------|
| `decrypt_zip_ms` | ~45ms | RSA-OAEP key + AES-CBC data decryption |
| `decrypt_csv_ms` | ~45ms | CSV payload decryption |
| `script_execution_ms` | ~33ms | Python subprocess execution |
| `attestation_generation_ms` | ~9ms | NSM ioctl + CBOR serialization |

## Versioning

Version is managed in the `VERSION` file and auto-bumped on every push to `main`:

- CI workflow reads `VERSION`, bumps patch, commits, tags, builds and pushes to GHCR
- Image: `ghcr.io/epsilon-data/epsilon-enclave:<version>`
- Each version produces unique PCR values (SHA-384 hashes of the enclave image)

### Current PCR Values (v1.1.0)

```
PCR0: 78e341a193ca5c138b4f3c7f134e9ae7f09f519ae8bc01b858223965f5666987adeacb1281f7150b79ff2142f70fc522
PCR1: 4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493
PCR2: f709ec700918e00db8d6e11efdb297f03384805869ea6354330ffb5fde7e3a0cb9bbbce815cdc1f79478687ad29f207f
```

## Deploy on EC2

```bash
# Pull image, build EIF, register PCRs in DB, start enclave
./scripts/deploy-ec2.sh 1.1.0
```

Or manually:

```bash
docker pull ghcr.io/epsilon-data/epsilon-enclave:1.1.0
nitro-cli build-enclave --docker-uri ghcr.io/epsilon-data/epsilon-enclave:1.1.0 --output-file epsilon-enclave.eif
nitro-cli run-enclave --eif-path epsilon-enclave.eif --memory 4096 --cpu-count 2 --enclave-cid 18
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VSOCK_PORT` | 5000 | VSock port for communication |
| `MAX_REQUEST_SIZE` | 10MB | Maximum request size |
| `LOG_LEVEL` | INFO | Logging level |
| `EXECUTION_TIMEOUT` | 300 | Script execution timeout (seconds) |
| `SESSION_TTL` | 3600 | Session time-to-live (seconds) |
| `DEFAULT_KEY_SIZE` | 2048 | Default RSA key size |

## API Operations

### Generate Keypair
```json
{"operation": "generate_keypair", "job_id": "job-123"}
```

### Execute Script (RSA Hybrid)
```json
{"operation": "execute_script_rsa_hybrid", "session_id": "rsa-session-...", "encrypted_data": "base64...", "encrypted_csv": "base64..."}
```

### Health Check
```json
{"operation": "health"}
```

## License

Private - Epsilon Platform
