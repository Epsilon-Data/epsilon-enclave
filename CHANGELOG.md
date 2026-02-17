# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0 (2026-02-17)


### Features

* v2.0.0 - code quality overhaul and open source preparation ([9e30d82](https://github.com/Epsilon-Data/epsilon-enclave/commit/9e30d82e6bec3ecd3d9381890888ed57676beca6))


### Bug Fixes

* add pull-requests read permission to pr-title workflow ([2932023](https://github.com/Epsilon-Data/epsilon-enclave/commit/293202350976664fc127f0380e031f10129cd05b))

## [Unreleased]

### Removed

- Direct database access feature (`ENABLE_DIRECT_DB`) and all gvforwarder/gvproxy networking
- `EnclaveDatabaseService` and `CsvGenerator` implementations
- `psycopg2-binary` dependency
- `start.sh` (redundant with Dockerfile CMD)
- `P384EncryptionService` (unused dead code)

### Changed

- Server now handles concurrent connections via threading
- Request framing uses 4-byte length-prefix protocol (with raw JSON fallback)
- Responses sent with `sendall()` instead of `send()` to prevent truncation
- ZIP extraction validates entry count, total size, and path traversal
- Script validation uses AST-based call analysis instead of string matching
- Script validation now runs on bundle execution (primary code path)
- Execution limits read from `config.py` instead of hardcoded values
- `subprocess.run()` uses `cwd=` parameter instead of `os.chdir()`
- Keypair manager is now thread-safe with `threading.Lock`
- Expired sessions are purged by background cleanup thread

### Fixed

- Missing `Fernet` import in decrypt service (`decrypt_csv_data` would crash)
- `validate_request()` now called before operation dispatch
- `get_session()` called nonexistent `get_keypair_metadata()` method
- Bare `except:` clauses replaced with specific exception types
- Socket timeout added to prevent hung server on stuck clients
- Orphaned temp directory leak in `setup_execution_environment()`

## [1.1.0] - 2026-02-08

### Added

- AWS Nitro attestation via direct `/dev/nsm` ioctl (CBOR COSE_Sign1)
- Execution attestation with output hash, timing metadata, and verification guide
- KMS attestation service using `kmstool_enclave_cli`
- PCR registry (`published/pcr-registry.json`) for enclave image verification
- CI/CD workflow for auto-versioning, Docker build, and GHCR push
- Deploy script for EC2 with EIF build and PCR extraction

### Changed

- Decryption uses combined hybrid format: `[encrypted_key][iv][ciphertext]`

## [1.0.0] - 2026-02-01

### Added

- Initial release
- Clean architecture with interfaces (`IRequestHandler`, `IDecryptService`, `IExecuteService`, `IKeyPairManager`)
- Factory pattern for dependency injection
- RSA-OAEP + AES-256-CBC hybrid encryption/decryption
- Secure Python script execution in subprocess with timeout and resource limits
- ZIP bundle extraction and execution with CSV data injection
- Session-based RSA keypair management with TTL expiration
- VSock server for AWS Nitro Enclave communication
- Multi-stage Dockerfile building all AWS dependencies from source
