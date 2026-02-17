# Contributing to Epsilon Enclave

Thanks for your interest in contributing! This document explains how to get started.

## Development Setup

### Prerequisites

- Python 3.8+
- Docker (for building the enclave image)

### Local Development

```bash
# Clone the repo
git clone https://github.com/epsilon-data/epsilon-enclave.git
cd epsilon-enclave

# Install dependencies
pip install -r requirements.txt

# Run the local test server (TCP, no Nitro required)
python scripts/local-test-server.py
```

The local test server binds to `127.0.0.1:5005` using TCP instead of VSock, so you can develop and test without an EC2 instance.

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/). This is **enforced on PR titles** (not individual commits).

### Format

```
<type>: <short description>
```

### Types

| Type | When to use | Version bump |
|------|------------|--------------|
| `feat` | New feature | Minor (1.x.0) |
| `fix` | Bug fix | Patch (1.0.x) |
| `docs` | Documentation only | None |
| `refactor` | Code change that neither fixes a bug nor adds a feature | None |
| `test` | Adding or updating tests | None |
| `chore` | Build, CI, dependency updates | None |
| `feat!` or `fix!` | Breaking change (append `!`) | Major (x.0.0) |

### Examples

```
feat: add P-384 ECDH encryption support
fix: prevent ZIP path traversal in bundle extraction
docs: add attestation verification guide
refactor: replace os.chdir with subprocess cwd parameter
chore: upgrade cryptography to 42.0.0
feat!: change response framing to length-prefix protocol
```

### How it works

1. You make commits with any message style in your feature branch
2. Your **PR title** must follow conventional commit format
3. PRs are **squash-merged** into `main`, so the PR title becomes the commit message
4. `release-please` reads those commits and automatically determines the version bump and generates the changelog

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Ensure your code works with the local test server
4. Open a PR with a conventional commit title
5. The PR title CI check must pass
6. A maintainer will review and merge

## Architecture

Before making changes, understand the clean architecture:

```
interfaces/     <- Abstract contracts (do not modify lightly)
implementations/ <- Concrete implementations (most changes go here)
server/         <- VSock transport layer
factory.py      <- Dependency injection wiring
config.py       <- All configuration with env var overrides
```

### Key principles

- **Interface-first**: New capabilities should be defined in interfaces before implementation
- **No hardcoded values**: All limits and settings go in `config.py` with env var overrides
- **Thread-safe**: The server handles concurrent connections; shared state needs locking
- **Subprocess isolation**: User scripts run in subprocess with `cwd=` pointing to a temp directory

## Security

This is a Trusted Execution Environment. Security-sensitive areas:

- **Script validation** (`execute_service_impl.py`): AST-based import/call analysis
- **ZIP extraction** (`execute_service_impl.py`): Path traversal and zip bomb protection
- **Key management** (`keypair_manager_impl.py`): In-memory private keys with TTL
- **Attestation** (`attestation_service_impl.py`): Direct `/dev/nsm` ioctl

If you find a security issue, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
