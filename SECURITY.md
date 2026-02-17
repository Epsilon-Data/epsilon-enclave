# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in epsilon-enclave, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@epsilon-data.com** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and provide a timeline for a fix.

## Scope

The following are in scope for security reports:

- Enclave escape or isolation bypass
- Cryptographic weaknesses (RSA, AES, attestation)
- Script sandbox escape (executing code outside allowed imports/operations)
- Private key leakage from enclave memory
- Attestation forgery or bypass
- ZIP extraction vulnerabilities (path traversal, zip bombs)

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | No — upgrade to the latest version |

## Disclosure Policy

- We follow coordinated disclosure. We ask that you give us 90 days to address the issue before public disclosure.
- We will credit reporters in the CHANGELOG unless they prefer to remain anonymous.
