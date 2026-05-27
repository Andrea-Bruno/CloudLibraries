# CloudBox – Security Policy

## Security Model

CloudBox implements the **trustless** security model derived from Bitcoin cryptography:

- **Identity** = BIP39 passphrase → ECDSA key-pair. No user accounts on any server.
- **All sync data** is AES-256-GCM encrypted and ECDSA-521 signed before leaving the device.
- **The server is zero-knowledge**: it stores and forwards only ciphertext; it cannot decrypt or tamper with data.
- **Private keys are protected** by `SecureStorage` with hardware-backed storage where available.
- **QR pairing** establishes the server's public key through physical proximity (implicit trust anchor).

## Threat Model

| Threat | Mitigation |
|---|---|
| Server breach | Server holds only ciphertext; no plaintext or private keys |
| Man-in-the-middle | ECDSA-521 signatures on all packets |
| Credential theft | Private key in SecureStorage; never transmitted |
| Rogue server | Server authenticated via QR-established public key |
| Replay attacks | Per-message ephemeral keys + timestamp validation |
| Network eavesdropping | AES-256-GCM end-to-end encryption |

## Private Key Protection

The private key is stored by `SecureStorage`. On platforms with a Secure Enclave or TPM, the key is hardware-bound and cannot be extracted even with OS-level access.

## Passphrase Responsibility

The 12/24-word BIP39 passphrase is the **sole recovery mechanism**. CloudBox does not implement server-side account recovery. Losing the passphrase = permanent loss of access.

## Reporting a Vulnerability

1. **Do not** open a public GitHub issue.
2. Contact the maintainer privately (see repository contacts).
3. Allow up to **90 days** for remediation before public disclosure.

## Supported Versions

Only the latest released version receives security patches.

## Dependency Audit

```bash
dotnet list package --vulnerable
```
