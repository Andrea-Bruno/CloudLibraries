# CloudSync – Security Policy

## Security Model

CloudSync relies entirely on the **EncryptedMessaging** layer for security. By itself, CloudSync transfers binary commands and file data that are already AES-256-GCM encrypted and ECDSA-521 signed before reaching the transport.

### What CloudSync Adds

| Feature | Security relevance |
|---|---|
| **Role-Based Access Control** | Server-side enforcement prevents unauthorised file access |
| **Zero-Knowledge Proof** | Client proves identity without transmitting the private key |
| **Two-Factor Authentication** | TOTP adds a second factor to login |
| **Digital signatures on sync packets** | Every sync command is signed; tampering is detected |

## Threat Model

| Threat | Mitigation |
|---|---|
| Unauthorised file access | RBAC + ZKP-based authentication |
| Packet injection during sync | ECDSA-521 signatures (via EncryptedMessaging) |
| Credential theft | Private key never leaves the device (SecureStorage) |
| Brute-force login | TOTP + exponential back-off on failed attempts |
| Antivirus evasion | Files scanned at sync time before being written to local storage |

## Reporting a Vulnerability

1. **Do not** open a public GitHub issue.
2. Contact the maintainer privately (see repository contacts).
3. Allow up to **90 days** for a fix before public disclosure.

## Supported Versions

Only the latest released version receives security patches.
