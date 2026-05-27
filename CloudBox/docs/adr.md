# CloudBox – Architecture Decision Records

## ADR-001: Symmetric Client/Server Library

**Date**: 2024  
**Status**: Accepted

### Context
Traditional cloud storage requires separate codebases for client and server, doubling maintenance effort and making it hard to create hybrid nodes (a machine that is both a client of one server and a server for other clients).

### Decision
`CloudBox` is a **symmetric library**: the same NuGet package and the same API surface are used for both client and server instances. The role (client vs. server) is determined at runtime when the instance is created.

### Consequences
- **Positive**: single codebase; consistent behaviour; hybrid nodes trivially supported.
- **Positive**: reduces the attack surface (server and client share the same audited code).
- **Negative**: the library is larger than a dedicated client or server would be.

---

## ADR-002: Bitcoin-Derived Identity (No User Accounts)

**Date**: 2024  
**Status**: Accepted

### Context
Centralised user account databases are a prime target for breaches. A cloud server with a user database can be compelled by authorities or hacked.

### Decision
Adopt the Bitcoin wallet model: identity = BIP39 passphrase → ECDSA key-pair. No user accounts on the server. The server stores only the client's public key as an authorisation token.

### Consequences
- **Positive**: no account database to breach.
- **Positive**: account recovery is fully client-side (passphrase).
- **Negative**: losing the passphrase = permanent loss of access (no account recovery via a third party).

---

## ADR-003: QR Code Pairing

**Date**: 2024  
**Status**: Accepted

### Context
The client needs to securely learn the server's public key without an out-of-band trust anchor (no certificate authority).

### Decision
The server generates a QR code containing its public key. The client scans it once to establish the pairing. All subsequent connections are authenticated with this key.

### Consequences
- **Positive**: zero-configuration pairing with no CA dependency.
- **Positive**: the QR scan is an in-person trust establishment (physical proximity = implicit trust).
- **Negative**: if the server regenerates its key-pair, all clients must re-pair.

---

## ADR-004: Dual Transport (TCP Binary + Encrypted REST)

**Date**: 2024  
**Status**: Accepted

### Context
TCP binary sockets are optimal but may be blocked by restrictive firewalls or corporate proxies. A fallback HTTP-based transport increases deployability.

### Decision
Support two transports:
1. **TCP binary socket** – primary; minimal overhead.
2. **Encrypted REST API** – secondary; wraps the same encrypted payload over HTTPS POST requests.

### Consequences
- **Positive**: works in virtually any network environment.
- **Negative**: REST transport has higher latency and overhead.
- **Negative**: REST server-side requires the companion `CloudServer` library.
