# CloudBox – System Overview

## Purpose

**CloudBox** is the symmetric, multi-purpose cloud library that can instantiate both **cloud clients** and **cloud servers** from a single codebase. It abstracts the creation and lifecycle management of cloud instances and provides the complete feature set needed for a private cloud storage system.

"Symmetric" means the same library code powers both ends of the connection — client and server share the same cryptographic model, the same command protocol, and the same identity system.

## Architecture

```
Application (Cloud / CloudClient)
	│
	▼
CloudBox  (instance manager)
	│
	├── CloudSync  (file synchronization engine)
	│       └── HashFileTable, Spooler, Commands, Events
	│
	├── EncryptedMessaging  (identity + AES-256 messaging)
	│       └── CommunicationChannel (TCP socket / custom transport)
	│
	├── DigitalSignature  (document signing with private key)
	├── EncryptionXorAB   (additional XOR encryption layer)
	├── FileTransferList  (transfer queue management)
	└── OnCommandList     (incoming command handler registry)
```

## Key Features

| Feature | Description |
|---|---|
| **Hot instantiation** | Create/destroy cloud instances at runtime without restart |
| **Symmetric client/server** | Same library, same API for both roles |
| **Bitcoin-based identity** | Key-pair from BIP39 passphrase; no user accounts on server |
| **Encrypted binary protocol** | Minimalistic binary packets, no JSON/XML overhead |
| **QR-code pairing** | Server QR code scanned by client to establish the encrypted connection |
| **Digital signatures** | All sync packets are signed; documents can be signed with the private key |
| **Sub-clouds** | Logical sub-cloud areas can be created within a single server instance |
| **Dual transport** | Binary TCP socket (performance) + encrypted REST API (compatibility) |

## Identity & Security

- Each instance (client or server) is created with a BIP39 passphrase → ECDSA key-pair.
- The private key never leaves the device (`SecureStorage` prevents extraction).
- The server is identified by a QR code containing its public key.
- The client must authenticate with a PIN derived from the server's public key.
- All sync data is AES-256 encrypted + ECDSA signed in transit.

## Communication Protocols

### Binary TCP Socket
The primary protocol. Packets are length-prefixed binary frames carrying encrypted command + payload. Zero overhead; optimal for LAN and fast internet connections.

### Encrypted REST API
An HTTP-based alternative that adds an encryption tunnel on top of HTTPS. Useful when TCP is blocked by firewalls. The server side is provided by the companion `CloudServer` library.

## Target Framework

**.NET Standard 2.1**
