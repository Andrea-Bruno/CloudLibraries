# CloudSync – System Overview

## Purpose

**CloudSync** is a high-performance, binary-protocol file synchronization library. It monitors local and remote file systems and keeps them in sync in real time between a cloud client and a cloud server, using the **EncryptedMessaging** stack for secure, authenticated transport.

CloudSync sits above `CloudBox` in the dependency chain and provides the actual file-difference detection, scheduling, and transfer logic.

## Architecture

```
CloudBox (cloud instance management)
    │
    ▼
CloudSync (sync engine)
    │
    ├── Sync.cs            – core diff & schedule logic
    ├── HashFileTable.cs   – fast hash-based file index
    ├── Spooler.cs         – transfer queue
    ├── FileIO.cs          – file read/write with retry
    ├── Commands.cs        – binary command definitions
    ├── OnCommand.cs       – incoming command dispatcher
    ├── OnCommandExecute.cs – command execution
    ├── Events.cs          – typed event surface
    ├── RoleManager.cs     – user role management
    ├── LoginCredential.cs – credential handling
    └── TwoFactAuth.cs     – 2-factor authentication
            │
            ▼
    EncryptedMessaging  ──► CommunicationChannel (TCP)
```

## Synchronization Algorithm

1. Both client and server build a `HashFileTable` (file path → CRC hash).
2. The client computes the difference set between local and remote tables.
3. Differences are added to the `Spooler` as ordered transfer operations.
4. The spooler executes uploads / downloads; failed items are retried automatically.
5. `CloudRootWatcher` (file-system watcher) triggers incremental syncs when local files change.

## Event System

CloudSync fires strongly-typed events that consuming applications can subscribe to:

| Event category | Description |
|---|---|
| Sync status | `SyncStatus` changes (Pending, InProgress, Synchronized) |
| File transfer progress | Bytes transferred, file name, direction |
| I/O events | Send/receive raw command events |
| File errors | Per-file error notifications |
| Antivirus alerts | Infected file detected during sync |

## Role Management

`RoleManager` supports multiple user roles with different access levels (read-only, read-write, admin). Roles are enforced server-side.

## Two-Factor Authentication

`TwoFactAuth` implements TOTP-based 2FA for additional login security.

## Zero-Knowledge Proof

`ZeroKnowledgeProof.cs` allows a client to prove identity to the server without transmitting the private key.

## Target Framework

**.NET Standard 2.1**
