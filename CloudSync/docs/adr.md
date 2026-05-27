# CloudSync – Architecture Decision Records

## ADR-001: Binary Protocol Over JSON/XML

**Date**: 2024  
**Status**: Accepted

### Context
Cloud sync between client and server involves frequent small commands (file hash checks, change notifications, transfer progress). JSON or XML would add significant framing overhead and parsing cost.

### Decision
Use a custom **minimalistic binary protocol** for all client-server communication. Each command is a byte constant followed by a length-prefixed binary payload.

### Consequences
- **Positive**: minimal bandwidth; fast parsing; optimal for mobile/metered connections.
- **Negative**: not human-readable; requires binary tooling to inspect traffic.

---

## ADR-002: Hash-Based Differential Sync

**Date**: 2024  
**Status**: Accepted

### Context
Scanning a directory with hundreds of thousands of files must be fast, and only changed files should be transferred.

### Decision
Maintain a `HashFileTable` on both client and server. At sync time, compute the symmetric difference of the two tables. Only differing entries are added to the `Spooler`.

### Consequences
- **Positive**: O(n) diff computation; scales to 100k+ files without performance degradation.
- **Positive**: resilient to partial transfers: if a transfer is interrupted, only the missing file is re-queued.
- **Negative**: initial `HashFileTable` build on large file systems takes time.

---

## ADR-003: Spooler with Auto-Retry

**Date**: 2024  
**Status**: Accepted

### Context
Network interruptions during file transfers should not require manual intervention. The sync should resume seamlessly.

### Decision
All transfer operations are queued in a `Spooler`. Failed operations are automatically re-enqueued after a back-off delay.

### Consequences
- **Positive**: zero manual intervention on transient failures.
- **Positive**: on reconnect, sync resumes from exactly the point of failure.
- **Negative**: persistent errors (e.g., deleted remote file) require error-event handling by the application.

---

## ADR-004: Role-Based Access Control

**Date**: 2024  
**Status**: Accepted

### Context
A cloud server may serve multiple users with different access requirements (read-only guests, read-write collaborators, administrators).

### Decision
Implement a `RoleManager` that assigns roles (read-only, read-write, admin) per user, enforced server-side on every command.

### Consequences
- **Positive**: fine-grained access control without a separate auth server.
- **Negative**: role changes require the client to reconnect.
