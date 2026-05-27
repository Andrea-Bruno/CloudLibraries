# CloudSync – Developer Guide

## Integration

CloudSync is consumed indirectly through `CloudBox`. Direct use is only needed when building custom sync clients or servers.

```csharp
using CloudSync;

// CloudSync is initialized internally by CloudBox.
// Access sync operations through the CloudBox API.
```

## Sync Status Monitoring

Subscribe to status events exposed by `CloudBox`:

```csharp
cloudBox.OnLocalSyncStatusChangesActionList.Add((status, pendingFiles) =>
{
    Console.WriteLine($"Sync status: {status}, pending: {pendingFiles}");
});
```

`SyncStatus` values:

| Value | Meaning |
|---|---|
| `Undefined` | Initial / unknown state |
| `Pending` | Files waiting to be synced |
| `InProgress` | Active transfer |
| `Synchronized` | All files up-to-date |

## File Transfer Events

```csharp
cloudBox.OnProgressFileTransferEvent += (fileName, bytes, total, upload) =>
{
    int pct = (int)(bytes * 100 / total);
    Console.WriteLine($"{(upload ? "↑" : "↓")} {fileName} {pct}%");
};
```

## Credential Management

```csharp
var cred = new LoginCredential
{
    Username = "alice",
    Pin = "1234"
};
// Pass to CloudBox constructor or Set method
```

## Two-Factor Authentication

```csharp
// Generate a TOTP secret for a user
string secret = TwoFactAuth.GenerateSecret();

// Verify a TOTP code
bool valid = TwoFactAuth.Verify(secret, userCode);
```

## Hash File Table

`HashFileTable` is used internally by the sync engine. It can be inspected for diagnostics:

```csharp
var table = new HashFileTable(rootPath);
table.Build();
// table.Entries contains path → CRC mappings
```

## Building

```powershell
dotnet build ..\CloudBox\CloudLibraries\CloudSync\CloudSync.csproj
```
