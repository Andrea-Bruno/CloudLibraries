# CloudBox – Developer Guide

## Creating a Cloud Client Instance

```csharp
using CloudBox;

var cloud = new CloudBox(
	cloudPath: "/home/user/MyCloud"
);

// Subscribe to sync events
cloud.OnLocalSyncStatusChangesActionList.Add((status, pending) =>
	Console.WriteLine($"Status: {status}, pending: {pending}"));

// Connect (uses stored or provided credentials)
cloud.Connect();
```

## Creating a Cloud Server Instance

A server instance is created the same way. The `CloudServer` companion library adds server-specific features (thumbnail generation, proxy, encrypted API exposure):

```csharp
// CloudBox itself handles the symmetric protocol.
// Add the CloudServer package for full server functionality.
var server = new CloudBox(cloudPath: "/srv/cloud");
server.StartServer();
```

## Digital Signature

Sign a file using the instance's private key:

```csharp
byte[] signature = cloud.DigitalSignature.Sign(fileBytes);
bool valid = cloud.DigitalSignature.Verify(fileBytes, signature, signerPublicKey);
```

## Sub-Clouds

```csharp
var subCloud = cloud.CreateSubCloud("projects");
// subCloud behaves as an independent cloud area
```

## OnCommand Handling

Register custom binary command handlers:

```csharp
cloud.OnCommandList.Add((command, data, context) =>
{
	if (command == MyCommands.CustomSync)
	{
		// handle
		return true; // consumed
	}
	return false; // pass to next handler
});
```

## Client-Server Commands

`ClientServerCommands.cs` defines the binary command vocabulary. Each command is a `byte` constant. Use `Commands` enum from CloudSync for standard operations.

## File Transfer Progress

```csharp
cloud.OnProgressFileTransferEvent += (file, transferred, total, isUpload) =>
{
	Console.WriteLine($"{file}: {transferred}/{total}");
};
```

## Encryption Layer (XorAB)

`EncryptionXorAB` provides an additional XOR obfuscation layer applied before AES encryption for extra defence in depth. This is handled automatically; no application-level intervention is needed.

## Building

```powershell
dotnet build ..\CloudBox\CloudLibraries\CloudBox\CloudBox.csproj
```
