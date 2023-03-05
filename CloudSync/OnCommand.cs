using NBitcoin;
using NBitcoin.Protocol;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using static CloudSync.Util;

namespace CloudSync
{
    public partial class Sync
    {
        private int OnCommandRunning;
        public bool CommandIsRunning => OnCommandRunning > 0;

        internal void OnCommand(ulong? fromUserId, ushort command, params byte[][] values)
        {
            OnCommandRunning++;
            OnCommand(fromUserId, (Commands)command, values);
            OnCommandRunning--;
        }
        public DateTime LastCommunicationReceived { get; private set; }
        private void OnCommand(ulong? fromUserId, Commands command, params byte[][] values)
        {
            LastCommunicationReceived = DateTime.UtcNow;
            RaiseOnCommandEvent(command, fromUserId);
            Debug.WriteLine("IN " + command);
            if (command == Commands.RequestOfAuthentication)
            {
                // The server receives an access request, sends random data to the client to start a cryptographic problem that the client can solve only if it knows the pin
                var host = values.Length > 0 ? Encoding.ASCII.GetString(values[0]) : null;
                var userAgent = values.Length > 1 ? Encoding.ASCII.GetString(values[1]) : null;
                RoleManager.LoginRequest((client, random) => Authentication(fromUserId, random), null, fromUserId, host, userAgent);
            }
            else if (command == Commands.Authentication)
            {
                if (IsServer)
                {
                    // The server must check if the client knows the PIN (If it has solved the cryptographic problem then the PIN is known)
                    if (RoleManager.TryToGetCient((ulong)fromUserId, out var client, out var isTemp))
                    {
                        if (client.Authenticate(values[0]))
                        {
                            if (isTemp)
                                Console.WriteLine("New client connected " + fromUserId);

                            Notification(fromUserId, Notice.LoginSuccessful);
                        }
                        else
                        {
                            Notification(fromUserId, Notice.LoginError);
                        }
                    }
                }
                else
                {
                    // The client must prove that they know the PIN by solving a cryptographic problem
                    if (Credential != null)
                    {
                        var Client = new Client(this, (ulong)fromUserId);
                        var proof = RoleManager.CryptographicProofOfPinKnowledge(values[0], Credential.Pin);
                        Authentication(fromUserId, proof.GetBytes());
                        Credential = null;
                    }
                }
            }
            else
            {
                if (RoleManager.TryToGetCient((ulong)fromUserId, out var Interlocutor, out var isTemp))
                {
                    RefreshCheckSyncTimer(); // Reset the timer that checks the synchronization (This is an additional verification check)
                    if (command == Commands.Notification)
                    {
                        var notice = (Notice)values[0][0];
                        if (!IsServer)
                        {
                            if (notice == Notice.LoginSuccessful)
                            {
                                Context.SecureStorage.Values.Set("Logged", true);
                                StartSyncClient();
                            }
                        }
                        if (notice == Notice.Synchronized)
                            RaiseOnStatusChangesEvent(SynchronizationStatus.Synchronized);
                        if (OnNotification != null)
                            new Thread(() => OnNotification?.Invoke(fromUserId, notice)).Start();
                    }
                    else if (command == Commands.SendHashStructure)
                    {
                        var structure = values[0];
                        var remoteHashes = new Dictionary<ulong, uint>(); // key = hash, value = timestamp
                        var hash8 = new byte[8];
                        var timestamp4 = new byte[4];
                        for (var offset = 0; offset < structure.Length; offset += 12)
                        {
                            Buffer.BlockCopy(structure, offset, hash8, 0, 8);
                            Buffer.BlockCopy(structure, offset + 8, timestamp4, 0, 4);
                            remoteHashes.Add(BitConverter.ToUInt64(hash8, 0), BitConverter.ToUInt32(timestamp4, 0));
                        }
                        var delimitsRange = values.Length == 1 ? null : new BlockRange(values[1], values[2], values[3], values[4]);
                        if (HashFileTable(out var localHashes, delimitsRange: delimitsRange))
                        {
                            if (localHashes != null)
                            {
                                //Update file
                                foreach (var hash in remoteHashes.Keys)
                                {
                                    if (localHashes.TryGetValue(hash, out var dateTime))
                                    {
                                        var remoteDate = remoteHashes[hash];
                                        var localDate = dateTime.UnixLastWriteTimestamp();
                                        if (remoteDate > localDate)
                                        {
                                            Spooler.AddOperation(Spooler.OperationType.Request, fromUserId, hash);
                                            //RequestFile(fromUserId, hash);
                                        }
                                        else if (remoteDate < localDate)
                                        {
                                            Spooler.AddOperation(Spooler.OperationType.Send, fromUserId, hash);
                                            //SendFile(fromUserId, localHashes[hash]);
                                        }
                                    }
                                }
                                // Send missing files to the remote (or delete local if is removed)
                                foreach (var hash in localHashes.Keys)
                                {
                                    if (!remoteHashes.ContainsKey(hash))
                                    {
                                        Spooler.AddOperation(Spooler.OperationType.Send, fromUserId, hash);
                                    }
                                }

                                // Request missing files locally
                                foreach (var hash in remoteHashes.Keys)
                                {
                                    var wasDeleted = Existed(hash);
                                    if (!localHashes.ContainsKey(hash) && !Existed(hash))
                                    {
                                        Spooler.AddOperation(Spooler.OperationType.Request, fromUserId, hash);
                                    }
                                }
                            }
                        }
                    }
                    else if (command == Commands.RequestHashStructure)
                    {
                        var delimitsRange = values.Length == 0 ? null : new BlockRange(values[0], values[1], values[2], values[3]);
                        SendHashStructure(fromUserId, delimitsRange);
                    }
                    else if (command == Commands.SendHashBlocks)
                    {
                        var remoteHash = values[0];
                        if (GetHasBlock(out var localHash))
                        {
                            if (!remoteHash.SequenceEqual(localHash))
                            {
                                RaiseOnStatusChangesEvent(SynchronizationStatus.Pending);
                                var range = HashBlocksToBlockRange(remoteHash, localHash);
                                if (IsServer)
                                    SendHashStructure(fromUserId, range);
                                else
                                    RequestHashStructure(fromUserId, range);
                            }
                            else
                            {
                                RaiseOnStatusChangesEvent(SynchronizationStatus.Synchronized);
                                Notification(fromUserId, Notice.Synchronized);
                            }
                        }
                    }
                    else if (command == Commands.SendHashRoot)
                    {
                        if (GetHasRoot(out var hashRoot))
                        {
                            var localHash = BitConverter.ToUInt64(hashRoot, 0);
                            var remoteHash = BitConverter.ToUInt64(values[0], 0);
                            if (localHash != remoteHash)
                            {
                                RaiseOnStatusChangesEvent(SynchronizationStatus.Pending);
                                SendHashBlocks(fromUserId);
                                //SendHashStructure(fromUserId);
                            }
                            else
                            {
                                RaiseOnStatusChangesEvent(SynchronizationStatus.Synchronized);
                                Notification(fromUserId, Notice.Synchronized);
                            }
                        }
                    }
                    else if (command == Commands.RequestChunkFile)
                    {
                        if (HashFileTable(out var hashDirTable))
                        {
                            var hash = BitConverter.ToUInt64(values[0], 0);
                            if (hashDirTable.TryGetValue(hash, out var fileSystemInfo))
                            {
                                var chunkPart = BitConverter.ToUInt32(values[1], 0);
                                SendChunkFile(fromUserId, fileSystemInfo, chunkPart);
                            }
                        }
                    }
                    else if (command == Commands.SendChunkFile)
                    {
                        var hashFileName = BitConverter.ToUInt64(values[0], 0);
                        var part = BitConverter.ToUInt32(values[1], 0);
                        var total = BitConverter.ToUInt32(values[2], 0);
                        var data = values[3];
                        var tmpFile = GetTmpFile(this, fromUserId, hashFileName);
                        var crcId = (ulong)fromUserId ^ hashFileName;
                        Debug.WriteLine("IN #" + part + "/" + total);

                        lock (CrcTable)
                        {
                            if (part == 1)
                            {
                                FileDelete(tmpFile, out Exception ex);
                                if (ex != null)
                                    RaiseOnFileError(ex, tmpFile);
                                CrcTable[crcId] = startCrc;
                            }
                            else
                            {
                                if (!(File.Exists(tmpFile)))
                                    return;
                            }
                            if (!CrcTable.ContainsKey(crcId))
                                Debugger.Break();
                            CrcTable[crcId] = ULongHash(CrcTable[crcId], data);
                        }
                        if (!FileAppend(tmpFile, data, out Exception exception, 10, 50, DefaultChunkSize, part))
                        {
                            if (exception != null)
                                RaiseOnFileError(exception, tmpFile);
                            return;
                        }

                        if (part == total)
                        {
                            var length = values[5].ToUint32();
                            var expectedCrc = BitConverter.ToUInt64(values[7], 0);
                            if (expectedCrc == CrcTable[crcId] && new FileInfo(tmpFile).Length.Equals(length)) // Use the length to check if the file was received correctly
                            {
                                var target = FullName(values[6]);
                                var unixTimestamp = values[4].ToUint32();
                                TotalFilesReceived++;
                                TotalBytesReceived += length;
                                if (File.Exists(target))
                                {
                                    if (new FileInfo(target).UnixLastWriteTimestamp() > unixTimestamp)
                                        return;
                                    FileDelete(target, out Exception exception1);
                                    if (exception1 != null)
                                        RaiseOnFileError(exception1, target);
                                }
                                else
                                {
                                    var targetDirectory = new FileInfo(target).Directory;
                                    DirectoryCreate(targetDirectory.FullName, out Exception exception1);
                                    if (exception1 != null)
                                        RaiseOnFileError(exception1, targetDirectory.FullName);
                                }
                                FileMove(tmpFile, target, out Exception exception2);
                                if (exception2 != null)
                                    RaiseOnFileError(exception2, target);
                                var fileInfo = new FileInfo(target);
                                fileInfo.LastWriteTimeUtc = UnixTimestampToDateTime(unixTimestamp);
                                RaiseOnFileTransfer(false, hashFileName, part, total, target, (int)length);
                            }
                            else
                            {
                                // Debugger.Break();
                                FileDelete(tmpFile, out Exception exception1);
                                if (exception1 != null)
                                    RaiseOnFileError(exception1, tmpFile);
                            }
                            CrcTable.Remove(crcId);
                            ReportReceiptFileCompleted(fromUserId, hashFileName, total);
                        }
                        else
                        {
                            RaiseOnFileTransfer(false, hashFileName, part, total);
                            RequestChunkFile(fromUserId, hashFileName, part + 1);
                        }
                    }
                    else if (command == Commands.DeleteFile)
                    {
                        var hash = values[0].ToUint64();
                        var timestamp = values[1].ToUint32();
                        if (HashFileTable(out var hashDirTable))
                        {
                            if (hashDirTable.TryGetValue(hash, out var fileInfo))
                            {
                                if (fileInfo.UnixLastWriteTimestamp() == timestamp)
                                {
                                    FileDelete(fileInfo.FullName, out Exception exception);
                                    if (exception != null)
                                        RaiseOnFileError(exception, fileInfo.FullName);
                                    hashDirTable.Remove(hash);
                                }
                            }
                        }
                    }
                    else if (command == Commands.CreateDirectory)
                    {
                        var fullDirectoryName = FullName(values[0]);
                        DirectoryCreate(fullDirectoryName, out Exception exception);
                        if (exception != null)
                            RaiseOnFileError(exception, fullDirectoryName);
                        var hash = HashFileName(values[0].ToText(), true);
                        ReceptionInProgress.Completed(hash);
                        StatusNotification(fromUserId, false);
                    }
                    else if (command == Commands.DeleteDirectory)
                    {
                        var fullDirectoryName = FullName(values[0]);
                        DirectoryDelete(fullDirectoryName, out Exception exception);
                        if (exception != null)
                            RaiseOnFileError(exception, fullDirectoryName);
                    }
                    else if (command == Commands.StatusNotification)
                    {
                        var busy = values[0][0] == 1;
                        if (!IsServer && busy == false)
                        {
                            Spooler.ExecuteNext(fromUserId);
                            //StartSynchronization(null, null);
                        }
                    }
                }
            }
        }
        public uint TotalFilesReceived;
        public uint TotalBytesReceived;
        public readonly ProgressFileTransfer ReceptionInProgress;
        private static readonly Dictionary<ulong, ulong> CrcTable = new Dictionary<ulong, ulong>();
        private string FullName(byte[] unixRelativeName)
        {
            var text = unixRelativeName.ToText();
            return Path.Combine(CloudRoot, text.Replace('/', Path.DirectorySeparatorChar));
        }
    }
}
