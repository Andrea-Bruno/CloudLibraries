using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static CloudSync.Util;

namespace CloudSync
{
    public partial class Sync
    {
        private int OnCommandRunning;
        public bool CommandIsRunning => OnCommandRunning > 0;

        internal void OnCommand(ulong? fromUserId, ushort command, params byte[][] values)
        {
            Task.Run(() =>
            {
                lastFromUserId = fromUserId;
                if (!Enum.IsDefined(typeof(Commands), command))
                    return; // Commend not supported from this version
                OnCommandRunning++;
                try
                {
                    OnCommand(fromUserId, (Commands)command, out string infoData, values);
                    RaiseOnCommandEvent(fromUserId, (Commands)command, infoData);
                }
                catch (Exception ex)
                {
                    RecordError(ex);
                    Debugger.Break(); // Error! Investigate the cause of the error!
                    Debug.WriteLine(ex);
                }                
                OnCommandRunning--;
            });
        }

        ulong? lastFromUserId;
#if DEBUG
        public void TestSendReady()
        {
            StatusNotification(lastFromUserId, Status.Ready);
        }
#endif

        public DateTime LastCommandReceived { get; private set; }
        private void OnCommand(ulong? fromUserId, Commands command, out string infoData, params byte[][] values)
        {
            infoData = null;
            LastCommandReceived = DateTime.UtcNow;
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
                    if (RoleManager.TryToGetClient((ulong)fromUserId, out var client, out var isTemp))
                    {
                        if (client.Authenticate(values[0]))
                        {
                            if (isTemp)
                                Console.WriteLine("New client connected " + fromUserId);

                            SendNotification(fromUserId, Notice.LoginSuccessful);
                        }
                        else
                        {
                            SendNotification(fromUserId, Notice.LoginError);
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
                if (!RoleManager.TryToGetClient((ulong)fromUserId, out var Interlocutor, out var isTemp))
                {
#if DEBUG
                    Debugger.Break(); // Client not found!
#endif
                }
                else
                {
                    RestartCheckSyncTimer(); // Reset the timer that checks the synchronization (This is an additional verification check)
                    if (command == Commands.Notification)
                    {
                        var notice = (Notice)values[0][0];
                        infoData = notice.ToString();
                        if (!IsServer)
                        {
                            if (notice == Notice.LoginSuccessful)
                                IsLogged = true;
                            else if (notice == Notice.LoginError)
                            {
                                LoginError = true;
                                OnLoginCompleted?.Set();
                            }
                        }
                        if (notice == Notice.Synchronized)
                            RaiseOnStatusChangesEvent(SyncStatus.Monitoring);
                        else if (notice == Notice.FullSpace)
                        {
                            Spooler.RemoteDriveOverLimit = true;
                        }
                        else if (notice == Notice.FullSpaceOff)
                        {
                            Spooler.RemoteDriveOverLimit = false;
                        }
                        if (OnNotification != null)
                            OnNotify(fromUserId, notice);
                    }
                    if (!IsReachable)
                    {
                        infoData = "Operation rejected. The cloud path is not mounted";
                        return;
                    }
                    if (command == Commands.SendHashStructure)
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
                        OnSendHashStructure(fromUserId, remoteHashes, delimitsRange);
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
                            if (remoteHash.SequenceEqual(localHash))
                            {
                                RaiseOnStatusChangesEvent(SyncStatus.Monitoring);
                                SendNotification(fromUserId, Notice.Synchronized);
                            }
                            else
                            {
                                RaiseOnStatusChangesEvent(SyncStatus.Pending);
                                var range = HashBlocksToBlockRange(remoteHash, localHash);
                                if (IsServer)
                                    SendHashStructure(fromUserId, range);
                                else
                                    RequestHashStructure(fromUserId, range);
                            }
                        }
                    }
                    else if (command == Commands.SendHashRoot) // NOTE: if command does not arrive check that the cloud is mounted!
                    {
                        if (GetHasRoot(out var hashRoot))
                        {
                            var localHash = BitConverter.ToUInt64(hashRoot, 0);
                            var remoteHash = BitConverter.ToUInt64(values[0], 0);
                            if (localHash != remoteHash)
                            {
                                RaiseOnStatusChangesEvent(SyncStatus.Pending);
                                SendHashBlocks(fromUserId);
                                //SendHashStructure(fromUserId);
                            }
                            else
                            {
                                RaiseOnStatusChangesEvent(SyncStatus.Monitoring);
                                SendNotification(fromUserId, Notice.Synchronized);
                            }
                        }
                    }
                    else if (command == Commands.RequestChunkFile)
                    {
                        if (HashFileTable(out var hashDirTable))
                        {
                            var hash = BitConverter.ToUInt64(values[0], 0);
                            var chunkPart = BitConverter.ToUInt32(values[1], 0);
                            infoData = "#" + chunkPart + " " + hash;
                            if (hashDirTable.TryGetValue(hash, out var fileSystemInfo))
                            {
                                SendChunkFile(fromUserId, fileSystemInfo, chunkPart);
                            }
                            else
                            {
                                infoData += " not found";
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
                        infoData = "#" + part + "/" + total + " " + hashFileName;
                        Debug.WriteLine("IN #" + part + "/" + total);
                        var maxFileSize = total * data.Length;
                        // If the disk is about to be full notify the sender, and finish the operation.
                        lock (FlagsDriveOverLimit)
                            if (!PreserveDriveSpace(CloudRoot, preserveSize: maxFileSize))
                            {
                                if (!FlagsDriveOverLimit.Contains(fromUserId))
                                    FlagsDriveOverLimit.Add(fromUserId);
                                SendNotification(fromUserId, Notice.FullSpace);
                                return;
                            }
                        if (part != 1)
                        {
                            if (!(File.Exists(tmpFile)))
                                return;
                        }
                        if (CRC.Update(fromUserId, hashFileName, ref part, data, tmpFile, true, out var isRestored, part == 1 ? data : null))
                        {
                            if (!isRestored && !FileAppend(tmpFile, data, out Exception exception, 10, 50, DefaultChunkSize, part))
                            {
                                if (exception != null)
                                    RaiseOnFileError(exception, tmpFile);
                                return;
                            }
                            if (part == total)
                            {
                                var length = values[5].ToUint32();
                                var expectedCrc = BitConverter.ToUInt64(values[7], 0);
                                if (expectedCrc == CRC.GetCRC(fromUserId, hashFileName, part) && new FileInfo(tmpFile).Length.Equals(length)) // Use the length to check if the file was received correctly
                                {
                                    var target = FullName(values[6]);
                                    var fileInfo = new FileInfo(target);
                                    if (hashFileName != HashFileName(values[6].ToText(), false))
                                    {
                                        Debugger.Break();
                                        return;
                                    }
                                    var unixTimestamp = values[4].ToUint32();
                                    TotalFilesReceived++;
                                    TotalBytesReceived += length;
                                    if (File.Exists(target))
                                    {
                                        if (fileInfo.UnixLastWriteTimestamp() > unixTimestamp)
                                        {
                                            // Debugger.Break();
                                            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                                            {
                                                // In Windows, duplicate file names with different case are not allowed
                                                var currentNameFile = (fileInfo.Directory.GetFiles(fileInfo.Name).FirstOrDefault())?.Name;
                                                if (currentNameFile != fileInfo.Name) // Check if the file is the same not case sensitive
                                                    DeleteFile(fromUserId, hashFileName, unixTimestamp, fileInfo.FullName);
                                            }
                                            return;
                                        }
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
                                CRC.RemoveCRC(fromUserId, hashFileName);
                                ReportReceiptFileCompleted(fromUserId, hashFileName, total);
                            }
                            else
                            {
                                RaiseOnFileTransfer(false, hashFileName, part, total);
                                //Thread.Sleep(5000);
                                RequestChunkFile(fromUserId, hashFileName, part + 1);
                            }
                        }
                    }
                    else if (command == Commands.DeleteFile)
                    {
                        var hash = values[0].ToUint64();
                        infoData = hash.ToString();
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
                                    lock (FlagsDriveOverLimit)
                                        if (FlagsDriveOverLimit.Contains(fromUserId))
                                        {
                                            if (PreserveDriveSpace(CloudRoot))
                                            {
                                                FlagsDriveOverLimit.Remove(fromUserId);
                                                SendNotification(fromUserId, Notice.FullSpaceOff);
                                                return;
                                            }
                                        }
                                }
                            }
                        }
                    }
                    else if (command == Commands.CreateDirectory)
                    {
                        // If the disk is about to be full notify the sender, and finish the operation.
                        var fullDirectoryName = FullName(values[0]);
                        infoData = fullDirectoryName;
                        lock (FlagsDriveOverLimit)
                            if (!PreserveDriveSpace(CloudRoot))
                            {
                                if (!FlagsDriveOverLimit.Contains(fromUserId))
                                    FlagsDriveOverLimit.Add(fromUserId);
                                SendNotification(fromUserId, Notice.FullSpace);
                                return;
                            }
                        DirectoryCreate(fullDirectoryName, out Exception exception);
                        if (exception != null)
                            RaiseOnFileError(exception, fullDirectoryName);
                        var hash = HashFileName(values[0].ToText(), true);
                        ReceptionInProgress.Completed(hash);
                        StatusNotification(fromUserId, Status.Ready);
                    }
                    else if (command == Commands.DeleteDirectory)
                    {
                        var fullDirectoryName = FullName(values[0]);
                        infoData = fullDirectoryName;
                        DirectoryDelete(fullDirectoryName, out Exception exception);
                        if (exception != null)
                            RaiseOnFileError(exception, fullDirectoryName);
                    }
                    else if (command == Commands.StatusNotification)
                    {
                        var status = (Status)values[0][0];
                        infoData = status.ToString();
                        if (status == Status.Busy)
                            return;
                    }
                    Spooler.ExecuteNext(fromUserId);
                }
            }
        }
        /// <summary>
        /// Flags that indicates that the disk over limit has been notified to the remote device
        /// </summary>
        public List<ulong?> FlagsDriveOverLimit = new List<ulong?>();
        private Task TaskOnSendHashStructure;
        /// <summary>
        /// Add the operations to be performed for file synchronization to the spooler.
        /// This task with many files may take a long time, so it runs in baskground!
        /// </summary>
        /// <param name="fromUserId">User who sent the data required for synchronization</param>
        /// <param name="remoteHashes">The structure of the remote files used to calculate the synchronization</param>
        /// <param name="delimitsRange">A possible delimiter that restricts the area of files to be checked for synchronization</param>
        private void OnSendHashStructure(ulong? fromUserId, Dictionary<ulong, uint> remoteHashes, BlockRange delimitsRange)
        {
            if (TaskOnSendHashStructure == null)
                TaskOnSendHashStructure = Task.Run(() =>
                {
                    try
                    {
                        Spooler.Clear();
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
                                        }
                                        else if (remoteDate < localDate)
                                        {
                                            Spooler.AddOperation(Spooler.OperationType.Send, fromUserId, hash);
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
                                    if (!localHashes.ContainsKey(hash) && !wasDeleted)
                                    {
                                        Spooler.AddOperation(Spooler.OperationType.Request, fromUserId, hash);
                                    }
                                }
                            }
                        }
                        TaskOnSendHashStructure = null;
                    }
                    catch (Exception ex)
                    {
                        RecordError(ex);
                        Debugger.Break(); // Error! Investigate the cause of the error!
                        Debug.WriteLine(ex);
                    }
                });
        }

        public uint TotalFilesReceived;
        public uint TotalBytesReceived;
        public readonly ProgressFileTransfer ReceptionInProgress;
        private string FullName(byte[] unixRelativeName)
        {
            var text = unixRelativeName.ToText();
            return Path.Combine(CloudRoot, text.Replace('/', Path.DirectorySeparatorChar));
        }
    }
}
