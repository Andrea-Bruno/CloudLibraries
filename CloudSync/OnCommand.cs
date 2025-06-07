using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static CloudSync.Util;

namespace CloudSync
{
    public partial class Sync
    {
        /// <summary>
        /// Counter for currently running commands
        /// </summary>
        private int OnCommandRunning;

        /// <summary>
        /// Indicates if a command is currently being processed
        /// </summary>
        public bool CommandIsRunning => OnCommandRunning > 0;

        /// <summary>
        /// Handles incoming commands from remote users
        /// </summary>
        /// <param name="fromUserId">ID of the user sending the command</param>
        /// <param name="command">Command identifier</param>
        /// <param name="values">Command parameters</param>
        /// <returns>True if command was processed successfully, false otherwise</returns>
        internal bool OnCommand(ulong? fromUserId, ushort command, params byte[][] values)
        {
            lastFromUserId = fromUserId;
            if (!Enum.IsDefined(typeof(Commands), command))
                return false; // Command not supported in this version

            OnCommandRunning++;
            try
            {
                OnCommand(fromUserId, (Commands)command, values);
            }
            catch (Exception ex)
            {
                RecordError(ex);
                Debugger.Break(); // Error! Investigate the cause!
                Debug.WriteLine(ex);
                OnCommandRunning--;
                return false;
            }
            OnCommandRunning--;
            return true;
        }

        /// <summary>
        /// Stores the last user ID that sent a command
        /// </summary>
        ulong? lastFromUserId;

#if DEBUG
        /// <summary>
        /// Test method to send ready status (DEBUG only)
        /// </summary>
        public void TestSendReady()
        {
            StatusNotification(lastFromUserId, Status.Ready);
        }
#endif

        /// <summary>
        /// Timestamp of the last received command
        /// </summary>
        public DateTime LastCommandReceived { get; private set; }

        /// <summary>
        /// Processes incoming commands with detailed handling
        /// </summary>
        /// <param name="fromUserId">ID of the user sending the command</param>
        /// <param name="command">Command type</param>
        /// <param name="values">Command parameters</param>
        private void OnCommand(ulong? fromUserId, Commands command, params byte[][] values)
        {
            bool onCommandEventFlag = false;

            // Helper function to raise command events
            void onCommandEvent(string literalInfo)
            {
                onCommandEventFlag = true;
                RaiseOnCommandEvent(fromUserId, command, literalInfo);
            }

            LastCommandReceived = DateTime.UtcNow;
            Debug.WriteLine("IN " + command);

            #region RequestOfAuthentication
            if (command == Commands.RequestOfAuthentication)
            {
                // Server receives access request, sends cryptographic challenge to client
                var host = values.Length > 0 ? Encoding.ASCII.GetString(values[0]) : null;
                var userAgent = values.Length > 1 ? Encoding.ASCII.GetString(values[1]) : null;

                RoleManager.LoginRequest((client, random) => Authentication(fromUserId, random),
                    null, fromUserId, host, userAgent);
            }
            #endregion

            #region Authentication
            else if (command == Commands.Authentication)
            {
                if (IsServer)
                {
                    // Server verifies client's solution to cryptographic challenge
                    if (RoleManager.TryToGetClient((ulong)fromUserId, out var client, out var isTemp))
                    {
                        if (client.Authenticate(values[0], values.Length == 1 ? null : values[1]))
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
                    // Client solves cryptographic challenge to prove PIN knowledge
                    if (Credential != null)
                    {
                        var Client = new Client(this, (ulong)fromUserId);
                        var proof = RoleManager.CryptographicProofOfPinKnowledge(values[0], Credential.Pin);
                        Authentication(fromUserId, proof.GetBytes());
                        Credential = null;
                    }
                }
            }
            #endregion

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
                    // Restart synchronization timer on command receipt
                    ClientToolkit?.RestartTimerClientRequestSynchronization();

                    #region Notification
                    if (command == Commands.Notification)
                    {
                        var notice = (Notice)values[0][0];
                        onCommandEvent(notice.ToString());

                        if (ClientToolkit != null)
                        {
                            if (notice == Notice.LoginSuccessful)
                                ClientToolkit.IsLogged = true;
                            else if (notice == Notice.LoginError)
                            {
                                ClientToolkit.LoginError = true;
                                OnLoginCompleted?.Set();
                            }
                        }

                        if (notice == Notice.Synchronized)
                        {
                            if (_HashFileTable?.ResetIsRequired == true)
                            {
                                // Reset hash table for more secure sync
                                ResetHashFileTable();
                            }
                            RaiseOnStatusChangesEvent(SyncStatus.Monitoring);
                        }
                        else if (notice == Notice.OperationCompleted)
                        {
                            PendingConfirmation--;
                        }
                        else if (notice == Notice.FullSpace)
                        {
                            RemoteDriveOverLimit = true;
                        }
                        else if (notice == Notice.FullSpaceOff)
                        {
                            RemoteDriveOverLimit = false;
                        }

                        if (OnNotification != null)
                            OnNotify(fromUserId, notice);
                    }
                    #endregion

                    // Reject commands if sync is suspended
                    if (ClientToolkit?.SyncIsEnabled == false)
                    {
                        onCommandEvent("Operation rejected. Sync is suspended!");
                        return;
                    }

                    #region SendHashStructure
                    if (command == Commands.SendHashStructure)
                    {
                        var structure = values[0];
                        var remoteHashes = new Dictionary<ulong, uint>();

                        // Parse hash structure into dictionary
                        var hash8 = new byte[8];
                        var timestamp4 = new byte[4];
                        for (var offset = 0; offset < structure.Length; offset += 12)
                        {
                            Buffer.BlockCopy(structure, offset, hash8, 0, 8);
                            Buffer.BlockCopy(structure, offset + 8, timestamp4, 0, 4);
                            var hash = BitConverter.ToUInt64(hash8, 0);
                            var timestamp = BitConverter.ToUInt32(timestamp4, 0);
                            remoteHashes.Add(hash, timestamp);
                        }

                        OnSendHashStructure(fromUserId, remoteHashes);
                    }
                    #endregion

                    #region RequestHashStructure
                    else if (command == Commands.RequestHashStructure)
                    {
                        SendHashStructure(fromUserId);
                    }
                    #endregion

                    #region SendHashRoot
                    else if (command == Commands.SendHashRoot)
                    {
                        if (ClientToolkit?.WatchCloudRoot.IsPending == true)
                        {
                            onCommandEvent("Waiting for all files to be closed!");
                            return;
                        }

                        if (GetHashFileTable(out HashFileTable hashFileTable))
                        {
                            var localHash = BitConverter.ToUInt64(hashFileTable.GetHasRoot(), 0);
                            var remoteHash = BitConverter.ToUInt64(values[0], 0);

                            if (localHash != remoteHash)
                            {
                                // Hashes differ - need full sync
                                RaiseOnStatusChangesEvent(SyncStatus.Pending);
                                SendHashStructure(fromUserId);
                            }
                            else
                            {
                                // Hashes match - synchronization complete
                                RaiseOnStatusChangesEvent(SyncStatus.Monitoring);
                                SendNotification(fromUserId, Notice.Synchronized);
                            }
                        }
                    }
                    #endregion

                    #region RequestChunkFile
                    else if (command == Commands.RequestChunkFile)
                    {
                        if (GetHashFileTable(out var hashDirTable))
                        {
                            var hash = BitConverter.ToUInt64(values[0], 0);
                            var chunkPart = BitConverter.ToUInt32(values[1], 0);
                            var infoData = "#" + chunkPart + " " + hash;

                            if (hashDirTable.TryGetValue(hash, out var fileSystemInfo))
                            {
                                SendChunkFile(fromUserId, fileSystemInfo, chunkPart);
                            }
                            else
                            {
                                infoData += " not found";
                            }

                            onCommandEvent(infoData);
                        }
                    }
                    #endregion

                    #region SendChunkFile
                    else if (command == Commands.SendChunkFile)
                    {
                        var hashFileName = BitConverter.ToUInt64(values[0], 0);
                        var part = BitConverter.ToUInt32(values[1], 0);
                        var total = BitConverter.ToUInt32(values[2], 0);
                        var data = values[3];
                        var tmpFile = GetTmpFile(this, fromUserId, hashFileName);

                        onCommandEvent("#" + part + "/" + total + " " + hashFileName);
                        Debug.WriteLine("IN #" + part + "/" + total);

                        var maxFileSize = total * data.Length;

                        // Check disk space before proceeding
                        lock (FlagsDriveOverLimit)
                            if (!CheckDiskSPace(this, preserveSize: maxFileSize))
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

                        if (CRC.Update(IsClient, fromUserId, hashFileName, ref part, data, tmpFile, true, out var isRestored, part == 1 ? data : null))
                        {
                            if (!isRestored && !FileAppend(tmpFile, data, out Exception exception, 10, 50, DefaultChunkSize, part))
                            {
                                if (exception != null)
                                    RaiseOnFileError(exception, tmpFile);
                                return;
                            }

                            if (part == total)
                            {
                                // Final chunk processing
                                var length = values[5].ToUint32();
                                var expectedCrc = BitConverter.ToUInt64(values[7], 0);
                                var infoTmpFile = new FileInfo(tmpFile);

                                if (!infoTmpFile.Exists)
                                {
                                    Debugger.Break(); // File missing - investigate!
                                    return;
                                }

                                if (expectedCrc == CRC.GetCRC(IsClient, fromUserId, hashFileName, part) && infoTmpFile.Length.Equals(length))
                                {
                                    var target = FullName(values[6], out bool isEncrypted, out string nameFile);
                                    var fileInfo = new FileInfo(target);

                                    if (hashFileName != HashFileName(values[6].ToText(), false))
                                    {
                                        Debugger.Break(); // Hash mismatch
                                        return;
                                    }

                                    var unixTimestamp = values[4].ToUint32();
                                    TotalFilesReceived++;
                                    TotalBytesReceived += length;

                                    // Check if file was intentionally deleted
                                    if (ClientToolkit?.PersistentDeletedFileListContains(FileId.GetFileId(hashFileName, unixTimestamp)) == true)
                                    {
                                        ClientToolkit?.Spooler.AddOperation(Spooler.OperationType.DeleteFile, hashFileName, unixTimestamp);
                                        return;
                                    }

                                    if (File.Exists(target))
                                    {
                                        if (fileInfo.UnixLastWriteTimestamp() > unixTimestamp)
                                        {
                                            // Handle case-sensitive filename conflicts on Windows
                                            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                                            {
                                                var currentNameFile = (fileInfo.Directory.GetFiles(fileInfo.Name).FirstOrDefault())?.Name;
                                                if (currentNameFile != fileInfo.Name)
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
                                        // Create target directory if needed
                                        var targetDirectory = new FileInfo(target).Directory;
                                        DirectoryCreate(targetDirectory.FullName, Owner, out Exception exception1);
                                        if (exception1 != null)
                                            RaiseOnFileError(exception1, targetDirectory.FullName);
                                    }

                                    // Set correct timestamp for decryption
                                    infoTmpFile.LastWriteTimeUtc = UnixTimestampToDateTime(unixTimestamp);
                                    infoTmpFile.Refresh();

                                    // Move temp file to final location
                                    FileMove(tmpFile, target, isEncrypted, Owner, out Exception exception2, context: this);
                                    if (exception2 != null)
                                        RaiseOnFileError(exception2, target);
                                    else
                                    {
                                        fileInfo.Refresh();
#if DEBUG
                                        if (fileInfo.UnixLastWriteTimestamp() != unixTimestamp)
                                        {
                                            Debugger.Break(); // Timestamp mismatch!
                                        }
#endif
                                        RaiseOnFileTransfer(false, hashFileName, part, total, target, (int)length);

                                        // Update hash table with new file
                                        if (GetHashFileTable(out var hashFileTable))
                                        {
                                            hashFileTable.Add(fileInfo);
                                        }

                                        ClientToolkit?.UpdateDeletedFileList(fileInfo.FullName);
                                    }
                                }
                                else
                                {
                                    // CRC or length mismatch - delete corrupted temp file
                                    Debugger.Break();
                                    FileDelete(tmpFile, out Exception exception1);
                                    if (exception1 != null)
                                        RaiseOnFileError(exception1, tmpFile);
                                }

                                CRC.RemoveCRC(IsClient, fromUserId, hashFileName);
                                ReportReceiptFileCompleted(fromUserId, hashFileName, total);
                            }
                            else
                            {
                                // Request next chunk
                                RaiseOnFileTransfer(false, hashFileName, part, total);
                                RequestChunkFile(fromUserId, hashFileName, part + 1);
                            }
                        }
                    }
                    #endregion

                    #region DeleteFile
                    else if (command == Commands.DeleteFile)
                    {
                        SendNotification(fromUserId, Notice.OperationCompleted);
                        var hash = values[0].ToUint64();
                        onCommandEvent(hash.ToString());
                        var timestamp = values[1].ToUint32();

                        if (GetHashFileTable(out var hashDirTable))
                        {
                            if (hashDirTable.TryGetValue(hash, out var fileSystemInfo))
                            {
                                if (fileSystemInfo is FileInfo fileInfo && fileInfo.Exists)
                                {
                                    if (fileInfo.UnixLastWriteTimestamp() == timestamp)
                                    {
                                        // Track deletion request
                                        ClientToolkit?.WatchCloudRoot?.AddDeletedByRemoteRequest(FileId.GetFileId(hash, fileInfo.UnixLastWriteTimestamp()));

                                        // Perform deletion
                                        FileDelete(fileInfo.FullName, out Exception exception);
                                        if (exception != null)
                                            RaiseOnFileError(exception, fileInfo.FullName);

                                        bool fileNotExists()
                                        {
                                            fileInfo.Refresh();
                                            return !fileInfo.Exists;
                                        }

                                        if (exception == null || fileNotExists())
                                            hashDirTable.Remove(hash);

                                        // Check if disk space was freed
                                        lock (FlagsDriveOverLimit)
                                            if (FlagsDriveOverLimit.Contains(fromUserId))
                                            {
                                                if (CheckDiskSPace(this))
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
                    }
                    #endregion

                    #region CreateDirectory
                    else if (command == Commands.CreateDirectory)
                    {
                        var fullDirectoryName = FullName(values[0], out _, out string nameFile);
                        onCommandEvent(fullDirectoryName);

                        // Check disk space before creating directory
                        lock (FlagsDriveOverLimit)
                            if (!CheckDiskSPace(this))
                            {
                                if (!FlagsDriveOverLimit.Contains(fromUserId))
                                    FlagsDriveOverLimit.Add(fromUserId);
                                SendNotification(fromUserId, Notice.FullSpace);
                                return;
                            }

                        DirectoryCreate(fullDirectoryName, Owner, out Exception exception);
                        if (exception != null)
                            RaiseOnFileError(exception, fullDirectoryName);
                        else
                        {
                            // Add new directory to hash table
                            if (GetHashFileTable(out var hashFileTable))
                            {
                                var directoryInfo = new DirectoryInfo(fullDirectoryName);
                                hashFileTable.Add(directoryInfo);
                            }
                        }

                        var hash = HashFileName(values[0].ToText(), true);
                        ReceptionInProgress.Completed(hash);
                        StatusNotification(fromUserId, Status.Ready);
                    }
                    #endregion

                    #region DeleteDirectory
                    else if (command == Commands.DeleteDirectory)
                    {
                        SendNotification(fromUserId, Notice.OperationCompleted);
                        var hash = values[0].ToUint64();
                        onCommandEvent(hash.ToString());

                        if (GetHashFileTable(out var hashDirTable))
                        {
                            if (hashDirTable.TryGetValue(hash, out var fileSystemInfo))
                            {
                                if (fileSystemInfo is DirectoryInfo directoryInfo && directoryInfo.Exists)
                                {
                                    // Remove directory and all contents from hash table
                                    var removed = hashDirTable.RemoveDirectory(directoryInfo.FullName);
                                    var removedIds = removed.Select(x => x.fileId).ToList();

                                    // Track deletion requests
                                    ClientToolkit?.WatchCloudRoot?.AddDeletedByRemoteRequest(removedIds);

                                    // Perform directory deletion
                                    DirectoryDelete(directoryInfo.FullName, out Exception exception);
                                    if (exception != null)
                                        RaiseOnFileError(exception, directoryInfo.FullName);
                                }
                            }
                        }
                    }
                    #endregion

                    #region StatusNotification
                    else if (command == Commands.StatusNotification)
                    {
                        var status = (Status)values[0][0];
                        onCommandEvent(status.ToString());
                        if (status == Status.Busy)
                            return;
                        if (IsServer)
                            StatusNotification(null, Sync.Status.Ready);
                    }
                    #endregion

                    // Execute next spooler operation if available
                    ClientToolkit?.Spooler.ExecuteNext();
                }
            }

            if (!onCommandEventFlag)
                onCommandEvent(null);
        }

        /// <summary>
        /// Tracks which remote devices have been notified about disk space limits
        /// </summary>
        public List<ulong?> FlagsDriveOverLimit = [];

        /// <summary>
        /// Indicates if the remote server's disk is full
        /// </summary>
        public bool RemoteDriveOverLimit
        {
            get { return _RemoteDriveOverLimit; }
            internal set
            {
                _RemoteDriveOverLimit = value;
                if (value)
                {
                    // Remove pending send operations when disk is full
                    ClientToolkit?.RemoveSendOperationFromSpooler();
                }
            }
        }
        private bool _RemoteDriveOverLimit;

        /// <summary>
        /// Processes received file hash structure and queues sync operations
        /// </summary>
        /// <param name="fromUserId">User who sent the hash structure</param>
        /// <param name="remoteHashes">Dictionary of remote file hashes and timestamps</param>
        private void OnSendHashStructure(ulong? fromUserId, Dictionary<ulong, uint> remoteHashes)
        {
#if DEBUG
            if (ClientToolkit == null)
            {
                Debugger.Break(); // ClientToolkit should never be null!
                return;
            }
#endif

            if (GetHashFileTable(out var localHashes))
            {
                HashStructureComparer.Compare(this, remoteHashes, localHashes);
            }
        }

        /// <summary>
        /// Counters for received files and bytes
        /// </summary>
        public uint TotalFilesReceived;
        public uint TotalBytesReceived;

        /// <summary>
        /// Tracks progress of file transfers being received
        /// </summary>
        public readonly ProgressFileTransfer ReceptionInProgress;

        /// <summary>
        /// Converts Unix-style relative path to full local path
        /// </summary>
        /// <param name="unixRelativeName">Encoded path bytes</param>
        /// <param name="isEncrypted">Output indicating if filename was encrypted</param>
        /// <param name="virtualName">Output of decrypted filename</param>
        /// <returns>Full local filesystem path</returns>
        private string FullName(byte[] unixRelativeName, out bool isEncrypted, out string virtualName)
        {
            virtualName = unixRelativeName.ToText();
            if (ZeroKnowledgeProof != null)
            {
                isEncrypted = virtualName.EndsWith(ZeroKnowledgeProof.EncryptFileNameEndChar);
                virtualName = ZeroKnowledgeProof.DecryptFullFileName(virtualName);
            }
            else
                isEncrypted = false;

            return Path.Combine(CloudRoot, virtualName.Replace('/', Path.DirectorySeparatorChar));
        }

        /// <summary>
        /// Simplified version of FullName without encryption outputs
        /// </summary>
        private string FullName(byte[] unixRelativeName) => FullName(unixRelativeName, out _, out _);
    }
}