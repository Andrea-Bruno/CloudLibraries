using OtpNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using static CloudSync.Util;
using System.Timers;
namespace CloudSync
{
    public partial class Sync
    {
        // Timer used to debounce ForceSyncAllClients calls (reuse instance, reset with Stop/Start)
        private Timer? _forceSyncTimer;
        private readonly object _forceSyncTimerLock = new object();

        public bool CreateDirectory(string fullDirectoryName, ulong? fromUserId = null)
        {

            // Check disk space before creating directory
            lock (FlagsDriveOverLimit)
                if (!CheckDiskSPace(this))
                {
                    if (fromUserId != null)
                    {
                        if (!FlagsDriveOverLimit.Contains(fromUserId))
                            FlagsDriveOverLimit.Add(fromUserId);
                        SendNotification(fromUserId, Notice.FullSpace);
                    }
                    return false;
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
            return true;
        }

        /// <summary>
        /// Convert full path -> hash and delegate to DeleteFile(hash,...)
        /// </summary>
        public bool DeleteFile(string fullFileName)
        {
            if (string.IsNullOrEmpty(fullFileName))
                return false;

            try
            {
                if (!TryGetHashFromFullPath(fullFileName, out var hash, out _))
                    return false;

                return DeleteFile(hash, null, null);
            }
            catch (Exception ex)
            {
                RaiseOnFileError(ex, fullFileName);
                return false;
            }
        }

        public bool DeleteFile(ulong hash, uint? timestamp, ulong? fromUserId = null)
        {
            if (GetHashFileTable(out var hashDirTable))
            {
                if (hashDirTable.TryGetValue(hash, out var fileSystemInfo))
                {
                    if (fileSystemInfo is FileInfo fileInfo && fileInfo.Exists)
                    {
                        if (timestamp == null || fileInfo.UnixLastWriteTimestamp() == timestamp)
                        {
                            // Track deletion request
                            var fid = FileId.GetFileId(hash, fileInfo.UnixLastWriteTimestamp());
                            ClientToolkit?.WatchCloudRoot?.AddDeletedByRemoteRequest(fid);
                            ClientToolkit?.AddDeletedFileToPersistentList(fid);

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
                                if (fromUserId != null)
                                {
                                    if (FlagsDriveOverLimit.Contains(fromUserId))
                                    {
                                        if (CheckDiskSPace(this))
                                        {
                                            FlagsDriveOverLimit.Remove(fromUserId);
                                            SendNotification(fromUserId, Notice.FullSpaceOff);
                                            return false;
                                        }
                                    }
                                }
                        }
                    }
                }
            }
            return true;
        }

        /// <summary>
        /// Convert full directory path -> hash and delegate to DeleteDirectory(hash)
        /// </summary>
        public bool DeleteDirectory(string fullDirectoryName)
        {
            if (string.IsNullOrEmpty(fullDirectoryName))
                return false;

            try
            {
                if (!TryGetHashFromFullPath(fullDirectoryName, out var hash, out var isDirectory))
                    return false;

                // Ensure target is treated as directory for safety (hash LSB depends on isDirectory)
                if (!isDirectory)
                {
                    // If path doesn't exist as directory, still allow forwarding (hash derived from name)
                }

                return DeleteDirectory(hash);
            }
            catch (Exception ex)
            {
                RaiseOnFileError(ex, fullDirectoryName);
                return false;
            }
        }

        public bool DeleteDirectory(ulong hash)
        {
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
                        if (ClientToolkit != null)
                        {
                            foreach (var fid in removedIds)
                                ClientToolkit.AddDeletedFileToPersistentList(fid);
                        }

                        // Perform directory deletion
                        DirectoryDelete(directoryInfo.FullName, out Exception exception);
                        if (exception != null)
                            RaiseOnFileError(exception, directoryInfo.FullName);
                    }
                }
            }
            return true;
        }

        /// <summary>
        /// At the end of a file transfer (when the last chunk is received), and the file is written, we add its hash to the filetable hash.
        /// </summary>
        public void FileTransferCompleted(string fullFilename, ulong? fromUserId = null)
        {
            var fileInfo = new FileInfo(fullFilename);
            FileTransferCompleted(fileInfo, fromUserId);
        }


        /// <summary>
        /// At the end of a file transfer (when the last chunk is received), and the file is written, we add its hash to the filetable hash.
        /// Optional fromUserId is used to notify client-specific space flags when file was uploaded remotely.
        /// </summary>
        public void FileTransferCompleted(FileInfo fileInfo, ulong? fromUserId = null)
        {
            // Update hash table with new file
            if (GetHashFileTable(out var hashFileTable))
            {
                hashFileTable.Add(fileInfo);
            }
            ClientToolkit?.UpdateDeletedFileList(fileInfo.FullName);

            // If a remote user uploaded a file, verify disk-space flags and notify if needed
            if (fromUserId != null)
            {
                lock (FlagsDriveOverLimit)
                {
                    if (!CheckDiskSPace(this))
                    {
                        if (!FlagsDriveOverLimit.Contains(fromUserId))
                            FlagsDriveOverLimit.Add(fromUserId);
                        SendNotification(fromUserId, Notice.FullSpace);
                    }
                }
            }
        }

        // -------------------------
        // Private helpers
        // -------------------------

        /// <summary>
        /// Try to compute the file/directory hash from a full path.
        /// Returns false if the path is invalid or outside CloudRoot.
        /// Comments minimal and in English as requested.
        /// </summary>
        private bool TryGetHashFromFullPath(string fullPathInput, out ulong hash, out bool isDirectory)
        {
            hash = 0;
            isDirectory = false;
            if (string.IsNullOrEmpty(fullPathInput))
                return false;

            try
            {
                // Normalize paths
                var fullPath = Path.GetFullPath(fullPathInput);
                var root = Path.GetFullPath(CloudRoot ?? string.Empty)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    + Path.DirectorySeparatorChar;

                // Ensure target is inside CloudRoot
                if (!fullPath.StartsWith(root, StringComparison.InvariantCultureIgnoreCase))
                    return false;

                // Build unix-style relative path expected by HashFileName
                var relative = fullPath.Substring(root.Length)
                    .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    .Replace(Path.DirectorySeparatorChar, '/')
                    .Replace(Path.AltDirectorySeparatorChar, '/');

                // Determine if path is a directory
                isDirectory = Directory.Exists(fullPath);

                // Compute hash using utility (LSB set for directory)
                hash = Util.HashFileName(relative, isDirectory);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public List<ulong> RemoveHashesForDirectory(string fullDirectoryName)
        {
            var result = new List<ulong>();
            if (string.IsNullOrEmpty(fullDirectoryName))
                return result;

            if (GetHashFileTable(out var hashDirTable))
            {
                var directoryInfo = new DirectoryInfo(fullDirectoryName);
                if (!directoryInfo.Exists)
                    return result;

                var removed = hashDirTable.RemoveDirectory(directoryInfo.FullName);
                if (removed != null)
                    result = removed.Select(x => x.fileId.HashFile).ToList();
            }
            return result;
        }

        public void AddHashesForDirectory(string fullDirectoryName)
        {
            if (string.IsNullOrEmpty(fullDirectoryName))
                return;

            if (!GetHashFileTable(out var hashFileTable))
                return;

            var directoryInfo = new DirectoryInfo(fullDirectoryName);
            if (!directoryInfo.Exists)
                return;

            // Add the directory itself
            hashFileTable.Add(directoryInfo);

            // Add subdirectories (so directories are present in hash table)
            foreach (var dir in directoryInfo.GetDirectories("*", SearchOption.AllDirectories))
            {
                hashFileTable.Add(dir);
            }

            // Add files using existing FileTransferCompleted logic (updates hash table and deleted-list)
            foreach (var file in directoryInfo.GetFiles("*", SearchOption.AllDirectories))
            {
                FileTransferCompleted(file);
            }
        }

        public bool RemoveHashForFile(string fullFileName)
        {
            if (string.IsNullOrEmpty(fullFileName))
                return false;

            if (!TryGetHashFromFullPath(fullFileName, out var hash, out _))
                return false;

            if (GetHashFileTable(out var hashFileTable))
            {
                return hashFileTable.Remove(hash);
            }
            return false;
        }

        public void ForceSyncAllClients()
        {
            // Only server should perform broadcast
            if (!IsServer)
                return;

            lock (_forceSyncTimerLock)
            {
                if (_forceSyncTimer == null)
                {
                    _forceSyncTimer = new Timer(30_000) { AutoReset = false };
                    _forceSyncTimer.Elapsed += (s, e) =>
                    {
                        try
                        {
                            PerformForceSyncAllClients();
                        }
                        catch
                        {
                            // swallow exceptions from background handler
                        }
                    };
                }
                else
                {
                    // reset countdown by stopping; Start will restart from zero
                    try { _forceSyncTimer.Stop(); } catch { }
                }

                _forceSyncTimer.Start();
            }
        }

        // Extracted original logic to be invoked by timer
        private void PerformForceSyncAllClients()
        {
            try
            {
                var clients = RoleManager?.Clients?.Values;
                if (clients == null)
                    return;

                foreach (var client in clients.ToList())
                {
                    try
                    {
                        if (client?.IsConnected == true && client?.TypeOfClient == Client.ClientType.Socket)
                        {
                            SendHashStructure(client.Id, true);
                        }
                    }
                    catch
                    {
                        // ignore single client failures
                    }
                }
            }
            catch
            {
                // silent: do not throw from force-sync
            }
        }
    }
}
