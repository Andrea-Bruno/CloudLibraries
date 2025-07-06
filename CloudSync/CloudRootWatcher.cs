using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace CloudSync
{
    /// <summary>
    /// Sync Agent: Offers all the low-level functions to sync the cloud in an encrypted and secure way
    /// </summary>
    public class CloudRootWatcher : IDisposable
    {
        // Constructor that initializes the CloudRootWatcher with a Sync context
        public CloudRootWatcher(Sync context)
        {
            Context = context;
            _checkPendingTimer = new System.Timers.Timer(1000);
            _checkPendingTimer.Elapsed += CheckPendingFiles;
            StartWakeUpMonitoring();
        }

        // Reference to the Sync context that contains configuration and state
        private Sync Context;
        // File system watchers for files and directories
        private FileSystemWatcher Watcher;


        #region Monitor files still open for writing
        private readonly List<string> PendingFiles = new();
        private readonly System.Timers.Timer _checkPendingTimer;

        /// <summary>
        /// Checks if there are any files pending for processing
        /// </summary>
        public bool IsPending => PendingFiles.Count > 0;
        private void CheckPendingFiles(object sender, System.Timers.ElapsedEventArgs e)
        {
            _checkPendingTimer.Stop();
            foreach (var fileName in PendingFiles.ToArray())
            {
                if (Util.FileIsAvailable(fileName, out _, out bool notExists))
                {
                    PendingFiles.Remove(fileName);
                    // If the file is no longer locked, notify the change
                    OnChanged(fileName);
                }
                if (notExists)
                {
                    PendingFiles.Remove(fileName);
                    // If the file does not exist anymore, treat it as deleted
                    OnDeleted(fileName);
                }
            }
            if (PendingFiles.Count != 0)
                _checkPendingTimer.Start();
        }

        #endregion


        /// <summary>
        /// Stops all file system watchers from raising events
        /// </summary>
        public void StopWatch()
        {
            if (Watcher != null)
            Watcher.EnableRaisingEvents = false;
        }

        /// <summary>
        /// Starts the file system watchers with retry logic
        /// </summary>
        /// <param name="maxAttempts">Maximum number of attempts to start the watchers</param>
        /// <returns>True if watchers were successfully started, false otherwise</returns>
        public bool StartWatch(int maxAttempts = 10)
        {
            lock (this)
            {
                if (Watcher != null)
                {
                    Watcher.EnableRaisingEvents = false;
                    Watcher.Dispose();
                }
                Watcher = new FileSystemWatcher();
                var attempts = 0;
                while (attempts < maxAttempts)
                {
                    try
                    {
                        if (string.IsNullOrEmpty(Watcher.Path))
                        {
                            // Configure notify filters based on whether we're watching files or directories
                            var notifyFilter = NotifyFilters.DirectoryName | NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime;

                            // Configure the watcher properties
                            Watcher.Path = Context.CloudRoot;
                            Watcher.NotifyFilter = notifyFilter;
                            Watcher.Filter = "*.*";
                            Watcher.IncludeSubdirectories = true;
                        }
                        Watcher.EnableRaisingEvents = true;
                        // Handle file/directory creation
                        Watcher.Created += (s, e) =>
                        {
                            if (!Util.CanBeSeen(Context, e.FullPath))
                                return;
                            OnCreated(e.FullPath);
                            Context.ClientToolkit?.RestartTimerClientRequestSynchronization();
                        };

                        // Handle file/directory changes
                        Watcher.Changed += (s, e) =>
                        {
                            if (!Util.CanBeSeen(Context, e.FullPath))
                                return;
                            OnChanged(e.FullPath);
                            Context.ClientToolkit?.RestartTimerClientRequestSynchronization();
                        };

                        // Handle file/directory deletion
                        Watcher.Deleted += (s, e) =>
                        {
                            if (!Util.CanBeSeen(Context, e.FullPath, false))
                                return;
                            OnDeleted(e.FullPath);
                            Context.ClientToolkit?.RestartTimerClientRequestSynchronization();
                        };

                        // Handle file/directory renaming
                        Watcher.Renamed += (s, e) =>
                        {
                            var sync = false;
                            if (Util.CanBeSeen(Context, e.OldFullPath, false))
                            {
                                OnDeleted(e.OldFullPath);
                                sync = true;
                            }
                            if (Util.CanBeSeen(Context, e.FullPath))
                            {
                                OnCreated(e.FullPath);
                                sync = true;
                            }
                            if (sync)
                                Context.ClientToolkit?.RestartTimerClientRequestSynchronization();
                        };
                        return true;
                    }
                    catch (Exception ex)
                    {
                        attempts++;
                        Thread.Sleep(1000); // Wait before retrying
                    }
                }
                return false;
            }
        }

        #region Events associated with file operations

        /// <summary>
        /// Handles deletion of files or directories
        /// </summary>
        /// <param name="fileName">Path of the deleted item</param>
        private void OnDeleted(string fileName)
        {
            if (Context.GetHashFileTable(out var hashFileTable))
            {
                // Get information about the deleted item from the hash table
                var fileSystemInfo = hashFileTable.GetByFileName(fileName, out ulong hash, out uint unixLastWriteTimestamp);
                if (fileSystemInfo != null)
                {
                    OnDeletedUnderlying(hashFileTable, fileName, fileSystemInfo is DirectoryInfo, hash, unixLastWriteTimestamp, true);
                }
            }
        }

        private void OnDeletedUnderlying(HashFileTable hashFileTable, string fullName, bool isDirectory, ulong hash, uint unixLastWriteTimestamp, bool removeSubdirectorycontents = false)
        {
            Context.ClientToolkit?.TemporaryDeletedHashFileDictionary.Add(hash, fullName);
            if ( isDirectory && removeSubdirectorycontents)
            {
                // Handle directory deletion
                var deleted = hashFileTable.RemoveDirectory(fullName);
                foreach (var element in deleted)
                {
                    if (hash != element.fileId.HashFile)
                    // Recursively delete contents of the directory
                    OnDeletedUnderlying(hashFileTable, element.fullName, element.fileId.IsDirectory, element.fileId.HashFile, element.fileId.UnixLastWriteTimestamp, false);
                }

            }
            else if (!isDirectory)
            {
                var fileId = FileId.GetFileId(hash, unixLastWriteTimestamp);
                if (DeletedByRemoteRequest.Contains(fileId))
                {
                    // File was deleted by a remote request - just remove from tracking
                    DeletedByRemoteRequest.Remove(fileId);
                }
                else
                {
                    // File was deleted locally - notify and remove from hash table
                    Context.ClientToolkit?.AddDeletedFileToPersistentList(fileId);
                    hashFileTable.Remove(hash);
                }
            }
        }
        
        /// <summary>
        /// Handles creation of files or directories
        /// </summary>
        /// <param name="fileName">Path of the created item</param>
        private void OnCreated(string fileName)
        {
            OnChanged(fileName, true);
        }

        /// <summary>
        /// Handles changes to files or directories
        /// </summary>
        /// <param name="fileName">Path of the changed item</param>
        private void OnChanged(string fileName, bool isOnCreated = false)
        {
            if (!Util.FileIsAvailable(fileName, out var fileSystemInfo, out _))
            {
                PendingFiles.Add(fileName);
                _checkPendingTimer.Start();
            }
            else
            {
                if (fileSystemInfo is FileInfo)
                {
                    if (isOnCreated)
                    {
                        // For files, check if this is a recovery from recycle bin
                        var fileId = FileId.GetFileId(fileSystemInfo, Context);
                        Context.ClientToolkit?.RemoveDeletedFileFromPersistentList(fileId);
                    }

                }

                // Update the hash file table with the changed item
                if (Context.GetHashFileTable(out var hashFileTable))
                {
                    hashFileTable.Add(fileSystemInfo);
                }
            }
        }

        #endregion

        #region WakeUp monitoring

        private DateTime lastCheckTime;
        private Timer WakeUpTimer;
        private int WakeUpCheckMs = 60000;

        private void StartWakeUpMonitoring()
        {
            lastCheckTime = DateTime.UtcNow;

            // Set the timer to check every 10 seconds
            WakeUpTimer = new Timer(CheckWakeUp, null, 0, WakeUpCheckMs);
        }

        private void CheckWakeUp(object? state)
        {
            DateTime currentTime = DateTime.UtcNow;

            // If the time jump is significantly larger than the check interval, the system was sleeping
            if ((currentTime - lastCheckTime).TotalMilliseconds > WakeUpCheckMs + 5000)
            {
                OnWakeUp();
            }

            lastCheckTime = currentTime;
        }

        private void OnWakeUp()
        {
#if !DEBUG
            ResumeWatch();
#endif
        }

        public void ResumeWatch()
        {
            if (StartWatch())
            {
                Context.ClientToolkit?.Spooler?.SpoolerRun();
                Context.ClientToolkit?.RestartTimerClientRequestSynchronization();
            }
        }

        #endregion

        // List to track files deleted by remote requests
        private readonly List<FileId> DeletedByRemoteRequest = [];

        /// <summary>
        /// Adds a file ID to the list of files deleted by remote requests
        /// </summary>
        /// <param name="fileId">The file ID to add</param>
        public void AddDeletedByRemoteRequest(FileId fileId)
        {
            lock (DeletedByRemoteRequest)
            {
                DeletedByRemoteRequest.Add(fileId);
            }
        }

        /// <summary>
        /// Adds multiple file IDs to the list of files deleted by remote requests
        /// </summary>
        /// <param name="fileIds">The list of file IDs to add</param>
        public void AddDeletedByRemoteRequest(List<FileId> fileIds)
        {
            lock (DeletedByRemoteRequest)
            {
                DeletedByRemoteRequest.ForEach(fileId => DeletedByRemoteRequest.Add(fileId));
            }
        }

        // Flag to track disposal status
        private bool _disposed = false;

        /// <summary>
        /// Releases all resources used by the WatchCloudRoot
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by the WatchCloudRoot and optionally releases the managed resources
        /// </summary>
        /// <param name="disposing">True to release both managed and unmanaged resources; false to release only unmanaged resources</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources
                    StopWatch();
                    WakeUpTimer.Dispose();
                    if (Watcher != null)
                    {
                        Watcher.EnableRaisingEvents = false;
                        Watcher.Dispose();
                        Watcher = null;
                    }
                }
                _disposed = true;
            }
        }

        // Finalizer as a safety net in case Dispose wasn't called
        ~CloudRootWatcher()
        {
            Dispose(false);
        }
    }
}