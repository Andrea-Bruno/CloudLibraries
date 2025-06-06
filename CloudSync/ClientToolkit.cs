using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using static CloudSync.Sync;

namespace CloudSync
{
    /// <summary>
    /// Provides client-side functionality for cloud synchronization operations,
    /// including monitoring changes, managing synchronization state, and handling file operations.
    /// </summary>
    public class ClientToolkit : IDisposable
    {
        /// <summary>
        /// Initializes a new instance of the ClientToolkit class.
        /// </summary>
        /// <param name="context">The synchronization context this toolkit operates within</param>
        /// <param name="clientCredential">Optional login credentials for authentication</param>
        internal ClientToolkit(Sync context, LoginCredential? clientCredential = null)
        {
            Context = context;
            Spooler = new Spooler(context);
            TimerClientRequestSynchronization = new Timer((o) => PerformNewSyncronization());

            Task.Run(() =>
            {
                // Initialize cloud root watcher
                WatchCloudRoot = new CloudRootWatcher(context);

                // Initialize persistent file ID list if not already initialized
                if (!PersistentFileIdList.Initialized)
                {
                    PersistentFileIdList.Initialize(Context);
                }

                // Notify authentication status
                Context.OnNotify(null, Notice.Authentication);

                // Attempt login if credentials provided and not already logged in
                if (!IsLogged && clientCredential != null)
                    Context.RequestOfAuthentication(null, clientCredential, Util.PublicIpAddressInfo(), Environment.MachineName);

                // Initialize sync enabled status
                _ = SyncIsEnabled;
            });
        }

        private Sync Context { get; }

        /// <summary>
        /// Gets the spooler instance for managing file operations
        /// </summary>
        internal readonly Spooler Spooler;

        /// <summary>
        /// Removes all send operations from the spooler queue
        /// </summary>
        internal void RemoveSendOperationFromSpooler() => Spooler.RemoveSendOperationFromSpooler();

        /// <summary>
        /// Gets the estimated time of completion for current synchronization operations
        /// </summary>
        /// <returns>Estimated completion time in UTC</returns>
        public DateTime SyncETA() => Spooler.ETA();

        /// <summary>
        /// Gets the number of pending operations in the spooler
        /// </summary>
        public int PendingOperations => Spooler.PendingOperations;

        #region CloudRoot Watcher (monitoring changes in the cloud root directory)

        /// <summary>
        /// Watcher for monitoring changes in the cloud root directory
        /// </summary>
        internal CloudRootWatcher WatchCloudRoot;

        /// <summary>
        /// Handles actions when synchronization is disabled
        /// </summary>
        private void OnDisableSync()
        {
            WatchCloudRoot?.StopWatch();
            Context.SendingInProgress?.Stop();
            Context.ReceptionInProgress?.Stop();
        }

        /// <summary>
        /// Handles actions when synchronization is enabled
        /// </summary>
        private void OnEnabledSync()
        {
            if (IsLogged)
            {
                if (WaitForDirectory(Context.CloudRoot))
                {
                    if (Context.ResetHashFileTable())
                    {
                        WatchCloudRoot.ResumeWatch();
                    }
                }
            }
        }

        /// <summary>
        /// Waits for a directory to become available
        /// </summary>
        /// <param name="path">Directory path to wait for</param>
        /// <param name="timeout">Maximum wait time in milliseconds</param>
        /// <returns>True if directory exists within timeout, false otherwise</returns>
        private static bool WaitForDirectory(string path, int timeout = 10000)
        {
            return SpinWait.SpinUntil(() => Directory.Exists(path), timeout);
        }

        #endregion

        /// <summary>
        /// Gets or sets the logged-in status of the client
        /// </summary>
        public bool IsLogged
        {
            get
            {
                _isLogged ??= Context.SecureStorage.Values.Get(nameof(IsLogged), false);
                return _isLogged.Value;
            }
            internal set
            {
                LoginError = false;
                _isLogged = value;
                Context.SecureStorage.Values.Set(nameof(IsLogged), value);
                if (value)
                {
                    FlagLogin = true;
                    if (SyncIsEnabled)
                    {
                        Util.CreateUserFolder(Context.CloudRoot, Context.Owner, !Context.DontCreateSpecialFolders);
                    }
                    RestartTimerClientRequestSynchronization();
                    Context.OnLoginCompleted?.Set();
                    if (SyncIsEnabled)
                    {
                        OnEnabledSync();
                    }
                }
            }
        }
        private bool? _isLogged = null;
        private bool FlagLogin;

        /// <summary>
        /// Gets or sets whether there was a login error
        /// </summary>
        public bool LoginError { get; set; }

        /// <summary>
        /// Gets whether synchronization is currently enabled
        /// </summary>
        /// <remarks>
        /// Returns false if using a virtual disk as storage that is currently synchronized,
        /// indicating synchronization is suspended.
        /// </remarks>
        public bool SyncIsEnabled
        {
            get
            {
                var suspended = Context.SuspendSync?.Invoke() == true;
                if (suspended)
                    return false;
                var isEnabled = !Util.IsMountingPoint(Context.CloudRoot) && !suspended;

                // Initialize check timer if not already created
                CheckSyncStatusChanged ??= new Timer((o) => { var check = SyncIsEnabled; });

                if (_SyncIsEnabled != isEnabled)
                {
                    _SyncIsEnabled = isEnabled;
                    if (isEnabled)
                    {
                        // Disable periodic checks when sync is enabled
                        CheckSyncStatusChanged.Change(Timeout.Infinite, Timeout.Infinite);
                        OnEnabledSync();
                    }
                    else
                    {
                        // Check every 30 seconds when sync is disabled
                        CheckSyncStatusChanged.Change(30000, 30000);
                        OnDisableSync();
                    }
                }
                return _SyncIsEnabled == true;
            }
        }
        private Timer CheckSyncStatusChanged;
        private bool? _SyncIsEnabled = null;

        /// <summary>
        /// Gets whether there are pending synchronization operations
        /// </summary>
        internal bool SyncIsInPending => Context.RemoteStatus != Notice.Synchronized ||
                                       Context.ConcurrentOperations() != 0 ||
                                       Context.LocalSyncStatus != SyncStatus.Monitoring ||
                                       Spooler.IsPending;

        /// <summary>
        /// Timer that periodically checks synchronization status after periods of inactivity
        /// </summary>
        /// <remarks>
        /// Provides extra security for synchronization status. Rare activations don't impact
        /// network data transmission. The system already monitors changes on both client
        /// and server sides, automatically starting synchronization when changes occur.
        /// </remarks>
        private Timer TimerClientRequestSynchronization;

        /// <summary>
        /// Time interval (in minutes) for periodic synchronization checks during inactivity
        /// </summary>
        public const int recheckSyncEveryMinutes = 60;

        /// <summary>
        /// Initial delay (in minutes) before first synchronization check after restart
        /// </summary>
        private const int firstResyncTimeMinutes = 1;

        /// <summary>
        /// Restarts the synchronization check timer
        /// </summary>
        /// <remarks>
        /// Each call resets the timer interval. If client is out of sync, it attempts
        /// to sync more frequently.
        /// </remarks>
        public void RestartTimerClientRequestSynchronization()
        {
            if (IsLogged)
            {
                int nextSyncMinutes;
                if (!FirstSyncFlag)
                {
                    FirstSyncFlag = true;
                    nextSyncMinutes = 0; // Immediate check for first sync
                }
                else
                    nextSyncMinutes = firstResyncTimeMinutes;

                var nextSync = TimeSpan.FromMinutes(nextSyncMinutes);
                TimerClientRequestSynchronization?.Change(nextSync, TimeSpan.FromMinutes(recheckSyncEveryMinutes));
            }
        }
        private bool FirstSyncFlag;

        /// <summary>
        /// Initiates a new synchronization between client and server
        /// </summary>
        /// <remarks>
        /// It's recommended to use RequestSynchronization() instead of calling this directly
        /// </remarks>
        internal void PerformNewSyncronization()
        {
            if (!performingStartSynchronization)
            {
                performingStartSynchronization = true;
                if (!SyncIsEnabled)
                    return;
                if (!Context.IsTransferring())
                {
                    if (IsLogged)
                    {
                        if (Spooler.IsPending)
                            Spooler.SpoolerRun();
                        else
                            Context.SendHashRoot();
                    }
                }
                performingStartSynchronization = false;
            }
        }
        private bool performingStartSynchronization;

        #region Operation with FileIdList

        /// <summary>
        /// Adds a deleted file to the persistent deletion tracking list
        /// </summary>
        /// <param name="fileId">ID of the deleted file</param>
        public void AddDeletedFileToPersistentList(FileId fileId)
        {
            PersistentFileIdList.AddItem(Context, Context.UserId, ScopeType.Deleted, fileId);
        }

        /// <summary>
        /// Removes a file from the persistent deletion tracking list
        /// </summary>
        /// <param name="fileId">ID of the file to remove</param>
        /// <returns>True if file was found and removed, false otherwise</returns>
        public bool RemoveDeletedFileFromPersistentList(FileId fileId)
        {
            return PersistentFileIdList.RemoveItem(Context.UserId, ScopeType.Deleted, fileId);
        }

        /// <summary>
        /// Loads a deleted file list from the specified file
        /// </summary>
        /// <param name="fileName">Path to the file containing the deletion list</param>
        public void LoadDeletedFilePersistentList(string fileName)
        {
            PersistentFileIdList.Load(Context, fileName);
        }

        /// <summary>
        /// Checks if a file exists in the persistent deletion list
        /// </summary>
        /// <param name="fileId">ID of the file to check</param>
        /// <returns>True if file is in the deletion list, false otherwise</returns>
        public bool PersistentDeletedFileListContains(FileId fileId)
        {
            return PersistentFileIdList.ContainsItem(ScopeType.Deleted, fileId, out _);
        }

        /// <summary>
        /// Checks if a file was deleted locally by this client
        /// </summary>
        /// <param name="fileId">ID of the file to check</param>
        /// <returns>True if file was deleted by this client, false otherwise</returns>
        public bool FileWasDeletedLocally(FileId fileId)
        {
            if (PersistentFileIdList.ContainsItem(ScopeType.Deleted, fileId, out var userId))
            {
                return userId == Context.UserId;
            }
            return false;
        }

        /// <summary>
        /// Updates the deleted files list if the file belongs to another client's list
        /// </summary>
        /// <param name="fileName">Full path to the file containing the list</param>
        public void UpdateDeletedFileList(string fileName)
        {
            // Check if the change is in the cloud cache directory for deleted files
            var cloudCachePath = Path.Combine(Context.CloudRoot, PersistentFileIdList.CloudCacheDirectory);
            if (fileName.StartsWith(cloudCachePath))
            {
                string extension = Path.GetExtension(fileName)?.TrimStart('.');
                if (ScopeType.TryParse(extension, true, out ScopeType _))
                {
                    // Handle updates to the deleted files list from other users
                    string fileNameWithExtension = Path.GetFileName(fileName);
                    string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileNameWithExtension);
                    if (ulong.TryParse(fileNameWithoutExtension, NumberStyles.None, CultureInfo.InvariantCulture, out var userId))
                    {
                        if (Context.UserId != userId)
                        {
                            // Load the updated deleted files list from another user
                            Context.ClientToolkit?.LoadDeletedFilePersistentList(fileName);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Temporary storage for deleted file hashes and their paths
        /// </summary>
        public Dictionary<ulong, string> TemporaryDeletedHashFileDictionary = new Dictionary<ulong, string>();

        #endregion

        /// <summary>
        /// Identifies files deleted while client was offline and queues them for deletion
        /// </summary>
        /// <param name="newHashFileTable">Current state of the file system</param>
        public void FindDeletedFilesOnStartup(HashFileTable newHashFileTable)
        {
            if (!FlagLogin || Debugger.IsAttached)
            {
                var savedHashFileTable = new HashFileTable(Context, HashFileTable.LoadMode.LoadFormFile);
                FlagLogin = false;

                // Only process deletions if cloud folder isn't empty and previous state loaded successfully
                if (newHashFileTable.Count > 0 && !savedHashFileTable.LoadFailure)
                {
                    // Check for deleted files/directories
                    foreach (var element in savedHashFileTable.KeyTimestampCollection())
                    {
                        if (!newHashFileTable.ContainsKey(element.Key))
                        {
                            if (element.UnixLastWriteTimestamp == default)
                            {
                                // Queue directory deletion
                                Spooler.AddOperation(Spooler.OperationType.DeleteDirectory, element.Key);
                            }
                            else
                            {
                                // Queue file deletion and add to persistent list
                                var fileId = FileId.GetFileId(element.Key, element.UnixLastWriteTimestamp);
                                AddDeletedFileToPersistentList(fileId);
                                Spooler.AddOperation(Spooler.OperationType.DeleteFile, element.Key, element.UnixLastWriteTimestamp);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Handles changes to the file hash table
        /// </summary>
        /// <param name="newHashFileTable">Updated file hash table</param>
        public void OnHashFileTableChanged(HashFileTable newHashFileTable)
        {
            // Remove recovered files from deletion list
            foreach (var item in newHashFileTable)
            {
                if (item.Value is FileInfo)
                {
                    var fileId = FileId.GetFileId(item.Key, item.Value.UnixLastWriteTimestamp());
                    var removed = RemoveDeletedFileFromPersistentList(fileId);
                }
            }
        }

        #region IDisposable Implementation

        /// <summary>
        /// Disposes of all resources used by the ClientToolkit
        /// </summary>
        public void Dispose()
        {
            Spooler.Dispose();

            if (TimerClientRequestSynchronization != null)
            {
                TimerClientRequestSynchronization.Change(Timeout.Infinite, Timeout.Infinite);
                TimerClientRequestSynchronization.Dispose();
                TimerClientRequestSynchronization = null;
            }

            PersistentFileIdList.DisposeAll();

            if (CheckSyncStatusChanged != null)
            {
                CheckSyncStatusChanged.Change(Timeout.Infinite, Timeout.Infinite);
                CheckSyncStatusChanged.Dispose();
                CheckSyncStatusChanged = null;
            }

            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Finalizer for ClientToolkit
        /// </summary>
        ~ClientToolkit()
        {
            Dispose();
        }

        #endregion
    }
}