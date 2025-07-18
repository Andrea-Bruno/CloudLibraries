using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace CloudSync
{
    /// <summary>
    /// Queue for the operations that the client wants to do on the server
    /// </summary>
    internal class Spooler : IDisposable
    {
        public Spooler(Sync context)
        {
            Context = context;
            SpoolerStarterTimer = new Timer((x) => { ExecuteNext(); }, null, Timeout.Infinite, Timeout.Infinite);
            SpoolerUnlockTimer = new Timer((x) => { TryUnlockSpooler(); }, null, Timeout.Infinite, Timeout.Infinite);
        }

        private readonly Sync Context;
        private DateTime StartSyncUtc;
        private int Executed;

        /// <summary>
        /// Approximate value of the end of synchronization (calculated in a statistical way)
        /// </summary>
        /// <returns>Time when synchronization is expected to end (UTC value)</returns>
        public DateTime ETA()
        {
            if (StartSyncUtc == default || Executed < 20)
                return default;
            var diffTime = DateTime.UtcNow - StartSyncUtc;
            if (diffTime.TotalMinutes < 1)
                return default;
            if ((DateTime.UtcNow - LastETAUpdate).TotalMinutes < 5) // Update ETA each 5 minutes
                return LastETA;
            LastETA = DateTime.UtcNow.Add(new TimeSpan(diffTime.Ticks / Executed * ToDoOperations.Count));
            var round = LastETA.Ticks / TimeSpan.TicksPerMinute * TimeSpan.TicksPerMinute;
            LastETA = new DateTime(round);
            LastETAUpdate = DateTime.UtcNow;
            return LastETA;
        }

        private DateTime LastETAUpdate;
        private DateTime LastETA;

        /// <summary>
        /// Adds a new operation to the spooler queue
        /// </summary>
        /// <param name="type">Type of operation to perform</param>
        /// <param name="hashFile">Hash of the file/directory to operate on</param>
        /// <param name="timestamp">Timestamp for delete operations (optional)</param>
        public void AddOperation(OperationType type, ulong hashFile, uint timestamp = 0)
        {
            // Check if the file was intentionally deleted            

#if DEBUG_AND || DEBUG          
            if (Context.IsServer)
                System.Diagnostics.Debugger.Break(); // the operations must be given by the client, it is preferable that the server works in slave mode
            if (type == OperationType.DeleteDirectory && timestamp != default)
                System.Diagnostics.Debugger.Break(); // The timestamp must be set only for the delete file operation, and not for the send or request operations
#endif
            var fileId = FileId.GetFileId(hashFile, timestamp); ;
            lock (ToDoOperations)
            {
                if (Context.RemoteDriveOverLimit && type == OperationType.SendFile) // Do not add send operations if the remote disk is full
                {
                    Context.RaiseOnStatusChangesEvent(Sync.SyncStatus.RemoteDriveOverLimit);
                }
                else
                {
                    // Remove duplicate
                    if (ToDoOperations.ContainsKey(fileId))
                        ToDoOperations.Remove(fileId);
                    if (!type.ToString().StartsWith("Delete"))
                        SetFilePendingStatus(hashFile, true);
                    ToDoOperations.Add(fileId, new Operation { Type = type, FileId = fileId });
                    Context.RaiseOnStatusChangesEvent(Sync.SyncStatus.Pending);
                }
            }
            if (ToDoOperations.Count == 1)
            {
                StartSyncUtc = DateTime.UtcNow;
                SpoolerRun();
            }
        }

        private readonly Dictionary<FileId, Operation> ToDoOperations = [];

        /// <summary>
        /// Gets the number of pending operations in the queue
        /// </summary>
        public int PendingOperations => ToDoOperations.Count;

        /// <summary>
        /// Checks if there are any pending operations
        /// </summary>
        public bool IsPending => PendingOperations > 0;

        /// <summary>
        /// Enumeration of possible operation types
        /// </summary>
        public enum OperationType
        {
            /// <summary>
            /// Send the file or create a directory on the remote server
            /// </summary>
            SendFile,
            /// <summary>
            /// Request remote file or info to create a missing directory
            /// </summary>
            RequestFile,
            /// <summary>
            /// Delete a file on the remote server
            /// </summary>
            DeleteFile,
            /// <summary>
            /// Delete a directory on the remote server
            /// </summary>
            DeleteDirectory
        }

        /// <summary>
        /// Represents a single operation in the spooler queue
        /// </summary>
        public class Operation
        {
            public OperationType Type;
            public FileId FileId;
        }

        /// <summary>
        /// Maximum number of concurrent operations allowed
        /// </summary>
        public static int MaxConcurrentOperations = 1;


        /// <summary>
        /// Schedules the execution of the next operation after a delay
        /// </summary>
        public void SpoolerRun() => SpoolerStarterTimer.Change(5000, Timeout.Infinite);
        private readonly Timer SpoolerStarterTimer;

        /// <summary>
        /// In case the connection is lost, or the router is offline, and there are scheduled jobs still in the spooler, this timer helps to verify the connection is restored and restart the spooler.
        /// </summary>
        /// <param name="enable"></param>
        public void SpoolerUnlock(bool enable)
        {
            var timespan = enable ? SpoolerUnlockTimespan : Timeout.InfiniteTimeSpan;
            SpoolerUnlockTimer.Change(timespan, timespan);
        }

        internal static TimeSpan SpoolerUnlockTimespan => TimeSpan.FromMinutes(5);

        private readonly Timer SpoolerUnlockTimer;
        private void TryUnlockSpooler()
        {
            if (IsPending && Context.CurrentConcurrentSpoolerOperations() == 0)
            {
                Context.StatusNotification(null, Sync.Status.Ready);
            }
        }

        /// <summary>
        /// Executes the next operation in the queue
        /// </summary>
        public void ExecuteNext(bool forceExecution = false)
        {
            lock (ToDoOperations)
            {
                Context.RaiseOnStatusChangesEvent(ToDoOperations.Count == 0 ? Sync.SyncStatus.Monitoring : Sync.SyncStatus.Pending);
                var start = Context.CurrentConcurrentSpoolerOperations();
                var end = MaxConcurrentOperations;
                if (forceExecution)
                {
                    start = 0;
                    end = 1;
                }
                int i = start;
                while (i < end)
                {
                    if (ToDoOperations.Count == 0)
                        break;
                    bool skip = false;
                    var toDo = ToDoOperations.Values.First();
                    RemoveOperation(toDo.FileId);
                    if (toDo.Type == OperationType.SendFile)
                    {
                        if (Context.GetHashFileTable(out var localHashes))
                        {
                            if (localHashes.TryGetValue(toDo.FileId.HashFile, out var fileSystemInfo))
                            {
                                Context.SendFile(null, fileSystemInfo);
                            }
                            else
                            {
                                // the file has been modified or no longer exists
                                skip = true;
                            }
                        }
                    }
                    else if (toDo.Type == OperationType.RequestFile)
                    {
                        Context.RequestFile(null, toDo.FileId.HashFile);
                    }
                    else if (toDo.Type == OperationType.DeleteFile)
                    {
                        Context.DeleteFile(null, toDo.FileId.HashFile, toDo.FileId.UnixLastWriteTimestamp, null);
                    }
                    else if (toDo.Type == OperationType.DeleteDirectory)
                    {
                        Context.DeleteDirectory(null, toDo.FileId.HashFile, null);
                    }
                    if (!skip)
                    {
                        Executed++;
                        i++;
                    }
                }
            }
            if (ToDoOperations.Count == 0)
            {
                SpoolerUnlock(false);

                Context.PendingConfirmation = 0;
                StartSyncUtc = default;
                Executed = 0;
            }
            else
            {
                SpoolerUnlock(true);
            }
        }

        /// <summary>
        /// Remove all pending operations
        /// </summary>
        public void Clear()
        {
            lock (ToDoOperations)
            {
                ToDoOperations.Clear();
            }
        }

        /// <summary>
        /// Adds or removes the pending status flag for a file/directory
        /// </summary>
        /// <param name="hashFile">Hash of the file/directory</param>
        /// <param name="pendingStatus">True to set pending status, false to remove it</param>
        /// <returns>True if the operation was successful</returns>
        public bool SetFilePendingStatus(ulong hashFile, bool pendingStatus)
        {
            if (Context.GetHashFileTable(out var localHashes))
            {
                if (localHashes.TryGetValue(hashFile, out var fileSystemInfo))
                {
                    try
                    {
                        var parentDirectory = new DirectoryInfo(fileSystemInfo is FileInfo file ? file.DirectoryName : (fileSystemInfo as DirectoryInfo)?.Parent?.FullName);
                        if (pendingStatus)
                        {   // ADD
                            fileSystemInfo.Attributes |= Pending;
                            if (parentDirectory.FullName != LastDirAddPending)
                            {
                                LastDirAddPending = parentDirectory.FullName;
                                parentDirectory.Attributes |= Pending; // Add pending status to the parent directory
                            }
                            return true;
                        }
                        else
                        {  // REMOVE
                            fileSystemInfo.Attributes &= ~Pending;
                            if (parentDirectory.FullName != LastDirRemovePending)
                            {
                                LastDirRemovePending = parentDirectory.FullName;
                                parentDirectory.Attributes &= ~Pending; // Remove pending status to the parent directory
                            }
                            return true;
                        }
                    }
                    catch (Exception) { }
                }
            }
            return false;
        }
        private string LastDirAddPending;
        private string LastDirRemovePending;

        /// <summary>
        /// Removes a specific operation from the queue
        /// </summary>
        /// <param name="fileId">Identifier of the operation to remove</param>
        private void RemoveOperation(FileId fileId)
        {
            Context.ClientToolkit?.RestartTimerClientRequestSynchronization();
            lock (ToDoOperations)
            {
                if (ToDoOperations.TryGetValue(fileId, out var operation))
                {
                    if (!operation.Type.ToString().StartsWith("Delete"))
                        SetFilePendingStatus(fileId.HashFile, false);
                    ToDoOperations.Remove(fileId);
                    if (ToDoOperations.Count == 0)
                        Context.RaiseOnStatusChangesEvent(Sync.SyncStatus.Analysing);
                }
            }
        }

        /// <summary>
        /// File attributes combination that represents the "pending sync" status
        /// </summary>
        const FileAttributes Pending = FileAttributes.Archive | FileAttributes.Offline;

        /// <summary>
        /// Removes all send operations from the queue
        /// </summary>
        public void RemoveSendOperationFromSpooler()
        {
            lock (ToDoOperations)
            {
                ToDoOperations.Values.ToList().ForEach(toDo =>
                {
                    if (toDo.Type == OperationType.SendFile)
                        RemoveOperation(toDo.FileId);
                });
            }
        }

        #region IDisposable Implementation

        private bool _disposed = false;

        /// <summary>
        /// Disposes the spooler resources
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Protected implementation of Dispose pattern
        /// </summary>
        /// <param name="disposing">True if called from Dispose(), false if called from finalizer</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                // Dispose managed resources
                SpoolerStarterTimer?.Dispose();
                SpoolerUnlockTimer?.Dispose();
                Clear();
            }

            _disposed = true;
        }

        ~Spooler()
        {
            Dispose(false);
        }

        #endregion
    }
}