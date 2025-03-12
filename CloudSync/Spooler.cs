using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CloudSync
{
    /// <summary>
    /// Queue for the operations that the client wants to do on the server
    /// </summary>
    internal class Spooler
    {
        public Spooler(Sync context)
        {
            Context = context;
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

        public void AddOperation(OperationType type, ulong? userId, ulong hashFile)
        {
            // Check if the file was intentionally deleted            

#if DEBUG_AND || DEBUG
            if (Context.IsServer)
                System.Diagnostics.Debugger.Break(); // the operations must be given by the client, it is preferable that the server works in slave mode

#endif
            //Context.ClientFileMonitoring?.Stop();
            lock (ToDoOperations)
            {
                if (RemoteDriveOverLimit && type == OperationType.Send) // Do not add send operations if the remote disk is full
                {
                    Context.RaiseOnStatusChangesEvent(Sync.SyncStatus.RemoteDriveOverLimit);
                }
                else
                {
                    // Remove duplicate
                    if (ToDoOperations.ContainsKey(hashFile))
                        ToDoOperations.Remove(hashFile);
                    SetRecursiveFilePendingStatus(hashFile, true);
                    ToDoOperations.Add(hashFile, new Operation { Type = type, UserId = userId, HashFile = hashFile });
                    Context.RaiseOnStatusChangesEvent(Sync.SyncStatus.Pending);
                }
            }
            if (ToDoOperations.Count == 1)
            {
                StartSyncUtc = DateTime.UtcNow;
                ExecuteNext();
            }
        }

        private readonly Dictionary<ulong, Operation> ToDoOperations = [];
        public int PendingOperations => ToDoOperations.Count;

        public enum OperationType
        {
            Send,
            Request,
        }
        public class Operation
        {
            public OperationType Type;
            public ulong? UserId;
            public ulong HashFile;
        }
        public int InPending => ToDoOperations.Count;

        /// <summary>
        /// It checks if there are any pending operations for a particular user, and if not, informs the client that there are no pending operations to be performed
        /// </summary>
        public void CheckOperationsInPending(ulong notifyToUserId)
        {
            if (Context.IsServer)
            {
                lock (ToDoOperations)
                {
                    foreach (var item in ToDoOperations.Values)
                    {
                        if (item.UserId == notifyToUserId)
                            return;
                    }
                }
                Context.StatusNotification(notifyToUserId, Sync.Status.Ready);
            }
        }
        public static int MaxConcurrentOperations = 3;

        public void ExecuteNext(ulong? userId = null)
        {
            lock (ToDoOperations)
            {
                Context.RaiseOnStatusChangesEvent(ToDoOperations.Count == 0 ? Sync.SyncStatus.Monitoring : Sync.SyncStatus.Pending);
                for (int i = Context.ConcurrentOperations(); i < MaxConcurrentOperations; i++)
                {
                    if (ToDoOperations.Count > 0)
                    {
                        Executed++;
                        var toDo = ToDoOperations.Values.ToArray()[0];
                        RemoveOperation(toDo.HashFile);
                        if (toDo.Type == OperationType.Send)
                        {
                            if (Context.HashFileTable(out var localHashes))
                            {
                                if (localHashes.TryGetValue(toDo.HashFile, out var fileSystemInfo))
                                {
                                    Context.SendFile(toDo.UserId, fileSystemInfo);
                                }
                                // the file has been modified or no longer exists
                            }
                        }
                        else
                        {
                            Context.RequestFile(toDo.UserId, toDo.HashFile);
                        }
                    }
                }
            }
            if (ToDoOperations.Count == 0)
            {
                StartSyncUtc = default;
                Executed = 0;
            }
        }

        /// <summary>
        /// Remove all pending operations
        /// </summary>
        public void Clear(bool removePendingFileAttribute = false)
        {
            if (removePendingFileAttribute)
                foreach (var toDO in ToDoOperations.ToArray())
                    SetRecursiveFilePendingStatus(toDO.Value.HashFile, false);
            if (FilePendingTree.Count != 0)
                FilePendingTree.Clear();
            lock (ToDoOperations)
            {
                ToDoOperations.Clear();
            }
        }

        /// <summary>
        /// Add a flag that shows the pending status in the operating system's file explorer
        /// </summary>
        /// <param name="hashFile">The hash of the file to set the pending state</param>
        /// <param name="pendingStatus">True to set the state that indicates the file is waiting to sync with the cloud</param>
        private void SetRecursiveFilePendingStatus(ulong hashFile, bool pendingStatus)
        {
            if (Context.HashFileTable(out var localHashes))
                if (localHashes.TryGetValue(hashFile, out var fileSystemInfo))
                    SetRecursiveFilePendingStatus(fileSystemInfo, pendingStatus);
        }

        /// <summary>
        /// Add a flag that shows the pending status in the operating system's file explorer
        /// </summary>
        /// <param name="fileSystemInfo">The fileSystemInfo of the file to set the pending state</param>
        /// <param name="pendingStatus">True to set the state that indicates the file is waiting to sync with the cloud</param>
        private void SetRecursiveFilePendingStatus(FileSystemInfo fileSystemInfo, bool pendingStatus)
        {
            try
            {
                if (pendingStatus)
                {   // ADD
                    if (fileSystemInfo.Attributes.HasFlag(FileAttributes.Directory))
                    {
                        var hash = fileSystemInfo.HashFileName(Context);
                        if (!FilePendingTree.ContainsKey(hash))
                            FilePendingTree[hash] = 0;
                        FilePendingTree[hash]++;
                    }
                    SetFilePendingStatus(fileSystemInfo, pendingStatus);
                    var parent = new DirectoryInfo(fileSystemInfo.FullName).Parent;
                    if (Path.GetFullPath(parent.FullName) != Path.GetFullPath(Context.CloudRoot))
                        SetRecursiveFilePendingStatus(parent, pendingStatus);
                }
                else
                {  // REMOVE
                    int subCount = 0;
                    if (fileSystemInfo.Attributes.HasFlag(FileAttributes.Directory))
                    {
                        var hash = fileSystemInfo.HashFileName(Context);
                        if (FilePendingTree.ContainsKey(hash))
                        {
                            FilePendingTree[hash]--;
                            subCount = FilePendingTree[hash];
                            if (subCount == 0)
                                FilePendingTree.Remove(hash);
                        }
                    }
                    if (subCount == 0)
                        SetFilePendingStatus(fileSystemInfo, pendingStatus);
                }
            }
            catch (Exception) { }
        }

        /// <summary>
        /// Add a flag that shows the pending status in the operating system's file explorer
        /// </summary>
        /// <param name="fileSystemInfo">The fileSystemInfo of the file to set the pending state</param>
        /// <param name="pendingStatus">True to set the state that indicates the file is waiting to sync with the cloud</param>

        public static void SetFilePendingStatus(FileSystemInfo fileSystemInfo, bool pendingStatus)
        {
            try
            {
                if (pendingStatus)
                {   // ADD
                    if (!fileSystemInfo.Attributes.HasFlag(Pending))
                        fileSystemInfo.Attributes |= Pending;
                }
                else
                {  // REMOVE
                    if (fileSystemInfo.Attributes.HasFlag(Pending))
                        fileSystemInfo.Attributes &= ~Pending;
                }
            }
            catch (Exception) { }
        }

        private Dictionary<ulong, int> FilePendingTree = [];


        private void RemoveOperation(ulong hashFile)
        {
            SetRecursiveFilePendingStatus(hashFile, false);
            ToDoOperations.Remove(hashFile);
        }

        const FileAttributes Pending = FileAttributes.Archive | FileAttributes.Offline;

        /// <summary>
        /// Memorize that the remote server device has a full disk and is no longer available to receive data
        /// </summary>
        public bool RemoteDriveOverLimit
        {
            get { return _RemoteDriveOverLimit; }
            set
            {
                _RemoteDriveOverLimit = value;
                if (value) // If the remote disk is full then remove the data send operations from the queue
                {
                    lock (ToDoOperations)
                    {
                        ToDoOperations.Values.ToList().ForEach(toDo =>
                        {
                            if (toDo.Type == OperationType.Send)
                                RemoveOperation(toDo.HashFile);
                        });
                    }
                }
            }
        }
        private bool _RemoteDriveOverLimit;
    }
}
