﻿using System.Collections.Generic;
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

        public void AddOperation(OperationType type, ulong? userId, ulong hashFile)
        {
#if DEBUG_AND || DEBUG
            if (Context.IsServer)
                System.Diagnostics.Debugger.Break(); // the operations must be given by the client, it is preferable that the server works in slave mode

#endif
            //Context.ClientFileMonitoring?.Stop();
            lock (ToDoOperations)
            {
                var duplicate = ToDoOperations.Find(x => x.UserId == userId && x.HashFile == hashFile);
                if (duplicate != null)
                    ToDoOperations.Remove(duplicate);
                if (!RemoteDriveOverLimit || type != OperationType.Send) // Do not add send operations if the remote disk is full
                {
                    ToDoOperations.Add(new Operation { Type = type, UserId = userId, HashFile = hashFile });
                }
                Context.RaiseOnStatusChangesEvent(Sync.SyncStatus.Pending);
            }
            if (ToDoOperations.Count == 1)
                ExecuteNext();
        }
        private readonly List<Operation> ToDoOperations = new List<Operation>();
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
                foreach (var item in ToDoOperations)
                {
                    if (item.UserId == notifyToUserId)
                        return;
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
                        var toDo = ToDoOperations[0];
                        ToDoOperations.Remove(toDo);
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
                        ToDoOperations.ToList().ForEach(toDo =>
                        {
                            if (toDo.Type == OperationType.Send)
                                ToDoOperations.Remove(toDo);
                        });
                    }
                }
            }
        }
        private bool _RemoteDriveOverLimit;
    }
}
