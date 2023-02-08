using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace CloudSync
{
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
                Debugger.Break(); // the operations must be given by the client, it is preferable that the server works in slave mode

#endif
            //Context.ClientFileMonitoring?.Stop();
            lock (ToDoOperations)
            {
                var duplicate = ToDoOperations.Find(x => x.UserId == userId && x.HashFile == hashFile);
                if (duplicate != null)
                    ToDoOperations.Remove(duplicate);
                ToDoOperations.Add(new Operation { Type = type, UserId = userId, HashFile = hashFile });
                Context.RaiseOnStatusChangesEvent();
            }
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
                Context.StatusNotification(notifyToUserId, false);
            }
        }
        public static int MaxConcurrentOperations = 3;

        public void ExecuteNext(ulong? userId = null, bool callFromFileTransferCompleted = false)
        {
            // if (Context.IsTransferring())
            if (Context.ConcurrentOperations() < MaxConcurrentOperations)
            {
                lock (ToDoOperations)
                {
                    if (ToDoOperations.Count == 0)
                    {
                        if (userId != null)
                            CheckOperationsInPending((ulong)userId);
                        //Context.ClientFileMonitoring?.Start();
                    }
                    else
                    {
                        var toDo = ToDoOperations[0];
                        ToDoOperations.Remove(toDo);
                        Context.RaiseOnStatusChangesEvent();
                        if (toDo.Type == OperationType.Send)
                        {
                            var localHashes = Context.HashFileTable();
                            if (localHashes.TryGetValue(toDo.HashFile, out var fileSystemInfo))
                            {
                                Context.SendFile(toDo.UserId, fileSystemInfo);
                            }
                            // the file has been modified or no longer exists
                        }
                        else
                        {
                            Context.RequestFile(toDo.UserId, toDo.HashFile);
                        }
                    }
                }
            }
        }
    }
}
