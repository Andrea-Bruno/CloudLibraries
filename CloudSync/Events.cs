using System.Threading;

namespace CloudSync
{
    public partial class Sync
    {
        // ===============================================================================
        // ======================= Events about the current status =======================
        // ===============================================================================

        public SynchronizationStatus SyncStatus { get; private set; }
        public int PendingFiles => Spooler.PendingOperations;

        public enum SynchronizationStatus
        {
            Undefined,
            Pending,
            Synchronized,
        }

        public delegate void StatusEventHandler(SynchronizationStatus syncStatus, int pendingFiles);

        public event StatusEventHandler OnSyncStatusChanges;
        internal void RaiseOnStatusChangesEvent(SynchronizationStatus? syncStatus = null)
        {
            var lastSyncStatus = SyncStatus;
            if (syncStatus == null)
            {
                syncStatus = SynchronizationStatus.Undefined;
            }
            else
            {
                SyncStatus = (SynchronizationStatus)syncStatus;
            }
            if (PendingFiles > 0)
                syncStatus = SynchronizationStatus.Pending;
            if (lastSyncStatus != SyncStatus)
                if (OnSyncStatusChanges != null)
                    new Thread(() => OnSyncStatusChanges?.Invoke(SyncStatus, PendingFiles)).Start();            
        }

        // ===============================================================================
        // ========================== Events about File Transfer =========================
        // ===============================================================================


        public delegate void FileTransferEventHandler(FileTransfer fileTransfer);

        public event FileTransferEventHandler OnFileTransfer;
        internal void RaiseOnFileTransfer(bool isUpload, ulong hash, uint part, uint total, string name = null, long? length = null )
        {
            if (OnFileTransfer != null)
                new Thread(() => OnFileTransfer?.Invoke(new FileTransfer { IsUpload = isUpload, Hash = hash, Part = part, Total = total, Name = name, Length = length })).Start();          
        }

        public class FileTransfer
        {
            public bool IsUpload;
            public ulong Hash;
            public uint Part;
            public uint Total;
            public string Name;
            public long? Length;
            public bool Completed => Part == Total;
        }

        // ===============================================================================
        // ==================== Events about Command in Input Output =====================
        // ===============================================================================


        public delegate void OnCommandEventHandler(Commands command, ulong? userId, bool InOutput);
        public event OnCommandEventHandler OnCommandEvent;

        internal void RaiseOnCommandEvent(Commands command, ulong? userId, bool IsOutput = false)
        {
            if (OnCommandEvent != null)
                new Thread(() => OnCommandEvent?.Invoke(command, userId, IsOutput)).Start();           
        }
    }
}

