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
                OnSyncStatusChanges?.Invoke(SyncStatus, PendingFiles);
        }

        // ===============================================================================
        // ========================== Events about File Transfer =========================
        // ===============================================================================


        public delegate void FileTransferEventHandler(FileTransfer fileTransfer);

        public event FileTransferEventHandler OnFileTransfer;
        internal void RaiseOnFileTransfer(bool isUpload, ulong hash, uint part, uint total, string name = null, long? length = null )
        {
            OnFileTransfer?.Invoke(new FileTransfer { IsUpload = isUpload, Hash = hash, Part = part, Total = total, Name = name, Length = length });
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
            OnCommandEvent?.Invoke(command, userId, IsOutput);
        }
    }
}

