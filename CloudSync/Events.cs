using System;
using System.Threading;

namespace CloudSync
{
    public partial class Sync
    {
        // ===============================================================================
        // =================== Events about the current remote status =====================
        // ===============================================================================

        private void OnNotify(ulong? fromUserId, Notice notice)
        {
            RemoteStatus = notice;
            if (OnNotification != null)
                new Thread(() => OnNotification?.Invoke(fromUserId, notice)).Start();
        }

        public Notice RemoteStatus { get; private set; }


        // ===============================================================================
        // =================== Events about the current local status =====================
        // ===============================================================================

        public SyncStatus LocalSyncStatus { get; private set; }
        public int PendingFiles => Spooler.PendingOperations;

        public enum SyncStatus
        {
            Undefined,
            Pending,
            Monitoring,
            RemoteDriveOverLimit,
        }

        public delegate void StatusEventHandler(SyncStatus syncStatus, int pendingFiles);

        public event StatusEventHandler OnLocalSyncStatusChanges;
        internal void RaiseOnStatusChangesEvent(SyncStatus localSyncStatus)
        {
            if (LocalSyncStatus != localSyncStatus)
            {
                LocalSyncStatus = localSyncStatus;
                if (OnLocalSyncStatusChanges != null)
                    new Thread(() => OnLocalSyncStatusChanges?.Invoke(LocalSyncStatus, PendingFiles)).Start();
                if (!SyncIsInPending)
                    RequestSynchronization(); //when synced, try syncing again to verify that no files changed while running commands in the spooler
                RestartCheckSyncTimer();
            }
        }

        // ===============================================================================
        // ========================== Events about File Transfer =========================
        // ===============================================================================

        public delegate void FileTransferEventHandler(FileTransfer fileTransfer);

        public event FileTransferEventHandler OnFileTransfer;
        internal void RaiseOnFileTransfer(bool isUpload, ulong hash, uint part, uint total, string name = null, long? length = null)
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


        public delegate void OnCommandEventHandler(ulong? userId, Commands command, string infoData, bool isOutput);
        public event OnCommandEventHandler OnCommandEvent;

        internal void RaiseOnCommandEvent(ulong? userId, Commands command, string infoData = null, bool isOutput = false)
        {
            if (OnCommandEvent != null)
                new Thread(() => OnCommandEvent?.Invoke(userId, command, infoData, isOutput)).Start();
        }

        // ===============================================================================
        // ==================== Events about File Error ==================================
        // ===============================================================================

        public delegate void OnFileErrorHandler(Exception error, string fileName);
        public event OnFileErrorHandler OnFileError;

        internal void RaiseOnFileError(Exception error, string fileName)
        {
            if (error.HResult == -2147024671)
            {
                RaiseOnAntivirus(error.Message, fileName);
                return;
            }
            if (OnFileError != null)
                new Thread(() => OnFileError?.Invoke(error, fileName)).Start();
        }

        // ===============================================================================
        // ==================== Events about Antivirus warnings ==========================
        // ===============================================================================


        public delegate void OnAntivirusHandler(string warning, string fileName);
        public event OnAntivirusHandler OnAntivirus;

        internal void RaiseOnAntivirus(string warning, string fileName)
        {
            if (OnAntivirus != null)
                new Thread(() => OnAntivirus?.Invoke(warning, fileName)).Start();
        }


        // ===============================================================================
        // ============================ Events about Client ==============================
        // ===============================================================================

        /// <summary>
        /// Represents an event involving a Client
        /// </summary>
        /// <param name="newClient">The Customer involved who will be passed when the event occurs</param>
        public delegate void OnClientEvent(Client newClient);
        /// <summary>
        /// Event that fires when a new client is created (the client user logged in successfully the first time)
        /// </summary>
        public event OnClientEvent OnNewClientIsCreated;
        internal void RaiseOnNewClientIsCreated(Client newClient)
        {
            OnNewClientIsCreated?.Invoke(newClient);
        }
        public event OnClientEvent OnClientIsRemoved;

        internal void RaiseOnClientIsRemoved(Client ClientRemoved)
        {
            OnClientIsRemoved?.Invoke(ClientRemoved);
        }

    }
}

