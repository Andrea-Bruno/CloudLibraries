using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Timers;
using EncryptedMessaging;
using static CloudSync.Util;

using HashFileTable = System.Collections.Generic.Dictionary<ulong, System.IO.FileSystemInfo>;

namespace CloudSync
{
    /// <summary>
    /// Sync Agent: Offers all the low-level functions to sync the cloud in an encrypted and secure way
    /// </summary>
    public partial class Sync
    {
        public Sync(SendCommand sendCommand, out SendCommand onCommand, Context context, string cloudRoot, LoginCredential isClient = null, bool doNotCreateSpecialFolders = false)
        {
            Context = context;
            InstanceId = InstanceCounter;
            InstanceCounter++;
            IsServer = isClient == null;
            CloudRoot = cloudRoot;
            var createIfNotExists = SetSpecialDirectory(cloudRoot, Icos.Cloud, false) && doNotCreateSpecialFolders == false;
            SetSpecialDirectory(cloudRoot, Icos.Documents, createIfNotExists: createIfNotExists && IsServer);
            SetSpecialDirectory(cloudRoot, Icos.Download, createIfNotExists: createIfNotExists && IsServer);
            SetSpecialDirectory(cloudRoot, Icos.Movies, createIfNotExists: createIfNotExists && IsServer);
            SetSpecialDirectory(cloudRoot, Icos.Pictures, createIfNotExists: createIfNotExists && IsServer);
            SetSpecialDirectory(cloudRoot, Icos.Photos, createIfNotExists: createIfNotExists && IsServer);
            SetSpecialDirectory(cloudRoot, Icos.Settings, createIfNotExists: createIfNotExists && IsServer);
            if (createIfNotExists)
                AddDesktopShorcut(cloudRoot);


            Execute = sendCommand;
            onCommand = OnCommand;
            Spooler = new Spooler(this);
            ReceptionInProgress = new ProgressFileTransfer(this);
            SendingInProgress = new ProgressFileTransfer(this);
            RoleManager = new RoleManager(this);
            if (IsServer)
            {
                var pin = GetPin(context);
                if (pin == null)
                {
                    pin = BitConverter.ToUInt64(Hash256(Context.My.GetPrivateKeyBinary()), 0).ToString().Substring(0, 6); // the default pin is the first 6 digits of the private key hash

                    SetPin(context, null, pin);
                }
                SetSyncTimeBuffer();
            }
            else
            {
                RequestOfAuthentication(null, isClient, PublicIpAddressInfo(), Environment.MachineName);

            }
            WatchCloudRoot(cloudRoot);
            HashFileTable(); // set cache initial state to check if file is deleted
        }
        private FileSystemWatcher pathWatcher;
        private void WatchCloudRoot(string path)
        {
            pathWatcher = new FileSystemWatcher
            {
                Path = path,
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.CreationTime,
                Filter = "*.*",
                EnableRaisingEvents = true,
                IncludeSubdirectories = true
            };
            pathWatcher.Changed += (s, e) => RequestSynchronization();
            pathWatcher.Deleted += (s, e) => RequestSynchronization();
        }

        /// <summary>
        /// After a certain period of inactivity this timer activates to see if there hasn't been a misalignment of the cloud synchronization anyway.
        /// It is a timer that gives extra security on the status of the synchronization. Rarely activating it does not weigh on the status of data transmission in the network.
        /// This check does not have to be performed frequently, the system already monitors the changes, both on the client and server side, and the synchronization is started automatically every time there has been a change.
        /// </summary>
        internal Timer CheckSync;
        /// <summary>
        /// After how much idle time, a check on the synchronization status is required
        /// </summary>
        public const int CheckEveryMinutes = 60;

        /// <summary>
        /// CheckSync timer trigger. Each time called it resets the timer time.
        /// </summary>
        internal void RefreshCheckSyncTimer()
        {
            CheckSync?.Stop();
            CheckSync?.Start();
        }

        /// <summary>
        /// Timer that starts the synchronization procedure when something in the cloud path has changed. The timer delays the synchronization of a few seconds because multiple changes may be in progress on the files and it is convenient to wait for the end of the operations.
        /// </summary>
        internal Timer SyncTimeBuffer;
        private void SetSyncTimeBuffer()
        {
            SyncTimeBuffer = new Timer(10000)
            {
                AutoReset = false,
            };
            SyncTimeBuffer.Elapsed += StartSynchronization;
        }
        public void RequestSynchronization()
        {
            SyncTimeBuffer?.Stop();
            SyncTimeBuffer?.Start();
        }

        private void StartSyncClient()
        {
            CheckSync = new Timer(CheckEveryMinutes * 60 * 1000)
            {
                AutoReset = false,
            };
            CheckSync.Elapsed += (s, e) => RequestSynchronization();
            SetSyncTimeBuffer();
            StartSynchronization(null, null);
        }

        public void StartSynchronization(object sender, ElapsedEventArgs e)
        {
            if (!IsTransferring())
            {
                if (IsServer)
                {
                    RoleManager.ClientsConnected().ForEach(client => SendHashRoot(client.Id));
                }
                else
                {
                    SendHashRoot();
                }
            }
        }

        public delegate void OnNotificationEvent(ulong? fromUserId, Notice notice);

        public event OnNotificationEvent OnNotification;

        internal readonly Context Context;

        public readonly RoleManager RoleManager;
        internal readonly Spooler Spooler;
        public int PendingOperations => Spooler.PendingOperations;
        public readonly int InstanceId;
        private static int InstanceCounter;
        public readonly bool IsServer;
        public readonly string CloudRoot;

        public bool IsTransferring() { return SendingInProgress.TransferInProgress() > 0 || ReceptionInProgress.TransferInProgress() > 0; }
        public static readonly ushort AppId = BitConverter.ToUInt16(Encoding.ASCII.GetBytes("sync"), 0);
        public delegate void SendCommand(ulong? contactId, ushort command, params byte[][] values);
        private void ExecuteCommand(ulong? contactId, Commands command, params byte[][] values)
        {
            Debug.WriteLine("OUT " + command);
            RaiseOnCommandEvent(command, contactId, true);
            Execute.Invoke(contactId, (ushort)command, values);
        }

        private readonly SendCommand Execute;

        private byte[] GetLocalHashStrucrure(BlockRange delimitsRange)
        {
            var hashFileTable = HashFileTable();
            if (delimitsRange != null)
            {
                hashFileTable = GetRestrictedHashFileTable(hashFileTable, out _, delimitsRange); // Returns null if the delimiterRange is invalid. In this case, all operations must be interrupted!
                if (hashFileTable == null)
                    return null;
            }
            var array = new byte[hashFileTable.Count * 12];
            var offset = 0;
            foreach (var item in hashFileTable)
            {
                Buffer.BlockCopy(BitConverter.GetBytes(item.Key), 0, array, offset, 8);
                offset += 8;
                Buffer.BlockCopy(BitConverter.GetBytes(item.Value.UnixLastWriteTimestamp()), 0, array, offset, 4);
                offset += 4;
            }
            return array;
        }

        private byte[] GetHasRoot(bool noCache = false)
        {
            ulong hash1 = 0;
            ulong hash2 = 0;
            foreach (var item in HashFileTable(noCache))
            {
                hash1 ^= item.Key;
                hash2 ^= item.Value.UnixLastWriteTimestamp();
            }
            return (hash1 ^ hash2).GetBytes();
        }

        private byte[] GetHasBlock(bool noCache = false)
        {
            var hashFileTable = HashFileTable(noCache);
            return HashFileTableToHashBlock(hashFileTable);
        }

        private bool Existed(ulong hashFile)
        {
            return OldHashFileTable != null && OldHashFileTable.ContainsKey(hashFile);
        }
        private HashFileTable OldHashFileTable;
        private HashFileTable CacheHashFileTable;
        private DateTime CacheHashFileTableExpire;
        /// <summary>
        /// timeout for the cache of HashFileTable, after the timeout the table will be regenerated
        /// </summary>
        private const int HashFileTableExpireCache = 10000;
        public HashFileTable HashFileTable(bool noCache = false, BlockRange delimitsRange = null)
        {
            void StartAnalyzeDirectory(string directoryName, out HashFileTable hashDirTable)
            {
                hashDirTable = new HashFileTable();
                AnalyzeDirectory(new DirectoryInfo(directoryName), ref hashDirTable);
            }
            void AnalyzeDirectory(DirectoryInfo directory, ref HashFileTable hashFileTable)
            {
                var hash = directory.HashFileName(this);
                hashFileTable.Add(hash, directory);
                var items = directory.GetFileSystemInfos();
                foreach (var item in items)
                {
                    if (CanBeSeen(item))
                    {
                        if (item.Attributes.HasFlag(FileAttributes.Directory))
                        {
                            AnalyzeDirectory((DirectoryInfo)item, ref hashFileTable);
                        }
                        else
                        {
                            hash = item.HashFileName(this);
                            hashFileTable[hash] = item;
                        }
                    }
                }
            }

            if (CacheHashFileTable == null || noCache || DateTime.UtcNow > CacheHashFileTableExpire)
            {
                StartAnalyzeDirectory(CloudRoot, out var newHashFileTable);
                if (CacheHashFileTable != null)
                {
                    // check if any files have been deleted
                    foreach (var item in CacheHashFileTable)
                    {
                        if (!newHashFileTable.ContainsKey(item.Key))
                        {
                            if (item.Value.Attributes.HasFlag(FileAttributes.Directory))
                            {
                                if (IsServer)
                                    RoleManager.ClientsConnected().ForEach(client => DeleteDirectory(client.Id, item.Value));
                                else
                                    DeleteDirectory(null, item.Value);
                            }
                            else
                            {
                                if (IsServer)
                                    RoleManager.ClientsConnected().ForEach(client => DeleteFile(client.Id, item.Key, item.Value.UnixLastWriteTimestamp()));
                                else
                                    DeleteFile(null, item.Key, item.Value.UnixLastWriteTimestamp());
                            }
                        }
                    }
                }
                OldHashFileTable = CacheHashFileTable ?? newHashFileTable;
                CacheHashFileTable = newHashFileTable;
                CacheHashFileTableExpire = DateTime.UtcNow.AddMilliseconds(HashFileTableExpireCache);
            }
            if (delimitsRange != null)
            {
                return GetRestrictedHashFileTable(CacheHashFileTable, out _, delimitsRange);
            }
            return CacheHashFileTable;
        }
    }
}
