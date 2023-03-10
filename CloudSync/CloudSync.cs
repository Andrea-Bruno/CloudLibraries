using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using EncryptedMessaging;
using Microsoft.Win32.SafeHandles;
using static CloudSync.Util;

using HashFileTable = System.Collections.Generic.Dictionary<ulong, System.IO.FileSystemInfo>;

namespace CloudSync
{
    /// <summary>
    /// Sync Agent: Offers all the low-level functions to sync the cloud in an encrypted and secure way
    /// </summary>
    public partial class Sync : IDisposable
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
            var task = new Task(() => {
                HashFileTable(out _); // set cache initial state to check if file is deleted
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
                    if (Context.SecureStorage.Values.Get("Logged", false))
                        StartSyncClient(); // It's already logged in, so start syncing immediately
                    else
                        RequestOfAuthentication(null, isClient, PublicIpAddressInfo(), Environment.MachineName); // Start the login process
                }
                WatchCloudRoot(cloudRoot);
            });
            task.Start();
        }

        public void Dispose()
        {
            Context.SecureStorage.Values.Delete("Logged", typeof(bool));
            if (SyncTimeBuffer != null)
            {
                SyncTimeBuffer.Stop();
                SyncTimeBuffer.Dispose();
                SyncTimeBuffer = null;
            }
            if (pathWatcher != null)
            {
                pathWatcher.EnableRaisingEvents = false;
                pathWatcher.Dispose();
                pathWatcher = null;
            }
            ReceptionInProgress.Dispose();
            SendingInProgress.Dispose();
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
            try
            {
                SyncTimeBuffer?.Stop();
                SyncTimeBuffer?.Start();
            }
            catch
            { // is disposed
            }
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
            //SyncTimeBuffer.Start();
        }

        public void StartSynchronization(object sender, ElapsedEventArgs e)
        {
            if (!IsTransferring())
            {
                if (IsServer)
                {
                    if (GetHasRoot(out var hashRoot, true))
                    {
                        RoleManager.ClientsConnected().ForEach(client => SendHashRoot(hashRoot, client.Id));
                    }
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
        public int ConcurrentOperations() { return SendingInProgress.TransferInProgress + ReceptionInProgress.TransferInProgress; }
        public bool IsTransferring() { return ConcurrentOperations() > 0; }
        public static readonly ushort AppId = BitConverter.ToUInt16(Encoding.ASCII.GetBytes("sync"), 0);
        public delegate void SendCommand(ulong? contactId, ushort command, params byte[][] values);
        private void ExecuteCommand(ulong? contactId, Commands command, params byte[][] values)
        {
            Debug.WriteLine("OUT " + command);
            RaiseOnCommandEvent(command, contactId, true);
            Execute.Invoke(contactId, (ushort)command, values);
        }

        private readonly SendCommand Execute;

        private bool GetLocalHashStrucrure(out byte[] localHashStrucrure, BlockRange delimitsRange)
        {
            if (HashFileTable(out var hashFileTable))
            {
                if (delimitsRange != null)
                {
                    hashFileTable = GetRestrictedHashFileTable(hashFileTable, out _, delimitsRange); // Returns null if the delimiterRange is invalid. In this case, all operations must be interrupted!
                    if (hashFileTable == null)
                    {
                        localHashStrucrure = null;
                        return false;

                    }
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
                localHashStrucrure = array;
                return true;
            }
            localHashStrucrure = null;
            return false;
        }

        private bool GetHasRoot(out byte[] hashRoot, bool noCache = false)
        {
            ulong hash1 = 0;
            ulong hash2 = 0;
            if (HashFileTable(out var hashFileTable, noCache))
            {
                foreach (var item in hashFileTable)
                {
                    hash1 ^= item.Key;
                    hash2 ^= item.Value.UnixLastWriteTimestamp();
                }
                hashRoot = (hash1 ^ hash2).GetBytes();
                return true;
            }
            hashRoot = null;
            return false;
        }

        private bool GetHasBlock(out byte[] hashBlock, bool noCache = false)
        {
            if (HashFileTable(out var hashFileTable, noCache))
            {
                hashBlock = HashFileTableToHashBlock(hashFileTable);
                return true;
            }
            hashBlock = null;
            return false;
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
        private int HashFileTableExpireCache => 10000 + HashFileTableElapsedMs;

        /// <summary>
        /// Get a hash table of contents (files and directories), useful to quickly identify what has changed. The table can be delimited within a certain range.
        /// </summary>
        /// <param name="hashTable">Returns the hash file table</param>
        /// <param name="noCache">If true then the cached table will not be returned (the table will be computed again)</param>
        /// <param name="delimitsRange">A delimiter that shrinks the table within a certain radius (for the partial table when changes have been detected in only part of the cloud)</param>
        /// <returns>True if the operation completed successfully, or false if there was a critical error</returns>
        public bool HashFileTable(out HashFileTable hashTable, bool noCache = false, BlockRange delimitsRange = null)
        {
            try
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
                    lock (this)
                    {
                        var watch = Stopwatch.StartNew();
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
                        watch.Stop();
                        HashFileTableElapsedMs = (int)(watch.ElapsedMilliseconds);
                    }
                }
                if (delimitsRange != null)
                {
                    hashTable = GetRestrictedHashFileTable(CacheHashFileTable, out _, delimitsRange);
                    return true;
                }
                hashTable = CacheHashFileTable;
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            hashTable = null;
            return false;
        }
        /// <summary>
        /// The time taken to compute the cloud path file table hash
        /// </summary>
        public int HashFileTableElapsedMs { get; internal set; }
    }
}
