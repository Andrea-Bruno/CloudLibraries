using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using static CloudSync.Util;

using HashFileTable = System.Collections.Generic.Dictionary<ulong, System.IO.FileSystemInfo>;
using System.Linq;

namespace CloudSync
{
    /// <summary>
    /// Sync Agent: Offers all the low-level functions to sync the cloud in an encrypted and secure way
    /// </summary>
    public partial class Sync : IDisposable
    {
        /// <summary>
        /// Instance initializer. Once initialized, this object will manage the synchronization protocol between client and server. It is a polyvalent object, it must be instantiated both on the client and on the server to manage the communication between the machines.
        /// </summary>
        /// <param name="sendCommand">The command of the underlying library that takes care of sending the commands to the remote machine, in the form of a data packet. The concept is to keep this library free from worrying about data transmission, leaving the pure task of managing the synchronization protocol to a higher layer.</param>
        /// <param name="onCommand">The command of the underlying library that takes care of sending the commands to the remote machine, in the form of a data packet. The concept is to keep this library free from worrying about data transmission, leaving the pure task of managing the synchronization protocol to a higher layer.</param>
        /// <param name="secureStorage">Library reference for saving local data in an encrypted way (to increase security)</param>
        /// <param name="cloudRoot">The path to the cloud root directory</param>
        /// <param name="isClient">Initialize this instance with this value set to true if the client machine is the master, if instead it is the server set this value to false to activate slave mode.</param>
        /// <param name="doNotCreateSpecialFolders">Set to true if you want to automatically create sub-folders in the cloud area to save images, photos, documents, etc..</param>
        /// <param name="isReachable">Indicate true if the path to the cloud space is reachable (true), or unmounted virtual disk (false)</param>
        public Sync(SendCommand sendCommand, out SendCommand onCommand, SecureStorage.Storage secureStorage, string cloudRoot, LoginCredential isClient = null, bool doNotCreateSpecialFolders = false, bool isReachable = true)
        {
            SecureStorage = secureStorage;
            InstanceId = InstanceCounter;
            InstanceCounter++;
            IsServer = isClient == null;
            DontCreateSpecialFolders = doNotCreateSpecialFolders;
            CloudRoot = cloudRoot;
            IsReachable = isReachable;
            var rootInfo = new DirectoryInfo(cloudRoot);
            if (IsServer)
                rootInfo.Create();
            if (rootInfo.Exists)
                rootInfo.Attributes |= FileAttributes.Encrypted;
            SendCommandDelegate = sendCommand;
            onCommand = OnCommand;
            Spooler = new Spooler(this);
            ReceptionInProgress = new ProgressFileTransfer(this);
            SendingInProgress = new ProgressFileTransfer(this);
            RoleManager = new RoleManager(this);
            var task = new Task(() =>
            {
                HashFileTable(out _); // set cache initial state to check if file is deleted
                if (IsServer)
                {
                    var pin = GetPin(secureStorage);
                    if (pin == null)
                    {
#if DEBUG
                        pin = "777777"; // To facilitate testing, in debug mode the pin will always be this: So use debug mode only for software development and testing!
#else
                        Random rnd = new Random();
                        int pinInt = rnd.Next(0, 1000000);
                        pin =  "000000" + pinInt.ToString(); // the default pin is the 6 random digits
                        pin = pin.Substring(pin.Length - 6);
#endif                        
                        SetPin(secureStorage, null, pin);
                    }
                    //SetSyncTimeBuffer();
                }
                else
                {
                    OnNotify(null, Notice.Authentication);
                    if (IsLogged)
                        ClientStartSync(); // It's already logged in, so start syncing immediately
                    else
                        RequestOfAuthentication(null, isClient, PublicIpAddressInfo(), Environment.MachineName); // Start the login process
                }
            });
            task.Start();
        }

        /// <summary>
        /// Approximate value of the end of synchronization (calculated in a statistical way)
        /// </summary>
        /// <returns>Time when synchronization is expected to end (UTC value)</returns>
        public DateTime SyncETA() => Spooler.ETA();

        /// <summary>
        /// Indicates if the client is connected. Persistent value upon restart from client application.
        /// </summary>
        public bool IsLogged
        {
            get { return SecureStorage != null && SecureStorage.Values.Get("Logged", false); }
            internal set
            {
                LoginError = false;
                SecureStorage.Values.Set("Logged", value);
                if (value)
                {
                    if (IsReachable)
                    {
                        CreateUserFolder(CloudRoot, !DontCreateSpecialFolders && !IsServer);
                    }
                    ClientStartSync();
                }
            }
        }

        public bool LoginError { get; private set; }

        /// <summary>
        /// True if there has been a communication from the remote machine (server or client), confirming that it is reachable.
        /// </summary>
        public bool RemoteHostReachable => LastCommandReceived != default;

        private bool DontCreateSpecialFolders;

        /// <summary>
        /// Function that the host app must call if the disk at the root of the cloud is mounted or unmounted.
        /// If you plan not to use a virtual disk for cloud space then this function should not be called.
        /// </summary>
        public void IsReachableDiskStateIsChanged(bool isMounted) => IsReachable = isMounted;

        /// <summary>
        /// Indicate true if the path to the cloud space is reachable (true), or unmounted virtual disk (false).
        /// </summary>
        internal bool IsReachable
        {
            get { return (bool)_IsReachable; }
            set
            {
                if (_IsReachable != value)
                {
                    _IsReachable = value;
                    if (!IsServer)
                    {
                        if (value)
                            OnMount();
                        else
                            OnUnmount();
                    }
                }
            }
        }
        private bool? _IsReachable = null;

        private void OnUnmount()
        {
            StopWatchCloudRoot();
            SendingInProgress?.Stop();
            ReceptionInProgress?.Stop();
        }

        private void OnMount()
        {
            if (IsLogged)
            {
                Spooler?.ExecuteNext();
                WatchCloudRoot();
                RequestSynchronization();
            }
        }

        private bool Disposed;
        public void Dispose()
        {
            if (!Disposed)
            {
                Disposed = true;
                RaiseOnStatusChangesEvent(SyncStatus.Undefined);
                OnNotify(null, Notice.LoggedOut);
                SecureStorage.Values.Delete("Logged", typeof(bool));
                if (SyncTimeBuffer != null)
                {
                    SyncTimeBuffer.Change(Timeout.Infinite, Timeout.Infinite);
                    SyncTimeBuffer.Dispose();
                    SyncTimeBuffer = null;
                }
                if (ClientCheckSync != null)
                {
                    ClientCheckSync.Change(Timeout.Infinite, Timeout.Infinite);
                    ClientCheckSync.Dispose();
                    ClientCheckSync = null;
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
        }

        private FileSystemWatcher pathWatcher;
        private void WatchCloudRoot()
        {
            if (pathWatcher != null)
            {
                pathWatcher.EnableRaisingEvents = true;
                return;
            }
            pathWatcher = new FileSystemWatcher
            {
                Path = CloudRoot,
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.CreationTime,
                Filter = "*.*",
                EnableRaisingEvents = true,
                IncludeSubdirectories = true
            };
            pathWatcher.Changed += (s, e) => RequestSynchronization();
            pathWatcher.Deleted += (s, e) => RequestSynchronization();
        }

        private void StopWatchCloudRoot()
        {
            if (pathWatcher != null)
                pathWatcher.EnableRaisingEvents = false;
        }

        /// <summary>
        /// After a certain period of inactivity this timer activates to see if there hasn't been a misalignment of the cloud synchronization anyway.
        /// It is a timer that gives extra security on the status of the synchronization. Rarely activating it does not weigh on the status of data transmission in the network.
        /// This check does not have to be performed frequently, the system already monitors the changes, both on the client and server side, and the synchronization is started automatically every time there has been a change.
        /// </summary>
        internal Timer ClientCheckSync;
        /// <summary>
        /// After how much idle time, a check on the synchronization status is required
        /// </summary>
        public const int CheckSyncEveryMinutes = 60;
        /// <summary>
        /// If the sync fails, a timer retries the sync. Usually the connection fails due to connection errors.
        /// </summary>
        public const int RetrySyncFailedAfterMinutes = 5;
        /// <summary>
        /// CheckSync timer trigger. Each time called it resets the timer time.
        /// </summary>
        internal void RestartCheckSyncTimer()
        {
            // If the client is out of sync, it tries to sync more frequently           
            var next = SyncIsInPending ? RetrySyncFailedAfterMinutes : CheckSyncEveryMinutes;
            var timespan = TimeSpan.FromMinutes(next);
            timespan.Add(TimeSpan.FromMilliseconds(CalculationTimeHashFileTableMS));
            ClientCheckSync?.Change(timespan, timespan);
        }

        private bool SyncIsInPending => RemoteStatus != Notice.Synchronized || ConcurrentOperations() != 0 || LocalSyncStatus != SyncStatus.Monitoring || Spooler.InPending != 0;

        /// <summary>
        /// Timer that starts the synchronization procedure when something in the cloud path has changed. The timer delays the synchronization of a few seconds because multiple changes may be in progress on the files and it is convenient to wait for the end of the operations.
        /// </summary>
        internal Timer SyncTimeBuffer;
        internal int SyncTimeBufferMs = 10000;

        /// <summary>
        /// This function starts the synchronization request, called this function a timer will shortly launch the synchronization.
        /// Synchronization requests are called whenever the system detects a file change, at regular times very far from a timer(the first method is assumed to be sufficient and this is just a check to make sure everything is in sync), or if the previous sync failed the timer with more frequent intervals will try to start the sync periodically.
        /// </summary>
        public void RequestSynchronization()
        {
            RestartCheckSyncTimer();
            try
            {
                SyncTimeBuffer?.Change(SyncTimeBufferMs, Timeout.Infinite);
            }
            catch
            { // is disposed
            }
        }

        private void ClientStartSync()
        {
            if (ClientCheckSync == null)
            {
                ClientCheckSync = new Timer((o) => RequestSynchronization());
                RestartCheckSyncTimer();
            }
            if (SyncTimeBuffer == null)
            {
                SyncTimeBuffer = new Timer((o) => StartSynchronization(), null, SyncTimeBufferMs, Timeout.Infinite);
            }
            //StartSynchronization();
            //SyncTimeBuffer.Start();
        }

        /// <summary>
        /// Start file synchronization between client and server, it is recommended not to use this command directly since starting synchronization via call RequestSynchronization()
        /// </summary>
        private void StartSynchronization()
        {
            if (!performingStartSynchronization)
            {
                performingStartSynchronization = true;
                if (!IsReachable)
                    return;
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
                        if (IsLogged)
                        {
                            Spooler.Clear();
                            SendHashRoot();
                        }
                    }
                }
                performingStartSynchronization = false;
            }
        }
        private bool performingStartSynchronization;

        public delegate void OnNotificationEvent(ulong? fromUserId, Notice notice);

        /// <summary>
        /// Procedure that is performed upon receipt of a notification from the remote machine. Can be used as an event to check the status of the remote machine.
        /// </summary>
        public event OnNotificationEvent OnNotification;

        internal readonly SecureStorage.Storage SecureStorage;

        //internal readonly Context Context;

        public readonly RoleManager RoleManager;
        internal readonly Spooler Spooler;
        public int PendingOperations => Spooler.PendingOperations;
        public readonly int InstanceId;
        private static int InstanceCounter;
        public readonly bool IsServer;
        public readonly string CloudRoot;
        public int ConcurrentOperations() { return SendingInProgress == null ? 0 : SendingInProgress.TransferInProgress + ReceptionInProgress.TransferInProgress; }
        public bool IsTransferring() { return ConcurrentOperations() > 0; }
        public static readonly ushort AppId = BitConverter.ToUInt16(Encoding.ASCII.GetBytes("sync"), 0);
        public delegate void SendCommand(ulong? contactId, ushort command, params byte[][] values);
        public DateTime LastCommandSent { get; private set; }
        private void ExecuteCommand(ulong? contactId, Commands command, string infoData, params byte[][] values)
        {
            if (!Disposed)
            {
                LastCommandSent = DateTime.UtcNow;
                Task.Run(() =>
                {
                    Debug.WriteLine("OUT " + command);
                    RaiseOnCommandEvent(contactId, command, infoData, true);
                    SendCommandDelegate.Invoke(contactId, (ushort)command, values);
                });
            }
        }

        private readonly SendCommand SendCommandDelegate;

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

        public void ResetCacheHashFileTable() => CacheHashFileTable = null;
        private HashFileTable OldHashFileTable;
        private HashFileTable CacheHashFileTable;
        private DateTime CacheHashFileTableExpire;
        /// <summary>
        /// timeout for the cache of HashFileTable, after the timeout the table will be regenerated
        /// </summary>
        private int HashFileTableExpireCache => 10000 + CalculationTimeHashFileTableMS;

        /// <summary>
        /// Get a hash table of contents (files and directories), useful to quickly identify what has changed. The table can be delimited within a certain range.
        /// </summary>
        /// <param name="hashTable">Returns the hash file table</param>
        /// <param name="noCache">If true then the cached table will not be returned (the table will be computed again)</param>
        /// <param name="delimitsRange">A delimiter that shrinks the table within a certain radius (for the partial table when changes have been detected in only part of the cloud)</param>
        /// <returns>True if the operation completed successfully, or false if there was a critical error</returns>
        public bool HashFileTable(out HashFileTable hashTable, bool noCache = false, BlockRange delimitsRange = null)
        {
#if DEBUG && !TEST
            var timer = new Stopwatch();
            timer.Start();
#endif
            try
            {
                void StartAnalyzeDirectory(string directoryName, out HashFileTable hashDirTable)
                {
                    hashDirTable = new HashFileTable();
                    AnalyzeDirectory(new DirectoryInfo(directoryName), ref hashDirTable);
                }
                void AnalyzeDirectory(DirectoryInfo directory, ref HashFileTable hashFileTable)
                {
                    try
                    {
                        var items = directory.GetFileSystemInfos();
                        var hash = directory.HashFileName(this);
                        hashFileTable.Add(hash, directory);
                        foreach (var item in items)
                        {
                            if (CanBeSeen(item))
                            {
                                if (!SyncIsInPending)
                                    Spooler.SetFilePendingStatus(item, false);
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
                    catch (Exception ex)
                    {
                        Debugger.Break();
                        RaiseOnFileError(ex, directory.FullName);
                    }
                }

                if (CacheHashFileTable == null || noCache || DateTime.UtcNow > CacheHashFileTableExpire)
                {
                    lock (this)
                    {
                        var watch = Stopwatch.StartNew();
                        StartAnalyzeDirectory(CloudRoot, out var newHashFileTable);
                        if (!IsReachable)
                            return false;
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
                                            RoleManager.ClientsConnected().ForEach(client => DeleteFile(client.Id, item.Key, item.Value));
                                        else
                                            DeleteFile(null, item.Key, item.Value);
                                    }
                                }
                            }
                        }
                        OldHashFileTable = CacheHashFileTable ?? newHashFileTable;
                        CacheHashFileTable = newHashFileTable;
                        CacheHashFileTableExpire = DateTime.UtcNow.AddMilliseconds(HashFileTableExpireCache);
                        watch.Stop();
                        CalculationTimeHashFileTableMS = (int)(watch.ElapsedMilliseconds);
                    }
                }

                if (delimitsRange != null)
                {
                    hashTable = GetRestrictedHashFileTable(CacheHashFileTable, out _, delimitsRange);

#if DEBUG && !TEST
                    timer.Stop();
                    if (timer.ElapsedMilliseconds > 10000)
                        Debugger.Break();
#endif
                    return true;
                }
                hashTable = CacheHashFileTable;
#if DEBUG && !TEST
                timer.Stop();
                if (timer.ElapsedMilliseconds > 10000)
                    Debugger.Break();
#endif
                return true;
            }
            catch (Exception ex)
            {
                RaiseOnFileError(ex, null);
                Console.WriteLine(ex.Message);
            }
            hashTable = null;
            return false;
        }
        /// <summary>
        /// The time taken to compute the cloud path file table hash in milliseconds
        /// </summary>
        public int CalculationTimeHashFileTableMS { get; internal set; }
    }
}
