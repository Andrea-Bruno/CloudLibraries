using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using static CloudSync.Util;
using System.Linq;
using System.Collections.Generic;
using System.Xml.Serialization;

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
        /// <param name="userId">User id that identifies the client or server</param>
        /// <param name="sendCommand">The command of the underlying library that takes care of sending the commands to the remote machine, in the form of a data packet. The concept is to keep this library free from worrying about data transmission, leaving the pure task of managing the synchronization protocol to a higher layer.</param>
        /// <param name="onCommand">The command of the underlying library that takes care of sending the commands to the remote machine, in the form of a data packet. The concept is to keep this library free from worrying about data transmission, leaving the pure task of managing the synchronization protocol to a higher layer.</param>
        /// <param name="secureStorage">Library reference for saving local data in an encrypted way (to increase security)</param>
        /// <param name="cloudRoot">The path to the cloud root directory</param>
        /// <param name="clientCredential">If the current machine is a client, the first time you need to pass the connection credentials to be able to log in to the server</param>
        /// <param name="doNotCreateSpecialFolders">Set to true if you want to automatically create sub-folders in the cloud area to save images, photos, documents, etc..</param>
        /// <param name="owner">If set, during synchronization operations (creating files and directories), the owner will be the one specified here</param>
        /// <param name="encryptionMasterKey">If set, zero knowledge proof is enabled, meaning files will be sent encrypted with keys derived from this, and once received, if encrypted, they will be decrypted.</param>
        /// <param name="storageLimitGB">Limit cloud storage (useful for assigning storage to users with subscription plans)</param>
        [DebuggerHidden]
        public Sync(ulong userId, SendCommandDelegate sendCommand, out SendCommandDelegate onCommand, SecureStorage.Storage secureStorage, string cloudRoot, LoginCredential clientCredential = null, bool doNotCreateSpecialFolders = false, string owner = null, byte[] encryptionMasterKey = null, int storageLimitGB = -1)
        {
            onCommand = OnCommand;
            UserId = userId;
            if (owner != null)
            {
                Owner = GetUserIds(owner);
            }
            if (encryptionMasterKey != null)
                ZeroKnowledgeProof = new ZeroKnowledgeProof(this, encryptionMasterKey);
            StorageLimitGB = storageLimitGB;
            SecureStorage = secureStorage;
            RoleManager = new RoleManager(this);
            InstanceId = InstanceCounter;
            InstanceCounter++;
            var isLogged = IsLogged;
            IsClient = clientCredential != null;
            if (IsClient)
            {
                secureStorage.Values.Set(nameof(IsClient), IsClient);
            }
            else
            {
                IsClient = secureStorage.Values.Get(nameof(IsClient), false);
            }

            DontCreateSpecialFolders = doNotCreateSpecialFolders;
            CloudRoot = cloudRoot;
            var rootInfo = new DirectoryInfo(cloudRoot);
            if (IsServer)
                DirectoryCreate(cloudRoot, Owner, out _);
            if (rootInfo.Exists)
            {
                rootInfo.Attributes |= FileAttributes.Encrypted;
                SetOwner(Owner, cloudRoot);
            }

            Share = new Share(this);
            Send = sendCommand;
            Spooler = new Spooler(this);
            ReceptionInProgress = new ProgressFileTransfer(this);
            SendingInProgress = new ProgressFileTransfer(this);

            if (IsClient)
            {
                OnNotify(null, Notice.Authentication);
                if (!isLogged)
                    RequestOfAuthentication(null, clientCredential, PublicIpAddressInfo(), Environment.MachineName); // Start the login process

                // initialize SyncIsEnabled status
                Task.Run(delegate { _ = SyncIsEnabled; });

                //if (SyncIsEnabled)
                //{
                //    //if (Debugger.IsAttached)
                //    //    GetHashFileTable(out _);
                //    //else
                //    Task.Run(() => GetHashFileTable(out _)); // set cache initial state to check if file is deleted
                //}
            }
            else
            {
                var pin = GetPin(secureStorage);
                if (pin == null)
                {
#if DEBUG
                    pin = "777777"; // To facilitate testing, in debug mode the pin will always be this: So use debug mode only for software development and testing!
#else
                    Random rnd = new Random();
                    int pinInt = rnd.Next(0, 1000000);
                    pin = "000000" + pinInt.ToString(); // the default pin is the 6 random digits
                    pin = pin.Substring(pin.Length - 6);
#endif
                    SetPin(secureStorage, null, pin);
                }
            }
        }

        internal ZeroKnowledgeProof ZeroKnowledgeProof;
        internal ulong UserId;
        internal (uint, uint)? Owner;
        public readonly Share Share;
        /// <summary>
        /// The amount of space reserved for file storage expressed in gigabytes
        /// </summary>
        public int StorageLimitGB { get; private set; }

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
            get { return SecureStorage != null && SecureStorage.Values.Get(nameof(IsLogged), false); }
            internal set
            {
                LoginError = false;
                SecureStorage.Values.Set(nameof(IsLogged), value);
                if (value)
                {
                    if (SyncIsEnabled)
                    {
                        CreateUserFolder(CloudRoot, Owner, !DontCreateSpecialFolders && !IsServer);
                    }

                    InitializeClientSynchronization();
                    OnLoginCompleted?.Set();
                }
            }
        }

        public AutoResetEvent OnLoginCompleted;

        public bool LoginError { get; private set; }

        /// <summary>
        /// True if there has been a communication from the remote machine (server or client), confirming that it is reachable.
        /// </summary>
        public bool RemoteHostReachable => LastCommandReceived != default;

        private bool DontCreateSpecialFolders;


        /// <summary>
        /// Set this function to externally hook the command to pause and resume synchronization
        /// </summary>
        public Func<bool> SuspendSync;

        /// <summary>
        /// If you are using a virtual disk as storage and it is synchronized, this function will return false, which indicates that synchronization is suspended.
        /// </summary>
        public bool SyncIsEnabled
        {
            get
            {
                var suspended = SuspendSync?.Invoke() == true;
                if (suspended)
                    return false;
                if (IsServer)
                {
                    return Directory.Exists(CloudRoot); // Enable this code line if the server can disconnect the cloud path location
                    //return true;
                }
                var isEnabled = !IsMountingPoint(CloudRoot) && !suspended;
                CheckSyncStatusChanged ??= new Timer((o) => { var check = SyncIsEnabled; });
                if (_SyncIsEnabled != isEnabled)
                {
                    _SyncIsEnabled = isEnabled;
                    if (isEnabled)
                    {
                        CheckSyncStatusChanged.Change(Timeout.Infinite, Timeout.Infinite);
                        OnEnabledSync();
                    }
                    else
                    {
                        CheckSyncStatusChanged.Change(30000, 30000); //30 sec.
                        OnDisableSync();
                    }
                }
                return _SyncIsEnabled == true;
            }
        }
        private Timer CheckSyncStatusChanged;


        private bool? _SyncIsEnabled = null;

        ///// <summary>
        ///// Block or enable synchronization. Possible use:
        ///// Function that the host app must call if the disk at the root of the cloud is mounted or unmounted.
        ///// If you plan not to use a virtual disk for cloud space then this function should not be called.
        ///// If you use a virtual disk as a path to the cloud, this feature will suspend synchronization when the disk is unmounted.
        ///// </summary>
        //public void SetSyncState(bool isMounted) => SyncIsEnabled = isMounted;

        //protected bool SyncIsEnabled
        //{
        //    get { return (bool)_SyncIsEnabled; }
        //    private set
        //    {
        //        if (_SyncIsEnabled != value)
        //        {
        //            _SyncIsEnabled = value;
        //            if (!IsServer)
        //            {
        //                if (value)
        //                    OnEnabledSync();
        //                else
        //                    OnDisableSync();
        //            }
        //        }
        //    }
        //}


        private void OnDisableSync()
        {
            StopWatchCloudRoot();
            SendingInProgress?.Stop();
            ReceptionInProgress?.Stop();
        }

        private void OnEnabledSync()
        {
            if (IsLogged)
            {
                if (WaitForDirectory(CloudRoot))
                {
                    GetHashFileTable(out _, true);
                    if (WatchCloudRoot())
                    {
                        Spooler?.ExecuteNext();
                        ClientRequestSynchronization();
                    }
                }
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
                SecureStorage.Values.Delete(nameof(IsLogged), typeof(bool));
                SecureStorage.Values.Delete(nameof(IsClient), typeof(bool));

                if (TimerStartClientSynchronization != null)
                {
                    TimerStartClientSynchronization.Change(Timeout.Infinite, Timeout.Infinite);
                    TimerStartClientSynchronization.Dispose();
                    TimerStartClientSynchronization = null;
                }

                if (TimerClientRequestSynchronization != null)
                {
                    TimerClientRequestSynchronization.Change(Timeout.Infinite, Timeout.Infinite);
                    TimerClientRequestSynchronization.Dispose();
                    TimerClientRequestSynchronization = null;
                }

                if (CheckSyncStatusChanged != null)
                {
                    CheckSyncStatusChanged.Change(Timeout.Infinite, Timeout.Infinite);
                    CheckSyncStatusChanged.Dispose();
                    CheckSyncStatusChanged = null;
                }

                if (PathWatcher != null)
                {
                    PathWatcher.EnableRaisingEvents = false;
                    PathWatcher.Dispose();
                    PathWatcher = null;
                }

                ReceptionInProgress.Dispose();
                SendingInProgress.Dispose();
            }
        }

        /// <summary>
        /// Delete all sensitive data created by this instance
        /// </summary>
        public void Destroy()
        {
            SecureStorage?.Destroy();
        }

        /// <summary>
        /// After a certain period of inactivity this timer activates to see if there hasn't been a misalignment of the cloud synchronization anyway.
        /// It is a timer that gives extra security on the status of the synchronization. Rarely activating it does not weigh on the status of data transmission in the network.
        /// This check does not have to be performed frequently, the system already monitors the changes, both on the client and server side, and the synchronization is started automatically every time there has been a change.
        /// </summary>
        internal Timer TimerClientRequestSynchronization;

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
        internal void RestartTimerClientRequestSynchronization()
        {
            if (TimerClientRequestSynchronization != null)
            {

                // If the client is out of sync, it tries to sync more frequently           
                int nextSyncMinutes;
                if (!FirstSyncFlag)
                {
                    FirstSyncFlag = true;
                    nextSyncMinutes = 0;
                }
                else
                    nextSyncMinutes = SyncIsInPending ? RetrySyncFailedAfterMinutes : CheckSyncEveryMinutes;

                var timespan = TimeSpan.FromMinutes(nextSyncMinutes);
                timespan.Add(TimeSpan.FromMilliseconds(CalculationTimeHashFileTableMS));
                TimerClientRequestSynchronization?.Change(timespan, timespan);
            }
        }

        private bool FirstSyncFlag;

        private bool SyncIsInPending => RemoteStatus != Notice.Synchronized || ConcurrentOperations() != 0 || LocalSyncStatus != SyncStatus.Monitoring || Spooler.IsPending;

        /// <summary>
        /// Timer that starts the synchronization procedure when something in the cloud path has changed. The timer delays the synchronization of a few seconds because multiple changes may be in progress on the files and it is convenient to wait for the end of the operations.
        /// </summary>
        internal Timer TimerStartClientSynchronization;
        internal int PauseBeforeSyncing = 10000;

        private void InitializeClientSynchronization()
        {
            if (TimerClientRequestSynchronization == null)
            {
                TimerClientRequestSynchronization = new Timer((o) => ClientRequestSynchronization());
                RestartTimerClientRequestSynchronization();
            }
            if (TimerStartClientSynchronization == null)
            {
                TimerStartClientSynchronization = new Timer((o) => StartClientSynchronization(), null, PauseBeforeSyncing, Timeout.Infinite);
            }
        }

        /// <summary>
        /// Start file synchronization between client and server, it is recommended not to use this command directly since starting synchronization via call RequestSynchronization()
        /// </summary>
        private void StartClientSynchronization()
        {
            if (!performingStartSynchronization)
            {
                performingStartSynchronization = true;
                if (!SyncIsEnabled)
                    return;
                if (!IsTransferring())
                {
                    if (IsServer)
                    {
                        if (GetHasRoot(out var hashRoot))
                        {
                            RoleManager.ClientsConnected().ForEach(client => SendHashRoot(hashRoot, client.Id));
                        }
                    }
                    else
                    {
                        if (IsLogged)
                        {
                            if (Spooler.IsPending)
                                Spooler.ExecuteNext();
                            else
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

        //internal readonly Context;

        public readonly RoleManager RoleManager;
        internal readonly Spooler Spooler;
        public int PendingOperations => Spooler.PendingOperations;
        public readonly int InstanceId;
        private static int InstanceCounter;
        public bool IsServer
        {
            get { return !IsClient; }
        }

        public readonly bool IsClient;
        public readonly string CloudRoot;
        public string AppDataPath => Path.Combine(CloudRoot, FileIdList.CloudCache);

        public int ConcurrentOperations()
        {
            return SendingInProgress == null
                ? 0
                : SendingInProgress.TransferInProgress + ReceptionInProgress.TransferInProgress;
        }

        public bool IsTransferring()
        {
            return ConcurrentOperations() > 0;
        }

        public static readonly ushort AppId = BitConverter.ToUInt16(Encoding.ASCII.GetBytes("sync"), 0);

        public delegate bool SendCommandDelegate(ulong? contactId, ushort command, params byte[][] values);

        public DateTime LastCommandSent { get; private set; }


        private readonly SendCommandDelegate Send;

        private bool GetLocalHashStructure(out byte[] localHashStructure)
        {
            if (GetHashFileTable(out var hashFileTable))
            {
                //if (delimitsRange != null)
                //{
                //    hashFileTable = GetRestrictedHashFileTable(hashFileTable, out _, delimitsRange); // Returns null if the delimiterRange is invalid. In this case, all operations must be interrupted!
                //    if (hashFileTable == null)
                //    {
                //        localHashStructure = null;
                //        return false;
                //    }
                //}

                var array = new byte[hashFileTable.Count * 12];
                var offset = 0;

                for (var phase = 0; phase <= 1; phase++)
                {
                    foreach (var item in hashFileTable)
                    {
                        var priority = item.Value is FileInfo fileInfo && SpecialDirectories.Contains(fileInfo.DirectoryName);
                        if ((phase == 0 && priority) || (phase == 1 && !priority))
                        {
                            Buffer.BlockCopy(BitConverter.GetBytes(item.Key), 0, array, offset, 8);
                            offset += 8;
                            Buffer.BlockCopy(BitConverter.GetBytes(item.Value.UnixLastWriteTimestamp()), 0, array, offset, 4);
                            offset += 4;
                        }
                    }
                }
                localHashStructure = array;
                return true;
            }

            localHashStructure = null;
            return false;
        }

        private bool GetHasRoot(out byte[] hashRoot)
        {
            ulong hash1 = 0;
            ulong hash2 = 0;
            if (GetHashFileTable(out var hashFileTable))
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

        private bool GetHasBlock(out byte[] hashBlock)
        {
            if (GetHashFileTable(out var hashFileTable))
            {
                hashBlock = HashFileTableToHashBlock(hashFileTable);
                return true;
            }

            hashBlock = null;
            return false;
        }

        private bool Existed(ulong hashFile)
        {
            return DeletedHashTable.Contains(hashFile);
        }
        private List<ulong> DeletedHashTable = [];

        public void ResetCacheHashFileTable() => _CacheHashFileTable = null;

        /// <summary>
        /// Don't use directly: Get it with GetHashFileTable(out value)
        /// </summary>
        private HashFileTable _CacheHashFileTable;


        /// <summary>
        /// Get a hash table of contents (files and directories), useful to quickly identify what has changed. The table can be delimited within a certain range.
        /// </summary>
        /// <param name="hashTable">Returns the hash file table</param>
        /// <returns>True if the operation completed successfully, or false if there was a critical error</returns>
        public bool GetHashFileTable(out HashFileTable hashTable, bool refresh = false)
        {
            if (!Directory.Exists(CloudRoot))
            {
                RaiseOnFileError(new Exception("Cloud root not found!"), CloudRoot);
                hashTable = null;
                return false;
            }
            if (Disposed)
            {
                hashTable = null;
                return false;
            }
            if (!refresh && !SyncIsEnabled)
            {
                hashTable = null;
                return false;
            }

            try
            {
                long usedSpace = 0;

                void AnalyzeDirectory(DirectoryInfo directory, ref HashFileTable hashFileTable, ref long usedSpace)
                {
                    try
                    {
                        var items = directory.GetFileSystemInfos();
                        hashFileTable.Add(directory);
                        foreach (var item in items)
                        {
                            if (Disposed)
                                return;
                            if (CanBeSeen(item))
                            {
                                if (!SyncIsInPending)
                                    Spooler.SetFilePendingStatus(item, false);
                                if (item.Attributes.HasFlag(FileAttributes.Directory))
                                {
                                    if (!DirToExclude((DirectoryInfo)item))
                                    {
                                        AnalyzeDirectory((DirectoryInfo)item, ref hashFileTable, ref usedSpace);
                                    }
                                }
                                else  // Id a FIle
                                {
                                    usedSpace += ((FileInfo)item).Length;
                                    hashFileTable.Add(item);
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

                lock (this)
                {
                    if (_CacheHashFileTable == null || refresh)
                    {
                        var watch = Stopwatch.StartNew();

                        var newHashFileTable = new HashFileTable(this);
                        AnalyzeDirectory(new DirectoryInfo(CloudRoot), ref newHashFileTable, ref usedSpace);
                        UsedSpace = usedSpace;

                        if (_CacheHashFileTable != null)
                        {
                            // check if any files have been deleted
                            foreach (var item in _CacheHashFileTable)
                            {
                                if (!newHashFileTable.ContainsKey(item.Key))
                                {
                                    if (item.Value.Attributes.HasFlag(FileAttributes.Directory))
                                    {
                                        if (IsServer)
                                            RoleManager.ClientsConnected().ForEach(client =>
                                                DeleteDirectory(client.Id, item.Value));
                                        else
                                            DeleteDirectory(null, item.Value);
                                    }
                                    else
                                    {
                                        if (IsServer)
                                            RoleManager.ClientsConnected().ForEach(client =>
                                                DeleteFile(client.Id, item.Key, item.Value));
                                        else
                                            DeleteFile(null, item.Key, item.Value);
                                    }
                                }
                            }
                        }

                        //                        OldHashFileTable = CacheHashFileTable ?? newHashFileTable;
                        _CacheHashFileTable = newHashFileTable;
                        OnHashFileTableChanged(_CacheHashFileTable);
                        watch.Stop();
                        CalculationTimeHashFileTableMS = (int)(watch.ElapsedMilliseconds);
                    }
                }
                hashTable = _CacheHashFileTable;
                if (IsClient && IsLogged)
                    InitializeClientSynchronization(); // It's already logged in, so start syncing immediately
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
        /// Cloud storage space used in bytes
        /// </summary>
        public long UsedSpace { get; private set; }

        private void OnHashFileTableChanged(HashFileTable newHashFileTable)
        {
            if (!FileIdList.Initialized)
            {
                FileIdList.Initialize(this);
                // Remove from the deleted files list, files that may have been recovered from the recycle bin when the client was turned off
                foreach (var item in newHashFileTable)
                {
                    if (!item.Value.Attributes.HasFlag(FileAttributes.Directory))
                    {
                        var fileId = FileId.GetFileId(item.Key, item.Value.UnixLastWriteTimestamp());
                        var removed = FileIdList.RemoveItem(UserId, ScopeType.Deleted, fileId);
                    }
                }
            }
        }

        internal void OnUpdateFileIdList(ScopeType scope, ulong user, List<FileId> fileIdList)
        {
            if (scope == ScopeType.Deleted)
            {
                if (GetHashFileTable(out var hashFileTable))
                {
                    foreach (var item in fileIdList.ToArray())
                    {
                        if (hashFileTable.TryGetValue(item.HashFile, out var fileSystemInfo))
                        {
                            if (fileSystemInfo.UnixLastWriteTimestamp() == item.UnixLastWriteTimestamp)
                            {
                                if (fileSystemInfo.Attributes.HasFlag(FileAttributes.Directory))
                                {
                                    DirectoryDelete(fileSystemInfo.FullName, out _);
                                }
                                else
                                {
                                    FileDelete(fileSystemInfo.FullName, out _);
                                }
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// The time taken to compute the cloud path file table hash in milliseconds
        /// </summary>
        public int CalculationTimeHashFileTableMS { get; internal set; }

        private static readonly string[] ExcludeDir = ["bin", "obj", ".vs", "packages", "apppackages"];

        private static bool DirToExclude(DirectoryInfo directory)
        {
            return ExcludeDir.Contains(directory.Name.ToLower());
        }
    }
}