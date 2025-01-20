﻿using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using static CloudSync.Util;
using HashFileTable = System.Collections.Generic.Dictionary<ulong, System.IO.FileSystemInfo>;
using System.Linq;
using System.Collections.Generic;

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
        /// <param name="syncIsEnabled"> False to suspend sync, or true. It is important to suspend synchronization if the path is not available (for example when using virtual disks)! Indicate true if the path to the cloud space is reachable (true), or unmounted virtual disk (false). Use IsReachableDiskStateIsChanged to notify that access to the cloud path has changed.</param>
        /// <param name="owner">If set, during synchronization operations (creating files and directories), the owner will be the one specified here</param>
        public Sync(ulong userId, SendCommandDelegate sendCommand, out SendCommandDelegate onCommand, SecureStorage.Storage secureStorage, string cloudRoot, LoginCredential clientCredential = null, bool doNotCreateSpecialFolders = false, bool syncIsEnabled = true, string owner = null)
        {
            UserId = userId;
            if (owner != null)
            {
                Owner = GetUserIds(owner);
            }
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
            SyncIsEnabled = syncIsEnabled;
            var rootInfo = new DirectoryInfo(cloudRoot);
            if (IsServer)
                DirectoryCreate(cloudRoot, Owner, out _);
            if (rootInfo.Exists)
            {
                rootInfo.Attributes |= FileAttributes.Encrypted;
                SetOwner(Owner, cloudRoot);
            }

            Send = sendCommand;
            onCommand = OnCommand;
            Spooler = new Spooler(this);
            ReceptionInProgress = new ProgressFileTransfer(this);
            SendingInProgress = new ProgressFileTransfer(this);
            if (syncIsEnabled)
            {
                var task = new Task(() =>
                {
                    HashFileTable(out _); // set cache initial state to check if file is deleted
                });
                task.Start();
            }

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
                        pin = "000000" + pinInt.ToString(); // the default pin is the 6 random digits
                        pin = pin.Substring(pin.Length - 6);
#endif
                    SetPin(secureStorage, null, pin);
                }
                //SetSyncTimeBuffer();
            }
            else
            {
                OnNotify(null, Notice.Authentication);
                if (isLogged)
                    ClientStartSync(); // It's already logged in, so start syncing immediately
                else
                    RequestOfAuthentication(null, clientCredential, PublicIpAddressInfo(),
                        Environment.MachineName); // Start the login process
            }
            //});
            //task.Start();
        }
        private ulong UserId;
        private (uint, uint)? Owner;

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

                    ClientStartSync();
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
        /// Block or enable synchronization. Possible use:
        /// Function that the host app must call if the disk at the root of the cloud is mounted or unmounted.
        /// If you plan not to use a virtual disk for cloud space then this function should not be called.
        /// If you use a virtual disk as a path to the cloud, this feature will suspend synchronization when the disk is unsmounted.
        /// </summary>
        public void SetSyncState(bool isMounted) => SyncIsEnabled = isMounted;

        /// <summary>
        /// If set to false, suspends all sync operations. Useful if you are working with virtual disks and want to unmount a disk (you must suspend sync operations before unmounting the disk).
        /// </summary>
        protected bool SyncIsEnabled
        {
            get { return (bool)_SyncIsEnabled; }
            private set
            {
                if (_SyncIsEnabled != value)
                {
                    _SyncIsEnabled = value;
                    if (!IsServer)
                    {
                        if (value)
                            OnEnabledSync();
                        else
                            OnDisableSync();
                    }
                }
            }
        }

        protected bool? _SyncIsEnabled = null;

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
                    if (WatchCloudRoot())
                    {
                        Spooler?.ExecuteNext();
                        RequestSynchronization();
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
            ClientCheckSync?.Change(timespan, timespan);
        }

        private bool FirstSyncFlag;

        private bool SyncIsInPending => RemoteStatus != Notice.Synchronized || ConcurrentOperations() != 0 ||
                                        LocalSyncStatus != SyncStatus.Monitoring || Spooler.InPending != 0;

        /// <summary>
        /// Timer that starts the synchronization procedure when something in the cloud path has changed. The timer delays the synchronization of a few seconds because multiple changes may be in progress on the files and it is convenient to wait for the end of the operations.
        /// </summary>
        internal Timer SyncTimeBuffer;

        internal int SyncTimeBufferMs = 10000;

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
                if (!SyncIsEnabled)
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

        public bool IsServer
        {
            get { return !IsClient; }
        }

        public readonly bool IsClient;
        public readonly string CloudRoot;

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

        public delegate void SendCommandDelegate(ulong? contactId, ushort command, params byte[][] values);

        public DateTime LastCommandSent { get; private set; }

        private void SendCommand(ulong? contactId, Commands command, string infoData, params byte[][] values)
        {
            if (!Disposed)
            {
                LastCommandSent = DateTime.UtcNow;
                Task.Run(() =>
                {
                    try
                    {
                        Debug.WriteLine("OUT " + command);
                        RaiseOnCommandEvent(contactId, command, infoData, true);
                        Send.Invoke(contactId, (ushort)command, values);
                    }
                    catch (Exception ex)
                    {
                        RecordError(ex);
                        Debugger.Break(); // Error! Investigate the cause of the error!
                        Debug.WriteLine(ex);
                    }
                });
            }
        }

        private readonly SendCommandDelegate Send;

        private bool GetLocalHashStructure(out byte[] localHashStructure, BlockRange delimitsRange)
        {
            if (HashFileTable(out var hashFileTable))
            {
                if (delimitsRange != null)
                {
                    hashFileTable =
                        GetRestrictedHashFileTable(hashFileTable, out _,
                            delimitsRange); // Returns null if the delimiterRange is invalid. In this case, all operations must be interrupted!
                    if (hashFileTable == null)
                    {
                        localHashStructure = null;
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

                localHashStructure = array;
                return true;
            }

            localHashStructure = null;
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
            if (!Directory.Exists(CloudRoot))
            {
                RaiseOnFileError(new Exception("Cloud root not found!"), CloudRoot);
                hashTable = null;
                return false;
            }

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
                                    if (!DirToExclude((DirectoryInfo)item))
                                    {
                                        AnalyzeDirectory((DirectoryInfo)item, ref hashFileTable);
                                    }
                                }
                                else
                                {
                                    hash = item.HashFileName(this);
                                    hashFileTable.Add(hash, item);
                                    // hashFileTable[hash] = item;
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
                        if (!SyncIsEnabled)
                        {
                            hashTable = null;
                            return false;
                        }

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
                OnHashFileTableChanged();
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


        private void OnHashFileTableChanged()
        {
            if (!HashFileList.Initialized)
            {
                HashFileList.Initialize(this);
            }
        }


        internal void OnUpdateHashFileList(ScopeType scope, ulong user, List<ulong> hashList)
        {
            if (scope == ScopeType.Deleted)
            {
                if (HashFileTable(out var hashFileTable))
                {
                    foreach (var item in hashList.ToArray())
                    {
                        if (hashFileTable.TryGetValue(item, out var fileSystemInfo))
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


        /// <summary>
        /// The time taken to compute the cloud path file table hash in milliseconds
        /// </summary>
        public int CalculationTimeHashFileTableMS { get; internal set; }

        private static readonly string[] ExcludeDir = { "bin", "obj", ".vs", "packages", "apppackages" };

        private static bool DirToExclude(DirectoryInfo directory)
        {
            return ExcludeDir.Contains(directory.Name.ToLower());
        }
    }
}