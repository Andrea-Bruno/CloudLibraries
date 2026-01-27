using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using static CloudSync.Util;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

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
        public Sync(ulong userId, SendCommandDelegate sendCommand, out SendCommandDelegate onCommand, SecureStorage.Storage secureStorage, string cloudRoot, LoginCredential? clientCredential = null, bool doNotCreateSpecialFolders = false, string owner = null, byte[] encryptionMasterKey = null, int storageLimitGB = -1)
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
            CloudRoot = cloudRoot.TrimEnd(Path.DirectorySeparatorChar).TrimEnd(Path.AltDirectorySeparatorChar);
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
            ReceptionInProgress = new ProgressFileTransfer();
            SendingInProgress = new ProgressFileTransfer();

            if (IsClient)
            {
                ClientToolkit = new ClientToolkit(this, clientCredential);

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
        public ClientToolkit? ClientToolkit = null;
        internal ZeroKnowledgeProof ZeroKnowledgeProof;
        internal ulong UserId;
        internal (uint, uint)? Owner;
        public readonly Share Share;

        public long GetFreeSpace()
        {
            if (GetHashFileTable(out var hashFileTable))
            {
                if (StorageLimitGB == -1) // - 1 values = unlimited
                    return -1;
                var free = StorageLimitGB * 1000000000L - hashFileTable.UsedSpace;
                return free < 0 ? 0 : free;
            }
            return 0;
        }

        public long GetUsedSpace()
        {
            if (GetHashFileTable(out var hashFileTable))
            {
                return hashFileTable.UsedSpace;
            }
            return 0;
        }


        /// <summary>
        /// The amount of space reserved for file storage expressed in gigabytes
        /// </summary>
        public int StorageLimitGB { get; private set; }

        public AutoResetEvent OnLoginCompleted;

        /// <summary>
        /// True if there has been a communication from the remote machine (server or client), confirming that it is reachable.
        /// </summary>
        public bool RemoteHostReachable => LastCommandReceived != default;

        internal bool DontCreateSpecialFolders;


        /// <summary>
        /// Set this function to externally hook the command to pause and resume synchronization
        /// </summary>
        public Func<bool> SuspendSync;

        internal bool Disposed;

        public void Dispose()
        {
            if (!Disposed)
            {
                Disposed = true;
                RaiseOnStatusChangesEvent(SyncStatus.Undefined);
                OnNotify(null, Notice.LoggedOut);
                SecureStorage.Values.Delete(nameof(ClientToolkit.IsLogged), typeof(bool));
                SecureStorage.Values.Delete(nameof(IsClient), typeof(bool));
                ClientToolkit?.WatchCloudRoot?.Dispose();
                ReceptionInProgress.Dispose();
                SendingInProgress.Dispose();
                ClientToolkit?.Dispose();
            }
        }

        /// <summary>
        /// Delete all sensitive data created by this instance
        /// </summary>
        public void Destroy()
        {
            if (GetHashFileTable(out var hashFileTable))
            {
                hashFileTable.RemoveCache();
            }
            SecureStorage?.Destroy();
        }

        public delegate void OnNotificationEvent(ulong? fromUserId, Notice notice);

        /// <summary>
        /// Procedure that is performed upon receipt of a notification from the remote machine. Can be used as an event to check the status of the remote machine.
        /// </summary>
        public event OnNotificationEvent OnNotification;

        internal readonly SecureStorage.Storage SecureStorage;

        //internal readonly Context;

        public readonly RoleManager RoleManager;
        public readonly int InstanceId;
        private static int InstanceCounter;
        public bool IsServer
        {
            get { return !IsClient; }
        }

        public readonly bool IsClient;
        public readonly string CloudRoot;
        public string AppDataPath => Path.Combine(CloudRoot, PersistentFileIdList.CloudCacheDirectory);

        public int CurrentConcurrentSpoolerOperations()
        {
            return SendingInProgress == null ? 0 : SendingInProgress.TransferInProgress + ReceptionInProgress.TransferInProgress + PendingConfirmation;
        }

        public bool IsTransferring()
        {
            return CurrentConcurrentSpoolerOperations() > 0;
        }

        public static readonly ushort AppId = BitConverter.ToUInt16(Encoding.ASCII.GetBytes("sync"), 0);

        public delegate bool SendCommandDelegate(ulong? contactId, ushort command, params byte[][] values);

        public DateTime LastCommandSent { get; private set; }


        private readonly SendCommandDelegate Send;


        public void ResetCacheHashFileTable() => _HashFileTable = null;

        /// <summary>
        /// Don't use directly: Get it with GetHashFileTable(out value)
        /// </summary>
        internal HashFileTable _HashFileTable;


        /// <summary>
        /// Reset the hash file table, useful to force a regeneration of the hash file table.
        /// </summary>
        /// <returns></returns>
        internal bool ResetHashFileTable()
        {
            return GetHashFileTable(out _, true);
        }

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
            if (!refresh && ClientToolkit?.SyncIsEnabled == false)
            {
                hashTable = null;
                return false;
            }

            try
            {
                lock (this)
                {
                    if (_HashFileTable == null || refresh)
                    {
                        if (_HashFileTable != null)
                            _HashFileTable.AutoSave = false;
                        var newHashFileTable = new HashFileTable(this, HashFileTable.LoadMode.Regenerate);

                        if (_HashFileTable == null)
                            ClientToolkit?.FindDeletedFilesOnStartup(newHashFileTable); //Delete deleted files from server

                        newHashFileTable.AutoSave = true;
                        _HashFileTable = newHashFileTable;
#if DEBUG                      
                        foreach (var item in _HashFileTable.Elements())
                        {
                            if (!item.FileInfo.Exists)
                                Debugger.Break();
                        }
#endif

                        ClientToolkit?.OnHashFileTableChanged(_HashFileTable); // Remove from the list of deleted files, those that have been restored
                    }
                }
                hashTable = _HashFileTable;
                // ClientToolkit?.RestartTimerClientRequestSynchronization(); // It's already logged in, so start syncing immediately
                return true;
            }
            catch (Exception ex)
            {
                Debugger.Break();
                RaiseOnFileError(ex, null);
                Console.WriteLine(ex.Message);
            }

            hashTable = null;
            return false;
        }

        public void ExecuteNext()
        {
            ClientToolkit?.Spooler.ExecuteNext(true);
        }

        public void SendReadyMessage()
        {
            StatusNotification(null, Sync.Status.Ready);
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
                                if (fileSystemInfo is DirectoryInfo)
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
    }
}