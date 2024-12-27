using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using CloudSync;
using EncryptedMessaging;
using NBitcoin;
using static CommunicationChannel.Channel;

namespace CloudBox
{
    /// <summary>
    /// The main part of the cloud: This part is identical between client and server because there are no substantial differences at this level. The server can create an object inheriting from this class and add new functionality to it
    /// </summary>
    public abstract partial class CloudBox
    {
        static CloudBox()
        {
            AppDomain.CurrentDomain.UnhandledException += UnhandledExceptionEventHandler;
        }
#if DEBUG
        protected readonly string TestServerPassphrase = "damage exit piece auto enough mom quantum remain sting crouch little hill";
        protected readonly string TestClientPassphrase = "enact struggle torch clutch pear maid goose region believe predict tonight oppose";
#elif DEBUG_AND
        protected readonly string TestServerPassphrase = "rack bacon scrub mirror code music mad force step laundry boat chronic";
        protected readonly string TestClientPassphrase = "river hint into tobacco section turn enforce lunch multiply basket police captain";
#endif

        /// <summary>
        /// Cloud Server will communicate to clients for making operations on cloud storage.
        /// </summary>
        /// <param name="cloudPath">Directory position of the cloud (a null value will be considered the default path)</param>
        /// <param name="isServer">True if this instance is a server cloud</param>
        /// <param name="id">Used to create multiple instances</param>
        /// <param name="licenseOEM">The OEM private key for activating licenses.</param>
        /// <param name="name">A label name to assign to this instance (this does not affect how the cloud works)</param>
        /// <param name="doNotCreateSpecialFolders">If instantiated as a server it will automatically create specific subdirectories for documents, photos, etc., unless this parameter is specified</param>
        /// <param name="syncIsEnabled"> False to suspend sync, or true. It is important to suspend synchronization if the path is not available (for example when using virtual disks)! Indicate true if the path to the cloud space is reachable (true), or unmounted virtual disk (false). Use IsReachableDiskStateIsChanged to notify that access to the cloud path has changed.</param>
        public CloudBox(string cloudPath = null, bool isServer = false, ulong? id = null, string licenseOEM = null, string name = null, bool doNotCreateSpecialFolders = false, bool syncIsEnabled = true)
        {
            SyncIsEnabled = syncIsEnabled;
            DoNotCreateSpecialFolders = doNotCreateSpecialFolders; ;
            _Name = name;
            //if (string.IsNullOrEmpty(routerEntryPoint))
            //{
            //    throw new Exception("Missing entryPoint");
            //}
            // RouterEntryPoint = routerEntryPoint;


            if (string.IsNullOrEmpty(licenseOEM) && isServer)
                licenseOEM = TestNetDefaultLicenseOEM;
            LicenseOEM = licenseOEM;
            IsServer = isServer;
            ID = id == null ? BitConverter.ToUInt64(Util.Hash256(cloudPath.GetBytes()), 0) : id.Value;
            if (!string.IsNullOrEmpty(cloudPath) && cloudPath != GetCloudPath(null, isServer))
                _cloudPath = cloudPath;
            lock (Instances)
                Instances.Add(this);
        }

        /// <summary>
        /// Returns true if it is a good time to perform the software update. If some operation is in progress then it returns false;
        /// </summary>
        /// <returns></returns>
        public bool CanRestart()
        {
            return Context != null && Context.LastOUT.AddMinutes(10) < DateTime.UtcNow;
        }

        /// <summary>
        /// Digitally sign a document
        /// </summary>
        /// <param name="scopeOfSignature">Indicates the intention of the signer (the purpose for which the signature is placed on the document)</param>
        /// <param name="signatureFileName">Returns the name of the file containing the digital signature</param>
        /// <param name="fileName">The name of the file being signed</param>
        /// <param name="document">The file you are signing (in the form of binary data)</param>
        /// <param name="saveToCloud">If true, both the document and the digital signature will be saved in the cloud area</param>
        /// <returns>Digital signature in json format</returns>
        public string SignDocument(DigitalSignature.Scope scopeOfSignature, out string signatureFileName, string fileName, byte[] document, bool saveToCloud = true)
        {
            var sign = new DigitalSignature(Context.My.GetPrivateKeyBinary(), scopeOfSignature, fileName, document);
            var jsonSignature = sign.Save();
            signatureFileName = fileName + sign.FileExtension();

            if (saveToCloud)
            {
                if (CloudPath != null && SyncIsEnabled)
                {
                    var n = 0;
                    string signatureDir;
                    do
                    {
                        signatureDir = Path.Combine(CloudPath, "Documents", "Signed", Path.GetFileNameWithoutExtension(fileName) + (n == 0 ? "" : n.ToString()));
                        if (!Directory.Exists(signatureDir))
                        {
                            Directory.CreateDirectory(signatureDir);
                            break;
                        }
                        n++;
                    } while (true);
                    File.WriteAllBytes(Path.Combine(signatureDir, fileName), document);
                    File.WriteAllText(Path.Combine(signatureDir, signatureFileName), jsonSignature);
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        Process.Start("explorer", signatureDir);
                    }
                    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        Process.Start("xdg-open", signatureDir);
                    }
                    else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        Process.Start("open", signatureDir);
                    }
                }
            }

            return jsonSignature;
        }

        private static void UnhandledExceptionEventHandler(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex)
            {
                var description = string.Format("Exception: {0}: {1} Source: {2} {3}", ex.GetType(), ex.Message, ex.Source, ex.StackTrace);
                OnAppError?.Invoke(description);
            }
        }
        private string _Name;

        /// <summary>
        /// A label name to assign to this instance (this does not affect how the cloud works)
        /// </summary>
        public string Name { get { return Context.SecureStorage.Values.Get("Name", null); } set { Context.SecureStorage.Values.Set("Name", value); } }
        /// <summary>
        /// Delegate for error events
        /// </summary>
        /// <param name="description"></param>
        public delegate void OnAppErrorEventHandler(string description);
        /// <summary>
        /// Event that is called when there are errors (useful for creating a log)
        /// </summary>
        public static event OnAppErrorEventHandler OnAppError;
        /// <summary>
        /// Unique identifier for this instance
        /// </summary>
        public ulong ID { get; private set; }

        /// <summary>
        /// Returns the next Id that can be used to create a new cloud instance
        /// </summary>
        /// <param name="cloudPath"></param>
        /// <returns></returns>
        public static ulong NextIdAvailable(string cloudPath)
        {
            ulong id;
            var ids = GetCloudsIDs(cloudPath);
            if (ids.Count > 0)
            {
                var max = ulong.MinValue;
                foreach (var i in ids)
                    if (i > max)
                        max = i;
                id = max + 1;
            }
            else
                id = 0;
            return id;
        }
        /// <summary>
        /// Returns the list of all cloud IDs mounted under a given path
        /// </summary>
        /// <param name="cloudPath"></param>
        /// <returns></returns>
        public static List<ulong> GetCloudsIDs(string cloudPath)
        {
            var result = new List<ulong>();
            var dirInfo = new DirectoryInfo(cloudPath);
            if (dirInfo.Exists)
            {
                var dirs = dirInfo.GetDirectories();
                foreach (var dir in dirs)
                {
                    if (dir.Name.StartsWith(CloudDirName))
                    {
                        try
                        {
                            result.Add(ulong.Parse(dir.Name.Substring(CloudDirName.Length)));
                        }
                        catch (Exception)
                        {
                            // It is not a directory used for the cloud;
                        }
                    }
                }
            }
            return result;
        }

        /// <summary>
        /// Generate the context, i.e. initialize the environment for encrypted socket communication between devices
        /// </summary>
        /// <param name="routerEntryPoint">IP or domain name or QR code of the router used for the connection</param>
        /// <param name="passphrase">If you want to recover the account, you can specify the passphrase</param>
        /// <returns>True for Successful, or false if something went wrong</returns>  
        public Context CreateContext(string routerEntryPoint, string passphrase = null)
        {
            var isQRCode = !routerEntryPoint.Contains('.');
            string serverPublicKey = null;
            if (isQRCode)
            {
                var qrCode = routerEntryPoint;
                if (SolveQRCode(qrCode, out routerEntryPoint, out serverPublicKey, out EncryptedQR) == false)
                    return null;
            }
            File.WriteAllText(FileLastEntryPoint, routerEntryPoint);
            if (Context != null)
                Debugger.Break();
#if DEBUG || DEBUG_AND
            if (Instances.Count == 0)
                passphrase = IsServer ? TestServerPassphrase : TestClientPassphrase;
#endif
            // Creates a license activator if an OEM license is set during initialization
            var signLicense = string.IsNullOrEmpty(LicenseOEM) ? null : new OEM(LicenseOEM);
            Context = new Context(routerEntryPoint, NetworkName, modality: Modality.Server, privateKeyOrPassphrase: passphrase, licenseActivator: signLicense, instanceId: ID.ToString())
            {
                OnRouterConnectionChange = OnRouterConnectionChangeEvent,
                OnCommunicationErrorEvent = OnCommunicationError
            };
            if (serverPublicKey != null)
                Context.SecureStorage.Values.Set("ServerPublicKey", serverPublicKey);
            if (!string.IsNullOrEmpty(_Name))
            {
                Name = _Name;
            }
            Context.OnContactEvent += OnContactEvent;
            return Context;
        }

        /// <summary>
        /// Marking for a function that is changed when the connection status changes.
        /// This method is invoked when the connection is activated or deactivated.
        /// </summary>
        protected Action<bool> OnRouterConnectionChangeEvent;

        /// <summary>
        /// The encryption key of the QR code and for the client also the ID of the server useful for communicating with it
        /// </summary>
        public Tuple<ulong, byte[]> EncryptedQR;

        /// <summary>
        /// It receives the data of a QR code as input, validates it and if recognized returns true
        /// </summary>
        /// <param name="qrCode"></param>
        /// <param name="entryPoint">Returns the entry point of the router, to establish the connection</param>
        /// <param name="serverPublicKey">For type 1 and 2 QR codes, the server's public key is returned</param>
        /// <param name="EncryptedQR">For type 2 QR codes (the encrypted one), it returns the encryption code and the server ID so that it can be queried and given the public key when the connection to the router is established</param>
        /// <returns></returns>
        public static bool SolveQRCode(string qrCode, out string entryPoint, out string serverPublicKey, out Tuple<ulong, byte[]> EncryptedQR)
        {
            entryPoint = null;
            serverPublicKey = null;
            EncryptedQR = null;
            if (string.IsNullOrEmpty(qrCode))
                return false;
            try
            {
                var qr = qrCode.Base64ToBytes();
                var type = qr[0];
                var offset = 1;
                if (type == 1)
                {
                    offset += 256;
                    offset += 3;
                }
                else if (type == 2)
                {
                    var QRKey = qr.Skip(offset).Take(24);
                    offset += 24;
                    var serverId = BitConverter.ToUInt64(qr.Skip(offset).Take(8), 0);
                    offset += 8;
                    EncryptedQR = new Tuple<ulong, byte[]>(serverId, QRKey);
                }
                else if (type > 2)
                    return false;
                if (type == 0 || type == 1)
                {
                    serverPublicKey = qr.Skip(offset).Take(33).ToBase64();
                    var key = new PubKey(Convert.FromBase64String(serverPublicKey)); // pub key validator (throw error if is wrong)
                    offset += 33;
                }
                var ep = qr.Skip(offset).ToASCII();
                if (string.IsNullOrEmpty(ep))
                {
#if RELEASE

                    ShowEntryPoint = false;
                    ep = "server.tc0.it";
#elif DEBUG
                    ep = "test.tc0.it";
#endif
                }
                else if (!ep.Contains("."))
                {
                    ep += ".tc0.it";
                }

                if (!string.IsNullOrEmpty(ep))
                {
                    if (!Uri.TryCreate(ep, UriKind.RelativeOrAbsolute, out Uri myUri))
                        return false; // url not valid
                    entryPoint = ep;
                }
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        protected static readonly string FileLastEntryPoint = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LastEntryPoint");

        /// <summary>
        /// Last client entry. If the application was used as a client and the client was logged in, this function returns the last entry point used. Null if the application was not logged in as a client.
        /// </summary>
        /// <returns>Entry point (Url or IP), or null</returns>
        public static string LastEntryPoint()
        {
            return File.Exists(FileLastEntryPoint) ? File.ReadAllText(FileLastEntryPoint) : null;
        }

        /// <summary>
        /// True if logged
        /// </summary>
        public bool IsLogged => Sync != null && Sync.IsLogged;

        private readonly bool DoNotCreateSpecialFolders;

        /// <summary>
        /// Start sync (connection must be started first)
        /// </summary>
        /// <param name="credential">At the first synchronization, the credentials for logging in to the server must be passed</param>
        public void StartSync(LoginCredential credential = null)
        {
            Sync = new Sync(SendSyncCommand, out OnSyncCommand, Context.SecureStorage, CloudPath, credential, DoNotCreateSpecialFolders, SyncIsEnabled);
            // Sync.OnNotification += (fromUserId, notice) => OnNotificationAction?.Invoke(fromUserId, notice);
            Sync.OnNotification += (fromUserId, notice) => OnNotificationActionList.Concat(new[] { OnNotificationAction }).ToList().ForEach(x => x?.Invoke(fromUserId, notice));
            Sync.OnLocalSyncStatusChanges += (syncStatus, pendingFiles) =>
            {
                SyncStatus = syncStatus;
                PendingFiles = pendingFiles;
                // OnLocalSyncStatusChangesAction?.Invoke(syncStatus, pendingFiles);
                OnLocalSyncStatusChangesActionList.Concat(new[] { OnLocalSyncStatusChangesAction }).ToList().ForEach(x => x?.Invoke(syncStatus, pendingFiles));
            };
            Sync.OnFileTransfer += fileTransfer => TransferredFiles.UpdateList(fileTransfer);
            Sync.OnCommandEvent += (userId, command, infoData, isOutput) => OnCommands.AddOnCommand(userId, command, infoData, isOutput);
            Sync.OnFileError += (error, fileName) => AddFileError(error.Message, fileName);
            Sync.OnAntivirus += (message, fileName) => AddAntivirusWarning(message, fileName);
            OnSyncStart?.Set();
        }

        /// <summary>
        /// Event that can be used to intercept when the synchronization procedure is started
        /// </summary>
        public AutoResetEvent OnSyncStart;

        /// <summary>
        /// IWhen the value is set to false, a synchronization activity is suspended.
        /// </summary>
        private bool SyncIsEnabled { get { return _IsEnabled; } set { _IsEnabled = value; Sync?.SetSyncState(value); } }
        private bool _IsEnabled = true;


        /// <summary>
        /// Block or enable synchronization. Possible use:
        /// Function that the host app must call if the disk at the root of the cloud is mounted or unmounted.
        /// If you plan not to use a virtual disk for cloud space then this function should not be called.
        /// If you use a virtual disk as a path to the cloud, this feature will suspend synchronization when the disk is unsmounted.
        /// </summary>
        public void SetSyncState(bool isEnabled) => SyncIsEnabled = isEnabled;


        /// <summary>
        /// You can use this feature to receive warning messages generated by the file error. Massages will be added to the FileErrors list
        /// </summary>
        /// <param name="error"></param>
        /// <param name="fileName"></param>
        public void AddFileError(string error, string fileName)
        {
            FileErrors.Insert(0, new FileError() { Time = DateTime.UtcNow, Error = error, FileName = fileName });
            if (FileErrors.Count > 100)
                FileErrors.RemoveAt(FileErrors.Count - 1);
        }

        /// <summary>
        /// Log of errors occurred on files
        /// It could be that the antivirus is blocking file operations, or some application is keeping the files open.
        /// </summary>
        public readonly List<FileError> FileErrors = new List<FileError>();

        /// <summary>
        /// You can use this feature to receive warning messages generated by the antivirus. Massages will be added to the AntivirusWarnings list
        /// </summary>
        /// <param name="message">Text of message</param>
        /// <param name="fileName">Filename</param>
        public void AddAntivirusWarning(string message, string fileName)
        {
            AntivirusWarnings.Insert(0, new FileError() { Time = DateTime.UtcNow, Error = message, FileName = fileName });
            if (AntivirusWarnings.Count > 100)
                AntivirusWarnings.RemoveAt(AntivirusWarnings.Count - 1);
        }

        /// <summary>
        /// Log of Antivirus warning occurred
        /// It could be that the antivirus is blocking file operations, or some application is keeping the files open.
        /// </summary>
        public readonly List<FileError> AntivirusWarnings = new List<FileError>();

        /// <summary>
        /// Class to describe file errors
        /// </summary>
        public class FileError
        {
            /// <summary>
            /// Time of error
            /// </summary>
            public DateTime Time { get; set; }
            /// <summary>
            /// Error description
            /// </summary>
            public string Error { get; set; }
            /// <summary>/// Full path and file name
            /// </summary>
            public string FileName { get; set; }
        }

        public readonly FileTransferList TransferredFiles = new FileTransferList();
        public readonly OnCommandList OnCommands = new OnCommandList();
        /// <summary>
        /// Procedure that is performed upon receipt of a notification from the remote machine. Can be used as an event to check the status of the remote machine.
        /// </summary>
        public Sync.OnNotificationEvent OnNotificationAction;
        protected readonly List<Sync.OnNotificationEvent> OnNotificationActionList = new List<Sync.OnNotificationEvent>();
        /// <summary>
        /// Event that fires when the sync status changes
        /// </summary>
        public Sync.StatusEventHandler OnLocalSyncStatusChangesAction;
        protected readonly List<Sync.StatusEventHandler> OnLocalSyncStatusChangesActionList = new List<Sync.StatusEventHandler>();

        /// <summary>
        /// Event that tracks communication errors that occur with the remote device
        /// </summary>
        public OnErrorEvent OnCommunicationErrorEvent;
        /// <summary>
        /// Current status of the sync process. We recommend using the OnSyncStatusChangesAction event to update these values in the UI
        /// </summary>
        public Sync.SyncStatus SyncStatus { get; private set; }
        /// <summary>
        /// Number of files that are waiting to be synced. We recommend using the OnSyncStatusChangesAction event to update these values in the UI
        /// </summary>
        public int PendingFiles { get; private set; }

        public readonly List<Tuple<ErrorType, string>> CommunicationErrorLog = new List<Tuple<ErrorType, string>>();

        private void OnCommunicationError(ErrorType errorId, string description)
        {
            OnCommunicationErrorEvent?.Invoke(errorId, description);
            CommunicationErrorLog.Insert(0, new Tuple<ErrorType, string>(errorId, description));
            if (CommunicationErrorLog.Count > 10)
                CommunicationErrorLog.RemoveAt(CommunicationErrorLog.Count - 1);
        }
        /// <summary>
        /// Indicates the current status of the connection to the router. If false then the router is not connected, check the internet network, the connection of the cables to the network, etc..
        /// </summary>
        public bool IsConnected => Context != null && Context.IsConnected;
        private readonly string LicenseOEM;
        private const string TestNetDefaultLicenseOEM = "3z66WQrrQnlksDQEcqt7qxABMVBgqexgH/PuY8EmIT4="; // The license activation key on TestNet (for testing)
        /// <summary>
        /// Returns a detailed report of this cloud server or client instance
        /// </summary>
        public string Status
        {
            get
            {
                var sb = new StringBuilder();
                void AddTx(string name, object value = null) => sb.AppendLine(name + ((value == null) ? "" : ": " + value));
                var version = Assembly.GetEntryAssembly().GetName().Version.ToString();
                if (version != "1.0.0.0")
                    AddTx("Version", version);
                var context = Context;
                if (context != null)
                {
                    if (Context.InstancedTimeUtc != default)
                        AddTx("Started at", Context.InstancedTimeUtc + " UTC");
                    AddTx("User Id", context?.My.Id);
                    AddTx("Public Key", context?.My.GetPublicKey());
                    if (ShowEntryPoint)
                        AddTx("Entry point (router address)", context?.EntryPoint.ToString());
                    AddTx("Keep Alive Failures", context?.KeepAliveFailures);
                }
                if (LicenseOEM != null)
                    AddTx("OEM Id", OEM.GetIdOEM(LicenseOEM));
                if (LicenseOEM == TestNetDefaultLicenseOEM)
                {
                    AddTx("WARNING!", "TestNet license in use");
                }
                else if (IsServer && string.IsNullOrEmpty(LicenseOEM))
                {
                    AddTx("ERROR!", "Missing license");
                }
#if DEBUG
                AddTx("WARNING!", "compiled in debug mode");
#endif
                if (!IsServer)
                {
                    AddTx("Paired to server", (ServerCloud == null ? "None" : ServerCloud.UserId + " UserId"));
                    AddTx("Logged with server", (Sync != null));
                }
                AddTx("Connected to the router", context?.IsConnected);
                AddTx("Cloud path", CloudPath);
                //addTx("Public IP", Util.PublicIpAddressInfo());
                if (context != null)
                {
                    AddTx("# CHANNEL:");
                    AddTx("Last keep alive check", context?.LastKeepAliveCheck);
                    AddTx("Last IN (UTC)", context?.LastIN);
                    AddTx("Last command IN", context?.LastCommandIN);
                    AddTx("Last OUT (UTC)", context?.LastOUT);
                    AddTx("Last command OUT", context?.LastCommandOUT);
                }
                var sync = Sync;
                if (sync != null)
                {
                    AddTx("Pending operations", sync.PendingOperations);
                    // Reception
                    AddTx("# RECEPTION:");
                    AddTx("Last Command received", sync.LastCommandReceived != default ? (int)((DateTime.UtcNow - sync.LastCommandReceived).TotalSeconds) + " seconds ago" : (IsServer ? "No client connected" : "ERROR! cloud unreachable"));
                    AddTx("Total files received", sync.TotalFilesReceived);
                    AddTx("Total bytes received", sync.TotalBytesReceived);
                    AddTx("Reception file in progress", sync.ReceptionInProgress.TransferInProgress);
                    AddTx("Reception timeout", sync.ReceptionInProgress.TimeOutInfo());
                    AddTx("Total received failed by timeout", sync.ReceptionInProgress.FailedByTimeout);
                    AddTx("# SENDING:");
                    // Sending
                    AddTx("Last Command sent", sync.LastCommandSent != default ? (int)((DateTime.UtcNow - sync.LastCommandSent).TotalSeconds) + " seconds ago" : (IsServer ? "No client connected" : "ERROR! cloud unreachable"));
                    AddTx("Total files sent", sync.TotalFilesSent);
                    AddTx("Total bytes sent", sync.TotalBytesSent);
                    AddTx("Sending file in progress", sync.SendingInProgress.TransferInProgress);
                    AddTx("Sending timeout", sync.SendingInProgress.TimeOutInfo());
                    AddTx("Total sent failed by timeout", sync.SendingInProgress.FailedByTimeout);
                }
                return sb.ToString();
            }
        }
        /// <summary>
        /// Indicates whether the status should show the Entry Point;
        /// </summary>
        private static bool ShowEntryPoint { get; set; } = true;
        /// <summary>
        /// True if the current instance is a cloud server, otherwise false if it is a cloud client
        /// </summary>
        public readonly bool IsServer;
        /// <summary>
        /// Securely get the latest instance of the created CloudBox object
        /// </summary>
        public static CloudBox LastInstance
        {
            get
            {
                lock (Instances)
                {
                    return (Instances.Count == 0 ? null : Instances.Last());
                }
            }
        }
        /// <summary>
        /// List of all currently active instances
        /// </summary>
        public static readonly List<CloudBox> Instances = new List<CloudBox>();

        /// <summary>
        /// Unmount current instance
        /// </summary>
        public virtual void Remove()
        {
            OnCommandEvent = null;
            Instances.Remove(this);
            Context?.Dispose();
        }

        /// <summary>
        /// Dismount the instance and destroy all data within it. Since it is a dangerous operation this function requires the pin
        /// </summary>
        public virtual void Destroy()
        {
            Context?.SecureStorage.Destroy();
            var sync = Sync;
            StopSync();
            sync?.Destroy();
            var dir = CloudPath;
            Remove();
            Directory.Delete(dir, true);
        }

        private readonly string _cloudPath;

        /// <summary>
        /// The path where the cloud was mounted
        /// </summary>
        public string CloudPath => GetCloudPath(_cloudPath, IsServer, ID);

        /// <summary>
        /// Returns the default root path used by the cloud unless another path is specified
        /// </summary>
        /// <param name="defaultPath">Returns the default root path used by the cloud unless another path is specified</param>
        /// <param name="isServer">Indicates whether you want to get the path for a server or client</param>
        /// <param name="id">If an ID is specified then a sub directory will be added (for server paths only)</param>
        /// <returns>Default path of cloud</returns>
        public static string GetCloudPath(string defaultPath, bool isServer = true, ulong? id = null)
        {
            if (string.IsNullOrEmpty(defaultPath))
                if (isServer)
                {
                    defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), nameof(CloudBox));
                    if (id != null)
                        defaultPath = Path.Combine(defaultPath, CloudDirName + id);
                }
                else
                    defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), CloudDirName);
            return defaultPath;
        }

        private const string CloudDirName = "Cloud";
        /// <summary>
        /// You can set this item to intercept commands addressed to the cloud or server
        /// </summary>
        public ClientServerCommandEvent OnCommandEvent;
        /// <summary>
        /// Sync Agent: Offers all the low-level functions to sync the cloud in an encrypted and secure way
        /// </summary>
        public Sync Sync;
        /// <summary>
        /// It is set by Sync and is a reference to the event that is generated when a synchronization protocol command is received remotely
        /// </summary>
        protected Sync.SendCommandDelegate OnSyncCommand;

        /// <summary>
        /// Stops transmitting with the cloud server, but the connection with the router remains active
        /// </summary>
        protected void StopSync()
        {
            if (Sync != null)
            {
                OnSyncCommand = null;
                Sync?.Dispose();
                Sync = null;
            }
        }

        private static readonly ushort CloudAppId = BitConverter.ToUInt16(Encoding.ASCII.GetBytes("cloud"), 0);
        private void SendSyncCommand(ulong? toContactId, ushort command, byte[][] values)
        {
#if DEBUG
            if (Context == null)
                Debugger.Break();
#endif
            var sendToContact = ServerCloud;
            if (sendToContact == null && toContactId != null)
                CloudSyncUsers.TryGetValue((ulong)toContactId, out sendToContact);
            if (sendToContact != null && Sync != null)
            {
                Context?.Messaging.SendCommandToSubApplication(sendToContact, Sync.AppId, command, true, true, values);
            }
        }

        /// <summary>
        /// For the cloud instance this contact represents the cloud server and every sync protocol communication is done by communicating to this contact
        /// </summary>
        public Contact ServerCloud;


        private readonly string NetworkName = "mainnet";

        /// <summary>
        /// Reference to the underlying encrypted communication system between devices (the low-level communication protocol)
        /// </summary>
        public Context Context { get; protected set; }

        /// <summary>
        /// When the remote device (also known by the term contact), sends data to this device, this function is called as if it were an event, and the received data is then passed to the appropriate part of the software for processing
        /// </summary>
        /// <param name="message">The data package received</param>
        private void OnContactEvent(Message message)
        {
            if (message.Type == MessageFormat.MessageType.SubApplicationCommandWithParameters || message.Type == MessageFormat.MessageType.SubApplicationCommandWithData)
            {
                ushort appId = default;
                ushort command = default;
                List<byte[]> parameters = default;
                if (message.Type == MessageFormat.MessageType.SubApplicationCommandWithParameters)
                {
                    message.GetSubApplicationCommandWithParameters(out appId, out command, out parameters);
                }
                else if (message.Type == MessageFormat.MessageType.SubApplicationCommandWithData)
                {
                    message.GetSubApplicationCommandWithData(out appId, out command, out var data);
                    parameters = new List<byte[]>(new[] { data });
                }
                if (appId == CloudAppId) // The server application that communicates with smartphones
                {
                    var answeredToCommand = (Command)command;
                    OnCommandEvent?.Invoke(message.AuthorId, answeredToCommand, parameters);
                }
                else if (appId == Sync.AppId) // The client application that runs on desktop computers
                {
                    if (message.Contact.UserId != null)
                    {
                        var userId = (ulong)message.Contact.UserId;
                        if (!CloudSyncUsers.ContainsKey(userId))
                            CloudSyncUsers.Add(userId, message.Contact);
                        OnSyncCommand?.Invoke(userId, command, parameters?.ToArray());
                    }
                }
            }
        }

        private static readonly Dictionary<ulong, Contact> CloudSyncUsers = new Dictionary<ulong, Contact>();

        /// <summary>
        /// Get the report of all the instantiated clouds (server and client), i.e. the detailed status of operation
        /// </summary>
        public static string StatusInstances
        {
            get
            {
                var text = "";
                lock (Instances)
                {
                    foreach (var cloudBox in Instances)
                    {
                        text += cloudBox.Status + Environment.NewLine;
                    }
                }
                return text;
            }
        }
    }
}
