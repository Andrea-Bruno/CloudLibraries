using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using CloudSync;
using EncryptedMessaging;
using NBitcoin;
using SecureStorage;
using static CommunicationChannel.Channel;

namespace CloudBox
{
    /// <summary>
    /// The main part of the cloud: This part is identical between client and server because there are no substantial differences at this level. The server can create an object inheriting from this class and add new functionality to it
    /// </summary>
    public class CloudBox
    {
        static CloudBox()
        {
            AppDomain.CurrentDomain.UnhandledException += UnhandledExceptionEventHandler;
        }
#if DEBUG
        private readonly string TestServerPassphrase = "damage exit piece auto enough mom quantum remain sting crouch little hill";
        private readonly string TestClientPassphrase = "enact struggle torch clutch pear maid goose region believe predict tonight oppose";
#elif DEBUG_AND
        private readonly string TestServerPassphrase = "rack bacon scrub mirror code music mad force step laundry boat chronic";
        private readonly string TestClientPassphrase = "river hint into tobacco section turn enforce lunch multiply basket police captain";
#endif

        /// <summary>
        /// Cloud Server will communicate to clients for making operations on cloud storage.
        /// </summary>
        /// <param name="cloudPath">Directoty position of the cloud (a null value will be considered the default path)</param>
        /// <param name="isServer">True if this instance is a server cloud</param>
        /// <param name="id">Used to create multiple instances</param>
        /// <param name="licenseOEM">The OEM private key for activating licenses.</param>
        /// <param name="name">A label name to assign to this instance (this does not affect how the cloud works)</param>
        /// <param name="doNotCreateSpecialFolders">If instantiated as a server it will automatically create specific subdirectories for documents, photos, etc., unless this parameter is specified</param>
        /// <param name="isReachable">Indicate true if the path to the cloud space is reachable (true), or unmounted virtual disk (false)</param>
        public CloudBox(string cloudPath = null, bool isServer = false, ulong? id = null, string licenseOEM = null, string name = null, bool doNotCreateSpecialFolders = false, bool isReachable = true)
        {
            IsReachable = isReachable;
            DoNotCreateSpecialFolders = doNotCreateSpecialFolders; ;
            _Name = name;
            //if (string.IsNullOrEmpty(routerEntryPoint))
            //{
            //    throw new Exception("Missing entryPoint");
            //}
            // RouterEntryPoint = routerEntryPoint;


            if (string.IsNullOrEmpty(licenseOEM))
                licenseOEM = TestNetDefaultlicenseOEM;
            LicenseOEM = licenseOEM;
            IsServer = isServer;
            ID = id == null ? BitConverter.ToUInt64(Util.Hash256(cloudPath.GetBytes()), 0) : id.Value;
            if (!string.IsNullOrEmpty(cloudPath) && cloudPath != GetCloudPath(null, isServer))
                _cloudPath = cloudPath;
            Communication = new Communication(this);
            lock (Instances)
                Instances.Add(this);
        }

        /// <summary>
        /// Digitally sign a document
        /// </summary>
        /// <param name="scopeOfSignature">Indicates the intention of the signer (the purpose for which the signature is placed on the document)</param>
        /// <param name="signatureFileName">Returns the name of the file containing the digital signature</param>
        /// <param name="fileName">The name of the file being signed</param>
        /// <param name="document">The file you are signing (in the form of binary data)</param>
        /// <returns>Digital signature in json format</returns>
        public string SignDocument(DigitalSignature.Scope scopeOfSignature, out string signatureFileName, string fileName = null, byte[] document = null)
        {
            var sign = new DigitalSignature(Context.My.GetPrivateKeyBinary(), scopeOfSignature, fileName, document);
            var json = sign.Save();
            signatureFileName = fileName + sign.FileExtension();
            return json;
        }

        /// <summary>
        /// Function that is called when the connection changes (connected or disconnected)
        /// </summary>
        /// <param name="isConnected">Notify the new connection status</param>
        virtual protected void OnRouterConnectionChange(bool isConnected)
        {
            if (Sync == null)
                if (isConnected)
                {
                    ConnectToServer();
                }
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
        /// Connect to server and start sync
        /// </summary>
        /// <param name="serverPublicKey">It is the server to which this client must connect (the public key of the server)</param>
        /// <param name="pin">If the client is running, this is the Pin on the server that is required to log in and then connect the client to the server</param>       
        /// <returns>Successful</returns>        
        public void ConnectToServer(string serverPublicKey = null, string pin = null)
        {
            if (!IsServer)
            {
                if (EncryptedQR != null)
                {
                    // If the login was partially done with an encrypted QR code, once the connection with the router has been established, it asks the cloud for the QR code in order to log in definitively
                    Communication.SendCommand(EncryptedQR.Item1, Communication.Command.GetEncryptedQR, null);
                    return;
                }
                if (pin == null)
                    pin = Context.SecureStorage.Values.Get("pin", null);
                if (!string.IsNullOrEmpty(pin))
                    Context.SecureStorage.Values.Set("pin", pin);
                if (serverPublicKey == null)
                    serverPublicKey = Context.SecureStorage.Values.Get("ServerPublicKey", null);
                SetServerCloudContact(serverPublicKey);
            }
            var credential = IsServer ? null : new LoginCredential { Pin = pin, PublicKey = Context.My.GetPublicKeyBinary() };
            StartSync(credential);
            return;
        }

        /// <summary>
        /// Generate the context, i.e. initialize the environment for encrypted socket communication between devices
        /// </summary>
        /// <param name="routerEntryPoint">IP or domain name or QR code of the router used for the connection</param>
        /// <param name="passphrase">If you want to recover the account, you can specify the passphrase</param>
        /// <returns>True for Successful, or false if something went wrong</returns>  
        public bool CreateContext(string routerEntryPoint, string passphrase = null)
        {
            var isQRcode = !routerEntryPoint.Contains('.');
            string serverPublicKey = null;
            if (isQRcode)
            {
                var qrCode = routerEntryPoint;
                if (SolveQRCode(qrCode, out routerEntryPoint, out serverPublicKey, out EncryptedQR) == false)
                    return false;
            }
            File.WriteAllText(FileLastEntryPoint, routerEntryPoint);
            if (Context != null)
                Debugger.Break();
            //if (onRouterConnectionChange == null)
            //    onRouterConnectionChange = OnRouterConnectionChange;
#if DEBUG || DEBUG_AND
            if (Instances.Count == 0)
                passphrase = IsServer ? TestServerPassphrase : TestClientPassphrase;
#endif
            // Creates a license activator if an OEM license is set during initialization
            var signLicense = string.IsNullOrEmpty(LicenseOEM) ? null : new OEM(LicenseOEM);
            Context = new Context(routerEntryPoint, NetworkName, modality: Modality.Server, privateKeyOrPassphrase: passphrase, licenseActivator: signLicense, instanceId: ID.ToString())
            {
                OnRouterConnectionChange = OnRouterConnectionChange,
                OnCommunicationErrorEvent = OnCommunicationError
            };
            if (serverPublicKey != null)
                Context.SecureStorage.Values.Set("ServerPublicKey", serverPublicKey);
            if (!string.IsNullOrEmpty(_Name))
            {
                Name = _Name;
            }
            Context.OnContactEvent += OnContactEvent;
            return true;
        }

        private void SetServerCloudContact(string serverPublicKey)
        {
#if DEBUG || DEBUG_AND
            if (serverPublicKey == null)
            {
                var mnemo = new Mnemonic(TestServerPassphrase, Wordlist.AutoDetect(TestServerPassphrase));
                var hdRoot = mnemo.DeriveExtKey();
                var privateKey = hdRoot.PrivateKey;
                serverPublicKey = Convert.ToBase64String(privateKey.PubKey.ToBytes());
            }
#endif
#pragma warning disable
            // ReSharper disable once ConditionIsAlwaysTrueOrFalse
            if (serverPublicKey == null)
                // ReSharper disable once HeuristicUnreachableCode
                serverPublicKey = Context.SecureStorage.Values.Get("ServerPublicKey", null);
            else
                Context.SecureStorage.Values.Set("ServerPublicKey", serverPublicKey);
            // ReSharper disable once ConditionIsAlwaysTrueOrFalse
            if (serverPublicKey != null)
            {
                ServerCloud = Context.Contacts.AddContact(serverPublicKey, "Server cloud", Modality.Server, Contacts.SendMyContact.None);
            }
#pragma warning restore            
        }

        ///// <summary>
        ///// The entry point of the router/server, to connect the cloud server or client to the network
        ///// </summary>
        //public string RouterEntryPoint { get; private set; }

        /// <summary>
        /// Login the Client to the Cloud Server by entry QrCode and Pin of server
        /// </summary>
        /// <param name="qrCode">QR code generated by server cloud, in text format</param>
        /// <param name="pin">Pin</param>
        /// <param name="entryPoint">Router entry point, optional parameter for QR codes that do not contain the entry point</param>
        /// <returns>Validated for Successful, or other result if QR code or PIN is not valid</returns>        
        public LoginResult Login(string qrCode, string pin, string entryPoint = null)
        {
            var result = TryLogin(qrCode, pin, entryPoint);
            if (result != LoginResult.Successful)
                Logout();
            return result;
        }

        private LoginResult TryLogin(string qrCode, string pin, string entryPoint = null)
        {
            if (IsServer)
                Debugger.Break(); // non sense for server                     
            Logout();
            if (string.IsNullOrEmpty(pin))
                return LoginResult.WrongPassword;
            if (SolveQRCode(qrCode, out string entry, out string serverPublicKey, out EncryptedQR) == false) return LoginResult.WrongQR;
            if (entry != null)
                entryPoint = entry;
            CreateContext(entryPoint);
            // =================
            // NOTE: Login is performed when the context has established the connection with the router
            // =================
            Context.SecureStorage.Values.Set("pin", pin);
            Context.SecureStorage.Values.Set("ServerPublicKey", serverPublicKey);
            if (SpinWait.SpinUntil(() => Sync != null && (Sync.IsLogged || Sync.LoginError), 30000))
                return Sync.LoginError ? LoginResult.WrongPassword : LoginResult.Successful;
            else if (Context.LicenseExpired)
                return LoginResult.LicenseExpired;
            else if (Sync == null)
                return LoginResult.RemoteHostNotReachable;
            else if (Sync.RemoteHostReachable)
                return LoginResult.CloudNotResponding;
            return LoginResult.RemoteHostNotReachable;
        }

        /// <summary>
        /// The encryption key of the QR code and for the client also the ID of the server useful for communicating with it
        /// </summary>
        public Tuple<ulong, byte[]> EncryptedQR;

#pragma warning disable CS1591

        /// <summary>
        /// Result of login validation
        /// </summary>
        public enum LoginResult
        {
            Successful,
            LicenseExpired,
            WrongPassword,
            CloudNotResponding,
            WrongQR,
            RemoteHostNotReachable,
        }

#pragma warning restore CS1591
        /// <summary>
        /// It receives the data of a QR code as input, validates it and if recognized returns true
        /// </summary>
        /// <param name="qrCode"></param>
        /// <param name="entryPoint">Returns the entry point of the router, to establish the connection</param>
        /// <param name="serverPublicKey">For type 1 and 2 QR codes, the server's public key is returned</param>
        /// <param name="EncryptedQR">For type 2 QR codes (the encrypted one), it returns the encryption code and the server ID so that it can be queried and given the public key when the connection to the router is established</param>
        /// <returns></returns>
        internal static bool SolveQRCode(string qrCode, out string entryPoint, out string serverPublicKey, out Tuple<ulong, byte[]> EncryptedQR)
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
                    // var modulus = qr.Skyp(offset).Take(256);
                    offset += 256;
                    // var exponent = qr.Skyp(offset).Take(3);
                    offset += 3;
                }
                else if (type == 2)
                {
                    var QRkey = qr.Skyp(offset).Take(24);
                    offset += 24;
                    var serverId = BitConverter.ToUInt64(qr.Skyp(offset).Take(8), 0);
                    offset += 8;
                    EncryptedQR = new Tuple<ulong, byte[]>(serverId, QRkey);
                }
                else if (type > 2)
                    return false;
                if (type == 0 || type == 1)
                {
                    serverPublicKey = qr.Skyp(offset).Take(33).ToBase64();
                    var key = new PubKey(Convert.FromBase64String(serverPublicKey)); // pub key validator (throw error if is wrong)
                    offset += 33;
                }
                var ep = qr.Skip(offset).ToASCII();
                if (string.IsNullOrEmpty(ep))
                {
#if RELEASE

                    ShowEntryPoint = false;
                    ep = "server.cloudservices.agency";
#elif DEBUG
                    ep = "test.cloudservices.agency";
#endif
                }
                else if (!ep.Contains("."))
                {
                    ep += ".cloudservices.agency";
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

        private static readonly string FileLastEntryPoint = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LastEntryPoint");

        /// <summary>
        /// Last client entry. If the application was used as a client and the client was logged in, this function returns the last entry point used. Null if the application was not logged in as a client.
        /// </summary>
        /// <returns>Entry point (Url or IP), or null</returns>
        public static string LastEntryPoint()
        {
            return File.Exists(FileLastEntryPoint) ? File.ReadAllText(FileLastEntryPoint) : null;
        }

        /// <summary>
        /// Close socket connection to the router and stop syncing, stops transmitting with the cloud server, but the connection with the router remains active
        /// </summary>
        /// <returns>False if already logged out, true otherwise</returns>
        public bool Logout()
        {
            if (File.Exists(FileLastEntryPoint))
                File.Delete(FileLastEntryPoint);
            StopSync();
            if (Context != null)
            {
                Context.SecureStorage.Values.Set("pin", null);
                Context.SecureStorage.Values.Set("ServerPublicKey", null);
                Context.Dispose();
                Context = null;
                return true;
            }
            return false;
        }

        /// <summary>
        /// True if logged
        /// </summary>
        public bool IsLogged => Sync != null && Sync.IsLogged;

        private readonly bool DoNotCreateSpecialFolders;

        /// <summary>
        /// Start sync (connection must be started first)
        /// </summary>
        /// <param name="isClient">If it is the client, it must provide authentication credentials</param>
        public void StartSync(LoginCredential isClient = null)
        {
            Sync = new Sync(SendCommand, out OnCommand, Context.SecureStorage, CloudPath, isClient, DoNotCreateSpecialFolders, IsReachable);
            Sync.OnNotification += (fromUserId, notice) => OnNotificationAction?.Invoke(fromUserId, notice);
            Sync.OnLocalSyncStatusChanges += (syncStatus, pendingFiles) =>
            {
                SyncStatus = syncStatus;
                PendingFiles = pendingFiles;
                OnLocalSyncStatusChangesAction?.Invoke(syncStatus, pendingFiles);
            };
            Sync.OnFileTransfer += fileTransfer => TransferredFiles.UpdateList(fileTransfer);
            Sync.OnCommandEvent += (userId, command, infoData, isOutput) => OnCommands.AddOnCommand(userId, command, infoData, isOutput);
            Sync.OnFileError += (error, fileName) => AddFileError(error.Message, fileName);
            Sync.OnAntivirus += (message, fileName) => AddAntivirusWarning(message, fileName);
        }

        /// <summary>
        /// Indicates if the cloud path is an unmounted virtual disk.
        /// </summary>
        private bool IsReachable { get { return _IsReachable; } set { _IsReachable = value; Sync?.IsReachableDiskStateIsChanged(value); } }
        private bool _IsReachable = true;


        /// <summary>
        /// Function that the host app must call if the disk at the root of the cloud is mounted or unmounted.
        /// If you plan not to use a virtual disk for cloud space then this function should not be called.
        /// </summary>
        public void IsReachableDiskStateIsChanged(bool isReachable) => IsReachable = isReachable;


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

        /// <summary>
        /// Stops transmitting with the cloud server, but the connection with the router remains active
        /// </summary>
        private void StopSync()
        {
            if (Sync != null)
            {
                OnCommand = null;
                Sync.Dispose();
                Sync = null;
            }
        }

        public readonly FileTransferList TransferredFiles = new FileTransferList();
        public readonly OnCommandList OnCommands = new OnCommandList();
        /// <summary>
        /// Procedure that is performed upon receipt of a notification from the remote machine. Can be used as an event to check the status of the remote machine.
        /// </summary>
        public Sync.OnNotificationEvent OnNotificationAction;
        /// <summary>
        /// Event that fires when the sync status changes
        /// </summary>
        public Sync.StatusEventHandler OnLocalSyncStatusChangesAction;
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
        private const string TestNetDefaultlicenseOEM = "3z66WQrrQnlksDQEcqt7qxABMVBgqexgH/PuY8EmIT4="; // The license activation key on TestNet (for testing)
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
                if (Context != null)
                {
                    if (Context.InstancedTimeUtc != default)
                        AddTx("Started at", Context.InstancedTimeUtc + " UTC");
                    AddTx("User Id", Context?.My.Id);
                    AddTx("Pubblic Key", Context?.My.GetPublicKey());
                    if (ShowEntryPoint)
                        AddTx("Entry point (router address)", Context?.EntryPoint.ToString());
                    AddTx("Keep Alive Failures", Context?.KeepAliveFailures);
                }
                if (LicenseOEM == TestNetDefaultlicenseOEM)
                {
                    if (string.IsNullOrEmpty(LicenseOEM))
                        AddTx("ERROR!", "Missing license");
                    else
                        AddTx("WARNING!", "TestNet license in use");
#if DEBUG
                    AddTx("WARNING!", "compiled in debug mode");
#endif
                }
                if (!IsServer)
                {
                    AddTx("Paired to server", (ServerCloud == null ? "None" : ServerCloud.UserId + " UserId"));
                    AddTx("Logged with server", (Sync != null));
                }
                AddTx("Connected to the router", Context?.IsConnected);
                AddTx("OEM Id", OEM.GetIdOEM(LicenseOEM));
                AddTx("Cloud path", CloudPath);
                //addTx("Pubblic IP", Util.PublicIpAddressInfo());
                if (Context != null)
                {
                    AddTx("# CHANNEL:");
                    AddTx("Last keep alive check", Context?.LastKeepAliveCheck);
                    AddTx("Last IN (UTC)", Context?.LastIN);
                    AddTx("Last command IN", Context?.LastCommandIN);
                    AddTx("Last OUT (UTC)", Context?.LastOUT);
                    AddTx("Last command OUT", Context?.LastCommandOUT);
                }
                if (Sync != null)
                {
                    AddTx("Pending operations", Sync.PendingOperations);
                    // Reception
                    AddTx("# RECEPTION:");
                    AddTx("Last Command received", Sync.LastCommandReceived != default ? (int)((DateTime.UtcNow - Sync.LastCommandReceived).TotalSeconds) + " seconds ago" : (IsServer ? "No client connected" : "ERROR! cloud unreachable"));
                    AddTx("Total files received", Sync.TotalFilesReceived);
                    AddTx("Total bytes received", Sync.TotalBytesReceived);
                    AddTx("Reception file in progress", Sync.ReceptionInProgress.TransferInProgress);
                    AddTx("Reception timeout", Sync.ReceptionInProgress.TimeOutInfo());
                    AddTx("Total received failed by timeout", Sync.ReceptionInProgress.FailedByTimeout);
                    AddTx("# SENDING:");
                    // Sending
                    AddTx("Last Command sent", Sync.LastCommandSent != default ? (int)((DateTime.UtcNow - Sync.LastCommandSent).TotalSeconds) + " seconds ago" : (IsServer ? "No client connected" : "ERROR! cloud unreachable"));
                    AddTx("Total files sent", Sync.TotalFilesSent);
                    AddTx("Total bytes sent", Sync.TotalBytesSent);
                    AddTx("Sending file in progress", Sync.SendingInProgress.TransferInProgress);
                    AddTx("Sending timeout", Sync.SendingInProgress.TimeOutInfo());
                    AddTx("Total sent failed by timeout", Sync.SendingInProgress.FailedByTimeout);
                }
                return sb.ToString();
            }
        }

        private static bool ShowEntryPoint = true;
        /// <summary>
        /// True if the current instance is a cloud server, otherwise false if it is a cloud client
        /// </summary>
        public readonly bool IsServer;
        /// <summary>
        /// For the cloud instance this contact represents the cloud server and every sync protocol communication is done by communicating to this contact
        /// </summary>
        public Contact ServerCloud;
        /// <summary>
        /// Securely get the latest instance of the created cloudbox object
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
        /// Lista di tutte le istanze attualmente attive
        /// </summary>
        public static readonly List<CloudBox> Instances = new List<CloudBox>();

        /// <summary>
        /// Unmount corrent instance
        /// </summary>
        public virtual void Remove()
        {
            Instances.Remove(this);
            Context.Dispose();
        }

        /// <summary>
        /// Dismount the instance and destroy all data within it. Since it is a dangerous operation this function requires the pin
        /// </summary>
        public virtual void Destroy()
        {
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

        private readonly Communication Communication;
        /// <summary>
        /// Sync Agent: Offers all the low-level functions to sync the cloud in an encrypted and secure way
        /// </summary>
        public Sync Sync;
        private Sync.SendCommand OnCommand;
        private static readonly ushort CloudAppId = BitConverter.ToUInt16(Encoding.ASCII.GetBytes("cloud"), 0);
        private void SendCommand(ulong? toContactId, ushort command, byte[][] values)
        {
            var sendToContact = ServerCloud;
            if (sendToContact == null && toContactId != null)
                CloudSyncUsers.TryGetValue((ulong)toContactId, out sendToContact);
            if (sendToContact != null && Sync != null)
            {
                //if (IsServer)OnCommand
                //{
                //    var clientId = (ulong)sendToContact.UserId;
                //    return;
                //}
                Context.Messaging.SendCommandToSubApplication(sendToContact, Sync.AppId, command, true, true, values);
            }
        }

        private readonly string NetworkName = "mainnet";

        /// <summary>
        /// Reference to the underlying encrypted communication system between devices (the low-level communication protocol)
        /// </summary>
        public Context Context { get; private set; }

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
                    var answareToCommand = (Communication.Command)command;
                    Communication.OnCommand(message.AuthorId, answareToCommand, parameters);
                }
                else if (appId == Sync.AppId) // The client application that runs on desktop computers
                {
                    if (message.Contact.UserId != null)
                    {
                        var userId = (ulong)message.Contact.UserId;
                        if (!CloudSyncUsers.ContainsKey(userId))
                            CloudSyncUsers.Add(userId, message.Contact);
                        OnCommand?.Invoke(userId, command, parameters?.ToArray());
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
