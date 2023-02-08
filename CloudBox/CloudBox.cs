using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using CloudSync;
using EncryptedMessaging;
using NBitcoin;
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
        public CloudBox(string cloudPath = null, bool isServer = false, ulong? id = null, string licenseOEM = null, string name = null, bool doNotCreateSpecialFolders = false)
        {
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
            Communication = new Communication(CloudPath);
            lock (Instances)
                Instances.Add(this);
        }
        private void OnRouterConnectionChange(bool connectivity)
        {
            if (Sync == null)
                if (connectivity)
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
                if (pin == null)
                    pin = Context.SecureStorage.Values.Get("pin", null);
                if (pin == null)
                    return;
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
        /// <param name="routerEntryPoint">IP or domain name of the router used for the connection</param>
        /// <param name="onRouterConnectionChange">Function that acts as an event and will be called when the connection was successful and the client is logged into the router (return true), or when the connection with the router is lost (return false). You can set this action as an event.</param>
        public void CreateContext(string routerEntryPoint, Action<bool> onRouterConnectionChange = null)
        {
            if (Context != null)
                Debugger.Break();
            if (onRouterConnectionChange == null)
                onRouterConnectionChange = OnRouterConnectionChange;
            string passphrase = null;
#if DEBUG || DEBUG_AND
            if (Instances.Count == 0)
                passphrase = IsServer ? TestServerPassphrase : TestClientPassphrase;
#endif
            // Creates a license activator if an OEM license is set during initialization
            var signLicense = string.IsNullOrEmpty(LicenseOEM) ? null : new OEM(LicenseOEM);
            Context = new Context(routerEntryPoint, NetworkName, modality: Modality.Server, privateKeyOrPassphrase: passphrase, licenseActivator: signLicense, instanceId: ID.ToString())
            {
                OnRouterConnectionChange = onRouterConnectionChange,
                OnCommunicationErrorEvent = OnCommunicationError
            };
            if (!string.IsNullOrEmpty(_Name))
            {
                Name = _Name;
            }
            Context.OnContactEvent += OnContactEvent;
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
                ServerCloud = Context.Contacts.AddContact(serverPublicKey, "Server cloud", Modality.Server);
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
        /// <returns>True for Successful, or false if QR code is not valid (this routine don't check the pin)</returns>        
        public bool Login(string qrCode, string pin, string entryPoint = null)
        {
            if (IsServer)
                Debugger.Break(); // non sense for server                     
            Logout();
            string ServerPublicKey = null; // used for Login (in QR code)

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
            if (type > 2)
                return false;
            try
            {
                ServerPublicKey = qr.Skyp(offset).Take(33).ToBase64();
                var key = new PubKey(Convert.FromBase64String(ServerPublicKey)); // pub key validator (throw error if is wrong)
                offset += 33;
                var ep = qr.Skip(offset).ToASCII();
                if (!string.IsNullOrEmpty(ep))
                {
                    if (!Uri.TryCreate(ep, UriKind.RelativeOrAbsolute, out Uri myUri))
                        return false; // url not valid
                    entryPoint = ep;
                }
                else
                {
#if RELEASE
                    ShowEntryPoint = false;
#endif
                }
            }
            catch (Exception)
            {
                return false;
            }
            CreateContext(entryPoint);
            Context.SecureStorage.Values.Set("pin", pin);
            Context.SecureStorage.Values.Set("ServerPublicKey", ServerPublicKey);
            File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LastEntryPoint"), entryPoint);
            return true;
        }


        /// <summary>
        /// Close socket connection to the router and stop syncing, stops transmitting with the cloud server, but the connection with the router remains active
        /// </summary>
        /// <returns>False if already logged out, true otherwise</returns>
        public bool Logout()
        {
            if (Sync != null)
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
        public bool IsLogged => Sync != null;

        private readonly bool DoNotCreateSpecialFolders;

        /// <summary>
        /// Start sync (connection must be started first)
        /// </summary>
        /// <param name="isClient">If it is the client, it must provide authentication credentials</param>
        public void StartSync(LoginCredential isClient = null)
        {
            Sync = new Sync(SendCommand, out OnCommand, Context, CloudPath, isClient, DoNotCreateSpecialFolders);
            Sync.OnNotification += (fromUserId, notice) => { OnNotificationAction?.Invoke(fromUserId, notice); };
            Sync.OnSyncStatusChanges += (syncStatus, pendingFiles) => OnSyncStatusChangesAction?.Invoke(syncStatus, pendingFiles);
            Sync.OnFileTransfer += fileTransfer => TransferredFiles.UpdateList(fileTransfer);
            Sync.OnCommandEvent += (command, userId, isOutput) => OnCommands.AddOnCommand(command, userId, isOutput);
        }

        /// <summary>
        /// Stops transmitting with the cloud server, but the connection with the router remains active
        /// </summary>
        private void StopSync()
        {
            if (Sync != null)
            {
                Sync.Dispose();
                Sync = null;
            }
        }

        public readonly FileTransferList TransferredFiles = new FileTransferList();
        public readonly OnCommandList OnCommands = new OnCommandList();
        public Sync.OnNotificationEvent OnNotificationAction;
        public Sync.StatusEventHandler OnSyncStatusChangesAction;
        public OnErrorEvent OnCommunicationErrorEvent;
        public readonly List<Tuple<ErrorType, string>> CommunicationErrorLog = new List<Tuple<ErrorType, string>>();

        private void OnCommunicationError(ErrorType errorId, string description)
        {
            OnCommunicationErrorEvent?.Invoke(errorId, description);
            CommunicationErrorLog.Insert(0, new Tuple<ErrorType, string>(errorId, description));
            if (CommunicationErrorLog.Count > 10)
                CommunicationErrorLog.RemoveAt(CommunicationErrorLog.Count - 1);
        }

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
                if (!IsServer)
                {
                    AddTx("[CloudBox Client]");
                    AddTx("Paired to server", (ServerCloud == null ? "None" : ServerCloud.UserId + " UserId"));
                    AddTx("Logged with server", (Sync != null));
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
                AddTx("OEM Id", OEM.GetIdOEM(LicenseOEM));
                AddTx("Cloud path", CloudPath);
                //addTx("Pubblic IP", Util.PublicIpAddressInfo());
                if (Context != null)
                {
                    if (ShowEntryPoint)
                        AddTx("Entry point (router address)", Context?.EntryPoint.ToString());
                    AddTx("Connected to the router", Context?.IsConnected);
                    AddTx("PubKey", Context?.My.GetPublicKey());
                    AddTx("UserId", Context?.My.Id);
                    AddTx("Keep Alive Failures", Context?.KeepAliveFailures);
                }

                if (Sync != null)
                {
                    AddTx("Last Communication", Sync.LastCommunicationReceived != default ? (int)((DateTime.UtcNow - Sync.LastCommunicationReceived).TotalSeconds) + " seconds ago" : (IsServer ? "No client connected" : "ERROR! cloud unreachable"));
                    AddTx("Pending operations", Sync.PendingOperations);

                    // Sending
                    AddTx("Total files sent", Sync.TotalFilesSent);
                    AddTx("Total bytes sent", Sync.TotalBytesSent);
                    AddTx("Sending file in Progress", Sync.SendingInProgress.TransferInProgress());
                    AddTx("Sending timeout", Sync.SendingInProgress.TimeOutInfo());
                    AddTx("Total sent failed by timeout", Sync.SendingInProgress.FailedByTimeout);

                    // Reception
                    AddTx("Total files received", Sync.TotalFilesReceived);
                    AddTx("Total bytes received", Sync.TotalBytesReceived);
                    AddTx("Reception file in Progress", Sync.ReceptionInProgress.TransferInProgress());
                    AddTx("Reception timeout", Sync.ReceptionInProgress.TimeOutInfo());
                    AddTx("Total received failed by timeout", Sync.ReceptionInProgress.FailedByTimeout);
                }
                return sb.ToString();
            }
        }
        private bool ShowEntryPoint = true;
        public readonly bool IsServer;
        public Contact ServerCloud;
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
        public void Remove()
        {
            Instances.Remove(this);
            Context.Dispose();
        }

        /// <summary>
        /// Dismount the instance and destroy all data within it. Since it is a dangerous operation this function requires the pin
        /// </summary>
        public void Destroy()
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
            if (sendToContact != null)
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
        public Context Context { get; private set; }

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
                    Communication.OnCommand(message.Contact, answareToCommand, parameters);
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
