using EncryptedMessaging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Serialization;
using static CloudSync.RoleManager;

namespace CloudSync
{
    public class Client
    {
        /// <summary>
        /// Create a client object to save the values of the client that has access to this machine (this instance is for clients that use the API via proxy)
        /// </summary>
        /// <param name="sync"></param>
        /// <param name="clientKey">The publicKey/ID of the client, which is used to authenticate the client-side request</param>
        /// <param name="authenticationProof"></param>
        /// <param name="host">Non-TrustLess information as the proxy or whoever generates this data could falsify it. It is logged for access log purposes</param>
        /// <param name="userAgent">Non-TrustLess information as the proxy or whoever generates this data could falsify it. It is logged for access log purposes</param>
        /// <param name="generateAesKey">Generate a private key to be sent to the client to encrypt the data</param>
        public Client(Sync sync, byte[] clientKey, ProofOfPin authenticationProof, string host, string userAgent = null, bool generateAesKey = true)
        {
            Sync = sync;
            AddNewAccess(host, userAgent);
            AuthenticationProof = authenticationProof;
            PublicKey = clientKey; ;
            Id = RoleManager.PublicKeyToUserId(clientKey);
            if (generateAesKey)
                Aes = Aes.Create();
            Sync.RoleManager.TmpClients[Id] = this;
        }
        /// <summary>
        /// True if this client is currently connected
        /// </summary>
        public bool IsConnected => (DateTime.UtcNow - LastInteraction).TotalMinutes <= Sync.CheckEveryMinutes;

        /// <summary>
        /// Create a client object to save the values of the client that has access to this machine (This instance is for contacts with whom there is encrypted socket communication)
        /// </summary>
        /// <param name="sync"></param>
        /// <param name="id">The ID of the client</param>
        /// <param name="authenticationProof"></param>
        /// <param name="host">Non-TrustLess information as the proxy or whoever generates this data could falsify it. It is logged for access log purposes</param>
        /// <param name="userAgent">Non-TrustLess information as the proxy or whoever generates this data could falsify it. It is logged for access log purposes</param>
        /// <param name="generateAesKey">Generate a private key to be sent to the client to encrypt the data</param>

        public Client(Sync sync, ulong id, ProofOfPin authenticationProof, string host, string userAgent = null, bool generateAesKey = false)
        {
            Sync = sync;
            AddNewAccess(host, userAgent);
            AuthenticationProof = authenticationProof;
            Id = id;
            if (generateAesKey)
                Aes = Aes.Create();
            Sync.RoleManager.TmpClients[Id] = this;
        }

        /// <summary>
        /// Create an interlocutor and save it: This function is used by the client to create the interlocutor and thus have its session variables
        /// </summary>
        /// <param name="sync"></param>
        /// <param name="id">The ID of the server</param>
        /// <param name="generateAesKey">Generate a private key to be sent to the client to encrypt the data</param>
        public Client(Sync sync, ulong id, bool generateAesKey = false)
        {
            Sync = sync;
            Id = id;
            if (generateAesKey)
                Aes = Aes.Create();
            Sync.RoleManager.Clients[Id] = this;
            Save();
        }

        internal Sync Sync;
        public Client()
        {
            // for deserialization use;
        }
        private ProofOfPin AuthenticationProof;
        public void SetAuthenticationProof(ProofOfPin authenticationProof) => AuthenticationProof = authenticationProof;
        public bool Authenticate(byte[] authenticationProof)
        {
            var check = BitConverter.ToUInt32(authenticationProof, 0);
            return Authenticate(check);
        }
        public bool Authenticate(uint authenticationProof)
        {
            if ((DateTime.UtcNow - LastAttempt).TotalSeconds < (Attempts < 3 ? 5 : 600)) // Prevention of brute force attacks (The first 3 attempts at a distance of 5 seconds then wait 10 minutes)
            {
                Attempts++;
                return false;
            }
            LastAttempt = DateTime.UtcNow;
            var passed = AuthenticationProof.Validate(authenticationProof, out string pin);
            if (passed)
            {
                Util.RemoveFromPins(Sync.Context, pin);
                Save();
            }
            AuthenticationProof = null;
            return passed;
        }
        private DateTime LastAttempt; // Prevention of brute force attacks
        private int Attempts;
        /// <summary>
        /// Chunk file size supported for file transfer, if not set default values will be used
        /// </summary>
        public int? ChunkSize;

        public short ThumbanailSize; // The size of the larger side of the image preview images requested by the client. A value of zero indicates that this client does not want the thumbnails
        public ulong Id { get; set; }
        public byte[] IdBytes => BitConverter.GetBytes(Id);

        /// <summary>
        /// The public key generated by the browser or other client
        /// </summary>
        public byte[] PublicKey;

        /// <summary>
        /// It is the key with which the browser\client will have to use to send me the commands by API (Through the proxy). This key must be transmitted to the browser\client (encrypted) to allow it to communicate with me!
        /// </summary>
        public byte[] Key
        {
            get => Aes?.Key;
            set
            {
                if (Aes == null)
                    Aes = Aes.Create();
                Aes.Key = value;
            }
        }
        /// <summary>
        /// Parameter correlated with the symmetrical encryption Key (if key is set, then IV must also be set)
        /// </summary>
        public byte[] IV
        {
            get => Aes?.IV;
            set
            {
                if (Aes == null)
                    Aes = Aes.Create();
                Aes.IV = value;
            }
        }

        public enum EncryptionType { Unset, Aes, XorAB }

        public EncryptionType TypeOfEncryption => Aes != null ? EncryptionType.Aes : PublicKey != null ? EncryptionType.XorAB : EncryptionType.Unset;

        public void Save()
        {
            var roleManager = Sync.RoleManager;
            roleManager.Clients[Id] = this;
            if (roleManager.TmpClients.ContainsKey(Id))
            {
                roleManager.TmpClients.Remove(Id);
            }
            Sync.Context.SecureStorage.ObjectStorage.SaveObject(this, Id.ToString());
        }
        public void RemoveTemp()
        {
            if (Sync.RoleManager.TmpClients.ContainsKey(Id))
                Sync.RoleManager.TmpClients.Remove(Id);
        }
        [XmlIgnore]
        public Aes Aes { get; private set; }

        public LogAccess[] Accesses = { };

        public void AddNewAccess(string host, string userAgent = null)
        {
            var log = new LogAccess { DateTime = DateTime.UtcNow, Host = host, UserAgent = userAgent };
            var list = new List<LogAccess>(Accesses);
            list.Add(log);
            Accesses = list.ToArray();
            if (Accesses.Length > 1)
                Save();
        }
        public Status CurrentStatus;
        public class LogAccess
        {
            /// <summary>
            /// Date and Time of access (Utc)
            /// </summary>
            public DateTime DateTime;
            /// <summary>
            /// Non-TrustLess information as the proxy or whoever generates this data could falsify it. It is logged for access log purposes
            /// </summary>
            public string Host;
            /// <summary>
            /// Non-TrustLess information as the proxy or whoever generates this data could falsify it. It is logged for access log purposes
            /// </summary>
            public string UserAgent;
        }
        internal DateTime LastInteraction;

        [Flags]
        public enum Status
        {
            Enabled = 0, Blocked = 1, AuthenticationRequired = 2,
        }
    }
}
