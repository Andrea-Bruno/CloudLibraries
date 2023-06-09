using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using EncryptedMessaging;
using static EncryptedMessaging.MessageFormat;

namespace CloudBox
{
    public class Communication
    {
        public Communication(CloudBox cloudBox)
        {
            CloudBox = cloudBox;
        }

        private readonly CloudBox CloudBox;
        public enum Command : ushort // 2 byte - the names must start with Get or Set
        {
            SaveData,
            LoadData,
            LoadAllData,
            DeleteData,
            PushNotification,
            /// <summary>
            /// Implementation of the type 2 QR code, it is used to complete the QR code by sending part of it via proxy (in order to create a smaller QR code)
            /// </summary>
            GetEncryptedQR,
        }
        public static readonly Dictionary<Command, uint> Counter = new Dictionary<Command, uint>(); // used for statistical purposes(saves numbers of executed commands)
        private const string Extension = ".d";
        /// <summary>
        /// Method executes when new command is received from a cloud client. Depending on command it saves or loads data to/from the cloud.
        /// </summary>
        /// <param name="userId">Id of the client which sent command </param>
        /// <param name="responseToCommand"> command sent by the client (SaveData, LoadData, LoadAllData, DeleteData, PushNotification)</param>
        /// <param name="parameters"> list of parameters needed for the command:
        /// parameter 0: type - group i.e. folder name;
        /// parameter 1: name - key i.e. file name;
        /// parameter 2: data - data(file itslef) which needs to be stored;
        /// parameter 3: shared - if data is private i.e. stored in a specific user folder or public i.e. stored in a common folder (boolean);</param>
        public void OnCommand(ulong userId, Command responseToCommand, List<byte[]> parameters)
        {
            if (!Counter.ContainsKey(responseToCommand))
                Counter[responseToCommand] = 0;
            Counter[responseToCommand] += 1;
            lock (Extension)
            {
                try
                {
                    string type; // group i.e. folder name
                    string name; // key i.e. file name
                    bool shared; // if data is private(stored in a specific user folder) or public( stored in common folder)
                    byte[] data; // data(file) which needs to be stored
                    string path; // path to the folder with file
                    string file; // path to the file itself
                    switch (responseToCommand)
                    {
                        case Command.SaveData:
                            type = Encoding.ASCII.GetString(parameters[0]);
                            name = Encoding.ASCII.GetString(parameters[1]);
                            data = parameters[2];
                            shared = BitConverter.ToBoolean(parameters[3], 0);
                            path = GetPath(shared ? null : (ulong?)userId, type, true);
                            File.WriteAllBytes(Path.Combine(path, name + Extension), data);
                            break;
                        case Command.LoadData:
                            type = Encoding.ASCII.GetString(parameters[0]);
                            name = Encoding.ASCII.GetString(parameters[1]);
                            int? ifSizeIsDifferent = null;// check if data has changed or not(comparing old and new data size)
                            if (parameters[2].Length > 0)
                                ifSizeIsDifferent = BitConverter.ToInt32(parameters[2], 0);
                            shared = BitConverter.ToBoolean(parameters[3], 0);
                            path = GetPath(shared ? null : (ulong?)userId, type);
                            file = Path.Combine(path, name + Extension);
                            if (File.Exists(file))
                            {
                                data = File.ReadAllBytes(file);
                                if (ifSizeIsDifferent == null || data.Length != ifSizeIsDifferent)
                                {
                                    SendCommand(userId, responseToCommand, new[] { parameters[0], parameters[1], data, parameters[3] });
                                }
                            }
                            break;
                        case Command.LoadAllData:
                            type = Encoding.ASCII.GetString(parameters[0]);
                            shared = BitConverter.ToBoolean(parameters[1], 0);
                            path = GetPath(shared ? null : (ulong?)userId, type);
                            var files = Directory.GetFiles(path, "*" + Extension);
                            foreach (var filename in files)
                            {
                                name = filename.Substring(0, filename.Length - Extension.Length);
                                data = File.ReadAllBytes(filename);
                                SendCommand(userId, responseToCommand, new[] { parameters[0], Encoding.ASCII.GetBytes(name), data, parameters[1] });
                            }
                            break;
                        case Command.DeleteData:
                            type = Encoding.ASCII.GetString(parameters[0]);
                            name = Encoding.ASCII.GetString(parameters[1]);
                            shared = BitConverter.ToBoolean(parameters[2], 0);
                            path = GetPath(shared ? null : (ulong?)userId, type);
                            file = Path.Combine(path, name + Extension);
                            if (File.Exists(file))
                            {
                                File.Delete(file);
                            }
                            break;
                        case Command.PushNotification:
                            break;
                        case Command.GetEncryptedQR:
                            if (CloudBox.IsServer)
                            {
                                var encryptedPubKey = EncryptionXorAB.Encryp(CloudBox.EncryptedQR.Item2, CloudBox.Context.My.GetPublicKeyBinary());
                                SendCommand(userId, responseToCommand, new[] { encryptedPubKey });
                            }
                            else
                            {
                                var encryptedPubKey = parameters[0];
                                var serverPublicKey = EncryptionXorAB.Decrypt(CloudBox.EncryptedQR.Item2, encryptedPubKey);                              
                                CloudBox.EncryptedQR = null;
                                CloudBox.ConnectToServer(serverPublicKey.ToBase64());
                                // CloudBox.Login(qrCode.ToBase64(), CloudBox.Context.SecureStorage.Values.Get("pin", null));
                            }
                            break;
                    }
                }
                catch (Exception ex)
                {
                    // There is probably an error with system dependent files (files open or access denied)
                    Debug.WriteLine(ex.Message);
                }
            }
        }

        private UInt16 AppId => BitConverter.ToUInt16(Encoding.ASCII.GetBytes("cloud"), 0);

        internal void SendCommand(Contact contact, Command command, byte[][] data)
        {
            // Encryption is disabled because the data that must be encrypted by the client when it sends it is not saved in the clear, so it is not necessary to add additional encryption
            CloudBox.Context.Messaging.SendCommandToSubApplication(contact, AppId, (ushort)command, true, false, data);
        }

        internal void SendCommand(ulong ToIdUser, Command command, byte[][] data)
        {
            if (data == null)
                data = new byte[0][];
            // Encryption is disabled because the data that must be encrypted by the client when it sends it is not saved in the clear, so it is not necessary to add additional encryption
            CloudBox.Context.Messaging.SendMessage(MessageType.SubApplicationCommandWithParameters, Functions.JoinData(false, data).Combine(BitConverter.GetBytes(AppId), BitConverter.GetBytes((ushort)command)), null, null, null, new ulong[] { ToIdUser }, true, false);
        }

        private string GetPath(ulong? forUserId, string type = null, bool createFolder = false)
        {
            var appData = CloudBox.CloudPath;
            var directory = forUserId == null ? "shared" : "id" + forUserId;
            var path = type == null ? Path.Combine(appData, directory) : Path.Combine(appData, directory, type);
            if (createFolder && !Directory.Exists(path))
                Directory.CreateDirectory(path);
            return path;
        }
    }
}