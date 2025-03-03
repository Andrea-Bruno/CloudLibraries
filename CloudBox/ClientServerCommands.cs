using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using EncryptedMessaging;
using static EncryptedMessaging.MessageFormat;

namespace CloudBox
{
    /// <summary>
    /// Set of commands that allow you to carry out some operations on the cloud and access special functions
    /// </summary>
    public abstract partial class CloudBox
    {
        /// <summary>
        /// Represents the function that is triggered when client/server communications arrive
        /// </summary>
        /// <param name="userId">User ID who generated the command</param>
        /// <param name="responseToCommand">Represents the function that is triggered when client/server communications arrive</param>
        /// <param name="parameters">Binary row parameters</param>
        public delegate void ClientServerCommandEvent(ulong userId, Command responseToCommand, List<byte[]> parameters);

        /// <summary>
        /// Send commands between client and server
        /// </summary>
        public enum Command : ushort // 2 byte - the names must start with Get or Set
        {
            /// <summary>
            /// Save data command
            /// </summary>
            SaveData,
            /// <summary>
            /// Load data command
            /// </summary>
            LoadData,
            /// <summary>
            /// Load all data command
            /// </summary>
            LoadAllData,
            /// <summary>
            /// Delete data command
            /// </summary>
            DeleteData,
            /// <summary>
            /// Push notification command
            /// </summary>
            PushNotification,
            /// <summary>
            /// Implementation of the type 2 QR code, it is used to complete the QR code by sending part of it via proxy (in order to create a smaller QR code)
            /// </summary>
            GetEncryptedQR,
            /// <summary>
            /// Ask for the password used for the SSH session
            /// Parameters: programToExecute, passwordBinary, localIP, publicIP
            /// </summary>
            GetSSHAccess,
            /// <summary>
            /// Get supported applications
            /// </summary>
            GetSupportedApps
        }

        private static UInt16 AppId => BitConverter.ToUInt16(Encoding.ASCII.GetBytes("cloud"), 0);

        /// <summary>
        /// Send commands between client and server
        /// </summary>
        /// <param name="contact">Contact to send the command to</param>
        /// <param name="command">Command to send</param>
        /// <param name="data">Data to send</param>
        /// <returns>Returns true if the command has been forwarded, false if the connection between client and server has not been established.</returns>
        public bool SendCommand(Contact contact, Command command, byte[][] data)
        {
            if (Context?.IsConnected != true)
            {
                return false;
            }
            if (contact == null)
            {
                Debugger.Break();
                return false;
            }
            // Encryption is disabled because the data that must be encrypted by the client when it sends it is not saved in the clear, so it is not necessary to add additional encryption
            Context?.Messaging.SendCommandToSubApplication(contact, AppId, (ushort)command, true, false, data);
            return true;
        }

        /// <summary>
        /// Send commands between client and server
        /// </summary>
        /// <param name="ToIdUser">User ID to send the command to</param>
        /// <param name="command">Command to send</param>
        /// <param name="data">Data to send</param>
        /// <returns>Returns true if the command has been forwarded, false if the connection between client and server has not been established.</returns>
        public bool SendCommand(ulong ToIdUser, Command command, byte[][] data)
        {
            if (Context == null)
            {
                Debugger.Break();
                return false;
            }
            if (data == null)
                data = new byte[0][];
            // Encryption is disabled because the data that must be encrypted by the client when it sends it is not saved in the clear, so it is not necessary to add additional encryption
            Context?.Messaging.SendMessage(MessageType.SubApplicationCommandWithParameters, Functions.JoinData(false, data).Combine(BitConverter.GetBytes(AppId), BitConverter.GetBytes((ushort)command)), null, null, null, new ulong[] { ToIdUser }, true, false);
            return true;
        }
    }
}