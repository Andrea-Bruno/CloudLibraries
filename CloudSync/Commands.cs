using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static CloudSync.Util;

namespace CloudSync
{
    public partial class Sync
    {
        /// <summary>
        /// Enumeration of possible commands that can be sent between client and server
        /// </summary>
        public enum Commands : ushort
        {
            /// <summary>
            /// General notification command
            /// </summary>
            Notification,

            /// <summary>
            /// Send the public encryption key, the server creates a random byte array,
            /// adds the pin to it and creates the hash. To be authenticated, the client
            /// must receive the random byte array and prove that it knows the pin by
            /// sending the same hash that was computed on the server
            /// </summary>
            RequestOfAuthentication,

            /// <summary>
            /// The client sends the hash of the key random cipher plus pins to the server,
            /// as proof that it knows the pin but does not show it
            /// </summary>
            Authentication,

            /// <summary>
            /// Command to send the hash structure of files
            /// </summary>
            SendHashStructure,

            /// <summary>
            /// Command to request the hash structure from the remote
            /// </summary>
            RequestHashStructure,

            /// <summary>
            /// Command to send the root hash of the file structure
            /// </summary>
            SendHashRoot,

            /// <summary>
            /// Command to request a chunk of a file
            /// </summary>
            RequestChunkFile,

            /// <summary>
            /// Command to send a chunk of a file
            /// </summary>
            SendChunkFile,

            /// <summary>
            /// Command to delete a file
            /// </summary>
            DeleteFile,

            /// <summary>
            /// Command to create a directory
            /// </summary>
            CreateDirectory,

            /// <summary>
            /// Command to delete a directory
            /// </summary>
            DeleteDirectory,

            /// <summary>
            /// Command used by the slave machine to indicate if it is ready to receive
            /// new commands or if it is busy
            /// </summary>
            StatusNotification,
        }

        /// <summary>
        /// Enumeration of possible notification types
        /// </summary>
        public enum Notice : byte
        {
            /// <summary>
            /// Authentication notification
            /// </summary>
            Authentication,

            /// <summary>
            /// Successful login notification
            /// </summary>
            LoginSuccessful,

            /// <summary>
            /// Wrong pin notification
            /// </summary>
            LoginError,

            /// <summary>
            /// Synchronization completed notification
            /// </summary>
            Synchronized,

            /// <summary>
            /// Logged out notification
            /// </summary>
            LoggedOut,

            /// <summary>
            /// Warns the device is full and that no more write operations are allowed
            /// </summary>
            FullSpace,

            /// <summary>
            /// Warns that the device is no longer full, write operations are enabled again
            /// </summary>
            FullSpaceOff,

            /// <summary>
            /// Indicates that the operation has been completed, the client can now proceed with the next operation
            /// </summary>
            OperationCompleted,
        }

        /// <summary>
        /// Enumeration of possible status states
        /// </summary>
        public enum Status : byte
        {
            /// <summary>
            /// Ready to receive commands
            /// </summary>
            Ready = 0,

            /// <summary>
            /// Busy processing current commands
            /// </summary>
            Busy = 1,
        }

        /// <summary>
        /// Counter for pending confirmations
        /// </summary>
        internal int PendingConfirmation;

        /// <summary>
        /// Sends a notification to the specified user
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="notice">Notification type to send</param>
        private void SendNotification(ulong? toUserId, Notice notice)
        {
            SendCommand(toUserId, Commands.Notification, notice.ToString(), [(byte)notice]);
        }

        /// <summary>
        /// Command used by the client to request connection to the cloud server
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="credential">Login credentials</param>
        /// <param name="host">Host information</param>
        /// <param name="userAgent">Optional user agent information</param>
        internal void RequestOfAuthentication(ulong? toUserId, LoginCredential credential, string host, string userAgent = null)
        {
            Credential = credential;
            var hostArray = host == null ? [] : Encoding.ASCII.GetBytes(host);
            var userAgentArray = userAgent == null ? [] : Encoding.ASCII.GetBytes(userAgent);
            SendCommand(toUserId, Commands.RequestOfAuthentication, host, hostArray, userAgentArray);
        }

        /// <summary>
        /// Stores the current login credentials
        /// </summary>
        private LoginCredential Credential;

        /// <summary>
        /// Command used by the Server to send a cryptographic authentication request to the client,
        /// which authenticates it with a hash as proof of knowing the PIN
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="randomDataForAuthentication">Random data used for authentication</param>
        private void Authentication(ulong? toUserId, byte[] randomDataForAuthentication)
        {
            SendCommand(toUserId, Commands.Authentication, null,
                ZeroKnowledgeProof != null ?
                [randomDataForAuthentication, Util.Hash256(ZeroKnowledgeProof.FilenameObfuscationKey).Take(4).ToArray()] :
                [randomDataForAuthentication]);
        }

        /// <summary>
        /// Sends the hash structure to the specified user
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        private void SendHashStructure(ulong? toUserId)
        {
            if (GetHashFileTable(out HashFileTable hashFileTable))
            {
                SendCommand(toUserId, Commands.SendHashStructure, null, hashFileTable.GetHashStructure());
            }
        }

        /// <summary>
        /// Requests the hash structure from the specified user
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        private void RequestHashStructure(ulong? toUserId)
        {
            SendCommand(toUserId, Commands.RequestHashStructure, null);
        }

        /// <summary>
        /// Sends the root hash to the specified user
        /// </summary>
        /// <param name="toUserId">Optional target user ID (null for broadcast)</param>
        public void SendHashRoot(ulong? toUserId = null)
        {
            if (ClientToolkit?.WatchCloudRoot.IsPending == true)
                return; // Do not send the hash root if the cloud root is still being watched for changes

            if (GetHashFileTable(out HashFileTable hashFileTable))
            {
                SendCommand(toUserId, Commands.SendHashRoot, null, hashFileTable.GetHasRoot());
            }
        }

        /// <summary>
        /// Requests a specific chunk of a file from the specified user
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="hash">Hash of the requested file</param>
        /// <param name="chunkPart">Chunk number being requested</param>
        /// <param name="isReceptFileCompleted">Flag indicating if this is the final chunk</param>
        private void RequestChunkFile(ulong? toUserId, ulong hash, uint chunkPart, bool isReceptFileCompleted = false)
        {
            if (isReceptFileCompleted)
                ReceptionInProgress.Completed(hash, (ulong)toUserId);
            else
                ReceptionInProgress.SetTimeout(hash);

            SendCommand(toUserId, Commands.RequestChunkFile, "#" + chunkPart + " " + hash,
                hash.GetBytes(), chunkPart.GetBytes());
        }

        /// <summary>
        /// Reports that file reception has completed
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="hash">Hash of the completed file</param>
        /// <param name="totalParts">Total number of parts received</param>
        private void ReportReceiptFileCompleted(ulong? toUserId, ulong hash, uint totalParts)
        {
            RequestChunkFile(toUserId, hash, totalParts + 1, true);
        }

        /// <summary>
        /// Requests a file from the specified user
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="hash">Hash of the requested file</param>
        public void RequestFile(ulong? toUserId, ulong hash) => RequestChunkFile(toUserId, hash, 1);

        /// <summary>
        /// Tracks progress of file transfers being sent
        /// </summary>
        public readonly ProgressFileTransfer SendingInProgress;

        /// <summary>
        /// Initiates sending a file to the specified user
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="fileSystemInfo">File or directory to send</param>
        public void SendFile(ulong? toUserId, FileSystemInfo fileSystemInfo) => SendChunkFile(toUserId, fileSystemInfo, 1);

        /// <summary>
        /// Sends a chunk of a file to the specified user
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="fileSystemInfo">File or directory being sent</param>
        /// <param name="chunkPart">Current chunk number</param>
        private void SendChunkFile(ulong? toUserId, FileSystemInfo fileSystemInfo, uint chunkPart)
        {
            if (!fileSystemInfo.Exists)
            {
                Debugger.Break();
                return;
            }

#if RELEASE
            try
            {
#endif
            if (RemoteDriveOverLimit)
                return; // The remote disk is full, do not send any more data

            if (fileSystemInfo is DirectoryInfo)
            {
                CreateDirectory(toUserId, fileSystemInfo);
            }
            else
            {
                var hashFileName = fileSystemInfo.HashFileName(this);

                // Get the requested file chunk
                var chunk = GetChunk(chunkPart, fileSystemInfo.FullName, out var parts, out var fileLength);

#if DEBUG
                if (chunk == null && chunkPart != parts + 1)
                    Debugger.Break();
#endif

                if (chunk == null)
                {
                    // File send completed or File error
                    CRC.RemoveCRC(IsClient, toUserId, hashFileName);
                    TotalFilesSent++;
                    TotalBytesSent += (uint)fileLength;
                    SendingInProgress.Completed(hashFileName, (ulong)toUserId);
                }
                else if (CRC.Update(IsClient, toUserId, hashFileName, ref chunkPart, chunk, fileSystemInfo.FullName, false, out _))
                {
                    // Prepare the chunk data for sending
                    var values = new List<byte[]>([
                        BitConverter.GetBytes(hashFileName),
                            BitConverter.GetBytes(chunkPart),
                            BitConverter.GetBytes(parts),
                            chunk
                    ]);

                    if (chunkPart == parts)
                    {
                        // Add final file metadata for the last chunk
                        values.Add(BitConverter.GetBytes(fileSystemInfo.UnixLastWriteTimestamp()));
                        values.Add(BitConverter.GetBytes((uint)((FileInfo)fileSystemInfo).Length));
                        values.Add(fileSystemInfo.CloudRelativeUnixFullName(this).GetBytes());
                        values.Add(CRC.GetCRC(IsClient, toUserId, hashFileName, parts).GetBytes());
                    }

                    RaiseOnFileTransfer(true, hashFileName, chunkPart, parts, fileSystemInfo.FullName, fileLength);
                    SendingInProgress.SetTimeout(hashFileName, chunk.Length);
                    var info = "#" + chunkPart + "/" + parts + " " + hashFileName;
                    Debug.WriteLine("IN " + info);
                    SendCommand(toUserId, Commands.SendChunkFile, info, values.ToArray());
                }
            }
#if RELEASE
            }
            catch (Exception ex)
            {
                RaiseOnFileError(ex, fileSystemInfo.FullName);
                Debug.WriteLine(ex.Message);
            }
#endif
        }

        /// <summary>
        /// Counter for total files sent
        /// </summary>
        public uint TotalFilesSent;

        /// <summary>
        /// Counter for total bytes sent
        /// </summary>
        public uint TotalBytesSent;

        /// <summary>
        /// Deletes a file on the remote system
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="hash">Hash of the file to delete</param>
        /// <param name="unixTimestamp">Timestamp of the file</param>
        /// <param name="infoData">Optional information about the deletion</param>
        public void DeleteFile(ulong? toUserId, ulong hash, uint unixTimestamp, string infoData = null)
        {
            PendingConfirmation++;
            SendCommand(toUserId, Commands.DeleteFile, infoData, hash.GetBytes(), unixTimestamp.GetBytes());
        }

        /// <summary>
        /// Creates a directory on the remote system
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="fileSystemInfo">Directory to create</param>
        private void CreateDirectory(ulong? toUserId, FileSystemInfo fileSystemInfo)
        {
            if (RemoteDriveOverLimit == true)
                return; // The remote disk is full, do not send any more data

            SendCommand(toUserId, Commands.CreateDirectory, fileSystemInfo.FullName,
                [fileSystemInfo.CloudRelativeUnixFullName(this).GetBytes()]);
        }

        /// <summary>
        /// Deletes a directory on the remote system
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="hash">Hash of the directory to delete</param>
        /// <param name="infoData">Optional information about the deletion</param>
        public void DeleteDirectory(ulong? toUserId, ulong hash, string infoData = null)
        {
            PendingConfirmation++;
            SendCommand(toUserId, Commands.DeleteDirectory, infoData, hash.GetBytes());
        }

        /// <summary>
        /// Sends a status notification to the specified user
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="status">Current status (Ready/Busy)</param>
        internal void StatusNotification(ulong? toUserId, Status status)
        {
            SendCommand(toUserId, Commands.StatusNotification, status.ToString(), [(byte)status]);
        }

        /// <summary>
        /// Sends a command to the remote machine which will interpret and execute it
        /// </summary>
        /// <param name="toContactId">User ID of the machine receiving the command</param>
        /// <param name="command">Command to execute</param>
        /// <param name="infoData">Optional information about the command (used locally for logging)</param>
        /// <param name="values">Parameters associated with the sent command</param>
        private void SendCommand(ulong? toContactId, Commands command, string? infoData, params byte[][] values)
        {
#if DEBUG
            if (toContactId == UserId)
            {
                Debugger.Break(); // Do not send commands to yourself, this is a bug!
            }
#endif

            if (!Disposed)
            {
                LastCommandSent = DateTime.UtcNow;
                Task.Run(() =>
                {
                    try
                    {
                        Debug.WriteLine("OUT " + command);
                        RaiseOnCommandEvent(toContactId, command, infoData, true);
                        Send.Invoke(toContactId, (ushort)command, values);
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
    }
}