using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using static CloudSync.Util;

namespace CloudSync
{
    public partial class Sync
    {
        public enum Commands : ushort
        {
            Notification,
            /// <summary>
            /// Send the public encryption key, the server create a random byte array and adds the pin to it and creates the hash. To be authenticated, the client must be receive the random byte array and prove that it knows the pin by sending the same hash that was computed on the server
            /// </summary>
            RequestOfAuthentication,
            /// <summary>
            /// The client sends the hash of the key random cipher plus pins to the server, as proof that it knows the pin but does not show it
            /// </summary>
            Authentication,
            SendHashStructure,
            RequestHashStructure,
            SendHashBlocks,
            SendHashRoot,
            RequestChunkFile,
            SendChunkFile,
            DeleteFile,
            CreateDirectory,
            DeleteDirectory,
            /// <summary>
            /// Command used by the slave machine to indicate if it is ready to receive new commands or if it is busy
            /// </summary>
            StatusNotification,
        }

        public enum Notice : byte
        {
            Authentication,
            LoginSuccessful,
            /// <summary>
            /// Wrong pin
            /// </summary>
            LoginError,
            Synchronized,
            LoggedOut,
            /// <summary>
            /// Warns the device is full and that no more write operations are allowed
            /// </summary>
            FullSpace,
            /// <summary>
            /// Warns that the device is no longer full, write operations are enabled again
            /// </summary>
            FullSpaceOff,
        }
        public enum Status : byte
        {
            Ready = 0,
            Busy = 1,
        }

        private void SendNotification(ulong? toUserId, Notice notice)
        {
            SendCommand(toUserId, Commands.Notification, notice.ToString(), new[] { new[] { (byte)notice } });
        }

        /// <summary>
        /// Command used by the client to request connection to the cloud server
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="credential"></param>
        /// <param name="host"></param>
        /// <param name="userAgent"></param>
        private void RequestOfAuthentication(ulong? toUserId, LoginCredential credential, string host, string userAgent = null)
        {
            Credential = credential;
            var hostArray = host == null ? new byte[] { } : Encoding.ASCII.GetBytes(host);
            var userAgentArray = userAgent == null ? new byte[] { } : Encoding.ASCII.GetBytes(userAgent);
            SendCommand(toUserId, Commands.RequestOfAuthentication, host, hostArray, userAgentArray);
        }
        private LoginCredential Credential;

        /// <summary>
        /// Command used by the Server to send a cryptographic authentication request to the client, which authenticates it with a hash as proof of knowing the PIN
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="randomDataForAuthentication"></param>
        private void Authentication(ulong? toUserId, byte[] randomDataForAuthentication)
        {
            SendCommand(toUserId, Commands.Authentication, null, new[] { randomDataForAuthentication });
        }

        private void SendHashStructure(ulong? toUserId, BlockRange delimitsRange = null)
        {
            if (GetLocalHashStructure(out var structure, delimitsRange))
            {
                if (delimitsRange == null)
                    SendCommand(toUserId, Commands.SendHashStructure, null, new[] { structure });
                else
                    SendCommand(toUserId, Commands.SendHashStructure, null, new[] { structure, delimitsRange.BetweenHasBlockBynary, delimitsRange.BetweenHasBlockIndexBinary, delimitsRange.BetweenReverseHasBlockBinary, delimitsRange.BetweenReverseHasBlockIndexBinary });
            }
        }

        private void RequestHashStructure(ulong? toUserId, BlockRange delimitsRange = null)
        {
            if (delimitsRange == null)
                SendCommand(toUserId, Commands.RequestHashStructure, null);
            else
                SendCommand(toUserId, Commands.RequestHashStructure, null, new[] { delimitsRange.BetweenHasBlockBynary, delimitsRange.BetweenHasBlockIndexBinary, delimitsRange.BetweenReverseHasBlockBinary, delimitsRange.BetweenReverseHasBlockIndexBinary });
        }

        private void SendHashBlocks(ulong? toUserId)
        {
            if (GetHasBlock(out var hashBlock))
            {
                SendCommand(toUserId, Commands.SendHashBlocks, null, new[] { hashBlock });
            }
        }

        public void SendHashRoot(ulong? toUserId = null)
        {
            if (GetHasRoot(out var hashRoot, true))
            {
                SendCommand(toUserId, Commands.SendHashRoot, null, new[] { hashRoot });
            }
        }

        private void SendHashRoot(byte[] hashRoot, ulong? toUserId = null)
        {
            SendCommand(toUserId, Commands.SendHashRoot, null, hashRoot);
        }

        private void RequestChunkFile(ulong? toUserId, ulong hash, uint chunkPart, bool isReceptFileCompleted = false)
        {
            if (isReceptFileCompleted)
                ReceptionInProgress.Completed(hash, (ulong)toUserId);
            else
                ReceptionInProgress.SetTimeout(hash);
            SendCommand(toUserId, Commands.RequestChunkFile, "#" + chunkPart + " " + hash, new[] { hash.GetBytes(), chunkPart.GetBytes() });
        }

        private void ReportReceiptFileCompleted(ulong? toUserId, ulong hash, uint totalParts)
        {
            RequestChunkFile(toUserId, hash, totalParts + 1, true);
        }

        public void RequestFile(ulong? toUserId, ulong hash) => RequestChunkFile(toUserId, hash, 1);

        public readonly ProgressFileTransfer SendingInProgress;
        public void SendFile(ulong? toUserId, FileSystemInfo fileSystemInfo) => SendChunkFile(toUserId, fileSystemInfo, 1);
        private void SendChunkFile(ulong? toUserId, FileSystemInfo fileSystemInfo, uint chunkPart)
        {
            if (!fileSystemInfo.Exists)
                return;
#if RELEASE
            try
            {
#endif
            if (Spooler.RemoteDriveOverLimit)
                return; // The remote disk is full, do not send any more data
            if (fileSystemInfo.Attributes.HasFlag(FileAttributes.Directory))
            {
                CreateDirectory(toUserId, fileSystemInfo);
            }
            else
            {
                var hashFileName = fileSystemInfo.HashFileName(this);
                var tmpFile = GetTmpFile(this, toUserId, hashFileName);
                if (!File.Exists(tmpFile)) // old if (chunkPart == 1)
                {
                    FileCopy(fileSystemInfo, tmpFile, out Exception exception, context: this);
                    if (exception != null)
                        RaiseOnFileError(exception, fileSystemInfo.FullName);
                }

                var chunk = GetChunk(chunkPart, tmpFile, out var parts, out var fileLength);
#if DEBUG
                if (chunk == null && chunkPart != parts + 1)
                    Debugger.Break();
#endif

                if (chunk == null)
                {
                    //File send completed;
                    CRC.RemoveCRC(toUserId, hashFileName);
                    FileDelete(tmpFile, out Exception exception);
                    if (exception != null)
                        RaiseOnFileError(exception, fileSystemInfo.FullName);
                    TotalFilesSent++;
                    TotalBytesSent += (uint)fileLength;
                    SendingInProgress.Completed(hashFileName, (ulong)toUserId);
                }
                else if (CRC.Update(toUserId, hashFileName, ref chunkPart, chunk, tmpFile, false, out _))
                {
                    var values = new List<byte[]>(new[] { BitConverter.GetBytes(hashFileName), BitConverter.GetBytes(chunkPart), BitConverter.GetBytes(parts), chunk });
                    if (chunkPart == parts)
                    {
                        values.Add(BitConverter.GetBytes(fileSystemInfo.UnixLastWriteTimestamp()));
                        values.Add(BitConverter.GetBytes((uint)((FileInfo)fileSystemInfo).Length));
                        values.Add(fileSystemInfo.CloudRelativeUnixFullName(this).GetBytes());
                        values.Add(CRC.GetCRC(toUserId, hashFileName, parts).GetBytes());
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
                //if (ex.HResult == -2147024671) // Operation did not complete successfully because the file contains a virus or potentially unwanted software.
                RaiseOnFileError(ex, fileSystemInfo.FullName);
                Debug.WriteLine(ex.Message);
            }
#endif
        }
        public uint TotalFilesSent;
        public uint TotalBytesSent;

        private void DeleteFile(ulong? toUserId, ulong hash, FileSystemInfo fileSystemInfo)
        {
            var timestamp = fileSystemInfo.UnixLastWriteTimestamp();
            SendCommand(toUserId, Commands.DeleteFile, fileSystemInfo.FullName, new[] { hash.GetBytes(), timestamp.GetBytes() });
        }

        private void DeleteFile(ulong? toUserId, ulong hash, uint unixTimestamp, string infoData)
        {
            SendCommand(toUserId, Commands.DeleteFile, infoData, new[] { hash.GetBytes(), unixTimestamp.GetBytes() });
        }

        private void CreateDirectory(ulong? toUserId, FileSystemInfo fileSystemInfo)
        {
            if (Spooler.RemoteDriveOverLimit)
                return; // The remote disk is full, do not send any more data
            SendCommand(toUserId, Commands.CreateDirectory, fileSystemInfo.FullName, new[] { fileSystemInfo.CloudRelativeUnixFullName(this).GetBytes() });
        }

        private void DeleteDirectory(ulong? toUserId, FileSystemInfo fileSystemInfo)
        {
            SendCommand(toUserId, Commands.DeleteDirectory, fileSystemInfo.FullName, new[] { fileSystemInfo.CloudRelativeUnixFullName(this).GetBytes() });
        }

        /// <summary>
        /// The slave machine sends a message to indicate if it is ready to receive new commands or if it is busy
        /// </summary>
        /// <param name="toUserId">Target user ID</param>
        /// <param name="status">Busy otherwise Ready to request to proceed with the synchronization</param>
        internal void StatusNotification(ulong? toUserId, Status status)
        {
            SendCommand(toUserId, Commands.StatusNotification, status.ToString(), new[] { (byte)status });
        }

        /// <summary>
        /// Send the command to the remote machine which will interpret and execute it
        /// </summary>
        /// <param name="contactId">User ID of the machine receiving the command</param>
        /// <param name="command">Command to execute</param>
        /// <param name="infoData">A locally used log message containing information about the command sent.</param>
        /// <param name="values">Parameters associated with the sent command</param>
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

    }
}
