using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
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
            DeleteFIle,
            CreateDirectory,
            DeleteDirectory,
            /// <summary>
            /// Command used by the slave machine to indicate if it is ready to receive new commands or if it is busy
            /// </summary>
            StatusNotification,
        }

        public enum Notice : byte
        {
            LoginSuccessful,
            /// <summary>
            /// Wrong pin
            /// </summary>
            LoginError,
            Synchronized,
        }

        private void Notification(ulong? toUserId, Notice notice)
        {
            ExecuteCommand(toUserId, Commands.Notification, new[] { new[] { (byte)notice } });

        }

        /// <summary>
        /// Command used by the client to request connection to the cloud server
        /// </summary>
        /// <param name="toUserId"></param>
        /// <param name="credential"></param>
        /// <param name="host"></param>
        /// <param name="userAgent"></param>
        private void RequestOfAuthentication(ulong? toUserId, LoginCredential credential, string host, string userAgent = null)
        {
            Credential = credential;
            var hostArray = host == null ? new byte[] { } : Encoding.ASCII.GetBytes(host);
            var userAgentArray = userAgent == null ? new byte[] { } : Encoding.ASCII.GetBytes(userAgent);
            ExecuteCommand(toUserId, Commands.RequestOfAuthentication, hostArray, userAgentArray);
        }
        private LoginCredential Credential;

        /// <summary>
        /// Command used by the Server to send a cryptographic authentication request to the client, which authenticates it with a hash as proof of knowing the PIN
        /// </summary>
        /// <param name="toUserId"></param>
        /// <param name="randomDataForAuthentication"></param>
        private void Authentication(ulong? toUserId, byte[] randomDataForAuthentication)
        {
            ExecuteCommand(toUserId, Commands.Authentication, new[] { randomDataForAuthentication });
        }

        private void SendHashStructure(ulong? toUserId, BlockRange delimitsRange = null)
        {
            var structure = GetLocalHashStrucrure(delimitsRange);
            if (structure != null)
            {
                if (delimitsRange == null)
                    ExecuteCommand(toUserId, Commands.SendHashStructure, new[] { structure });
                else
                    ExecuteCommand(toUserId, Commands.SendHashStructure, new[] { structure, delimitsRange.BetweenHasBlockBynary, delimitsRange.BetweenHasBlockIndexBinary, delimitsRange.BetweenReverseHasBlockBynary, delimitsRange.BetweenReverseHasBlockIndexBinary });
            }
        }

        private void RequestHashStructure(ulong? toUserId, BlockRange delimitsRange = null)
        {
            if (delimitsRange == null)
                ExecuteCommand(toUserId, Commands.RequestHashStructure);
            else
                ExecuteCommand(toUserId, Commands.RequestHashStructure, new[] { delimitsRange.BetweenHasBlockBynary, delimitsRange.BetweenHasBlockIndexBinary, delimitsRange.BetweenReverseHasBlockBynary, delimitsRange.BetweenReverseHasBlockIndexBinary });
        }

        private void SendHashBlocks(ulong? toUserId)
        {
            ExecuteCommand(toUserId, Commands.SendHashBlocks, new[] { GetHasBlock() });
        }

        private void SendHashRoot(ulong? toUserId = null)
        {
            ExecuteCommand(toUserId, Commands.SendHashRoot, new[] { GetHasRoot(true) });
        }

        private void RequestChunkFile(ulong? toUserId, ulong hash, uint chunkPart)
        {
            ReceptionInProgress.SetTimeout(hash);
            ExecuteCommand(toUserId, Commands.RequestChunkFile, new[] { BitConverter.GetBytes(hash), chunkPart.GetBytes() });
        }
        private void ReportReceiptFileCompleted(ulong? toUserId, ulong hash, uint totalParts)
        {
            RequestChunkFile(toUserId, hash, totalParts + 1);
        }

        public void RequestFile(ulong? toUserId, ulong hash) => RequestChunkFile(toUserId, hash, 1);

        public readonly ProgressFileTransfer SendingInProgress;
        public void SendFile(ulong? toUserId, FileSystemInfo fileSystemInfo) => SendChunkFile(toUserId, fileSystemInfo, 1);
        private readonly Dictionary<ulong, ulong> TmpCrc = new Dictionary<ulong, ulong>();
        private void SendChunkFile(ulong? toUserId, FileSystemInfo fileSystemInfo, uint chunkPart)
        {
            if (!fileSystemInfo.Exists)
                return;
            try
            {
                if (fileSystemInfo.Attributes.HasFlag(FileAttributes.Directory))
                {
                    CreateDirectory(toUserId, fileSystemInfo);
                }
                else
                {
                    var hashFileName = fileSystemInfo.HashFileName(this);
                    var tmpFile = GetTmpFile(this, toUserId, hashFileName);
                    ulong crc = default;
                    if (chunkPart == 1)
                    {
                        File.Copy(fileSystemInfo.FullName, tmpFile, true);
                        TmpCrc.Remove(hashFileName);
                    }
                    else
                    {
                        crc = TmpCrc[hashFileName];
                    }
                    //var fileLength = new FileInfo(tmpFile).Length;
                    //uint parts = (uint)Math.Ceiling((double)fileLength / ChunkSize);
                    //parts = parts == 0 ? 1 : parts;

                    var chunk = GetChunk(chunkPart, tmpFile, out var parts, out var fileLength, ref crc);
                    if (chunk == null)
                    {
                        //File send completed;
                        TmpCrc.Remove(hashFileName);
                        File.Delete(tmpFile);
                        TotalFilesSent++;
                        TotalBytesSent += (uint)fileLength;
                        SendingInProgress.Completed(hashFileName, (ulong)toUserId);
                    }
                    else
                    {
                        TmpCrc[hashFileName] = crc;
                        var values = new List<byte[]>(new[] { BitConverter.GetBytes(hashFileName), BitConverter.GetBytes(chunkPart), BitConverter.GetBytes(parts), chunk });
                        if (chunkPart == parts)
                        {
                            values.Add(BitConverter.GetBytes(fileSystemInfo.UnixLastWriteTimestamp()));
                            values.Add(BitConverter.GetBytes((uint)((FileInfo)fileSystemInfo).Length));
                            values.Add(fileSystemInfo.ClaudRelativeUnixFullName(this).GetBytes());
                            values.Add(crc.GetBytes());
                        }
                        RaiseOnFileTransfer(true, hashFileName, chunkPart, parts, fileSystemInfo.FullName, fileLength);
                        SendingInProgress.SetTimeout(hashFileName, chunk.Length);
                        Debug.WriteLine("IN #" + chunkPart + "/" + parts);
                        ExecuteCommand(toUserId, Commands.SendChunkFile, values.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                Debugger.Break();
            }
        }
        public uint TotalFilesSent;
        public uint TotalBytesSent;

        //private void ConfirmChunkReceipt(ulong? toUserId, uint hash, uint chunkPart)
        //{
        //    ExecuteCommand(toUserId, Commands.ConfirmChunkReceipt, new byte[][] { hash.GetBytes(), chunkPart.GetBytes() });
        //}

        private void DeleteFile(ulong? toUserId, ulong hash, uint timestamp)
        {
            ExecuteCommand(toUserId, Commands.DeleteFIle, new[] { hash.GetBytes(), timestamp.GetBytes() });
        }

        private void CreateDirectory(ulong? toUserId, FileSystemInfo fileSystemInfo)
        {
            ExecuteCommand(toUserId, Commands.CreateDirectory, new[] { fileSystemInfo.ClaudRelativeUnixFullName(this).GetBytes() });
        }

        private void DeleteDirectory(ulong? toUserId, FileSystemInfo fileSystemInfo)
        {
            ExecuteCommand(toUserId, Commands.DeleteDirectory, new[] { fileSystemInfo.ClaudRelativeUnixFullName(this).GetBytes() });
        }

        /// <summary>
        /// The slave machine sends a message to indicate if it is ready to receive new commands or if it is busy
        /// </summary>
        /// <param name="toUserId"></param>
        /// <param name="busy"></param>
        internal void StatusNotification(ulong? toUserId, bool busy)
        {
            ExecuteCommand(toUserId, Commands.StatusNotification, new[] { busy ? (byte)0 : (byte)1 });
        }
    }
}
