using System.Collections.Generic;
using System.IO;

namespace CloudSync
{
    /// <summary>
    /// Utility to keep the computation of the progressive CRC in memory during file transfer.
    /// The CRC is computed for each chunk, and is updated considering the CRC of the previously received chunk.
    /// If a file transfer is resumed from a previously interrupted transfer, the CRC is recomputed for all chunks received and saved in the temporary receive file.
    /// </summary>
    static internal class CRC
    {
        public const ulong StartCRC = 2993167723948948793u;
        /// <summary>
        /// Update CRC when chunk is added, or when a file transfer is restored
        /// </summary>
        /// <param name="hashFileName"></param>
        /// <param name="part"></param>
        /// <param name="data">The chunk received, or null if a previously interrupted transfer is to be recovered.</param>
        /// <param name="restoreParts">Returns 0 if no aborted transfer is recovered, otherwise the number of chunks recovered</param>
        /// <param name="tmpFile"></param>
        /// <param name="firstChunkData"></param>
        /// <returns></returns>
        public static bool Update(ulong? userID, ulong hashFileName, ref uint part, byte[] data, string tmpFile, bool tryRestore, out bool isRestored, byte[] firstChunkData = null)
        {
            isRestored = false;
            PartialCRC partialCRC;
            if (part == 1 && tmpFile != null && tryRestore)
            {
                var oldDownload = new FileInfo(tmpFile);
                if (oldDownload.Exists)
                {
                    if ((oldDownload.Length % data.LongLength) == 0)
                    {
                        var restoreParts = (uint)(oldDownload.Length / data.LongLength);
                        if (TmpCRCs(userID).TryGetValue(hashFileName, out partialCRC))
                        {
                            if (restoreParts == partialCRC.LastPart)
                            {
                                part = restoreParts;
                                isRestored = true;
                                return true;
                            }
                        }
                        if (File.Exists(tmpFile) && ComputingCRC(tmpFile, out ulong CRC, 0, data.Length, firstChunkData))
                        {
                            TmpCRCs(userID)[hashFileName] = new PartialCRC()
                            {
                                LastPart = restoreParts,
                                TempCRC = CRC,
                            };
                            part = restoreParts;
                            isRestored = true;
                            return true;
                        }
                    }
                }
                if (oldDownload.Exists)
                {
                    oldDownload.Delete();
                }
            }

            if (part == 1)
            {
                partialCRC = new PartialCRC();
                TmpCRCs(userID)[hashFileName] = partialCRC;
            }
            else if (TmpCRCs(userID).TryGetValue(hashFileName, out partialCRC))
            {
                if (partialCRC.LastPart != part - 1)
                {
                    // The remote machine has resumed a previous file transfer
                    if (ComputingCRC(tmpFile, out var CRC, part))
                    {
                        partialCRC.LastPart = part;
                        partialCRC.TempCRC = CRC;
                        isRestored = true;
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            else
            {
                return false;
            }
            partialCRC.LastPart = part;
            partialCRC.TempCRC = Util.ULongHash(partialCRC.TempCRC, data);
            return true;
        }

        /// <summary>
        /// Computing CRC
        /// </summary>
        /// <param name="CRC">Current CRC</param>
        /// <param name="data">Chunk</param>
        /// <returns></returns>
        public static ulong ComputingCRC(ulong CRC, byte[] data)
        {
            return Util.ULongHash(CRC, data);
        }

        public static ulong GetCRC(ulong? userID, ulong hashFileName, uint part)
        {
            if (TmpCRCs(userID).TryGetValue(hashFileName, out var crc))
            {
                if (crc.LastPart == part)
                    return crc.TempCRC;
            }
            return 0;
        }

        public static void RemoveCRC(ulong? userID, ulong hashFileName)
        {
            TmpCRCs(userID).Remove(hashFileName);
        }

        /// <summary>
        /// Computes the CRC of a temporary receive file, when the transfer is resumed from a previously interrupted one
        /// If a file transfer is resumed from a previously interrupted transfer, the CRC is recomputed for all chunks received and saved in the temporary receive file.
        /// </summary>
        /// <param name="file">The file to compute the CRC</param>
        /// <param name="chunkSize">The size of the block</param>
        /// <param name="CRC">The partial CRC of the file</param>
        /// <param name="firstChunkData">The first block if you want to check this data</param>
        /// <returns>True if file recovery allowed partial CRC to be computed correctly</returns>
        public static bool ComputingCRC(string file, out ulong CRC, uint toChunkPart = 0, int chunkSize = Util.DefaultChunkSize, byte[] firstChunkData = null)
        {
            CRC = StartCRC;
            byte[] buffer = new byte[chunkSize]; // 5MB in bytes is 5 * 2^20
            uint parts = 0;
            using (var steam = new FileStream(file, FileMode.Open))
            {
                while (steam.Position < steam.Length)
                {
                    steam.Read(buffer, 0, buffer.Length);
                    CRC = Util.ULongHash(CRC, buffer);
                    if (parts == 0 && firstChunkData != null)
                    {
                        if (!firstChunkData.SequenceEqual(buffer))
                        {
                            return false;
                        }
                    }
                    parts++;
                    if (parts == toChunkPart)
                        return true;
                }
            }
            return toChunkPart == 0 || parts == toChunkPart;
        }

        private static Dictionary<ulong, Dictionary<ulong, PartialCRC>> _CollectionOfTmpCRCs = [];

        private static Dictionary<ulong, PartialCRC> TmpCRCs(ulong? userID)
        {
            lock (_CollectionOfTmpCRCs)
            {
                if (_CollectionOfTmpCRCs.TryGetValue(userID == null ? 0 : (ulong)userID, out var value))
                {
                    return value;
                }
                value = [];
                _CollectionOfTmpCRCs.Add(userID == null ? 0 : (ulong)userID, value);
                return value;
            }
        }

        class PartialCRC
        {
            public uint LastPart;
            public ulong TempCRC = StartCRC;
        }

    }

}