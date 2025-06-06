using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;

namespace CloudSync
{
    /// <summary>
    /// Utility class for computing progressive CRC values during file transfers.
    /// Maintains CRC state in memory during transfer and supports resuming interrupted transfers.
    /// </summary>
    static internal class CRC
    {
        /// <summary>
        /// Initial CRC value used as a starting point for computation
        /// </summary>
        public const ulong StartCRC = 2993167723948948793u;

        /// <summary>
        /// Thread-safe dictionary to store temporary CRC states for concurrent file transfers
        /// Key: Unique identifier combining client/file information
        /// Value: PartialCRC object tracking progress
        /// </summary>
        private static ConcurrentDictionary<ulong, PartialCRC> TmpCRCs = new();

        /// <summary>
        /// Generates a unique key for the CRC dictionary based on transfer parameters
        /// </summary>
        /// <param name="isClient">True if the caller is a client</param>
        /// <param name="toClientId">Destination client ID (null for server-to-server)</param>
        /// <param name="hashFileName">Hash of the filename being transferred</param>
        /// <returns>Unique key for the CRC dictionary</returns>
        private static ulong CrcKey(bool isClient, ulong? toClientId, ulong hashFileName)
        {
            if (isClient)
                toClientId = 0UL; // Clients use 0 as client ID to prevent collisions

#if DEBUG
            // Debug-only check to ensure servers always specify client ID
            else if (toClientId == null)
            {
                Debugger.Break(); // Server must set toClientId value
            }
#endif

            return (ulong)toClientId ^ hashFileName; // Combine IDs for unique key
        }

        /// <summary>
        /// Updates the CRC state with a new chunk of data or restores from interrupted transfer
        /// </summary>
        /// <param name="isClient">True if called by client</param>
        /// <param name="toClientId">Destination client ID</param>
        /// <param name="hashFileName">Hash of the filename</param>
        /// <param name="part">Current chunk number (1-based)</param>
        /// <param name="chunkData">Data for current chunk</param>
        /// <param name="transmittedFile">Path to temporary file being received</param>
        /// <param name="tryRestore">True to attempt recovery of interrupted transfer</param>
        /// <param name="isRestored">Output: True if recovery was successful</param>
        /// <param name="firstChunkData">Optional first chunk data for verification</param>
        /// <returns>True if operation succeeded, false otherwise</returns>
        public static bool Update(bool isClient, ulong? toClientId, ulong hashFileName, ref uint part,
                                byte[] chunkData, string transmittedFile, bool tryRestore,
                                out bool isRestored, byte[] firstChunkData = null)
        {
            var crcKey = CrcKey(isClient, toClientId, hashFileName);
            isRestored = false;
            PartialCRC? partialCRC;

            // Attempt to restore from interrupted transfer if requested
            if (tryRestore)
            {
                var oldDownload = part == 1 ? new FileInfo(transmittedFile) : null;
                if (oldDownload?.Exists == true)
                {
                    // Verify existing file matches expected chunk size
                    if (chunkData != null && chunkData.LongLength > 0 && (oldDownload.Length % chunkData.LongLength) == 0)
                    {
                        var restoreParts = (uint)(oldDownload.Length / chunkData.LongLength);

                        // Check if we already have CRC state for this file
                        if (TmpCRCs.TryGetValue(crcKey, out partialCRC))
                        {
                            if (restoreParts == partialCRC.LastPart)
                            {
                                part = restoreParts;
                                isRestored = true;
                                return true;
                            }
                        }

                        // Compute CRC from existing file if no state exists
                        if (File.Exists(transmittedFile) &&
                            ComputingCRC(transmittedFile, out ulong CRC, 0, chunkData.Length, firstChunkData))
                        {
                            TmpCRCs[crcKey] = new PartialCRC()
                            {
                                LastPart = restoreParts,
                                TempCRC = CRC,
                            };
                            part = restoreParts;
                            isRestored = true;
                            return true;
                        }
                    }
                    oldDownload.Delete(); // Clean up invalid partial file
                }
            }

            // Handle new chunk processing
            if (part == 1)
            {
                // Initialize new CRC state for first chunk
                partialCRC = new PartialCRC();
                TmpCRCs[crcKey] = partialCRC;
            }
            else if (TmpCRCs.TryGetValue(crcKey, out partialCRC))
            {
                // Verify chunk sequence is correct
                if (partialCRC.LastPart != part - 1)
                {
                    // If chunks are out of sequence, try to recompute from file
                    if (ComputingCRC(transmittedFile, out var CRC, part))
                    {
                        partialCRC.LastPart = part;
                        partialCRC.TempCRC = CRC;
                        isRestored = true;
                        return true;
                    }
                    else
                    {
                        return false; // Recovery failed
                    }
                }
            }
            else
            {
                Debugger.Break(); // CRC state missing unexpectedly
                return false;
            }

            // Update CRC with new chunk data
            partialCRC.LastPart = part;
            partialCRC.TempCRC = Util.ULongHash(partialCRC.TempCRC, chunkData);
            return true;
        }

        /// <summary>
        /// Computes CRC for a byte array using the current CRC as starting point
        /// </summary>
        /// <param name="CRC">Current CRC value</param>
        /// <param name="data">Data to include in computation</param>
        /// <returns>Updated CRC value</returns>
        public static ulong ComputingCRC(ulong CRC, byte[] data)
        {
            return Util.ULongHash(CRC, data);
        }

        /// <summary>
        /// Retrieves the stored CRC value for a specific transfer
        /// </summary>
        /// <param name="isClient">True if called by client</param>
        /// <param name="toClientId">Destination client ID</param>
        /// <param name="hashFileName">Hash of the filename</param>
        /// <param name="part">Chunk number to verify</param>
        /// <returns>Stored CRC value or 0 if not found</returns>
        public static ulong GetCRC(bool isClient, ulong? toClientId, ulong hashFileName, uint part)
        {
            if (TmpCRCs.TryGetValue(CrcKey(isClient, toClientId, hashFileName), out var crc))
            {
                if (crc.LastPart == part)
                    return crc.TempCRC;
            }
            return 0;
        }

        /// <summary>
        /// Removes temporary CRC state for a completed or abandoned transfer
        /// </summary>
        /// <param name="isClient">True if called by client</param>
        /// <param name="toClientId">Destination client ID</param>
        /// <param name="hashFileName">Hash of the filename</param>
        public static void RemoveCRC(bool isClient, ulong? toClientId, ulong hashFileName)
        {
            TmpCRCs.TryRemove(CrcKey(isClient, toClientId, hashFileName), out _);
        }

        /// <summary>
        /// Computes CRC for a file by processing it in chunks
        /// </summary>
        /// <param name="file">Path to file to process</param>
        /// <param name="CRC">Output: Computed CRC value</param>
        /// <param name="toChunkPart">Stop after processing this many chunks (0 for entire file)</param>
        /// <param name="chunkSize">Size of each chunk</param>
        /// <param name="firstChunkData">Optional verification data for first chunk</param>
        /// <returns>True if computation succeeded, false otherwise</returns>
        public static bool ComputingCRC(string file, out ulong CRC, uint toChunkPart = 0,
                                       int chunkSize = Util.DefaultChunkSize, byte[] firstChunkData = null)
        {
            CRC = StartCRC;
            byte[] buffer = new byte[chunkSize];
            uint parts = 0;

            using (var fileStream = new FileStream(file, FileMode.Open))
            using (var stream = fileStream)
            {
                while (stream.Position < stream.Length)
                {
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);

                    // Verify first chunk if verification data provided
                    if (parts == 0 && firstChunkData != null)
                    {
                        if (!firstChunkData.SequenceEqual(buffer))
                        {
                            return false;
                        }
                    }

                    CRC = Util.ULongHash(CRC, buffer);
                    parts++;

                    // Early exit if we've reached target chunk
                    if (parts == toChunkPart)
                        return true;
                }
            }

            // Verify we processed expected number of chunks
            return toChunkPart == 0 || parts == toChunkPart;
        }

        /// <summary>
        /// Tracks partial CRC computation state for a file transfer
        /// </summary>
        private class PartialCRC
        {
            /// <summary>
            /// Last successfully processed chunk number
            /// </summary>
            public uint LastPart;

            /// <summary>
            /// Current CRC value
            /// </summary>
            public ulong TempCRC = StartCRC;
        }
    }
}