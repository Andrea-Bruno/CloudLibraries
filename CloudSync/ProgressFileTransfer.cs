using System;
using System.Collections.Generic;

namespace CloudSync
{
    public class ProgressFileTransfer : IDisposable
    {
        private readonly Dictionary<ulong, DateTime> TimeoutChunkFileToTransfer = [];

        /// <summary>
        /// Returns the number of ongoing file transfers
        /// </summary>
        public int TransferInProgress
        {
            get
            {
                RemoveOverTimeout(); // Ensure expired transfers are cleaned up
                return TimeoutChunkFileToTransfer.Count;
            }
        }

        /// <summary>
        /// Number of transfers failed due to timeout
        /// </summary>
        public int FailedByTimeout
        {
            get
            {
                RemoveOverTimeout(); // Ensure expired transfers are accounted for
                return _failedByTimeout;
            }
        }
        private int _failedByTimeout = 0;

        /// <summary>
        /// Mark a file transfer as completed and remove its timeout entry
        /// </summary>
        public void Completed(ulong hashFileName, ulong? userId = null, bool executeNext = true)
        {
            lock (TimeoutChunkFileToTransfer)
            {
                TimeoutChunkFileToTransfer.Remove(hashFileName);
            }
        }

        /// <summary>
        /// Set the timeout for a new file transfer operation
        /// </summary>
        public void SetTimeout(ulong hashFileName, int chunkLength = Util.DefaultChunkSize)
        {
            var timeout = Util.DataTransferTimeOut(chunkLength);
            lock (TimeoutChunkFileToTransfer)
            {
                TimeoutChunkFileToTransfer[hashFileName] = DateTime.UtcNow.Add(timeout);
            }
        }

        /// <summary>
        /// Remove all file transfers that exceeded their timeout limit
        /// </summary>
        private void RemoveOverTimeout()
        {
            var expiredKeys = new List<ulong>();

            lock (TimeoutChunkFileToTransfer)
            {
                foreach (var kvp in TimeoutChunkFileToTransfer)
                {
                    if (DateTime.UtcNow >= kvp.Value)
                    {
                        expiredKeys.Add(kvp.Key);
                        _failedByTimeout++;
                    }
                }

                // Remove expired entries from the dictionary
                foreach (var key in expiredKeys)
                {
                    TimeoutChunkFileToTransfer.Remove(key);
                }
            }
        }

        /// <summary>
        /// Returns a descriptive information specifying time remaining for operations in progress
        /// </summary>
        public string TimeOutInfo()
        {
            string result = null;
            RemoveOverTimeout();
            lock (TimeoutChunkFileToTransfer)
                foreach (var expire in TimeoutChunkFileToTransfer.Values)
                {
                    if (result != null)
                        result += ", ";
                    result += Convert.ToInt32((expire - DateTime.UtcNow).TotalSeconds) + " sec.";
                }
            return result ?? "No transfer in progress";
        }

        /// <summary>
        /// Stop all active transfers
        /// </summary>
        public void Stop()
        {
            lock (TimeoutChunkFileToTransfer)
            {
                TimeoutChunkFileToTransfer.Clear();
            }
        }

        /// <summary>
        /// Dispose the instance of the object
        /// </summary>
        public void Dispose()
        {
            TimeoutChunkFileToTransfer.Clear();
        }
    }
}
