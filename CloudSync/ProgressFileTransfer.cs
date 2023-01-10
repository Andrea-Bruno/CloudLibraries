using System;
using System.Collections.Generic;
using System.Threading;

namespace CloudSync
{
    public class ProgressFileTransfer
    {
        public ProgressFileTransfer(Sync context)
        {
            Context = context;
        }
        private readonly Sync Context;
        private readonly Dictionary<ulong, DateTime> TimeoutChunkFileToTransfer = new Dictionary<ulong, DateTime>();
        public int TransferInProgress()
        {
            RemoveOverTimeout();
            return TimeoutChunkFileToTransfer.Count;
        }

        public int FailedByTimeout { get; private set; }

        public void Completed(ulong hashFileName, ulong? userId = null, bool executeNext = true)
        {
            lock (TimeoutChunkFileToTransfer)
                if (TimeoutChunkFileToTransfer.ContainsKey(hashFileName))
                {
                    TimeoutChunkFileToTransfer.Remove(hashFileName);
                }
            if (executeNext)
                Context.Spooler.ExecuteNext(userId);
        }
        public void SetTimeout(ulong hashFileName, int chunkLength = Util.DefaultChunkSize)
        {
            var timeout = Util.DataTransferTimeOut(chunkLength);
            lock (TimeoutChunkFileToTransfer)
                TimeoutChunkFileToTransfer[hashFileName] = DateTime.UtcNow.Add(timeout);
            new Timer(obj => RemoveOverTimeout(), null, (int)timeout.TotalMilliseconds + 1000, Timeout.Infinite);
        }

        /// <summary>
        /// Returns a descriptive information that specifies how long it is to timeout for operations in progress
        /// </summary>
        /// <returns>How long before the timeout (description)</returns>
        public string TimeOutInfo()
        {
            string result = null;
            RemoveOverTimeout();
            lock (TimeoutChunkFileToTransfer)
                foreach (var expire in TimeoutChunkFileToTransfer.Values)
                {
                    result = Convert.ToInt32((expire - DateTime.UtcNow).TotalSeconds) + "sec. ";
                }
            return result ?? "No transfer in progress";
        }
        private void RemoveOverTimeout()
        {
            var expired = new List<ulong>();
            lock (TimeoutChunkFileToTransfer)
                foreach (var key in TimeoutChunkFileToTransfer.Keys)
                {
                    if (DateTime.UtcNow >= TimeoutChunkFileToTransfer[key])
                    {
                        expired.Add(key);
                        FailedByTimeout++;
                    }
                }
            foreach (var key in expired)
                Completed(key, executeNext: key == expired[expired.Count - 1]);
        }
    }
}
