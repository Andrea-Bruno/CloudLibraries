using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace CloudSync
{
    /// <summary>
    /// Class that controls file transfer in progress and timeout of the operation
    /// </summary>
    public class ProgressFileTransfer : IDisposable
    {
        public ProgressFileTransfer(Sync context)
        {
            Context = context;
        }
        private readonly Sync Context;
        private readonly Dictionary<ulong, DateTime> TimeoutChunkFileToTransfer = new Dictionary<ulong, DateTime>();
        /// <summary>
        /// Property indicating the number of file transfers currently in progress
        /// </summary>
        public int TransferInProgress
        {
            get
            {
                RemoveOverTimeout();
                return TimeoutChunkFileToTransfer.Count;
            }
        }
        /// <summary>
        /// Counter that indicates how many transfers have failed (timeout failure could indicate an unsuitable data line or no connection)
        /// </summary>
        public int FailedByTimeout { get; private set; }

        /// <summary>
        /// Method that is called when the file transfer has completed
        /// </summary>
        /// <param name="hashFileName">Hash file</param>
        /// <param name="userId">Target user ID</param>
        /// <param name="executeNext">If true, then execute the next operation in spooler</param>
        public void Completed(ulong hashFileName, ulong? userId = null, bool executeNext = true)
        {
            lock (TimeoutChunkFileToTransfer)
                if (TimeoutChunkFileToTransfer.ContainsKey(hashFileName))
                {
                    TimeoutChunkFileToTransfer.Remove(hashFileName);
                }
                else
                {
                    if (!Context.IsServer)
                        Debugger.Break();
                }
            if (executeNext)
                Context.Spooler.ExecuteNext(userId);
        }
        /// <summary>
        /// When file transfer starts, this method sets the timeout. When the timeout expires, the transfer will be considered failed.
        /// </summary>
        /// <param name="hashFileName">Hasfile</param>
        /// <param name="chunkLength">Length of data to send</param>
        public void SetTimeout(ulong hashFileName, int chunkLength = Util.DefaultChunkSize)
        {
            var timeout = Util.DataTransferTimeOut(chunkLength).Add(TimeSpan.FromMilliseconds(Context.HashFileTableElapsedMs));
            lock (TimeoutChunkFileToTransfer)
                TimeoutChunkFileToTransfer[hashFileName] = DateTime.UtcNow.Add(timeout);
            var TimerReference = new TimerReference();
            var timer = new Timer(obj => { Timers.Remove(((TimerReference)obj).Timer); RemoveOverTimeout(); }, TimerReference, (int)timeout.TotalMilliseconds + 1000, Timeout.Infinite);
            TimerReference.Timer = timer;
            Timers.Add(timer);
        }
        private readonly List<Timer> Timers = new List<Timer>();
        private class TimerReference { public Timer Timer; }

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
                    result = Convert.ToInt32((expire - DateTime.UtcNow).TotalSeconds) + " sec.";
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

        /// <summary>
        /// Dispose the instance of the object
        /// </summary>
        public void Dispose()
        {
            Timers.ToList().ForEach(timer => { timer.Change(Timeout.Infinite, Timeout.Infinite); timer.Dispose(); });
        }
    }
}
