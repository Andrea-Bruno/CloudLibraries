using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;

namespace CloudSync
{
    /// <summary>
    /// Sync Agent: Offers all the low-level functions to sync the cloud in an encrypted and secure way
    /// </summary>
    public partial class Sync : IDisposable
    {
        private FileSystemWatcher pathWatcher;

        private bool WatchCloudRoot(int maxAttempts = 10)
        {
            int attempts = 0;
            while (attempts < maxAttempts)
            {
                try
                {
                    if (pathWatcher != null)
                    {
                        pathWatcher.EnableRaisingEvents = true;
                        return true;
                    }

                    pathWatcher = new FileSystemWatcher
                    {
                        Path = CloudRoot,
                        NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName |
                                       NotifyFilters.CreationTime,
                        Filter = "*.*",
                        EnableRaisingEvents = true,
                        IncludeSubdirectories = true
                    };
                    pathWatcher.Changed += (s, e) =>
                    {
                        OnChanged(e.FullPath);
                        RequestSynchronization();
                    };
                    pathWatcher.Deleted += (s, e) =>
                    {
                        OnDeleted(e.FullPath);
                        RequestSynchronization();
                    };
                    return true;
                }
                catch (Exception ex)
                {
                    attempts++;
                    Thread.Sleep(1000);
                }
            }

            return false;
        }

        private void StopWatchCloudRoot()
        {
            if (pathWatcher != null)
                pathWatcher.EnableRaisingEvents = false;
        }

        private void OnDeleted(string fileName)
        {
            if (HashFileTable(out var hashDirTable))
            {
                foreach (var item in hashDirTable.ToArray())
                {
                    if (item.Value.Name == fileName)
                    {
                        var hash = item.Key;
                        if (DeletedByRemoteRequest.Contains(hash))
                        {
                            // File deleted by remote request
                        }
                        else
                        {
                            // File deleted locally 
                            HashFileList.AddItem(this, UserId, ScopeType.Deleted, hash);
                        }
                        return;
                    }
                }
            }
        }

        private void OnChanged(string fileName)
        {
            // Check if the file is in the path reserved for HashFileList
            var cloudCachePath = Path.Combine(CloudRoot, HashFileList.CloudCache);
            if (fileName.StartsWith(cloudCachePath))
            {
                string fileNameWithExtension = Path.GetFileName(fileName);
                string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileNameWithExtension);
                if (ulong.TryParse(fileNameWithoutExtension, NumberStyles.None, CultureInfo.InvariantCulture, out var userId))
                {
                    if (UserId!= userId)
                    {
                        // Use the Load method of HashFileList to update the list with the new one
                        HashFileList.Load(this, fileName);
                    }
                }
            }
        }

        /// <summary>
        /// This function starts the synchronization request, called this function a timer will shortly launch the synchronization.
        /// Synchronization requests are called whenever the system detects a file change, at regular times very far from a timer(the first method is assumed to be sufficient and this is just a check to make sure everything is in sync), or if the previous sync failed the timer with more frequent intervals will try to start the sync periodically.
        /// </summary>
        public void RequestSynchronization()
        {
            RestartCheckSyncTimer();
            try
            {
                SyncTimeBuffer?.Change(SyncTimeBufferMs, Timeout.Infinite);
            }
            catch
            {
                // is disposed
            }
        }

        private List<ulong> DeletedByRemoteRequest = new List<ulong>();
        private void AddDeletedByRemoteRequest(ulong hashFile)
        {
            DeletedByRemoteRequest.Add(hashFile);
            if (DeletedByRemoteRequest.Count > HashFileList.MaxItems)
                DeletedByRemoteRequest.RemoveAt(0);
        }
    }
}
