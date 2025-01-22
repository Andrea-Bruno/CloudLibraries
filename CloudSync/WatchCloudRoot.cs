﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
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
                    pathWatcher.Created += (s, e) =>
                    {
                        if (!Util.CanBeSeen(e.FullPath))
                            return;
                        OnCreated(e.FullPath);
                        RequestSynchronization();
                    };
                    pathWatcher.Changed += (s, e) =>
                    {
                        if (!Util.CanBeSeen(e.FullPath))
                            return;
                        OnChanged(e.FullPath);
                        RequestSynchronization();
                    };
                    pathWatcher.Deleted += (s, e) =>
                    {
                        if (!Util.CanBeSeen(e.FullPath, false))
                            return;
                        OnDeleted(e.FullPath);
                        RequestSynchronization();
                    };
                    pathWatcher.Renamed += (s, e) =>
                    {
                        bool sync = false;
                        if (Util.CanBeSeen(e.OldFullPath, false))
                        {
                            OnDeleted(e.OldFullPath);
                            sync = true;
                        }
                        if (Util.CanBeSeen(e.FullPath))
                        {
                            OnCreated(e.FullPath);
                            sync = true;
                        }
                        if (sync)
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
            if (CacheHashFileTable != null)
            {
                foreach (var item in CacheHashFileTable)
                {
                    if (item.Value.FullName == fileName)
                    {
                        var hash = item.Key;
                        if (DeletedByRemoteRequest.Contains(new FileId(hash, item.Value.UnixLastWriteTimestamp())))
                        {
                            // File deleted by remote request
                        }
                        else
                        {
                            // File deleted locally 
                            FileIdList.AddItem(this, UserId, ScopeType.Deleted, new FileId(hash, item.Value.UnixLastWriteTimestamp()));
                        }
                        return;
                    }
                }
            }
        }

        private void OnCreated(string fileName)
        {
            var fileId = new FileId(fileName, this);
            // The file has been recovered from the recycle bin so there is no need to keep it in the deleted list anymore
            var removed = FileIdList.RemoveItem(this, UserId, ScopeType.Deleted, fileId);
            OnChanged(fileName);
        }

        private void OnChanged(string fileName)
        {
            // Check if the file is in the path reserved for HashFileList
            var cloudCachePath = Path.Combine(CloudRoot, FileIdList.CloudCache);
            if (fileName.StartsWith(cloudCachePath))
            {
                string fileNameWithExtension = Path.GetFileName(fileName);
                string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileNameWithExtension);
                if (ulong.TryParse(fileNameWithoutExtension, NumberStyles.None, CultureInfo.InvariantCulture, out var userId))
                {
                    if (UserId != userId)
                    {
                        // Use the Load method of HashFileList to update the list with the new one
                        FileIdList.Load(this, fileName);
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

        private List<FileId> DeletedByRemoteRequest = new List<FileId>();
        private void AddDeletedByRemoteRequest(FileId fileId)
        {
            DeletedByRemoteRequest.Add(fileId);
            if (DeletedByRemoteRequest.Count > FileIdList.MaxItems)
                DeletedByRemoteRequest.RemoveAt(0);
        }
    }
}
