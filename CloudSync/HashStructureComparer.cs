using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

using FileHashToLastWriteTable = System.Collections.Generic.Dictionary<ulong, uint>;


namespace CloudSync
{
    public static class HashStructureComparer
    {
        /// <summary>
        /// Compares a remote hash table with the local hash table and schedules synchronization operations.
        /// </summary>
        /// <remarks>
        /// This method analyzes differences between the provided remote hash-to-timestamp dictionary and
        /// the local hash file table, and enqueues the required operations into the client's spooler to
        /// bring the two sides into sync. Typical actions include requesting missing files from the remote,
        /// sending local files that are absent remotely, deleting files or directories remotely that were
        /// locally deleted, and resolving conflicts by comparing last-write timestamps. The method also
        /// takes into account temporary and persistent deletion tracking so that deletions are not
        /// inadvertently propagated back and forth. Any exceptions are recorded and a debugger break is
        /// triggered for investigation in debug scenarios. At the end of processing the temporary deleted
        /// dictionary is cleared.
        /// </remarks>
        /// <param name="context">Synchronization context providing access to client toolkit, spooler and state.</param>
        /// <param name="remoteHashes">Dictionary mapping file/directory hash (ulong) to UNIX last-write timestamp (uint). A timestamp of zero typically denotes a directory.</param>
        /// <param name="localHashes">Local hash file table representing known files and directories on disk.</param>
        /// <param name="isServerRequest">If true, indicates the hash structure was initiated by the server (for example after an API client modified server-side files) rather than by a client request.</param>
        public static void Compare(Sync context, FileHashToLastWriteTable remoteHashes, HashFileTable localHashes, bool isServerRequest)
        {
            if (context?.ClientToolkit?.Spooler.IsPending == true)
            {
                context?.ClientToolkit?.Spooler.SpoolerRun();
                return;
            }
            try
            {
                var toRemove = new List<ulong>();

                // Remove unnecessary directory to server
                // The TemporaryDeletedHashFileDictionary dictionary contains the locally deleted items
                List<string> deletedDirectories = new List<string>();
                foreach (var hash in remoteHashes.Keys)
                {
                    if (!localHashes.TryGetValue(hash, out var _))
                    {
                        uint timeStamp = remoteHashes[hash];
                        var isDirectory = timeStamp == default;
                        if (isDirectory)
                        {
                            if (context.ClientToolkit?.TemporaryDeletedHashFileDictionary.TryGetValue(hash, out string? dirName) == true)
                            {
                                toRemove.Add(hash);
                                deletedDirectories.Add(dirName + Path.DirectorySeparatorChar);
                                context.ClientToolkit?.Spooler.AddOperation(Spooler.OperationType.DeleteDirectory, hash);
                            }
                        }
                    }
                }

                //Update file
                foreach (var hash in remoteHashes.Keys)
                {
                    if (localHashes.TryGetValue(hash, out var dateTime))
                    {
                        var remoteDate = remoteHashes[hash];
                        var localDate = dateTime.UnixLastWriteTimestamp();
                        if (remoteDate > localDate)
                        {
                            context.ClientToolkit?.Spooler.AddOperation(Spooler.OperationType.RequestFile, hash, remoteDate);
                        }
                        else if (remoteDate < localDate)
                        {
                            context.ClientToolkit?.Spooler.AddOperation(Spooler.OperationType.SendFile, hash, localDate);
                        }
                    }
                    else
                    {
                        // Remove unnecessary file to server
                        uint timeStamp = remoteHashes[hash];
                        var isFile = timeStamp != default;
                        if (isFile)
                        {
                            var isInDeletedDirectory = false;
                            var isDeletedFile = false;
                            if (context.ClientToolkit?.TemporaryDeletedHashFileDictionary.TryGetValue(hash, out string? fileName) == true)
                            {
                                //  isInDeletedDirectory = deletedDirectories.Exists(x => fileName.StartsWith(x));
                                isInDeletedDirectory = false;

                                foreach (var path in deletedDirectories)
                                {
                                    if (fileName.StartsWith(path))
                                    {
                                        isInDeletedDirectory = true;
                                        break;
                                    }
                                }

                            }
                            if (!isDeletedFile)
                                isDeletedFile = (context.ClientToolkit?.PersistentDeletedFileListContains(FileId.GetFileId(hash, timeStamp)) == true);
                            if (isDeletedFile)
                            {
                                toRemove.Add(hash);
                                if (!isInDeletedDirectory) // Deleting the directory will also delete the file
                                    context.ClientToolkit?.Spooler.AddOperation(Spooler.OperationType.DeleteFile, hash, timeStamp);
                            }
                        }
                    }
                }

                toRemove.ForEach(x => remoteHashes.Remove(x)); //Remove files and directories scheduled for deletion from the server list

                // Operations for missing files on the server
                foreach (var element in localHashes.KeyTimestampCollection())
                {
                    if (!remoteHashes.ContainsKey(element.Key))
                    {
                        if (isServerRequest)
                        {
                            //Files are missing because they have been deleted from the server. Sync must therefore delete these files from the local server.
                            try
                            {
                                var ts = element.UnixLastWriteTimestamp;
                                var isDir = ts == default;
                                if (isDir)
                                {
                                    // Delete local directory by hash
                                    context?.DeleteDirectory(element.Key);
                                }
                                else
                                {
                                    // Delete local file by hash and timestamp
                                    context?.DeleteFile(element.Key, ts);
                                }
                            }
                            catch (Exception ex)
                            {
                                Util.RecordError(ex);
                            }
                        }
                        else
                        {
                            // Send missing files to the remote and create directory if it does not exist
                            context.ClientToolkit?.Spooler.AddOperation(Spooler.OperationType.SendFile, element.Key, element.UnixLastWriteTimestamp);
                        }
                    }
                }

                // Request missing files locally
                foreach (var hash in remoteHashes.Keys)
                {
                    var timestamp = remoteHashes[hash];
                    var wasDeleted = context.ClientToolkit?.FileWasDeletedLocally(new FileId(hash, timestamp)) == true;
                    if (!localHashes.ContainsKey(hash) && (!wasDeleted || isServerRequest))
                    {
                        context.ClientToolkit?.Spooler.AddOperation(Spooler.OperationType.RequestFile, hash, timestamp);
                    }
                }

            }
            catch (Exception ex)
            {
                Util.RecordError(ex);
                Debugger.Break(); // Error! Investigate the cause of the error!
                Debug.WriteLine(ex);
            }
            context.ClientToolkit?.TemporaryDeletedHashFileDictionary.Clear();
        }
    }
}
