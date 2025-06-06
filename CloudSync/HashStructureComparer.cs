using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

using FileHashToLastWriteTable = System.Collections.Generic.Dictionary<ulong, uint>;


namespace CloudSync
{
    public static class HashStructureComparer
    {
        public static void Compare(Sync context, FileHashToLastWriteTable remoteHashes, HashFileTable localHashes)
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


                // Send missing files to the remote create directory if it does not exist
                foreach (var element in localHashes.KeyTimestampCollection())
                {
                    if (!remoteHashes.ContainsKey(element.Key))
                    {
                        context.ClientToolkit?.Spooler.AddOperation(Spooler.OperationType.SendFile, element.Key, element.UnixLastWriteTimestamp);
                    }
                }

                // Request missing files locally
                foreach (var hash in remoteHashes.Keys)
                {
                    var timestamp = remoteHashes[hash];
                    var wasDeleted = context.ClientToolkit?.FileWasDeletedLocally(new FileId(hash, timestamp)) == true;
                    if (!localHashes.ContainsKey(hash) && !wasDeleted)
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
