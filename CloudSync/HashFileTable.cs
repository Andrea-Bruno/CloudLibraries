using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Timers;

namespace CloudSync
{
    public class HashFileTable : IEnumerable<KeyValuePair<ulong, FileSystemInfo>>
    {
        public HashFileTable(Sync context, LoadMode loadMode)
        {
            Context = context;

            var idRoot = BitConverter.ToUInt16(Util.Hash256(context.CloudRoot.GetBytes())).ToString("X4");
            filePath = context.UserId + "_" + idRoot + "." + nameof(HashFileTable);
            context.RaiseOnStatusChangesEvent(Sync.SyncStatus.Analysing);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                SetNotContentIndexedRecursively(context.CloudRoot);
            }

            if (loadMode == LoadMode.LoadFormFile)
            {
                DeserializeFromDisk();
            }
            else if (loadMode == LoadMode.Regenerate)
            {
                Regenerate(new DirectoryInfo(Context.CloudRoot));
            }
            context.RaiseOnStatusChangesEvent(Sync.SyncStatus.Active);
        }

        public enum LoadMode
        {
            LoadFormFile,
            Regenerate,
        }

        public bool LoadFailure { get; private set; }

        /// <summary>
        /// For privacy, indexing is disabled. In addition, it creates file change events, which can interfere with the proper functioning of the application.
        /// </summary>
        /// <param name="directoryPath"></param>
        private static void SetNotContentIndexedRecursively(string directoryPath)
        {
            DirectoryInfo dirInfo = new DirectoryInfo(directoryPath);
            if (!dirInfo.Attributes.HasFlag(FileAttributes.NotContentIndexed))
            {
                dirInfo.Attributes |= FileAttributes.NotContentIndexed;
                foreach (var subDir in dirInfo.GetDirectories())
                {
                    SetNotContentIndexedRecursively(subDir.FullName);
                }
            }
        }

        private void Regenerate(DirectoryInfo directory)
        {
            var watcher = new FileSystemWatcher();
            var notifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.FileName | NotifyFilters.DirectoryName;
            watcher = new FileSystemWatcher
            {
                Path = Context.CloudRoot,
                NotifyFilter = notifyFilter,
                Filter = "*.*",
                EnableRaisingEvents = true,
                IncludeSubdirectories = true
            };
            watcher.Created += (s, e) => { ResetIsRequired = true; Add(e.FullPath); };
            watcher.Changed += (s, e) => { ResetIsRequired = true; Add(e.FullPath); };
            watcher.Deleted += (s, e) => HasChanged = true;
            watcher.Renamed += (s, e) => HasChanged = true;
            do
            {
                ResetIsRequired = false;
                HasChanged = false;
                LoadFailure = false;
                AnalyzeDirectory(new DirectoryInfo(Context.CloudRoot));
                if (HasChanged)
                    System.Threading.Thread.Sleep(1000);

            } while (HasChanged && !Context.Disposed);
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }

        /// <summary>
        /// While indexing was being performed, disk operations were in progress and a hash table rebuild (reset) was required.
        /// </summary>
        public bool ResetIsRequired;

        /// <summary>
        /// While creating the hash table, a disk operation required repeating the indexing
        /// </summary>
        private bool HasChanged;

        private bool AnalyzeDirectory(DirectoryInfo directory)
        {
            try
            {
                Add(directory);
                foreach (var fileSystemInfo in directory.GetFileSystemInfos())
                {
                    if (Context.Disposed || HasChanged)
                        return false;
                    if (fileSystemInfo is DirectoryInfo dirInfo)
                    {
                        if (Util.CanBeSeen(fileSystemInfo))
                        {
                            AnalyzeDirectory(dirInfo);
                        }
                    }
                    else  // Id a FIle
                    {
                        Add(fileSystemInfo);
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                LoadFailure = true;
                Debugger.Break();
                Context.RaiseOnFileError(ex, directory.FullName);
            }
            return false;
        }

        public long UsedSpace { get; private set; }

        /// <summary>
        /// Dictionary that associates the hash with the FullNameFile
        /// </summary>
        private Dictionary<ulong, FileData> Dictionary = [];
        private readonly struct FileData
        {
            public readonly string FullName;
            public readonly uint UnixLastWriteTimestamp;
            public readonly long AllocatedStorageSize;

            public FileData(FileSystemInfo fileSystemInfo)
            {
                FullName = fileSystemInfo.FullName;
                AllocatedStorageSize = fileSystemInfo.GetAllocatedStorageSize();
                if (fileSystemInfo is FileInfo fileInfo)
                {
                    UnixLastWriteTimestamp = fileInfo.UnixLastWriteTimestamp();
                }
                else
                {
                    UnixLastWriteTimestamp = default; // Directories do not have a last write timestamp
                }
            }

            public FileData(string fullName, uint unixLastWriteTimestamp, long size)
            {
                FullName = fullName;
                UnixLastWriteTimestamp = unixLastWriteTimestamp;
                AllocatedStorageSize = size;
            }
        }

        public bool AutoSave
        {
            get
            {
                return unloadTimer != null;
            }
            set
            {
                if (value)
                {
                    if (unloadTimer == null)
                    {
                        var saveTimeSpan = Context.IsServer ? TimeSpan.FromMinutes(4) : TimeSpan.FromSeconds(15);
                        unloadTimer = new Timer(saveTimeSpan);
                        unloadTimer.Elapsed += (sender, e) => SerializeToDisk();
                        unloadTimer.AutoReset = false; // Ensure the timer only triggers once unless restarted
                    }
                }
                else
                {
                    unloadTimer?.Stop();
                    unloadTimer?.Dispose();
                    unloadTimer = null;
                }
            }
        }

        private readonly string filePath;
        private Timer? unloadTimer;

        private readonly Sync Context;
        // Property to get the number of items in the dictionary
        public int Count
        {
            get
            {
                lock (this)
                {
                    EnsureDictionaryLoaded(); // Load the dictionary before locking
                    return Dictionary.Count;
                }
            }
        }

        // Property to get all keys in the dictionary
        public IEnumerable<ulong> Keys
        {
            get
            {
                lock (this)
                {
                    EnsureDictionaryLoaded(); // Load the dictionary before locking
                    return [.. Dictionary.Keys]; // Return a copy of the keys to avoid external modification
                }
            }
        }

        // Indexer to allow hashFileTable[key] = value syntax
        public FileSystemInfo this[ulong key]
        {
            get
            {
                return Get(key); // Retrieve the value using the Get method
            }
            set
            {
                Add(key, value); // Add or update the value using the Add method
            }
        }


        /// <summary>
        /// Ad a file to collection and update the Used Space size
        /// </summary>
        /// <param name="key"></param>
        /// <param name="fileInfo"></param>
        private void Add(ulong key, FileSystemInfo fileInfo)
        {
#if DEBUG
            if (!fileInfo.Exists)
                Debugger.Break(); // The file does not exist, this should not happen!! Investigate!
            if (fileInfo is FileInfo fi && fi.LastWriteTimeUtc == default)
                Debugger.Break(); // The file does not have a last write time, this should not happen!! Investigate!
#endif
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                if (Dictionary.TryGetValue(key, out var fileData))
                {
                    UsedSpace -= fileData.AllocatedStorageSize; // Subtract the old size from UsedSpace
                }
                fileData = new FileData(fileInfo);
                UsedSpace += fileInfo.GetAllocatedStorageSize(); // Add the new size to UsedSpace
                Dictionary[key] = fileData;
            }
        }

        /// <summary>
        /// Ad a file to collection and update the Used Space size
        /// </summary>
        public bool Add(FileSystemInfo fileSystemInfo)
        {
            if (fileSystemInfo.FullName.StartsWith(Context.CloudRoot, StringComparison.InvariantCultureIgnoreCase))
                if (Util.CanBeSeen(fileSystemInfo))
                {
                    Add(fileSystemInfo.HashFileName(Context), fileSystemInfo);
                    return true;
                }
            return false;
        }

        public bool Add(string fullFileName)
        {
            if (Util.FileIsAvailable(fullFileName, out var fileSystemInfo))
            {
                return Add(fileSystemInfo);
            }
            HasChanged = true; // If the file is not available, regenerate the hash table
            Debugger.Break(); // The file does not exist or is not available, this should not happen!! Investigate!
            return false;
        }

        public FileSystemInfo Get(ulong key)
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                if (!Dictionary.TryGetValue(key, out FileData fileData))
                {
                    // Throw an exception if the key is not found
                    throw new KeyNotFoundException("The specified key was not found in the dictionary.");
                }

                // Convert the file path into a FileSystemInfo object
                return CreateFileSystemInfo(fileData);
            }
        }

        /// <summary>
        /// Returns the FileSystemInfo object associated with the specified file name.
        /// </summary>
        /// <param name="fullFileName">Full name file</param>
        /// <param name="key">Hash key</param>
        /// <returns>FileSystemInfo or null</returns>
        public FileSystemInfo? GetByFileName(string fullFileName, out ulong key)
        {
            return GetByFileName(fullFileName, out key, out _, true);
        }

        /// <summary>
        /// Returns the FileSystemInfo object associated with the specified file name, along with the key and Unix last write timestamp.
        /// </summary>
        /// <param name="fullFileName">Full name file</param>
        /// <param name="key">Hash key</param>
        /// <param name="unixLastWriteTimestamp">This value remains useful for deleted files, when it cannot be read by FileSystemInfo</param>
        /// <returns>FileSystemInfo or null</returns>
        public FileSystemInfo? GetByFileName(string fullFileName, out ulong key, out uint unixLastWriteTimestamp, bool isInternalCall = false)
        {
            if (!isInternalCall && Debugger.IsAttached && Context.IsServer)
            {
                Debugger.Break(); // Method not supported in server mode (server does not handle tracking of files needed to update UnixLastWriteTimestamp)
            }
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                foreach (var kvp in Dictionary)
                {
                    if (kvp.Value.FullName.Equals(fullFileName))
                    {
                        // Convert the file path into a FileSystemInfo object
                        key = kvp.Key;
                        unixLastWriteTimestamp = kvp.Value.UnixLastWriteTimestamp;
                        return CreateFileSystemInfo(kvp.Value);
                    }
                }
                key = default;
                unixLastWriteTimestamp = default;
                return null;
            }
        }


        public bool TryGetValue(ulong key, out FileSystemInfo? fileSystemInfo)
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                if (Dictionary.TryGetValue(key, out FileData fileData))
                {
                    // Convert the file path into a FileSystemInfo object
                    fileSystemInfo = CreateFileSystemInfo(fileData);
                    return true;
                }
                fileSystemInfo = null;
                return false;
            }
        }

        public bool ContainsKey(ulong key)
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                return Dictionary.ContainsKey(key); // Check if the key exists in the dictionary
            }
        }

        public bool Remove(ulong key)
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                if (Dictionary.TryGetValue(key, out FileData fileData))
                {
                    UsedSpace -= fileData.AllocatedStorageSize; // Subtract the size of the file being removed from UsedSpace
                }
                return Dictionary.Remove(key); // Remove the key and return true if it was removed
            }
        }


        /// <summary>
        /// Remove directory and all files and subdirectories that start with the specified directoryFullName.
        /// </summary>
        /// <param name="directoryFullName"></param>
        /// <returns>Collect the FileId of the removed file</returns>
        public List<(FileId fileId, string fullName)> RemoveDirectory(string directoryFullName)
        {
            var result = new List<(FileId fileId, string fullName)>();
            lock (this)
            {
                string normalizedDirectory = Path.GetFullPath(directoryFullName).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

                var toRemove = new List<ulong>();
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                foreach (var kvp in Dictionary)
                {
                    string fullName = kvp.Value.FullName;
                    if (fullName == directoryFullName || fullName.StartsWith(normalizedDirectory, StringComparison.OrdinalIgnoreCase))
                    {
                        UsedSpace -= kvp.Value.AllocatedStorageSize; // Subtract the size of the file being removed from UsedSpace
                        var fileId = new FileId(kvp.Key, kvp.Value.UnixLastWriteTimestamp);
                        result.Add((fileId, fullName)); // Collect the FileId of the removed file
                        toRemove.Add(kvp.Key); // Collect keys to remove
                    }
                }
                foreach (var key in toRemove)
                {
                    Dictionary.Remove(key); // Remove the key from the dictionary
                }
            }
            return result;
        }

        private void EnsureDictionaryLoaded()
        {
            // Restart the unload timer to prevent unloading
            unloadTimer?.Stop();
            unloadTimer?.Start();
            // Load the dictionary from disk if it is not already loaded
            if (Dictionary == null)
            {
                DeserializeFromDisk();
            }
        }

        private static FileSystemInfo CreateFileSystemInfo(FileData fileData)
        {
            return fileData.UnixLastWriteTimestamp == default ? new DirectoryInfo(fileData.FullName) : new FileInfo(fileData.FullName);

            //// Determine whether the path represents a file or directory
            //return !Directory.Exists(fileData.FullName) || fileData.UnixLastWriteTimestamp != default ? new FileInfo(fileData.FullName) : new DirectoryInfo(fileData.FullName);
        }

        private void SerializeToDisk()
        {
            // [8] bytes = UsedSpace

            // For each element:

            // [8] bytes = Hash
            // [2] bytes = Length of FullName
            // [N] bytes = FullName
            // [4] bytes = UnixLastWriteTimestamp
            // [8] bytes = AllocatedStorageSize

            lock (this)
            {
                try
                {
                    using (BinaryWriter writer = new BinaryWriter(File.Open(filePath, FileMode.Create)))
                    {
                        writer.Write(UsedSpace);
                        foreach (var kvp in Dictionary)
                        {
                            writer.Write(kvp.Key);
                            var stringBytes = Encoding.UTF8.GetBytes(kvp.Value.FullName);
                            writer.Write((ushort)stringBytes.Length);
                            writer.Write(stringBytes);
                            writer.Write(kvp.Value.UnixLastWriteTimestamp);
                            writer.Write(kvp.Value.AllocatedStorageSize);
                        }
                    }

                    if (Context.IsServer)
                        Dictionary = null;
                }
                catch (Exception)
                {
                }
            }
        }

        private void DeserializeFromDisk()
        {
            LoadFailure = false;
            lock (this)
            {
                Dictionary = [];

                if (!File.Exists(filePath))
                    return;

                try
                {
                    using FileStream fs = File.Open(filePath, FileMode.Open, FileAccess.Read);
                    using BinaryReader reader = new BinaryReader(fs);
                    UsedSpace = reader.ReadInt64();

                    while (reader.BaseStream.Position < reader.BaseStream.Length)
                    {
                        ulong key = reader.ReadUInt64();
                        ushort length = reader.ReadUInt16();
                        byte[] stringBytes = reader.ReadBytes(length);
                        string fullName = Encoding.UTF8.GetString(stringBytes);
                        uint unixLastWriteTimestamp = reader.ReadUInt32();
                        long size = reader.ReadInt64();
                        Dictionary[key] = new FileData(fullName, unixLastWriteTimestamp, size);
                    }
                }
                catch (Exception ex)
                {
                    LoadFailure = true;
                    Dictionary.Clear();
                    UsedSpace = 0;

                    try
                    {
                        if (File.Exists(filePath))
                            File.Delete(filePath);
                    }
                    catch (IOException deleteEx)
                    {
                        Debug.WriteLine($"Failed to delete corrupt file: {deleteEx.Message}");
                    }

                    Debug.WriteLine($"Deserialization failed: {ex.Message}");
                    Debugger.Break();
                }
            }
        }

        /// <summary>
        /// Returns the contained elements as a tuple containing both the file info and the last write date Utc (useful for getting the last write date Utc for files that have been deleted)
        /// </summary>
        /// <returns></returns>
        public (ulong Key, FileSystemInfo FileInfo, uint UnixLastWriteTimestamp)[] Elements()
        {
            lock (this)
            {
                EnsureDictionaryLoaded();
                var elements = new (ulong key, FileSystemInfo FileInfo, uint UnixLastWriteTimestamp)[Dictionary.Count];
                int index = 0;
                foreach (var kvp in Dictionary)
                {
                    elements[index] = (kvp.Key, CreateFileSystemInfo(kvp.Value), kvp.Value.UnixLastWriteTimestamp);
                    index++;
                }

                return elements;
            }
        }

        /// <summary>
        /// Returns the contained elements as a tuple containing both the file info and the last write date Utc (useful for getting the last write date Utc for files that have been deleted)
        /// </summary>
        /// <returns></returns>
        public (ulong Key, uint UnixLastWriteTimestamp)[] KeyTimestampCollection()
        {
            lock (this)
            {
                EnsureDictionaryLoaded();
                var elements = new (ulong key, uint UnixLastWriteTimestamp)[Dictionary.Count];
                int index = 0;
                foreach (var kvp in Dictionary)
                {
                    elements[index] = (kvp.Key, kvp.Value.UnixLastWriteTimestamp);
                    index++;
                }

                return elements;
            }
        }


        public byte[] GetHasRoot()
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                ulong hash1 = 0;
                ulong hash2 = 0;
#if DEBUG
                string path = "C:\\" + (Context.IsClient ? "client" : "server") + ".txt";
                using (StreamWriter writer = new StreamWriter(path))
                {
#endif

                    foreach (var item in Dictionary)
                    {
                        hash1 ^= item.Key;
                        hash2 ^= item.Value.UnixLastWriteTimestamp;
#if DEBUG
                        writer.WriteLine(item.Key + "  " + item.Value.UnixLastWriteTimestamp + "  " + item.Value.FullName);
                        FileSystemInfo fileSystemInfo = Directory.Exists(item.Value.FullName) ? new DirectoryInfo(item.Value.FullName) : new FileInfo(item.Value.FullName);
                        if (!fileSystemInfo.Exists)
                        {
                            Debugger.Break(); // The file does not exist, this should not happen!! Investigate!
                        }
                        if (item.Value.UnixLastWriteTimestamp != fileSystemInfo.UnixLastWriteTimestamp())
                        {
                            Debugger.Break(); // The UnixLastWriteTimestamp does not match the file system info, this should not happen!! Investigate!
                        }
#endif
                    }
#if DEBUG
                }

#endif

                return (hash1 ^ hash2).GetBytes();
            }
        }

        public byte[] GetHashStructure()
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking


                var array = new byte[this.Count * 12];
                var offset = 0;


                // ATTENZIONE:
                // VERIFICARE A COSA SERVONO LE DUE FASI (probabilmente è per aggiornare per prima la lista dei file cancellato favorendo l'invio del file apposito contenuto nella directory speciale)


                //for (var phase = 0; phase <= 1; phase++)
                //{
                foreach (var item in Dictionary)
                {
                    //var priority = item.FileInfo is FileInfo fileInfo && SpecialDirectories.Contains(fileInfo.DirectoryName);
                    //if ((phase == 0 && priority) || (phase == 1 && !priority))
                    //{
                    Buffer.BlockCopy(BitConverter.GetBytes(item.Key), 0, array, offset, 8);
                    offset += 8;
                    Buffer.BlockCopy(BitConverter.GetBytes(item.Value.UnixLastWriteTimestamp), 0, array, offset, 4);
                    offset += 4;
                    //}
                }
                //}


                return array;
            }
        }

        public IEnumerator<KeyValuePair<ulong, FileSystemInfo>> GetEnumerator()
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                foreach (var kvp in Dictionary)
                {
                    yield return new KeyValuePair<ulong, FileSystemInfo>(
                        kvp.Key,
                        CreateFileSystemInfo(kvp.Value)
                    );
                }
            }
        }

        // Required method for non-generic IEnumerable interface
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
