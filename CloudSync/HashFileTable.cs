using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.IO;
using System.Timers;

namespace CloudSync
{
    public class HashFileTable : IEnumerable<KeyValuePair<ulong, FileSystemInfo>>
    {
        private Dictionary<ulong, string> dictionary = new Dictionary<ulong, string>();
        private readonly string filePath;
        private readonly Timer unloadTimer;

        public HashFileTable(Sync context)
        {
            Context = context;
            filePath = context.UserId + "." + nameof(HashFileTable);

            if (context.IsServer)
            {
                // Initialize a timer to unload the dictionary after the specified time (flushMinute)                       
                int flushMinute = 4;
                unloadTimer = new Timer(TimeSpan.FromMinutes(flushMinute).TotalMilliseconds);
                unloadTimer.Elapsed += (sender, e) => SerializeToDisk();
                unloadTimer.AutoReset = false; // Ensure the timer only triggers once unless restarted
            }
        }
        private readonly Sync Context;
        // Property to get the number of items in the dictionary
        public int Count
        {
            get
            {
                lock (this)
                {
                    EnsureDictionaryLoaded(); // Load the dictionary before locking
                    return dictionary.Count;
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
                    return new List<ulong>(dictionary.Keys); // Return a copy of the keys to avoid external modification
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

        public void Add(ulong key, FileSystemInfo fileInfo)
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                dictionary[key] = fileInfo.FullName;
            }
        }

        public void Add(FileSystemInfo fileInfo)
        {
            Add(fileInfo.HashFileName(Context), fileInfo);
        }

        public FileSystemInfo Get(ulong key)
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                if (!dictionary.TryGetValue(key, out string fullName))
                {
                    // Throw an exception if the key is not found
                    throw new KeyNotFoundException("The specified key was not found in the dictionary.");
                }

                // Convert the file path into a FileSystemInfo object
                return CreateFileSystemInfo(fullName);
            }
        }

        public FileSystemInfo GetByFileName(string fullFileName, out ulong key)
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                foreach (var kvp in dictionary)
                {
                    if (kvp.Value.Equals(fullFileName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Convert the file path into a FileSystemInfo object
                        key = kvp.Key;
                        return CreateFileSystemInfo(kvp.Value);
                    }
                }
                key = default(ulong);
                return null;
            }
        }


        public bool TryGetValue(ulong key, out FileSystemInfo fileSystemInfo)
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                if (dictionary.TryGetValue(key, out string fullName))
                {
                    // Convert the file path into a FileSystemInfo object
                    fileSystemInfo = CreateFileSystemInfo(fullName);
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
                return dictionary.ContainsKey(key); // Check if the key exists in the dictionary
            }
        }

        public bool Remove(ulong key)
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                return dictionary.Remove(key); // Remove the key and return true if it was removed
            }
        }

        private void EnsureDictionaryLoaded()
        {
            // Restart the unload timer to prevent unloading
            unloadTimer?.Stop();
            unloadTimer?.Start();
            // Load the dictionary from disk if it is not already loaded
            if (dictionary == null)
            {
                DeserializeFromDisk();
            }
        }

        private FileSystemInfo CreateFileSystemInfo(string fullName)
        {
            // Determine whether the path represents a file or directory
            return Directory.Exists(fullName) ? new DirectoryInfo(fullName) : new FileInfo(fullName);
        }

        public void SerializeToDisk()
        {
            lock (this)
            {
                using var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write);
                using var writer = new BinaryWriter(stream);
                foreach (var kvp in dictionary)
                {
                    writer.Write(kvp.Key);
                    var stringBytes = System.Text.Encoding.UTF8.GetBytes(kvp.Value);
                    writer.Write((ushort)stringBytes.Length);
                    writer.Write(stringBytes);
                }
                dictionary = null;
            }
        }

        public void DeserializeFromDisk()
        {
            dictionary = [];
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            using var reader = new BinaryReader(stream);
            while (stream.Position < stream.Length)
            {
                ulong key = reader.ReadUInt64();
                ushort length = reader.ReadUInt16();
                var stringBytes = reader.ReadBytes(length);
                string value = System.Text.Encoding.UTF8.GetString(stringBytes);
                dictionary[key] = value;
            }
        }

        public IEnumerator<KeyValuePair<ulong, FileSystemInfo>> GetEnumerator()
        {
            lock (this)
            {
                EnsureDictionaryLoaded(); // Load the dictionary before locking
                foreach (var kvp in dictionary)
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
