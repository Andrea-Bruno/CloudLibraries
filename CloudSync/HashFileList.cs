using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace CloudSync
{
    /// <summary>
    /// Enum representing different types of scope.
    /// </summary>
    internal enum ScopeType
    {
        Deleted,
    }

    /// <summary>
    /// The HashFileList class manages a list of hashes for a specific user and scope.
    /// This class allows adding, saving, and loading hashes efficiently.
    /// It uses a static dictionary to store all instances of HashFileList,
    /// identifying them by a key composed of UserID and Scope.
    /// </summary>
    internal class HashFileList
    {
        // Static dictionary to store all instances of HashFileList
        private static readonly Dictionary<string, HashFileList> instances = new Dictionary<string, HashFileList>();

        /// <summary>
        /// Action to be called on successful load with parameters scope, userId, and newHashList.
        /// </summary>
        public static Action<ScopeType, ulong, List<ulong>> OnLoad { get; set; }

        /// <summary>
        /// Constructor for the HashFileList class.
        /// </summary>
        /// <param name="context">The synchronization context.</param>
        /// <param name="scope">The type of scope.</param>
        /// <param name="userId">The user ID.</param>
        public HashFileList(Sync context, ScopeType scope, ulong userId)
        {
            Context = context;
            Scope = scope;
            UserID = userId;
            saveTimer = new Timer(_ => Save(), null, Timeout.Infinite, Timeout.Infinite);

            var key = GetKey(userId, scope);
            lock (instances)
            {
                instances[key] = this;
            }
        }

        private ScopeType Scope;
        public const int MaxItems = 1000;
        internal const string CloudCache = ".cloud_cache";
        private string FileName => Path.Combine(Context.CloudRoot, CloudCache, UserID.ToString() + "." + Scope);
        private Sync Context;
        private ulong UserID;
        private List<ulong> hashList = new List<ulong>();
        private Timer saveTimer;

        /// <summary>
        /// Adds a hash to the list.
        /// </summary>
        /// <param name="hash">The hash to add.</param>
        private void AddItem(ulong hash)
        {
            if (hashList.Count > MaxItems)
                hashList.RemoveAt(0);
            hashList.Add(hash);

            // Reset the timer to save after 1 second
            saveTimer.Change(1000, Timeout.Infinite);
        }

        /// <summary>
        /// Saves the list of hashes to a file.
        /// </summary>
        private void Save()
        {
            if (!Directory.Exists(Path.GetDirectoryName(FileName)))
                Directory.CreateDirectory(Path.GetDirectoryName(FileName));

            using (var fileStream = new FileStream(FileName, FileMode.Create, FileAccess.Write))
            using (var binaryWriter = new BinaryWriter(fileStream))
            {
                foreach (var hash in hashList)
                {
                    binaryWriter.Write(hash);
                }
            }
        }

        /// <summary>
        /// Loads a HashFileList from a file.
        /// </summary>
        /// <param name="context">The synchronization context.</param>
        /// <param name="fileName">The name of the file to load the list from.</param>
        /// <returns>An instance of HashFileList.</returns>
        public static HashFileList Load(Sync context, string fileName)
        {
            var fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileName);
            var parts = fileNameWithoutExtension.Split('.');
            if (parts.Length < 2)
                return null;

            if (!ulong.TryParse(parts[0], out var userId))
                return null;

            if (!Enum.TryParse(parts[1], out ScopeType scope))
                return null;

            var key = GetKey(userId, scope);

            List<ulong> previousHashList = null;
            lock (instances)
            {
                if (instances.TryGetValue(key, out var existingInstance))
                {
                    previousHashList = new List<ulong>(existingInstance.hashList);
                }
            }

            var hashFileList = new HashFileList(context, scope, userId);

            if (File.Exists(fileName))
            {
                using (var fileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read))
                using (var binaryReader = new BinaryReader(fileStream))
                {
                    while (fileStream.Position < fileStream.Length)
                    {
                        var hash = binaryReader.ReadUInt64();
                        hashFileList.hashList.Add(hash);
                    }
                }
            }

            lock (instances)
            {
                instances[key] = hashFileList;
            }

            var newHashList = previousHashList == null ? hashFileList.hashList : hashFileList.hashList.Except(previousHashList).ToList();
            OnLoad?.Invoke(scope, userId, newHashList);

            return hashFileList;
        }

        /// <summary>
        /// Initializes all saved instances of HashFileList.
        /// </summary>
        /// <param name="context">The synchronization context.</param>
        public static void Initialize(Sync context)
        {
            if (Initialized)
                return;
            Initialized = true;
            OnLoad = context.OnUpdateHashFileList;
            var cloudCachePath = Path.Combine(context.CloudRoot, CloudCache);
            if (!Directory.Exists(cloudCachePath))
                return;

            var files = Directory.GetFiles(cloudCachePath, "*.*");
            foreach (var file in files)
            {
                Load(context, file);
            }
        }

        public static bool Initialized { get; private set; }

        /// <summary>
        /// Adds a hash to a HashFileList specified by userId and scope.
        /// </summary>
        /// <param name="context">The synchronization context.</param>
        /// <param name="userId">The user ID.</param>
        /// <param name="scope">The type of scope.</param>
        /// <param name="hash">The hash to add.</param>
        public static void AddItem(Sync context, ulong userId, ScopeType scope, ulong hash)
        {
            var key = GetKey(userId, scope);

            lock (instances)
            {
                if (!instances.TryGetValue(key, out var hashFileList))
                {
                    hashFileList = new HashFileList(context, scope, userId);
                    instances[key] = hashFileList;
                }
                hashFileList.AddItem(hash);
            }
        }

        /// <summary>
        /// Checks if a hash exists in any HashFileList instance for the specified scope and returns the corresponding userId.
        /// </summary>
        /// <param name="scope">The type of scope.</param>
        /// <param name="hash">The hash to check.</param>
        /// <param name="userId">The user ID associated with the hash if found.</param>
        /// <returns>True if the hash exists, otherwise false.</returns>
        public static bool ContainsItem(ScopeType scope, ulong hash, out ulong userId)
        {
            lock (instances)
            {
                foreach (var instance in instances)
                {
                    if (instance.Value.Scope == scope && instance.Value.hashList.Contains(hash))
                    {
                        userId = instance.Value.UserID;
                        return true;
                    }
                }
            }

            userId = 0;
            return false;
        }

        /// <summary>
        /// Gets the dictionary key using userId and scope.
        /// </summary>
        /// <param name="userId">The user ID.</param>
        /// <param name="scope">The type of scope.</param>
        /// <returns>The dictionary key.</returns>
        private static string GetKey(ulong userId, ScopeType scope)
        {
            return $"{userId}.{scope}";
        }
    }
}
