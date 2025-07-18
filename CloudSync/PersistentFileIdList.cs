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
    /// The FileIdList class manages a list of FileIds for a specific user and scope.
    /// This class allows adding, saving, and loading FileIds efficiently.
    /// It uses a static dictionary to store all instances of FileIdList,
    /// identifying them by a key composed of UserID and Scope.
    /// </summary>
    internal class PersistentFileIdList : IDisposable
    {
        // Static dictionary to store all instances of FileIdList
        private static readonly Dictionary<string, PersistentFileIdList> instances = [];

        /// <summary>
        /// Action to be called on successful load with parameters scope, userId, and newFileIdList.
        /// </summary>
        public static Action<ScopeType, ulong, List<FileId>> OnLoad { get; set; }

        /// <summary>
        /// Constructor for the FileIdList class.
        /// </summary>
        /// <param name="context">The synchronization context.</param>
        /// <param name="scope">The type of scope.</param>
        /// <param name="userId">The user ID.</param>
        public PersistentFileIdList(Sync context, ScopeType scope, ulong userId)
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
        internal const string CloudCacheDirectory = ".cloud_cache";
        private string FileName => Path.Combine(Context.CloudRoot, CloudCacheDirectory, GetKey(UserID, Scope));
        private Sync Context;
        private ulong UserID;
        private List<FileId> fileIdList = [];
        private Timer saveTimer;

        /// <summary>
        /// Adds a FileId to the list.
        /// </summary>
        /// <param name="fileId">The FileId to add.</param>
        private void AddItem(FileId fileId)
        {
            if (!fileIdList.Contains(fileId))
            {
                if (fileIdList.Count > MaxItems)
                    fileIdList.RemoveAt(0);
                fileIdList.Add(fileId);
                // Reset the timer to save after 1 second
                saveTimer.Change(1000, Timeout.Infinite);
            }
        }

        /// <summary>
        /// Schedules the save operation with debounce logic.
        /// </summary>
        private void Save()
        {
            lock (saveTimer)
            {
                for (int attempts = 0; attempts < 5; attempts++)
                {
                    try
                    {
                        var path = new DirectoryInfo(Path.GetDirectoryName(FileName));
                        if (!path.Exists)
                        {
                            path.Create();
                            path.Attributes |= FileAttributes.Hidden;
                            path.Refresh();
                        }

                        using var fileStream = new FileStream(FileName, FileMode.Create, FileAccess.Write);
                        using var binaryWriter = new BinaryWriter(fileStream);
                        foreach (var fileId in fileIdList)
                        {
                            binaryWriter.Write(fileId.Bytes);
                        }
                        return;
                    }
                    catch
                    {
                        Thread.Sleep(1000);
                    }
                }
            }
        }

        /// <summary>
        /// Loads a FileIdList from a file.
        /// </summary>
        /// <param name="context">The synchronization context.</param>
        /// <param name="fullFileName">The name of the file to load the list from.</param>
        /// <returns>An instance of FileIdList.</returns>
        public static PersistentFileIdList Load(Sync context, string fullFileName)
        {
            string fileName = Path.GetFileName(fullFileName);
            string[] parts = fileName.Split('.');
            if (parts.Length != 2)
                return null;
            if (!ulong.TryParse(parts[0], out var userId))
                return null;
            if (!Enum.TryParse(parts[1], out ScopeType scope))
                return null;

            List<FileId> previousFileIdList = null;
            lock (instances)
            {
                if (instances.TryGetValue(fileName, out var existingInstance))
                {
                    previousFileIdList = [.. existingInstance.fileIdList];
                }
            }

            var fileIdList = new PersistentFileIdList(context, scope, userId);

            if (File.Exists(fullFileName))
            {
                const int maxRetries = 5;
                int delayMilliseconds = 300;

                for (int attempt = 0; attempt < maxRetries; attempt++)
                {
                    try
                    {
                        using var fileStream = new FileStream(fullFileName, FileMode.Open, FileAccess.Read, FileShare.Read);
                        using var binaryReader = new BinaryReader(fileStream);

                        while (fileStream.Position < fileStream.Length)
                        {
                            byte[] fileIdBytes = binaryReader.ReadBytes(12);
                            var fileId = FileId.GetFileId(fileIdBytes);
                            fileIdList.fileIdList.Add(fileId);
                        }

                        break; // Successful read
                    }
                    catch (IOException)
                    {
                        if (attempt == maxRetries - 1)
                            throw;
                        Thread.Sleep(delayMilliseconds);
                        delayMilliseconds *= 2; // Exponential backoff
                    }
                }
            }

            var newFileIdList = previousFileIdList == null
                ? fileIdList.fileIdList
                : fileIdList.fileIdList.Except(previousFileIdList).ToList();

            OnLoad?.Invoke(scope, userId, newFileIdList);

            return fileIdList;
        }


        /// <summary>
        /// Initializes all saved instances of FileIdList.
        /// </summary>
        /// <param name="context">The synchronization context.</param>
        public static void Initialize(Sync context)
        {
            if (Initialized)
                return;
            Initialized = true;
            OnLoad = context.OnUpdateFileIdList;
            var cloudCachePath = new DirectoryInfo(Path.Combine(context.CloudRoot, CloudCacheDirectory));
            if (!cloudCachePath.Exists)
                return;

            var files = cloudCachePath.GetFiles("*.*");
            foreach (var file in files)
            {
                Load(context, file.FullName);
            }
        }

        public static bool Initialized { get; private set; }

        /// <summary>
        /// Adds a FileId to a FileIdList specified by userId and scope.
        /// </summary>
        /// <param name="context">The synchronization context.</param>
        /// <param name="userId">The user ID.</param>
        /// <param name="scope">The type of scope.</param>
        /// <param name="fileId">The FileId to add.</param>
        public static void AddItem(Sync context, ulong userId, ScopeType scope, FileId fileId)
        {
            var key = GetKey(userId, scope);

            if (!instances.TryGetValue(key, out var fileIdList))
            {
                fileIdList = new PersistentFileIdList(context, scope, userId);
            }
            fileIdList.AddItem(fileId);
        }

        /// <summary>
        /// Removes a FileId from a FileIdList specified by userId and scope.
        /// </summary>
        /// <param name="userId">The user ID.</param>
        /// <param name="scope">The type of scope.</param>
        /// <param name="fileId">The FileId to remove.</param>
        /// <returns>True if the FileId was removed, otherwise false.</returns>
        public static bool RemoveItem(ulong userId, ScopeType scope, FileId fileId)
        {
                var key = GetKey((ulong)userId, scope);
                if (instances.TryGetValue(key, out var fileIdList))
                {
                    lock (fileIdList.fileIdList)
                    {
                        if (fileIdList.fileIdList.Remove(fileId))
                        {
                            // Reset the timer to save after 1 second
                            fileIdList.saveTimer.Change(1000, Timeout.Infinite);
                            return true;
                        }
                    }
                }
            return false;
        }


        public static bool RemoveItem(ScopeType scope, FileId fileId)
        {
            var result = false;

            foreach (var instance in instances)
            {
                if (instance.Value.Scope == scope)
                {
                    if (instance.Value.fileIdList.Remove(fileId))
                    {
                        result = true;
                    }
                }
            }
            return result;
        }


        /// <summary>
        /// Checks if a FileId exists in any FileIdList instance for the specified scope and returns the corresponding userId.
        /// </summary>
        /// <param name="scope">The type of scope.</param>
        /// <param name="fileId">The FileId to check.</param>
        /// <param name="userId">The user ID associated with the FileId if found.</param>
        /// <returns>True if the FileId exists, otherwise false.</returns>
        public static bool ContainsItem(ScopeType scope, FileId fileId, out ulong userId)
        {
            lock (instances)
            {
                foreach (var instance in instances)
                {
                    if (instance.Value.Scope == scope && instance.Value.fileIdList.Contains(fileId))
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

        public static void DisposeAll()
        {
            lock (instances)
            {
                foreach (var instance in instances.Values)
                {
                    instance.Dispose();
                }
                instances.Clear();
            }
        }

        /// <summary>
        /// Disposes the FileIdList instance, releasing resources.
        /// </summary>
        public void Dispose()
        {
            lock (instances)
            {
                var key = GetKey(UserID, Scope);
                instances.Remove(key);
            }

            lock (saveTimer)
            {
                saveTimer?.Dispose();
                saveTimer = null;
            }
        }

    }
}
