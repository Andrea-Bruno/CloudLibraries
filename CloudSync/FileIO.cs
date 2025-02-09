using System;
using System.IO;
using System.Threading;

namespace CloudSync
{
    public static partial class Util
    {
        internal static void SetOwner((uint, uint)? owner, string path)
        {
            if (owner != null)
            {
                chown(path, owner.Value.Item1, owner.Value.Item2);
            }
        }

        /// <summary>
        /// Write binary data in append to a file, retrying if the file is busy with other processes.
        /// </summary>
        /// <param name="fileName">File name</param>
        /// <param name="data">Binary data to write</param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attempts</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt</param>
        /// <param name="chunkSize">Set a value different of 0 to check a file size if is consistent with the chunk size size</param>
        /// <param name="chunkNumber">Chunk number (base 1) if chunk size is different of 0</param>
        /// <returns>True for successful</returns>
        public static bool FileAppend(string fileName, byte[] data, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50, int chunkSize = 0, uint chunkNumber = 0)
        {
            if (!PreserveDriveSpace(fileName))
            {
                exception = DriveFullException;
                return false;
            }

            exception = null;
            for (int numTries = 0; numTries < attempts; numTries++)
            {
                try
                {
                    using (var fs = File.OpenWrite(fileName))
                    {
                        if (chunkNumber == 1)
                        {
                            fs.SetLength(0);
                            fs.Position = 0;
                        }

                        if (chunkSize > 0)
                        {
                            var expectedPart = fs.Length / DefaultChunkSize + 1;
                            if (expectedPart != chunkNumber)
                                return false;
                        }

                        fs.Position = fs.Length; // append
                        fs.Write(data, 0, data.Length);
                        fs.Flush();
                        return true;
                    }
                }
                catch (IOException ex)
                {
                    exception = ex;
                    Thread.Sleep(pauseBetweenAttempts);
                }
            }

            return false;
        }

        /// <summary>
        /// Delete a file and retrying if the file is busy with other processes.
        /// </summary>
        /// <param name="fileName">The fully qualified name of the file</param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attempts</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in milliseconds)</param>
        /// <returns>True for successful</returns>
        public static bool FileDelete(string fileName, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50)
        {
            exception = null;
            var fileInfo = new FileInfo(fileName);
            if (fileInfo.Exists)
            {
                for (int numTries = 0; numTries < attempts; numTries++)
                {
                    try
                    {
                        DeleteFile(fileInfo);
                        return true;
                    }
                    catch (IOException ex)
                    {
                        exception = ex;
                        Thread.Sleep(pauseBetweenAttempts);
                    }
                }
            }

            return false;
        }

        private static void DeleteFile(FileInfo fileInfo)
        {
            if (fileInfo.Attributes != FileAttributes.Normal)
                fileInfo.Attributes = FileAttributes.Normal;
            fileInfo.Delete();
            fileInfo.Refresh();
            while (fileInfo.Exists)
            {
                Thread.Sleep(100);
                fileInfo.Refresh();
            }
        }

        /// <summary>
        /// Delete a directory and retrying if any error occur.
        /// </summary>
        /// <param name="directoryName">The fully qualified name of the directory</param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attempts</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in milliseconds)</param>
        /// <returns>True for successful</returns>
        public static bool DirectoryDelete(string directoryName, out Exception exception, int attempts = 10,
            int pauseBetweenAttempts = 50)
        {
            exception = null;
            for (int numTries = 0; numTries < attempts; numTries++)
            {
                try
                {
                    ForceDeleteDirectory(directoryName);
                    return true;
                }
                catch (IOException ex)
                {
                    exception = ex;
                    Thread.Sleep(pauseBetweenAttempts);
                }
            }

            return false;
        }

        /// <summary>
        /// https://stackoverflow.com/questions/611921/how-do-i-delete-a-directory-with-read-only-files-in-c
        /// </summary>
        /// <param name="path"></param>
        private static void ForceDeleteDirectory(string path)
        {
            var directory = new DirectoryInfo(path);
            if (directory.Exists)
            {
                directory.Attributes = FileAttributes.Normal;
                foreach (var info in directory.GetFileSystemInfos("*", SearchOption.AllDirectories))
                    info.Attributes = FileAttributes.Normal;
                directory.Delete(true);
            }
        }


        /// <summary>
        /// Create a directory and retrying if any error occur.
        /// </summary>
        /// <param name="directoryName">The fully qualified name of the directory</param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attempts</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in milliseconds)</param>
        /// <returns>True for successful</returns>
        public static bool DirectoryCreate(string directoryName, (uint, uint)? owner, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50)
        {
            if (!PreserveDriveSpace(directoryName))
            {
                exception = DriveFullException;
                return false;
            }

            exception = null;
            for (int numTries = 0; numTries < attempts; numTries++)
            {
                try
                {
                    var directory = new DirectoryInfo(directoryName);
                    directory.Create();
                    SetOwner(owner, directoryName);
                    return true;
                }
                catch (IOException ex)
                {
                    exception = ex;
                    Thread.Sleep(pauseBetweenAttempts);
                }
            }

            return false;
        }

        /// <summary>
        /// Move a file (copy from source to target and delete source) and retrying if any error occur.
        /// </summary>
        /// <param name="source">Source file name</param>
        /// <param name="target">Target file name</param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attempts</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in milliseconds)</param>
        /// <returns>True for successful</returns>
        public static bool FileMove(string source, string target, (uint, uint)? owner, out Exception exception, int attempts = 10,
            int pauseBetweenAttempts = 50)
        {
            if (!PreserveDriveSpace(target))
            {
                exception = DriveFullException;
                return false;
            }

            exception = null;
            if (File.Exists(source))
            {
                for (int numTries = 0; numTries < attempts; numTries++)
                {
                    try
                    {
                        File.Move(source, target);
                        SetOwner(owner, target);
                        return true;
                    }
                    catch (IOException ex)
                    {
                        exception = ex;
                        Thread.Sleep(pauseBetweenAttempts);
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Copy a file (copy from source to target) and retrying if any error occur.
        /// </summary>
        /// <param name="source">Source file name</param>
        /// <param name="target">Target file name</param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attempts</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in milliseconds)</param>
        /// <returns>True for successful</returns>
        public static bool FileCopy(string source, string target, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50, Sync context = null)
        {
           return FileCopy(new FileInfo(source), target, out exception, attempts, pauseBetweenAttempts, context);
        }


        /// <summary>
        /// Copy a file (copy from source to target) and retrying if any error occur.
        /// </summary>
        /// <param name="source">Source file name</param>
        /// <param name="target">Target file name</param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attempts</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in milliseconds)</param>
        /// <returns>True for successful</returns>
        public static bool FileCopy(FileSystemInfo source, string target, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50, Sync context = null)
        {
            if (!PreserveDriveSpace(target))
            {
                exception = DriveFullException;
                return false;
            }

            exception = null;
            if (source.Exists)
            {
                for (int numTries = 0; numTries < attempts; numTries++)
                {
                    try
                    {
                        FileCopy(context, source, target);
                        return true;
                    }
                    catch (Exception ex)
                    {
                        exception = ex;
                        Thread.Sleep(pauseBetweenAttempts);
                    }
                }
            }
            return false;
        }

        private static void FileCopy(Sync context, FileSystemInfo source, string target)
        {
            if (context?.ZeroKnowledgeProof == null)
            {

                if (File.Exists(target))
                    File.Delete(target);
                using var outputStream = File.OpenWrite(target);
                using var inputStream = File.OpenRead(source.FullName);
                inputStream.CopyTo(outputStream);
            }
            else
            {
                ZeroKnowledgeProof.EncryptFile(source, target, context.ZeroKnowledgeProof.DerivedEncryptionKey(source));
            }
        }
    }
}