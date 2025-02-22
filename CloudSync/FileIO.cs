using Mono.Unix.Native;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace CloudSync
{
    public static partial class Util
    {
        /// <summary>
        /// Simulate a Unix chmod terminal command
        /// </summary>
        /// <param name="permissionsMode">Permissions mode to set (e.g., 755, 644)</param>
        /// <param name="filePath">Full file name to set</param>
        /// <returns>True if the operation was successful, otherwise false</returns>
        public static bool Chmod(int permissionsMode, string filePath)
        {
            uint uintMode = PermissionsBase10ToUnixOctal(permissionsMode);
            // Check if the operating system is Unix-like
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return false; // OS not supported
            var permission = (FilePermissions)uintMode;
            // Change the file permissions
            int result = Syscall.chmod(filePath, permission);
            return result == 0;
        }

        private static int GetOctalFilePermissions(string filePath)
        {
            if (Syscall.stat(filePath, out Stat statBuf) != 0)
                return -1; // Error while reading file information
            // Convert permissions to a human-readable string
            var mode = statBuf.st_mode;
            return (int)mode;
        }

        /// <summary>
        /// Converts Unix permissions from decimal (base 10) to their octal (base 8) representation.
        /// </summary>
        /// <param name="base10Permissions">Permissions in decimal format (e.g., 511, 420).</param>
        /// <returns>The octal representation of the permissions as a uint (e.g., 777, 644).</returns>
        private static uint PermissionsBase10ToUnixOctal(int base10Permissions)
        {
            var o = base10Permissions % 10;
            base10Permissions /= 10;
            var g = base10Permissions % 10;
            base10Permissions /= 10;
            var a = base10Permissions % 10;
            var result = o | g << 3 | a << 6;
            return (uint)result;
        }

        // Set file like trusted (GNOME)
        [DllImport("libgio-2.0.so.0", SetLastError = true)]
        private static extern int g_file_set_attribute(
            IntPtr file,
            string attribute,
            IntPtr valueP,
            IntPtr cancellable,
            out IntPtr error
        );

        const FilePermissions S_IXUSR = (FilePermissions)0x40; // User execute permission

        private static void SetExecutable(string filePath)
        {
            if (Syscall.chmod(filePath, S_IXUSR) != 0)
            {
                int errno = Marshal.GetLastWin32Error();
                Debugger.Break(); // error
            }
        }

        private static void AllowLaunching(string filePath)
        {
            try
            {
                IntPtr file = IntPtr.Zero;
                IntPtr error;
                string attribute = "metadata::trusted";
                IntPtr valueP = Marshal.StringToHGlobalAnsi("true");

                if (g_file_set_attribute(file, attribute, valueP, IntPtr.Zero, out error) != 0)
                {
                    int errno = Marshal.GetLastWin32Error();
                    Marshal.FreeHGlobal(valueP);
                    Debugger.Break(); // error
                }
                else
                {
                    Marshal.FreeHGlobal(valueP);
                }
            }
            catch (Exception)
            {

                throw;
            }
        }


        internal static void SetOwner((uint, uint)? owner, string path)
        {
            if (owner != null)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    Syscall.chown(path, owner.Value.Item1, owner.Value.Item2);
            }
        }

        static private void SetDefaultPermission(bool isDirectory, string path, (uint, uint)? owner)
        {
            SetOwner(owner, path);
            if (isDirectory)
            {
                Chmod(750, path);
            }
            else
            {
                Chmod(640, path);
            }
        }

        /// <summary>
        /// Change ownership
        /// </summary>
        /// <param name="path">Full path name file or directory</param>
        /// <param name="owner">Owner name</param>
        /// <param name="group">Group name</param>
        /// <returns></returns>
        public static bool Chown(string path, uint owner, uint group)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return false;
            try
            {
                return Syscall.chown(path, owner, group) == 0;
            }
            catch (Exception)
            {
                return false;
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
        /// <param name="chunkSize">Set a value different of 0 to check a file size if is consistent with the chunk size</param>
        /// <param name="chunkNumber">Chunk number (base 1) if chunk size is different of 0</param>
        /// <returns>True for successful</returns>
        public static bool FileAppend(string fileName, byte[] data, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50, int chunkSize = 0, uint chunkNumber = 0, Sync context = null)
        {
            if (!CheckDiskSPace(context))
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
        public static bool DirectoryDelete(string directoryName, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50)
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
            exception = null;
            for (int numTries = 0; numTries < attempts; numTries++)
            {
                try
                {
                    var directory = new DirectoryInfo(directoryName);
                    directory.Create();
                    SetDefaultPermission(true, directoryName, owner);
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
        public static bool FileMove(string source, string target, bool decrypt, (uint, uint)? owner, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50, Sync context = null)
        {
            if (!CheckDiskSPace(context))
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
                        if (decrypt)
                        {
                            File.Delete(target);
                            new FileInfo(source).Decrypt(target, context);
                        }
                        else
                            File.Move(source, target);
                        SetDefaultPermission(false, target, owner);
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
            if (!CheckDiskSPace(context))
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
            var pathParts = source.CloudRelativeUnixFullName(context).Split('/');
            if (context?.ZeroKnowledgeProof == null || pathParts.Intersect(SpecialDirectories).Any())
            {

                if (File.Exists(target))
                    File.Delete(target);
                using var outputStream = File.OpenWrite(target);
                using var inputStream = File.OpenRead(source.FullName);
                inputStream.CopyTo(outputStream);
            }
            else
            {
                context.ZeroKnowledgeProof.EncryptFile((FileInfo)source, target);
            }
        }
    }
}