using NBitcoin;
using Newtonsoft.Json.Linq;
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

        // Change file permission using the Unix chmod system call
        [DllImport("libc", SetLastError = true)]
        private static extern int chmod(string path, uint mode);

        /// <summary>
        /// Simulate a Unix chmod terminal command
        /// </summary>
        /// <param name="permissionMode">Permission mode to set (e.g., "755", "644", "+x", "u=rw")</param>
        /// <param name="filePath">Full file name to set</param>
        /// <returns>True if the operation was successful, otherwise false</returns>
        public static bool Chmod(string permissionMode, string filePath)
        {
            uint uintMode = PermissionModeToUint(permissionMode);
            // Check if the operating system is Unix-like
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return false; // OS not supported
            }

            // Change the file permissions
            int result = chmod(filePath, uintMode);
            return result == 0;
        }

        /// <summary>
        /// Convert a Unix permission mode string to a uint representation
        /// </summary>
        /// <param name="permissionMode">Permission mode string (e.g., "755", "644", "+x", "u=rw")</param>
        /// <returns>uint representation of the permission mode</returns>
        private static uint PermissionModeToUint(string permissionMode)
        {
            if (string.IsNullOrEmpty(permissionMode))
            {
                throw new ArgumentException("Permission mode cannot be null or empty.");
            }

            // If the mode is numeric (3 or 4 digits)
            if (permissionMode.All(char.IsDigit) && (permissionMode.Length == 3 || permissionMode.Length == 4))
            {
                return ParseNumericMode(permissionMode);
            }

            // If the mode is a symbolic command (e.g., "+x", "u=rw")
            return ParseSymbolicMode(permissionMode);
        }

        /// <summary>
        /// Parse a numeric permission mode (e.g., "755", "0640")
        /// </summary>
        /// <param name="permissionMode">Numeric permission mode string</param>
        /// <returns>uint representation of the permission mode</returns>
        private static uint ParseNumericMode(string permissionMode)
        {
            uint mode = 0;

            // If the mode is 4 digits, the first digit represents special flags
            if (permissionMode.Length == 4)
            {
                mode |= (uint)(permissionMode[0] - '0') << 9; // Special flags (setuid, setgid, sticky bit)
            }

            // Convert the last 3 digits into standard permissions
            int offset = permissionMode.Length == 4 ? 1 : 0;
            mode |= (uint)(permissionMode[offset + 0] - '0') << 6; // Owner permissions
            mode |= (uint)(permissionMode[offset + 1] - '0') << 3; // Group permissions
            mode |= (uint)(permissionMode[offset + 2] - '0');      // Others permissions

            return mode;
        }

        /// <summary>
        /// Parse a symbolic permission mode (e.g., "+x", "u=rw")
        /// </summary>
        /// <param name="permissionMode">Symbolic permission mode string</param>
        /// <returns>uint representation of the permission mode</returns>
        private static uint ParseSymbolicMode(string permissionMode)
        {
            uint mode = 0;

            // Example support for "+x" (add execute permission for all)
            if (permissionMode == "+x")
            {
                mode |= 0x49; // Set execute bits for owner, group, and others (--x--x--x)
            }
            // Example support for "u=rw" (set read and write permissions for owner)
            else if (permissionMode == "u=rw")
            {
                mode |= 0x180; // Set read and write bits for owner (rw-------)
            }
            // Add more cases here...
            else
            {
                throw new ArgumentException($"Unsupported permission mode: {permissionMode}");
            }

            return mode;
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

        const uint S_IXUSR = 0x40; // User execute permission

        private static void SetExecutable(string filePath)
        {
            if (chmod(filePath, S_IXUSR) != 0)
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

        [DllImport("libc", SetLastError = true)]
        private static extern int chown(string path, uint owner, uint group);

        internal static void SetOwner((uint, uint)? owner, string path)
        {
            if (owner != null)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    chown(path, owner.Value.Item1, owner.Value.Item2);
            }
        }

        static private void SetDefaultPermission(bool isDirectory, string path, (uint, uint)? owner)
        {
            SetOwner(owner, path);
            if (isDirectory)
            {
                Chmod("0750", path);
            }
            else
            {
                Chmod("0640", path);
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
                return chown(path, owner, group) == 0;
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