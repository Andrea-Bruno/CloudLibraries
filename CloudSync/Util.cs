using SecureStorage;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace CloudSync
{
    public static partial class Util
    {
        static Util()
        {
            Sha256Hash = SHA256.Create();
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Passwd
        {
            public IntPtr pw_name; // Username
            public IntPtr pw_passwd; // User password
            public uint pw_uid; // User ID
            public uint pw_gid; // Group ID
            public IntPtr pw_gecos; // Real name
            public IntPtr pw_dir; // Home directory
            public IntPtr pw_shell; // Shell program
        }

        [DllImport("libc", SetLastError = true)]
        public static extern IntPtr getpwnam(string name);

        internal static (uint, uint) GetUserIds(string username)
        {
            uint uid = 0;
            uint gid = 0;

            try
            {
                IntPtr passwdPtr = getpwnam(username);
                if (passwdPtr == IntPtr.Zero)
                {
                    throw new Exception("Error getting user information.");
                }
                Passwd passwd = Marshal.PtrToStructure<Passwd>(passwdPtr);

                uid = passwd.pw_uid;
                gid = passwd.pw_gid;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Errore: {ex.Message}");
            }
            return (uid, gid);
        }

        private static readonly SHA256 Sha256Hash;

        public static byte[] Hash256(byte[] data)
        {
            lock (Sha256Hash)
                return Sha256Hash.ComputeHash(data);
        }

        private const long BlockSize = 4096;
        public static long GetAllocatedStorageSize(this FileSystemInfo fileSystemInfo)
        {
            if (fileSystemInfo is FileInfo file)
            {
                return ((file.Length + BlockSize - 1) / BlockSize) * BlockSize;
            }
            return BlockSize;
        }

        /// <summary>
        /// Create user sub-folders: Documents, Pictures, Movies, etc..
        /// </summary>
        /// <param name="userPath"></param>
        /// <param name="createSubFolder"></param>
        public static void CreateUserFolder(string userPath, (uint, uint)? owner, bool createSubFolder = true)
        {
            var created = SetSpecialDirectory(userPath, Ico.Cloud, owner, false);
            if (createSubFolder && DesktopEnvironmentIsStarted)
                AddDesktopAndFavoritesShortcut(userPath);
            var createIfNotExists = createSubFolder && new DirectoryInfo(userPath).GetDirectories().FirstOrDefault(x => !x.Attributes.HasFlag(FileAttributes.Hidden) && !x.Name.StartsWith(".")) ==
                default;
            SetSpecialDirectory(userPath, Ico.Documents, owner, createIfNotExists: createIfNotExists);
            SetSpecialDirectory(userPath, Ico.Download, owner, createIfNotExists: createIfNotExists);
            SetSpecialDirectory(userPath, Ico.Movies, owner, createIfNotExists: createIfNotExists);
            SetSpecialDirectory(userPath, Ico.Pictures, owner, createIfNotExists: createIfNotExists);
            SetSpecialDirectory(userPath, Ico.Photos, owner, createIfNotExists: createIfNotExists);
            SetSpecialDirectory(userPath, Ico.Settings, owner, createIfNotExists: createIfNotExists);
        }

        /// <summary>
        /// Check if the desktop environment is started
        /// </summary>
        public static readonly bool DesktopEnvironmentIsStarted = !RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("XDG_CURRENT_DESKTOP"));

        public static bool CheckConnection(Uri uri)
        {
            try
            {
                var client = new TcpClient(uri.Host, uri.Port)
                {
                    LingerState = new LingerOption(true, 0),
                    NoDelay = true
                };
                client.Close();
                client.Dispose();
                return true;
            }
            catch (Exception)
            {
            }

            return false;
        }

        public static string PublicIpAddressInfo()
        {
            var ip = GetPublicIpAddress();
            return ip != null ? ip.ToString() : "ERROR!";
        }

        public static IPAddress GetPublicIpAddress(string serviceUrl = "https://ipinfo.io/ip")
        {
            try
            {
                return IPAddress.Parse(new WebClient().DownloadString(serviceUrl));
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static IPAddress GetLocalIpAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.IsLocalIPAddress())
                {
                    return ip;
                }
            }

            return null;
        }

        public static TimeSpan DataTransferTimeOut(int dataSize)
        {
            var timeOutMs = (dataSize / 10) * Spooler.MaxConcurrentOperations + 20000;
            return TimeSpan.FromMilliseconds(timeOutMs);
        }

        private static string GetPinsFile(Storage secureStorage)
        {
            var pins = secureStorage.Values.Get("pins", "");
            return pins;
        }

        /// <summary>
        /// Add a one-time pin to log in a client. The pin is valid only once.
        /// </summary>
        /// <param name="pin">Pins to add</param>
        /// <param name="expiresHours">Expires in hours</param>
        /// <param name="label">A tag name indicating who the pin was assigned to (as an optional reminder)</param>
        public static void AddPin(Storage secureStorage, string pin, int expiresHours, string label = null)
        {
            var pins = GetPinsFile(secureStorage);
            pins += pin + "\t" + DateTime.UtcNow.AddHours(expiresHours).ToFileTime() + "\t" + label + "\n";
            secureStorage.Values.Set("pins", pins);
        }

        /// <summary>
        /// The list of currently active pins with the expiration date
        /// </summary>
        /// <param name="context">Context object</param>
        /// <returns>list of active pins with their expiration</returns>
        public static List<OneTimeAccess> GetPins(Storage secureStorage)
        {
            var pinsList = new List<OneTimeAccess>();
            var twoFactorAuth = new TwoFactorAuth(secureStorage);
            pinsList.Add(new OneTimeAccess(twoFactorAuth.CurrentTotpCode(), DateTime.MaxValue, "2FA"));
            if (secureStorage.Values.Get(nameof(RoleManager.MasterPinEnabled), true))
            {
                var pin = GetPin(secureStorage);
                pinsList.Add(new OneTimeAccess(pin, DateTime.MaxValue, "master"));
            }

            string newPins = "";
            var pins = GetPinsFile(secureStorage);
            if (!string.IsNullOrEmpty(pins))
            {
                foreach (var pinParts in pins.Split('\n'))
                {
                    if (string.IsNullOrEmpty(pinParts)) continue;
                    var parts = pinParts.Split('\t');
                    var expires = DateTime.FromFileTime(long.Parse(parts[1]));
                    if (expires >= DateTime.UtcNow)
                    {
                        newPins += pinParts + '\n';
                        pinsList.Add(new OneTimeAccess(parts[0], expires, parts[2]));
                    }
                }
            }

            if (pins != newPins)
            {
                secureStorage.Values.Set("pins", newPins);
            }

            return pinsList;
        }

        /// <summary>
        /// Class with properties related to the temporary pin
        /// </summary>
        public class OneTimeAccess
        {
            public OneTimeAccess(string pin, DateTime expires, string label)
            {
                Pin = pin;
                Expires = expires;
                Label = label;
            }

            /// <summary>
            /// Pin
            /// </summary>
            public readonly string Pin;

            /// <summary>
            /// Class with properties related to the disposable pin
            /// </summary>
            public DateTime Expires;

            /// <summary>
            /// Label describing who was assigned the pin (optional reminder)
            /// </summary>
            public readonly string Label;
        }

        /// <summary>
        /// Remove a disposable pin
        /// </summary>
        /// <param name="pin"></param>
        public static bool RemoveFromPins(Storage secureStorage, string pin)
        {
            bool found = false;
            string newPins = "";
            var pins = GetPinsFile(secureStorage);
            if (!string.IsNullOrEmpty(pins))
            {
                foreach (var pinParts in pins.Split('\n'))
                {
                    if (string.IsNullOrEmpty(pinParts)) continue;
                    if (pinParts.StartsWith(pin + '\t'))
                    {
                        found = true;
                        continue;
                    }

                    newPins += pinParts + '\n';
                }
            }

            if (pins != newPins)
            {
                secureStorage.Values.Set("pins", newPins);
            }

            return found;
        }

        /// <summary>
        /// Get the master pin (the pin that doesn't expire)
        /// </summary>
        /// <param name="context">Context</param>
        /// <returns>Pin in text format</returns>
        public static string GetPin(Storage secureStorage)
        {
            return secureStorage.Values.Get("pin", null);
        }

        /// <summary>
        /// Set a 1 to 8 digit pin (this pin will replace the current master pin)
        /// </summary>
        /// <param name="secureStorage">Storage</param>
        /// <param name="oldPin">Old pin (for control check)</param>
        /// <param name="newPin">New pin</param>
        /// <returns></returns>
        public static bool SetPin(Storage secureStorage, string oldPin, string newPin)
        {
            if (oldPin == GetPin(secureStorage))
            {
                SetPin(secureStorage, newPin);
            }

            return false;
        }

        /// <summary>
        /// Set a 1 to 8 digit pin (this pin will replace the current one)
        /// </summary>
        /// <param name="secureStorage">Storage</param>
        /// <param name="newPin">New pin</param>
        /// <returns>True if the pin is accepted</returns>
        public static bool SetPin(Storage secureStorage, string newPin)
        {
            if (int.TryParse(newPin, out var _) && newPin.Length <= 8)
            {
                secureStorage.Values.Set("pin", newPin);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Since the cloud can be shared with multiple clients, files and directories typical of local use (for example temporary files) are not synchronized so as not to interfere with other clients.
        /// </summary>
        private static readonly List<string> ExcludeName = ["desktop.ini", "tmp", "temp", "cache", "bin", "obj", ".vs", "packages", "apppackages"];
        private static readonly List<string> ExcludeExtension = [".desktop", ".tmp", ".cache"];

        /// <summary>
        /// Return true if it is a hidden file or not subject to synchronization between cloud client and server
        /// </summary>
        /// <param name="fileSystemInfo">System info object of file</param>
        /// <returns>A Boolean value indicating whether the file is subject to synchronization or not</returns>
        public static bool CanBeSeen(FileSystemInfo fileSystemInfo, bool checkAttribute = true)
        {
            if (fileSystemInfo is DirectoryInfo && SpecialDirectories.Contains(fileSystemInfo.Name))
                return true;
            if (checkAttribute && (!fileSystemInfo.Exists || fileSystemInfo.Attributes.HasFlag(FileAttributes.Hidden)))
                return false;
            var name = fileSystemInfo.Name.ToLower();
            var excludeExtension = ExcludeExtension.Find(x => name.EndsWith(x)) != null;
            var excludeName = ExcludeName.Contains(name);
            return !fileSystemInfo.Name.StartsWith("~") && !fileSystemInfo.Name.StartsWith(".") && !fileSystemInfo.Name.EndsWith("_") && !excludeName && !excludeExtension;
        }

        public static bool FileIsAvailable(string filePath, [NotNullWhen(true)] out FileSystemInfo? fileSystemInfo)
        {
            bool FileExists(string fullFileName, [NotNullWhen(true)] out FileSystemInfo? fileSystemInfo)
            {
                DirectoryInfo directoryInfo = new DirectoryInfo(fullFileName);
                if (directoryInfo.Exists)
                {
                    fileSystemInfo = directoryInfo;
                    return true;
                }
                FileInfo fileInfo = new FileInfo(fullFileName);
                if (fileInfo.Exists)
                {
                    fileSystemInfo = fileInfo;
                    return true;
                }
                fileSystemInfo = null;
                return false;
            }
            if (FileExists(filePath, out fileSystemInfo))
            {
                if (fileSystemInfo is not FileInfo fileInfo)
                    return true;
                if (fileInfo.LastWriteTimeUtc == default)
                    return false; // If the file has never been written to, consider it unavailable
                try
                {
                    using FileStream stream = File.Open(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }
            return false;
        }

        /// <summary>
        /// Return true if it is a hidden file or not subject to synchronization between cloud client and server
        /// </summary>
        /// <param name="fullNameFile">Full name file</param>
        /// <returns>A Boolean value indicating whether the file is subject to synchronization or not</returns>
        public static bool CanBeSeen(Sync context, string fullNameFile, bool checkAttribute = true)
        {
            if (context.GetHashFileTable(out HashFileTable hashTable))
            {
                if (hashTable.GetByFileName(fullNameFile, out _) != null)
                    return true;
            }
            FileSystemInfo fileSystemInfo = Directory.Exists(fullNameFile) ? new DirectoryInfo(fullNameFile) : new FileInfo(fullNameFile);
            var root = new DirectoryInfo(context.CloudRoot);
            while (fileSystemInfo != null && fileSystemInfo.FullName != root.FullName)
            {
                if (!CanBeSeen(fileSystemInfo, checkAttribute))
                    return false;
                if (fileSystemInfo is DirectoryInfo dirInfo)
                    fileSystemInfo = dirInfo.Parent;
                else if (fileSystemInfo is FileInfo fileInfo)
                    fileSystemInfo = fileInfo.Directory;
            }
            return true;
        }

        internal static readonly string[] SpecialDirectories = [PersistentFileIdList.CloudCacheDirectory];

        /// <summary>
        /// Convert a date to Unix timestamp format
        /// </summary>
        /// <param name="dateTime">Date and time value to convert</param>
        /// <returns>Integer value indicating date and time in Unix format</returns>
        public static uint ToUnixTimestamp(DateTime dateTime)
        {
            return (uint)(dateTime - new DateTime(1970, 1, 1)).TotalSeconds;
        }

        /// <summary>
        /// Convert Unix timestamp to date and time format
        /// </summary>
        /// <param name="unixTimeStamp">Unix timestamp</param>
        /// <returns></returns>
        public static DateTime UnixTimestampToDateTime(uint unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            var dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTime = dateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dateTime;
        }

        public static ulong HashFileName(string relativeName, bool isDirectory)
        {
            var bytes = relativeName.GetBytes();
            byte[] hash;
            lock (Sha256) // ComputeHash in one case has generate StackOverFlow error, i try to fix by lock the instance
            {
                hash = Sha256.ComputeHash(bytes);
            }
            var hash64 = BitConverter.ToUInt64(hash);

            if (isDirectory)
                hash64 |= 1UL; // Set the least significant bit (LSB) to 1
            else
                hash64 &= ~1UL; // Set the least significant bit (LSB) to 0
            return hash64;
        }

        internal static readonly SHA256 Sha256 = SHA256.Create();

        public static ulong ULongHash(ulong startValue, byte[] bytes)
        {
            var add = BitConverter.GetBytes((ulong)bytes.Length ^ startValue);
            var dataLen = add.Length + bytes.Length;

            dataLen = (dataLen + 7) & ~7;

            var data = new byte[dataLen];
            Buffer.BlockCopy(bytes, 0, data, 0, bytes.Length);
            Buffer.BlockCopy(add, 0, data, bytes.Length, add.Length);
            ulong crc = 0;
            for (int i = 0; i < dataLen; i += 8)
                crc ^= BitConverter.ToUInt64(data, i);
            return crc;
        }

        /// <summary>
        /// Get a path suitable for large temporary files. The result can differ from Path.GetTempPath() because on Linux the latter could return a path allocated in the ram, not suitable for large files that could run out of memory.
        /// </summary>
        /// <returns>Temporary path folder</returns>
        public static string GetTempPath()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return Path.GetTempPath();
            var path = @"/var/tmp/"; // Linux
            if (Directory.Exists(path))
                return path;
            path = @"/private/tmp/"; // OSX
            if (Directory.Exists(path))
                return path;
            return Path.GetTempPath();
        }

        /// <summary>
        /// Gets a file name to be able to park a file during transfer from client to server or vice versa.
        /// </summary>
        /// <param name="sync">Instance of the sync object</param>
        /// <param name="userId">User id requesting the temporary file</param>
        /// <param name="hashFileName">The hash of the file to be momentarily parked during the transfer.</param>
        /// <returns></returns>
        public static string GetTmpFile(Sync sync, ulong? userId, ulong hashFileName)
        {
            userId ??= 0;
            return Path.Combine(GetTempPath(), ((ulong)userId).ToString("X16") + hashFileName.ToString("X16") + sync.UserId.ToString("X16"));
        }

        public const int DefaultChunkSize = 1024 * 1000; // 1 mb

        public static byte[]? GetChunk(uint chunkPart, string fullFileName, out uint parts, out long fileLength, int chunkSize = DefaultChunkSize)
        {
            if (chunkSize == 0)
                chunkSize = DefaultChunkSize;
            byte[] chunk;
            var fileInfo = new FileInfo(fullFileName);
            if (!fileInfo.Exists)
            {
                parts = 0;
                fileLength = 0;
                return null;
            }

            fileLength = fileInfo.Length;
            parts = (uint)Math.Ceiling((double)fileLength / chunkSize);
            parts = parts == 0 ? 1 : parts;
            if (chunkPart > parts)
                return null;
            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    using (var fs = File.OpenRead(fullFileName))
                    {
                        using var reader = new BinaryReader(fs);
                        fs.Position = (chunkPart - 1) * chunkSize;
                        var toTake = reader.BaseStream.Length - reader.BaseStream.Position;
                        if (toTake > chunkSize)
                            toTake = chunkSize;
                        chunk = reader.ReadBytes((int)toTake);
                    }

                    return chunk;
                }
                catch (Exception)
                {
                    Thread.Sleep(1000);
                }
            }

            return null;
        }

        public const ulong StartCRC = CRC.StartCRC;

        public enum Ico
        {
            Cloud,
            Documents,
            Download,
            Movies,
            Pictures,
            Photos,
            Settings,
            Share,
        }

        /// <summary>
        /// Set the icon for a special use directory, if specified by the parameters, create it if it does not exist
        /// </summary>
        /// <param name="path">The directory path which can be full or its parent</param>
        /// <param name="directoryName">The name of the directory that can be selected from an enum</param>
        /// <param name="pathIsParent">Specifies whether the path parameter is the parent or the full name</param>
        /// <param name="createIfNotExists">If true, create the directory if it doesn't exist</param>
        /// <returns>Returns true if the directory was created</returns>
        public static bool SetSpecialDirectory(string path, Ico directoryName, (uint, uint)? owner,
            bool pathIsParent = true,
            bool createIfNotExists = true)
        {
            var created = false;
            var pathDirectory = pathIsParent ? Path.Combine(path, directoryName.ToString()) : path;
            //if (Directory.Exists(pathDirectory))
            //    return false;
            if (createIfNotExists && !Directory.Exists(pathDirectory))
            {
                DirectoryCreate(pathDirectory, owner, out _);
                created = true;
            }

            if (Directory.Exists(pathDirectory))
            {
                // new FileInfo(pathDirectory).IsReadOnly = true; NOTE: Removed because it has inheritance problems in Linux
                var cloudIcoPath = IcoFullName(directoryName);
                if (File.Exists(cloudIcoPath))
                {
                    SetDirectoryIcon(pathDirectory, cloudIcoPath, owner);
                }
            }

            return created;
        }

        private static string IcoFullName(Ico ico) =>
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", ico + ".ico");

        public static void SetDirectoryIcon(string pathDirectory, string iconFilePath, (uint, uint)? owner)
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                var iniPath = Path.Combine(pathDirectory, "desktop.ini");
                var iniContents = new StringBuilder()
                    .AppendLine("[.ShellClassInfo]")
                    .AppendLine($"IconResource={iconFilePath},0")
                    .AppendLine($"IconFile={iconFilePath}")
                    .AppendLine("IconIndex=0")
                    .ToString();

                var iniNow = File.Exists(iniPath) ? File.ReadAllText(iniPath) : string.Empty;
                if (iniContents != iniNow)
                {
                    if (File.Exists(iniPath))
                    {
                        //remove hidden and system attributes to make ini file writable
                        File.SetAttributes(iniPath,
                            File.GetAttributes(iniPath) & ~(FileAttributes.Hidden | FileAttributes.System));
                    }

                    //create new ini file with the required contents
                    File.WriteAllText(iniPath, iniContents);

                    //hide the ini file and set it as system
                    File.SetAttributes(iniPath,
                        File.GetAttributes(iniPath) | FileAttributes.Hidden | FileAttributes.System);
                }
            }
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                var iniPath = Path.Combine(pathDirectory, ".directory");
                var iniContents = new StringBuilder()
                    .AppendLine("[Desktop Entry]")
                    .AppendLine($"Icon={iconFilePath}")
                    .ToString();
                var iniNow = File.Exists(iniPath) ? File.ReadAllText(iniPath) : string.Empty;
                if (iniContents != iniNow)
                {
                    if (File.Exists(iniPath))
                    {
                        //remove hidden and system attributes to make ini file writable
                        File.SetAttributes(iniPath,
                            File.GetAttributes(iniPath) & ~(FileAttributes.Hidden | FileAttributes.System));
                    }

                    //create new ini file with the required contents
                    File.WriteAllText(iniPath, iniContents);

                    //hide the ini file and set it as system
                    File.SetAttributes(iniPath,
                        File.GetAttributes(iniPath) | FileAttributes.Hidden | FileAttributes.System);
                }
                SetOwner(owner, pathDirectory);
            }
        }

        public static void AddDesktopAndFavoritesShortcut(string fullName, Ico ico = Ico.Cloud)
        {
            AddShortcut(fullName, DesktopPath(), ico);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                string script = $@"
tell application ""Finder""
    set targetFolder to POSIX file ""{fullName}"" as alias
    tell sidebar list of front Finder window
        make new sidebar item at end of sidebar items with properties {{name:""My Favorite"", target:targetFolder}}
    end tell
end tell";

                try
                {
                    Process.Start("osascript", $"-e '{script}'");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in AddDesktopAndFavoritesShortcut: {ex.Message}");
                }
            }
            else
                AddShortcut(fullName, Environment.GetFolderPath(Environment.SpecialFolder.Favorites), ico);
        }

        public static string DesktopPath()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            else
            {
                var desktopUser = GetDesktopEnvironmentUser();
                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    return $"/Users/{desktopUser}/Desktop";
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    return $"/home/{desktopUser}/Desktop";
                }
            }
            return null; // OS not supported
        }

        /// <summary>
        /// Get the user logged in to the desktop environment
        /// </summary>
        /// <returns></returns>
        public static string GetDesktopEnvironmentUser()
        {
            var desktop = (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) ? "seat" : "console";

            Process process = new Process();
            process.StartInfo.FileName = "bash";
            process.StartInfo.Arguments = $"-c \"who\"";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            string[] lines = output.Split([Environment.NewLine], StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                string[] parts = line.Split([' '], StringSplitOptions.RemoveEmptyEntries);
                if (parts[1].StartsWith(desktop))
                {
                    return parts[0];
                }
            }
            return null;
        }

        /// <summary>
        /// Add a link (Shortcut) to a file
        /// </summary>
        /// <param name="sourceFile">The file to link</param>
        /// <param name="targetDir">The directory (path location) where to put the link</param>
        /// <param name="ico">The icon to use</param>
        public static void AddShortcut(string sourceFile, string targetDir, Ico ico)
        {
            var icoFullName = IcoFullName(ico);
            AddShortcut(sourceFile, targetDir, icoFullName);
        }

        /// <summary>
        /// Add a link (Shortcut) to a file
        /// </summary>
        /// <param name="sourceFile">The file to link</param>
        /// <param name="targetDir">The directory (path location) where to put the link</param>
        /// <param name="icoFullName">The icon full file name to use</param>
        public static void AddShortcut(string sourceFile, string targetDir, string icoFullName)
        {
            var fileName = new FileInfo(sourceFile).Name;
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                using var writer = new StreamWriter(targetDir + "\\" + fileName + ".url");
                writer.WriteLine("[InternetShortcut]");
                writer.WriteLine("URL=file:///" + sourceFile);
                writer.WriteLine("IconIndex=0");
                var icon = icoFullName.Replace('\\', '/');
                writer.WriteLine("IconFile=" + icon);
            }
            else if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Process.Start("ln", "-s " + sourceFile + " " + targetDir);
                }
                else // Linux
                {
                    var targetFile = Path.Combine(targetDir, fileName + ".desktop");
                    using (var writer = new StreamWriter(targetFile))
                    {
                        writer.WriteLine(@"[Desktop Entry]");
                        writer.WriteLine(@"Type=Application");
                        writer.WriteLine(@"Terminal=false");
                        writer.WriteLine(@"Icon=" + icoFullName);
                        writer.WriteLine(@"Name=" + fileName);
                        writer.WriteLine(@"Exec=xdg-open " + sourceFile);
                        writer.Flush();
                    }
                    Thread.Sleep(500);
                    SetExecutable(targetFile);
                    AllowLaunching(targetFile);
                }
            }
        }

        /// <summary>
        /// Verify that the space occupied is sufficient and compatible with the assigned space
        /// </summary>
        /// <param name="cloudRoot">A path pointing to a disk location to test or a drive</param>
        /// <param name="preserveSize">Space limit to preserve, default is one gigabyte. If the free space is less then it will return false, or generate an error if set by parameter throwError. If this value is less than MinimumPreserveDiskSize, then MinimumPreserveDiskSize will still be treated as the value.</param>
        /// <returns>True if space is not running low</returns>
        /// <exception cref="Exception">If set by parameter, an exception can be generated if the space is close to running out</exception>
        internal static bool CheckDiskSPace(Sync context, long preserveSize = MinimumPreserveDiskSize)
        {
            if (context?._HashFileTable == null)
                return true;
            if (context.StorageLimitGB != -1 && (int)(context._HashFileTable.UsedSpace / 1000000000) > context.StorageLimitGB) // check over limit quota
                return false;
            var result = PreserveDriveSpace(context.CloudRoot, false, preserveSize);
            return result;
        }

        /// <summary>
        /// Check if the disk is close to being full and return true if it is within the limits, it can also generate an appropriate error if set by parameters.
        /// </summary>
        /// <param name="path">A path pointing to a disk location to test or a drive</param>
        /// <param name="throwError">If true then an error will be generated if the limit is exceeded</param>
        /// <param name="preserveSize">Space limit to preserve, default is one gigabyte. If the free space is less then it will return false, or generate an error if set by parameter throwError. If this value is less than MinimumPreserveDiskSize, then MinimumPreserveDiskSize will still be treated as the value.</param>
        /// <returns>True if space is not running low</returns>
        /// <exception cref="Exception">If set by parameter, an exception can be generated if the space is close to running out</exception>
        public static bool PreserveDriveSpace(string path, bool throwError = false, long preserveSize = MinimumPreserveDiskSize)
        {
            if (preserveSize < MinimumPreserveDiskSize)
                preserveSize = MinimumPreserveDiskSize;
            var fileInfo = new FileInfo(path);
            string drive = Path.GetPathRoot(fileInfo.FullName);
            var driveInfo = new DriveInfo(drive);
            var ok = driveInfo.AvailableFreeSpace > preserveSize;
            return throwError && !ok ? throw DriveFullException : ok;
        }

        /// <summary>
        /// The disk should never be filled completely to avoid blocking the operating system and disk operations. This is the minimum space you want to keep on the disk.
        /// </summary>
        internal const long MinimumPreserveDiskSize = 1000000000;

        public static Exception DriveFullException
        {
            get { return new Exception("Disk full beyond the allowed limit"); }
        }


        /// <summary>
        /// Event that is executed when the application crashes, to create a log on file of the event, useful for diagnostics, and restarts the application after it has gone into error
        /// </summary>
        /// <param name="sender">Sender object</param>
        /// <param name="e">Unhandled exception event args</param>
        public static void UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
#if DEBUG
            Debugger.Break();
            return;
#endif
            if (e.ExceptionObject != null)
            {
                if (e.ExceptionObject is not Exception exception)
                {
                    exception = new Exception(e.ExceptionObject.ToString());
                }
                RecordError(exception);
            }
            Thread.Sleep(60000); // 1 minute (prevent error fast loop crash)
            RestartApplication(sender, e);
        }

        public static void RestartApplication(object sender, EventArgs e)
        {
            Debugger.Break();
            if (Debugger.IsAttached)
                return;
            if (DisallowRestartApplicationOnEnd)
            {
                Process.Start(Process.GetCurrentProcess().MainModule.FileName);
            }
        }

        public static bool DisallowRestartApplicationOnEnd;

        /// <summary>
        /// Record an error in the local log (thus creating an error log useful for diagnostics)
        /// </summary>
        /// <param name="error">Exception to log</param>
        public static void RecordError(Exception error)
        {
            lock (Environment.OSVersion)
            {
                try
                {
                    var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, nameof(RecordError));
                    if (!Directory.Exists(path))
                        Directory.CreateDirectory(path);
                    File.WriteAllText(Path.Combine(path, DateTime.UtcNow.Ticks.ToString("X16") + "_" + error.HResult + ".txt"), error.ToString());
                    var files = (new DirectoryInfo(path)).GetFileSystemInfos("*.txt");
                    var orderedFiles = files.OrderBy(f => f.CreationTime).Reverse().ToArray();
                    // Keep 1024 errors
                    for (var index = 1024; index < orderedFiles.Length; index++)
                    {
                        var file = orderedFiles[index];
                        file.Delete();
                    }
                }
                catch (Exception)
                {
                    // ignored
                }
            }
        }

        /// <summary>
        /// If you use a virtual disk you need to mark the mount point with this function so that the synchronization is automatically suspended if the disk is unmounted and restarts when it is remounted.
        /// </summary>
        /// <param name="path"></param>
        public static void SetMountPointFlag(string path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var dir = new DirectoryInfo(path);
                dir.Attributes |= (FileAttributes.ReadOnly | FileAttributes.System);
            }
            else
            {
                Chmod(640, path);
            }
        }

        /// <summary>
        /// This function indicates whether a path has been marked as a mount point when there is no disk mounted on it. Used internally to suspend and resume synchronization when disks are unmounted at the cloud path location.
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        public static bool IsMountingPoint(string path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var dir = new DirectoryInfo(path);
                string linkTarget = null;
                PropertyInfo linkTargetProperty = typeof(DirectoryInfo).GetProperty("LinkTarget");
                if (linkTargetProperty != null)
                    linkTarget = linkTargetProperty.GetValue(dir) as string;
                return dir.Attributes.HasFlag(FileAttributes.ReadOnly) && dir.Attributes.HasFlag(FileAttributes.System) && linkTarget == null;
            }
            else
            {
                var permission = GetFilePermissionsOctal(path);
                var EXECUTE_OWNER = 64; // 0100 in octal
                // Check if the execute permission for the owner is enabled
                bool isExecuteOwnerEnabled = (permission & EXECUTE_OWNER) != 0;

                return !isExecuteOwnerEnabled;
            }
        }
    }
}