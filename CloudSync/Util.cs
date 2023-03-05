using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web;
using EncryptedMessaging;
using HashFileTable = System.Collections.Generic.Dictionary<ulong, System.IO.FileSystemInfo>;

namespace CloudSync
{
    public static class Util
    {
        static Util()
        {
            Sha256Hash = SHA256.Create();
        }

        private static readonly SHA256 Sha256Hash;
        public static byte[] Hash256(byte[] data)
        {
            lock (Sha256Hash)
                return Sha256Hash.ComputeHash(data);
        }

        public static bool CheckConnection(Uri uri)
        {
            try
            {
                var client = new TcpClient(uri.Host, uri.Port)
                {
                    LingerState = new LingerOption(true, 0)
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

        public static TimeSpan DataTransferTimeOut(int dataSize)
        {
            var timeOutMs = (dataSize / 10) * Spooler.MaxConcurrentOperations + 20000;
            return new TimeSpan(timeOutMs * TimeSpan.TicksPerMillisecond);
        }

        private static string GetPinsFile(Context context)
        {
            context.Session.TryGetValue("pins", out object pins);
            if (pins == null)
            {
                pins = context.SecureStorage.Values.Get("pins", "");
                context.Session["pins"] = pins;
            }
            return (string)pins;
        }

        /// <summary>
        /// Add a one-time pin to log in a client. The pin is valid only once.
        /// </summary>
        /// <param name="pin">Pins to add</param>
        /// <param name="expiresHours">Expires in hours</param>
        /// <param name="label">A tag name indicating who the pin was assigned to (as an optional reminder)</param>
        public static void AddPin(Context context, string pin, int expiresHours, string label = null)
        {
            var pins = GetPinsFile(context);
            pins += pin + "\t" + DateTime.UtcNow.AddHours(expiresHours).ToFileTime() + "\t" + label + "\n";
            context.Session["pins"] = pins;
            context.SecureStorage.Values.Set("pins", pins);
        }

        /// <summary>
        /// The list of currently active pins with the expiration date
        /// </summary>
        /// <param name="context">Context object</param>
        /// <returns>list of active pins with their expiration</returns>
        public static List<OneTimeAccess> GetPins(Context context)
        {
            var pinsList = new List<OneTimeAccess>();
            var pin = GetPin(context);
            pinsList.Add(new OneTimeAccess(pin, DateTime.MaxValue, "master"));
            string newPins = "";
            var pins = GetPinsFile(context);
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
                context.Session["pins"] = newPins;
                context.SecureStorage.Values.Set("pins", newPins);
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
            public string Pin;
            /// <summary>
            /// Class with properties related to the disposable pin
            /// </summary>
            public DateTime Expires;
            /// <summary>
            /// Label describing who was assigned the pin (optional reminder)
            /// </summary>
            public string Label;
        }

        /// <summary>
        /// Remove a disposable pin
        /// </summary>
        /// <param name="context">Context object</param>
        /// <param name="pin"></param>
        public static bool RemoveFromPins(Context context, string pin)
        {
            bool found = false;
            string newPins = "";
            var pins = GetPinsFile(context);
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
                context.Session["pins"] = newPins;
                context.SecureStorage.Values.Set("pins", newPins);
            }
            return found;
        }

        /// <summary>
        /// Get the master pin (the pin that doesn't expire)
        /// </summary>
        /// <param name="context">Context</param>
        /// <returns>Pin in text format</returns>
        public static string GetPin(Context context)
        {
            context.Session.TryGetValue("pin", out object pin);
            if (pin == null)
            {
                pin = context.SecureStorage.Values.Get("pin", null);
                context.Session["pin"] = pin;
            }
            return (string)pin;
        }

        /// <summary>
        /// Set a 1 to 8 digit pin (this pin will replace the current master pin)
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="oldPin">Old pin (for control check)</param>
        /// <param name="newPin">New pin</param>
        /// <returns></returns>
        public static bool SetPin(Context context, string oldPin, string newPin)
        {
            if (oldPin == GetPin(context))
            {
                SetPin(context, newPin);
            }
            return false;
        }

        /// <summary>
        /// Set a 1 to 8 digit pin (this pin will replace the current one)
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="newPin">New pin</param>
        /// <returns>True if the pin is accepted</returns>
        public static bool SetPin(Context context, string newPin)
        {
            if (int.TryParse(newPin, out var _) && newPin.Length <= 8)
            {
                context.Session["pin"] = newPin;
                context.SecureStorage.Values.Set("pin", newPin);
                return true;
            }
            return false;
        }

        private static readonly List<string> ExcludeFile = new List<string> { "desktop.ini" };
        private static readonly List<string> ExcludeExtension = new List<string> { ".desktop" };

        /// <summary>
        /// Return true if it is a hidden file or not subject to synchronization between cloud client and server
        /// </summary>
        /// <param name="fileSystemInfo">System info object of file</param>
        /// <returns>A Boolean value indicating whether the file is subject to synchronization or not</returns>
        public static bool CanBeSeen(FileSystemInfo fileSystemInfo)
        {
            var name = fileSystemInfo.Name.ToLower();
            var excludeExtension = ExcludeExtension.Find(x => name.EndsWith(x)) != null;
            var excludeFile = ExcludeFile.Contains(name);
            return !fileSystemInfo.Attributes.HasFlag(FileAttributes.Hidden) && !fileSystemInfo.Name.StartsWith("_") && !fileSystemInfo.Name.StartsWith(".") && fileSystemInfo.Exists && !excludeFile && !excludeExtension;
        }

        /// <summary>
        /// Convert a date to unix timestamp format
        /// </summary>
        /// <param name="dateTime">Date and time value to convert</param>
        /// <returns>Integer value indicating date and time in unix format</returns>
        public static uint ToUnixTimestamp(DateTime dateTime)
        {
            return (uint)(dateTime - new DateTime(1970, 1, 1)).TotalSeconds;
        }

        /// <summary>
        /// Convert unix timestamp to date and time format
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

        public static string ClaudRelativeUnixFullName(this FileSystemInfo fileSystemInfo, Sync cloudSync)
        {
            var name = fileSystemInfo.FullName.Substring(cloudSync.CloudRoot.Length);
            name = name.Replace('\\', '/');
            if (name.Length != 0 && name[0] == '/')
                name = name.Substring(1);
            return name;
        }

        /// <summary>
        /// the first 32 bits from the right are the unicode timestamp, the rest the hash on the full file name
        /// </summary>
        /// <param name="fileSystemInfo"></param>
        /// <returns></returns>
        public static ulong HashFileName(this FileSystemInfo fileSystemInfo, Sync cloudSync)
        {
            var relativeName = ClaudRelativeUnixFullName(fileSystemInfo, cloudSync);
            return HashFileName(relativeName, fileSystemInfo.Attributes.HasFlag(FileAttributes.Directory));
        }

        /// <summary>
        /// Compare two bytes arrays.
        /// </summary>
        /// <param name="source">source byte array</param>
        /// <param name="compareTo"> byte array to compare</param>
        /// <returns>Boolean</returns>
        public static bool SequenceEqual(this byte[] source, byte[] compareTo)
        {
            if (compareTo.Length != source.Length)
                return false;
            for (var i = 0; i < source.Length; i++)
                if (source[i] != compareTo[i])
                    return false;
            return true;
        }

        public static ulong HashFileName(string relativeName, bool isDirectory)
        {
            var bytes = relativeName.GetBytes();
            var startValue = isDirectory ? 5120927932783021125ul : 2993167789729610286ul;
            return ULongHash(startValue, bytes);
        }

        public static ulong ULongHash(ulong startValue, byte[] bytes)
        {
            var add = BitConverter.GetBytes((ulong)bytes.Length ^ startValue);
            var concat = new byte[add.Length + bytes.Length];
            Buffer.BlockCopy(bytes, 0, concat, 0, bytes.Length);
            Buffer.BlockCopy(add, 0, concat, bytes.Length, add.Length);
            //var hash = Sha256Hash.ComputeHash(concat);
            var hash = SHA256.Create().ComputeHash(concat);
            return BitConverter.ToUInt64(hash, 0);
            //var bl = (ulong)bytes.Length;
            //Array.Resize(ref bytes, (int)Math.Ceiling(bytes.Length / 8d) * 8);
            //startValue += bl;
            //for (var i = 0; i < bytes.Length; i += 8)
            //{
            //    var v = BitConverter.ToUInt64(bytes, i);
            //    startValue += v; // prevents zero value of startValue
            //    startValue *= (v + (ulong)i);
            //}
            //return startValue;
        }

        public static byte[] GetBytes(this string text)
        {
            return Encoding.Unicode.GetBytes(text);
        }

        public static string ToText(this byte[] bytes)
        {
            return Encoding.Unicode.GetString(bytes);
        }

        public static byte[] Concat(this byte[] thisArray, byte[] array)
        {
            var result = new byte[thisArray.Length + array.Length];
            Buffer.BlockCopy(thisArray, 0, result, 0, thisArray.Length);
            Buffer.BlockCopy(array, 0, result, thisArray.Length, array.Length);
            return result;
        }

        public static uint UnixLastWriteTimestamp(this FileSystemInfo fileSystemInfo)
        {
            return fileSystemInfo.Attributes.HasFlag(FileAttributes.Directory) ? 0 : ToUnixTimestamp(fileSystemInfo.LastWriteTimeUtc);
        }

        public static byte[] GetBytes(this uint number)
        {
            return BitConverter.GetBytes(number);
        }

        public static byte[] GetBytes(this ulong number)
        {
            return BitConverter.GetBytes(number);
        }

        public static uint ToUint32(this byte[] array)
        {
            return BitConverter.ToUInt32(array, 0);
        }

        public static ulong ToUint64(this byte[] array)
        {
            return BitConverter.ToUInt64(array, 0);
        }

        public static string GetTmpFile(Sync sync, ulong? userId, ulong hashFileName)
        {
            return Path.Combine(Path.GetTempPath(), ((ulong)userId).ToString("X") + hashFileName.ToString("X") + sync.InstanceId);
        }
        public const int DefaultChunkSize = 1024 * 1000; // 1 mb
        public const ulong startCrc = 2993167723948948793u;
        public static byte[] GetChunk(uint chunkPart, string fullFileName, out uint parts, out long fileLength, ref ulong crc, int chunkSize = DefaultChunkSize)
        {
            if (chunkSize == 0)
                chunkSize = DefaultChunkSize;
            byte[] chunk;
            fileLength = new FileInfo(fullFileName).Length;
            parts = (uint)Math.Ceiling((double)fileLength / chunkSize);
            parts = parts == 0 ? 1 : parts;
            crc = chunkPart == 1 ? startCrc : crc;

            if (chunkPart > parts)
                return null;
            using (var fs = File.OpenRead(fullFileName))
            {
                using (var reader = new BinaryReader(fs))
                {
                    fs.Position = (chunkPart - 1) * chunkSize;
                    var toTake = reader.BaseStream.Length - reader.BaseStream.Position;
                    if (toTake > chunkSize)
                        toTake = chunkSize;
                    chunk = reader.ReadBytes((int)toTake);
                    crc = ULongHash(crc, chunk);
                }
            }
            return chunk;
        }

        public enum Icos
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
        public static bool SetSpecialDirectory(string path, Icos directoryName, bool pathIsParent = true, bool createIfNotExists = true)
        {
            var created = false;
            var pathDirectory = pathIsParent ? Path.Combine(path, directoryName.ToString()) : path;
            //if (Directory.Exists(pathDirectory))
            //    return false;
            if (createIfNotExists && !Directory.Exists(pathDirectory))
            {
                Directory.CreateDirectory(pathDirectory);
                created = true;
            }
            if (Directory.Exists(pathDirectory))
            {
                // new FileInfo(pathDirectory).IsReadOnly = true; NOTE: Removed because it has inheritance problems in Linux
                var cloudIcoPath = IcoFullName(directoryName);
                if (File.Exists(cloudIcoPath))
                {
                    SetDirectoryIcon(pathDirectory, cloudIcoPath);
                }
            }
            return created;
        }

        private static string IcoFullName(Icos ico) => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", ico + ".ico");

        public static void SetDirectoryIcon(string pathDirectory, string iconFilePath)
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
                        File.SetAttributes(iniPath, File.GetAttributes(iniPath) & ~(FileAttributes.Hidden | FileAttributes.System));
                    }
                    //create new ini file with the required contents
                    File.WriteAllText(iniPath, iniContents);

                    //hide the ini file and set it as system
                    File.SetAttributes(iniPath, File.GetAttributes(iniPath) | FileAttributes.Hidden | FileAttributes.System);
                }
                //set the folder as system
                File.SetAttributes(pathDirectory, File.GetAttributes(pathDirectory) | FileAttributes.System);
            }
        }
        public static void AddDesktopShorcut(string fullName, Icos ico = Icos.Cloud)
        {
            var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            AddShorcut(fullName, desktopDir, ico);
        }

        public static void AddShorcut(string source, string target, Icos ico)
        {
            var icoFullName = IcoFullName(ico);
            var fileName = new FileInfo(source).Name;
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                using (var writer = new StreamWriter(target + "\\" + fileName + ".url"))
                {
                    writer.WriteLine("[InternetShortcut]");
                    writer.WriteLine("URL=file:///" + source);
                    writer.WriteLine("IconIndex=0");
                    var icon = icoFullName.Replace('\\', '/');
                    writer.WriteLine("IconFile=" + icon);
                }

                //var htmlName = HttpUtility.HtmlEncode(source);
                //using (var writer = new StreamWriter(Path.Combine(target, "cloud info.html")))
                //{
                //    writer.WriteLine("<head><link rel='icon' href='file:///" + icoFullName + "'/></head>");
                //    writer.WriteLine("<body>Your cloud folder is here:");
                //    writer.WriteLine("<a href='file:///" + htmlName + "'>" + htmlName + "</a></body>");
                //}
            }
            else if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                var targetFile = Path.Combine(target, fileName + ".desktop");
                using (var writer = new StreamWriter(targetFile))
                {
                    writer.WriteLine(@"[Desktop Entry]");
                    writer.WriteLine(@"Type=Link");
                    writer.WriteLine(@"Terminal=false");
                    writer.WriteLine(@"Icon=" + icoFullName);
                    writer.WriteLine(@"Name=" + fileName);
                    writer.WriteLine(@"URL=file:///" + source);
                }
            }
        }

        public class BlockRange
        {
            public BlockRange(ulong? betweenHasBlock, int betweenHasBlockIndex, ulong? betweenReverseHasBlock, int betweenReverseHasBlockIndex)
            {
                BetweenHasBlock = betweenHasBlock;
                BetweenHasBlockIndex = betweenHasBlockIndex;
                BetweenReverseHasBlock = betweenReverseHasBlock;
                BetweenReverseHasBlockIndex = betweenReverseHasBlockIndex;
#if (DEBUG)
                if (BetweenHasBlock == null && BetweenHasBlockIndex != -1)
                    Debugger.Break(); // wrong !
                if (BetweenReverseHasBlock == null && BetweenReverseHasBlockIndex != -1)
                    Debugger.Break(); // wrong !
#endif                      
            }

            public BlockRange(byte[] betweenHasBlockBinary, byte[] betweenHasBlockIndex, byte[] betweenReverseHasBlockBinary, byte[] betweenReverseHasBlockPIndex)
            {
                BetweenHasBlock = betweenHasBlockBinary.Length == 8 ? BitConverter.ToUInt64(betweenHasBlockBinary, 0) : (ulong?)null;
                BetweenHasBlockIndex = BitConverter.ToInt32(betweenHasBlockIndex, 0);
                BetweenReverseHasBlock = betweenReverseHasBlockBinary.Length == 8 ? BitConverter.ToUInt64(betweenReverseHasBlockBinary, 0) : (ulong?)null;
                BetweenReverseHasBlockIndex = BitConverter.ToInt32(betweenReverseHasBlockPIndex, 0);
#if (DEBUG)
                if (BetweenHasBlock == null && BetweenHasBlockIndex != -1)
                    Debugger.Break(); // wrong !
                if (BetweenReverseHasBlock == null && BetweenReverseHasBlockIndex != -1)
                    Debugger.Break(); // wrong !
#endif                      
            }
            public readonly ulong? BetweenHasBlock;
            public byte[] BetweenHasBlockBynary => BetweenHasBlock == null ? new byte[] { } : BitConverter.GetBytes((ulong)BetweenHasBlock);
            public readonly int BetweenHasBlockIndex;
            public byte[] BetweenHasBlockIndexBinary => BitConverter.GetBytes(BetweenHasBlockIndex);
            public readonly ulong? BetweenReverseHasBlock;
            public byte[] BetweenReverseHasBlockBynary => BetweenReverseHasBlock == null ? new byte[] { } : BitConverter.GetBytes((ulong)BetweenReverseHasBlock);
            public readonly int BetweenReverseHasBlockIndex;
            public byte[] BetweenReverseHasBlockIndexBinary => BitConverter.GetBytes(BetweenReverseHasBlockIndex);

            public bool TakeAll => BetweenHasBlock == null;
            public bool ReverseTakeAll => BetweenReverseHasBlock == null;
        }

        private const int BlockFileSize = 256; // Each hash represents a block of 256 files

        public static byte[] HashFileTableToHashBlock(HashFileTable hashFileTable)
        {
            GetRestrictedHashFileTable(hashFileTable, out var hashBlocks);
            return hashBlocks;
        }

        /// <summary>
        /// If delimitsRange != Null, returns HashFileTable of range, otherwise returns HashBlocks (out byte[] returnHashBlocks)
        /// </summary>
        /// <param name="hashFileTable">The whole hash table whitout delimits</param>
        /// <param name="returnHashBlocks">Return hash block if delimitsRange is null</param>
        /// <param name="delimitsRange">An object that indicates the portion of the filetable hash to take</param>
        /// <returns></returns>
        public static HashFileTable GetRestrictedHashFileTable(HashFileTable hashFileTable, out byte[] returnHashBlocks, BlockRange delimitsRange = null)
        {
            var returnValue = delimitsRange == null ? null : new HashFileTable();
            var elementInBlock = delimitsRange == null ? null : new List<KeyValuePair<ulong, HashFileTable>>();
            var elementInBlockReverse = delimitsRange == null ? null : new List<KeyValuePair<ulong, HashFileTable>>();
            var hashList = new List<byte[]>();
            void hashBlock(IEnumerable<KeyValuePair<ulong, FileSystemInfo>> hashTable, ref List<byte[]> result, ref List<KeyValuePair<ulong, HashFileTable>> outElementInBlock)
            {
                var toAdd = outElementInBlock == null ? null : new HashFileTable();
                ulong hash1 = 0;
                ulong hash2 = 0;
                var n = 1;
                var total = hashTable.Count();
                foreach (var item in hashTable)
                {
                    if (toAdd != null)
                        toAdd.Add(item.Key, item.Value);
                    hash1 ^= item.Key;
                    hash2 ^= item.Value.UnixLastWriteTimestamp();
                    if (1 % BlockFileSize == 0 || n == total)
                    {
                        var hash = (hash1 ^ hash2).GetBytes();
                        //var hash = hash1.GetBytes().Concat(hash2.GetBytes());
                        result.Add(hash);
                        hash1 = 0;
                        hash2 = 0;
                        if (outElementInBlock != null)
                        {
                            outElementInBlock.Add(new KeyValuePair<ulong, HashFileTable>(BitConverter.ToUInt64(hash, 0), toAdd));
                            toAdd = new HashFileTable();
                        }
                    }
                    n++;
                }
            }
            hashBlock(hashFileTable, ref hashList, ref elementInBlock);
            hashBlock(hashFileTable.Reverse(), ref hashList, ref elementInBlockReverse);

            if (returnValue == null)
            {
                returnHashBlocks = new byte[hashList.Count * 8];
                //Array.Resize(ref returnHashBlocks, hashList.Count * 8);
                for (var i = 0; i < hashList.Count; i++)
                {
                    var item = hashList[i];
                    var p = i * 8;
                    item.CopyTo(returnHashBlocks, p);
                }
            }
            else
            {
                returnHashBlocks = null;
                if (!PerformRange(false, ref elementInBlock, ref returnValue, delimitsRange.TakeAll, delimitsRange.BetweenHasBlock, delimitsRange.BetweenHasBlockIndex))
                    return null; // There is no block in the requested position, the operation must be canceled because there is something wrong

                if (!PerformRange(true, ref elementInBlock, ref returnValue, delimitsRange.ReverseTakeAll, delimitsRange.BetweenReverseHasBlock, delimitsRange.BetweenReverseHasBlockIndex))
                    return null; // There is no block in the requested position, the operation must be canceled because there is something wrong
            }
            return returnValue;
        }

        private static bool PerformRange(bool reverseStep, ref List<KeyValuePair<ulong, HashFileTable>> elementInBlock, ref HashFileTable returnValue, bool takeAll, ulong? betweenHasBlock, int betweenHasBlockIndex)
        {
            var startIndex = takeAll ? 0 : betweenHasBlockIndex;
            if (betweenHasBlockIndex != -1 && (elementInBlock.Count <= betweenHasBlockIndex || elementInBlock[betweenHasBlockIndex].Key != betweenHasBlock))
            {
                return false; // There is no block in the requested position, the operation must be canceled because there is something wrong
            }
            if (!reverseStep)
            {
                for (var i = startIndex; i < elementInBlock.Count; i++)
                {
                    var block = elementInBlock[i].Value;
                    foreach (var item in block)
                    {
                        returnValue[item.Key] = item.Value;
                    }
                }
            }
            else
            {
                if (!takeAll)
                {
                    for (var i = 0; i <= betweenHasBlockIndex; i++)
                    {
                        var block = elementInBlock[i].Value;
                        foreach (var item in block)
                        {
                            if (returnValue.ContainsKey(item.Key))
                                returnValue.Remove(item.Key);
                        }
                    }
                }
            }
            return true;
        }

        public static BlockRange HashBlocksToBlockRange(byte[] hashBlocksRemote, byte[] hashBlocksLocal)
        {
            var straightRemote = hashBlocksRemote.Take(hashBlocksRemote.Length / 2).ToArray();
            var straightLocal = hashBlocksLocal.Take(hashBlocksLocal.Length / 2).ToArray();
            HashBlockComparer(straightRemote, straightLocal, out var lastHashStraight, out var indexStraight);

            var reverseRemote = hashBlocksRemote.Skip(hashBlocksRemote.Length / 2).ToArray();
            var reverseLocal = hashBlocksLocal.Skip(hashBlocksLocal.Length / 2).ToArray();
            HashBlockComparer(reverseRemote, reverseLocal, out var lastHashReverse, out var indexReverse);
            return new BlockRange(lastHashStraight, indexStraight, lastHashReverse, indexReverse);
        }
        private static void HashBlockComparer(byte[] hashBlocksRemote, byte[] hashBlocksLocal, out ulong? lastHashMatch, out int index)
        {
            lastHashMatch = null;
            index = -1;
            var p = 0;
            while (p < hashBlocksRemote.Length && p < hashBlocksLocal.Length)
            {
                var h1 = BitConverter.ToUInt64(hashBlocksRemote, p);
                var h2 = BitConverter.ToUInt64(hashBlocksLocal, p);
                if (h1 == h2)
                {
                    lastHashMatch = h1;
                    p += 8;
                    index++;
                }
                else
                {
                    break;
                }
            }
        }

        /// <summary>
        /// Write binary data in append to a file, retrying if the file is busy with other processes.
        /// </summary>
        /// <param name="fileName">File name</param>
        /// <param name="data">Binary data to write</param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attemps</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt</param>
        /// <param name="chunkSize">Set a value different of 0 to check a file size if is consistent with the chunk size size</param>
        /// <param name="chunkNumber">Chunk number (base 1) if chunk size is different of 0</param>
        /// <returns>True for successful</returns>
        public static bool FileAppend(string fileName, byte[] data, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50, int chunkSize = 0, uint chunkNumber = 0)
        {
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
        /// <param name="fileName"></param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attemps</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in millisenconds)</param>
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
                        fileInfo.Delete();
                        fileInfo.Refresh();
                        while (fileInfo.Exists)
                        {
                            Thread.Sleep(100);
                            fileInfo.Refresh();
                        }
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
        /// Delete a directory and retrying if any error occur.
        /// </summary>
        /// <param name="directoryName"></param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attemps</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in millisenconds)</param>
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
        /// <param name="directoryName"></param>
        /// <param name="exception">Returns any errors encountered in performing the operation</param>
        /// <param name="attempts">number of attemps</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in millisenconds)</param>
        /// <returns>True for successful</returns>
        public static bool DirectoryCreate(string directoryName, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50)
        {
            exception = null;
            for (int numTries = 0; numTries < attempts; numTries++)
            {
                try
                {
                    var directory = new DirectoryInfo(directoryName);
                    directory.Create();
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
        /// <param name="attempts">number of attemps</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in millisenconds)</param>
        /// <returns>True for successful</returns>
        public static bool FileMove(string source, string target, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50)
        {
            exception = null;
            if (File.Exists(source))
            {
                for (int numTries = 0; numTries < attempts; numTries++)
                {
                    try
                    {
                        File.Move(source, target);
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
        /// <param name="attempts">number of attemps</param>
        /// <param name="pauseBetweenAttempts">Pause in the file is busy, before a new attempt (in millisenconds)</param>
        /// <returns>True for successful</returns>
        public static bool FileCopy(string source, string target, out Exception exception, int attempts = 10, int pauseBetweenAttempts = 50)
        {
            exception = null;
            if (File.Exists(source))
            {
                for (int numTries = 0; numTries < attempts; numTries++)
                {
                    try
                    {
                        FileCopy(source, target);
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
        private static void FileCopy(string source, string target)
        {
            if (File.Exists(target))
                File.Delete(target);
            using (var outputStream = File.OpenWrite(target))
            {
                using (var inputStream = File.OpenRead(source))
                {
                    inputStream.CopyTo(outputStream);
                }
            }
        }
    }
}
