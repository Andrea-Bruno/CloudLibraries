using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace CloudSync
{
    public static partial class Util
    {
        /// <summary>
        /// An extension method to determine if an IP address is internal, as specified in RFC1918
        /// </summary>
        /// <param name="toTest">The IP address that will be tested</param>
        /// <returns>Returns true if the IP is internal, false if it is external</returns>
        public static bool IsLocalIPAddress(this IPAddress toTest)
        {
            if (IPAddress.IsLoopback(toTest)) return true;
            if (toTest.ToString() == "::1") return false;
            var bytes = toTest.GetAddressBytes();
            if (bytes.Length != 4) return false;

            uint A(byte[] bts)
            {
                Array.Reverse(bts);
                return BitConverter.ToUInt32(bts, 0);
            }

            bool Ir(uint ipReverse, byte[] start, byte[] end)
            {
                return (ipReverse >= A(start) && ipReverse <= A(end));
            } // Check if is in range

            var ip = A(bytes);
            // IP for special use: https://en.wikipedia.org/wiki/Reserved_IP_addresses             
            if (Ir(ip, [0, 0, 0, 0], [0, 255, 255, 255])) return true;
            if (Ir(ip, [10, 0, 0, 0], [10, 255, 255, 255])) return true;
            if (Ir(ip, [100, 64, 0, 0], [100, 127, 255, 255])) return true;
            if (Ir(ip, [127, 0, 0, 0], [127, 255, 255, 255])) return true;
            if (Ir(ip, [169, 254, 0, 0], [169, 254, 255, 255])) return true;
            if (Ir(ip, [172, 16, 0, 0], [172, 31, 255, 255])) return true;
            if (Ir(ip, [192, 0, 0, 0], [192, 0, 0, 255])) return true;
            if (Ir(ip, [192, 0, 2, 0], [192, 0, 2, 255])) return true;
            if (Ir(ip, [192, 88, 99, 0], [192, 88, 99, 255])) return true;
            if (Ir(ip, [192, 168, 0, 0], [192, 168, 255, 255])) return true;
            if (Ir(ip, [198, 18, 0, 0], [198, 19, 255, 255])) return true;
            if (Ir(ip, [198, 51, 100, 0], [198, 51, 100, 255])) return true;
            if (Ir(ip, [203, 0, 113, 0], [203, 0, 113, 255])) return true;
            if (Ir(ip, [224, 0, 0, 0], [239, 255, 255, 255])) return true;
            if (Ir(ip, [233, 252, 0, 0], [233, 252, 0, 255])) return true;
            if (Ir(ip, [240, 0, 0, 0], [255, 255, 255, 254])) return true;
            return false;
        }

        // =============== START FileSystemInfo extension ===============

        /// <summary>
        /// Returns the path of the path relative to the cloud location. If Zero Knowledge technology is enabled, then it returns the encrypted virtual path
        /// </summary>
        /// <param name="fileSystemInfo"></param>
        /// <param name="context">Relative path o virtual encrypted path</param>
        /// <returns></returns>
        public static string CloudRelativeUnixFullName(this FileSystemInfo fileSystemInfo, Sync context)
        {
            var name = fileSystemInfo.FullName[context.CloudRoot.Length..];
            name = name.Replace('\\', '/');
            if (name.Length != 0 && name[0] == '/')
                name = name.Substring(1);
            return context.ZeroKnowledgeProof == null || fileSystemInfo.Name.EndsWith(ZeroKnowledgeProof.EncryptFileNameEndChar) ? name : context.ZeroKnowledgeProof.EncryptFullFileName(name);
        }

        /// <summary>
        /// Return Utc last write timestamp
        /// </summary>
        /// <param name="fileSystemInfo"></param>
        /// <returns>Timestamp Utc</returns>
        public static uint UnixLastWriteTimestamp(this FileSystemInfo fileSystemInfo)
        {
            return fileSystemInfo is DirectoryInfo ? default : ToUnixTimestamp(fileSystemInfo.LastWriteTimeUtc);
            //return fileSystemInfo.Attributes.HasFlag(FileAttributes.Directory) ? 0 : ToUnixTimestamp(fileSystemInfo.LastWriteTimeUtc);
        }

        /// <summary>
        /// Returns the virtual name of the file if using zero knowledge technology, or the real name
        /// </summary>
        /// <param name="fileSystemInfo"></param>
        /// <returns>Virtual or real name</returns>
        public static string Name(this FileSystemInfo fileSystemInfo, Sync context)
        {
            return context.ZeroKnowledgeProof == null ? fileSystemInfo.Name : context.ZeroKnowledgeProof.EncryptFileName(fileSystemInfo.Name);
        }

        /// <summary>
        /// the first 32 bits from the right are the Unicode timestamp, the rest the hash on the full file name
        /// </summary>
        /// <param name="fileSystemInfo"></param>
        /// <returns></returns>
        public static ulong HashFileName(this FileSystemInfo fileSystemInfo, Sync context)
        {
            var relativeName = CloudRelativeUnixFullName(fileSystemInfo, context);
            return HashFileName(relativeName, fileSystemInfo is DirectoryInfo);
       
            // return HashFileName(relativeName, fileSystemInfo.Attributes.HasFlag(FileAttributes.Directory));
        }

        public static void Decrypt(this FileInfo encryptedFile, string outputFile, Sync context)
        {
            context.ZeroKnowledgeProof.DecryptFile(encryptedFile, outputFile);
        }

        // =============== END   FileSystemInfo extension ===============

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

    }
}