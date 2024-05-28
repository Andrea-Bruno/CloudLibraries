using CloudSync;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace CloudSync
{
    /// <summary>
    /// A set of features useful for file sharing. These functions allow you to share files to those who do not have an account in the cloud, using the encrypted web interface and creating groups of files
    /// </summary>
    static public class Share
    {
        private static List<string> GetRecords(string cloudPath, string sharingGroup, out string shareSettingFile, bool removeComment = false)
        {
            if (string.IsNullOrEmpty(sharingGroup))
                sharingGroup = "generic";
            sharingGroup = sharingGroup.ToLower();
            shareSettingFile = Path.Combine(cloudPath, sharingGroup + ".share");
            var lines = new List<string>();
            if (File.Exists(shareSettingFile))
            {
                lines.AddRange(File.ReadLines(shareSettingFile));
            }
            if (removeComment)
            {
                lines = lines.FindAll(x => !x.StartsWith("#"));
            }
            return lines;
        }

        /// <summary>
        /// Get all groups
        /// </summary>
        /// <param name="cloudPath">Path of cloud</param>
        public static string[] GetGroups(string cloudPath)
        {
            var result = new List<string>();
            foreach (var item in Directory.GetFiles(cloudPath, "*.share", SearchOption.TopDirectoryOnly))
            {
                result.Add(Path.GetFileNameWithoutExtension(item));
            };
            if (result.Count == 0)
                result.Add("generic");
            return result.ToArray();
        }

        /// <summary>
        /// Return all shared file in a specific group
        /// </summary>
        /// <param name="cloudPath">Path of cloud</param>
        /// <param name="sharingGroup">Group name</param>
        /// <returns></returns>
        public static List<string> GetSharedFiles(string cloudPath, string sharingGroup)
        {
            return GetRecords(cloudPath, sharingGroup, out string _, true);
        }

        /// <summary>
        /// Add the file to the sharing group
        /// </summary>
        /// <param name="cloudPath">Path of cloud</param>
        /// <param name="sharingGroup">Group name</param>
        /// <param name="fileToShare">Full name file relative to cloudPath of file to share</param>
        public static void AddShareFile(string cloudPath, string sharingGroup, string fileToShare)
        {
            if (string.IsNullOrEmpty(fileToShare))
            {
                throw new Exception("You must first search for a file and select from the list");
            }
            if (!File.Exists(Path.Combine(cloudPath, fileToShare)))
            {
                throw new Exception("the file does not exist: " + fileToShare);
            }
            var lines = GetRecords(cloudPath, sharingGroup, out string ShareSettingFile);
            if (lines.Count == 0)
            {
                lines.Add("# Guid=" + Guid.NewGuid());
                lines.Add("# List of shared files.");
                lines.Add("# Edit this list to add or remove shared files!");
                lines.Add("# This file refers to the group with the name of this file + (.share), the file path names must be in Unix format, and the file must be located in the root of the cloud path.");
            }
            var fileToAdd = fileToShare.Replace('\\', '/');
            if (!lines.Contains(fileToAdd))
            {
                lines.Add(fileToAdd);
            }
            File.WriteAllLines(ShareSettingFile, lines);
        }

        /// <summary>
        /// Generate a 10 character pin using the file group guid as the seed
        /// </summary>
        /// <param name="cloudPath">Path of cloud</param>
        /// <param name="sharingGroup">Group name</param>
        /// <param name="date">Day on which the pin is valid</param>
        /// <returns></returns>
        public static string GetPin(string cloudPath, string sharingGroup, DateTime? date = null)
        {
            var records = GetRecords(cloudPath, sharingGroup, out string _);
            if (records == null)
                throw new Exception("Undefined file group!");
            var record = records.FirstOrDefault(x => x.StartsWith("# Guid="));
            if (record == null)
                throw new Exception("File group without Guid!");
            var guid = Guid.Parse(record.Split('=')[1]);
            if (date == null)
                date = DateTime.UtcNow;
            var days = ((DateTime)date).Ticks / (24L * 60L * 60L * 10000000L); // Math.floor() rounds a number downwards to the nearest whole integer, which in this case is the value representing the day
            var week = days / 7;
            using (HashAlgorithm algorithm = SHA256.Create())
            {
                var random = algorithm.ComputeHash(guid.ToByteArray().Concat(BitConverter.GetBytes(week)));
                var val = BitConverter.ToUInt64(random, 0);
                var numBase = "000000000" + val;
                return numBase.Substring(numBase.Length - 9);
            }
        }

        /// <summary>
        /// Return the last 2 pins for validation purposes
        /// </summary>
        /// <param name="cloudPath">Path of cloud</param>
        /// <param name="sharingGroup">Group name</param>
        /// <returns>If the pin is valid and not expired it returns true</returns>
        internal static List<string> GetPins(string cloudPath, string sharingGroup)
        {
            return new List<string>
            {
                GetPin(cloudPath, sharingGroup),
                GetPin(cloudPath, sharingGroup, DateTime.UtcNow.AddDays(-7))
            };
        }

        /// <summary>
        /// Remove a file from a group
        /// </summary>
        /// <param name="cloudPath">Path of cloud</param>
        /// <param name="sharingGroup">Group name</param>
        /// <param name="toRemove">File to remove</param>
        public static void RemoveSharedFile(string cloudPath, string sharingGroup, string toRemove)
        {
            var lines = GetRecords(cloudPath, sharingGroup, out string ShareSettingFile);
            lines = lines.FindAll(x => x != toRemove);
            File.WriteAllLines(ShareSettingFile, lines);
        }
    }
}
