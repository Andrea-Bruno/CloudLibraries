using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

namespace CloudSync
{
    /// <summary>
    /// A set of features useful for file sharing. These functions allow you to share files to those who do not have an account in the cloud, using the encrypted web interface and creating groups of files
    /// </summary>
    public class Share
    {
        public Share(Sync context)
        {
            Context = context;
        }
        private Sync Context;
        private string AppData => Context.AppDataPath;

        private List<string> GetRecords(string sharingGroup, out string shareSettingFile, bool removeComment = false)
        {

            if (string.IsNullOrEmpty(sharingGroup))
                sharingGroup = "generic";
            sharingGroup = sharingGroup.ToLower();
            shareSettingFile = Path.Combine(AppData, sharingGroup + ".share");
            var lines = new List<string>();
            if (File.Exists(shareSettingFile))
            {
                lines.AddRange(File.ReadLines(shareSettingFile));
            }
            if (removeComment)
            {
                lines = lines.FindAll(x => !x.StartsWith("#"));
            }
            for (int i = 0; i < lines.Count; i++)
            {
                string line = lines[i];
                if (!line.StartsWith("#"))
                {
                    lines[i] = Context.ZeroKnowledgeProof.DecryptFullFileName(line);
                }
            }
            return lines;
        }

        /// <summary>
        /// Get all groups
        /// </summary>
        public string[] GetGroups()
        {
            var result = new List<string>();
            foreach (var item in Directory.GetFiles(AppData, "*.share", SearchOption.TopDirectoryOnly))
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
        /// <param name="sharingGroup">Group name</param>
        /// <returns></returns>
        public List<string> GetSharedFiles(string sharingGroup)
        {
            return GetRecords(sharingGroup, out string _, true);
        }

        /// <summary>
        /// Add the file to the sharing group
        /// </summary>
        /// <param name="sharingGroup">Group name</param>
        /// <param name="fileToShare">Full name file relative to cloudPath of file to share</param>
        public void AddShareFile(string sharingGroup, string fileToShare)
        {
            if (string.IsNullOrEmpty(fileToShare))
            {
                throw new Exception("You must first search for a file and select from the list");
            }
            if (!File.Exists(Path.Combine(AppData, fileToShare)))
            {
                throw new Exception("the file does not exist: " + fileToShare);
            }
            var lines = GetRecords(sharingGroup, out string ShareSettingFile);
            if (lines.Count == 0)
            {
                lines.Add("# Guid=" + Guid.NewGuid());
                lines.Add("# List of shared files.");
                lines.Add("# Edit this list to add or remove shared files!");
                lines.Add("# This file refers to the group with the name of this file + (.share), the file path names must be in Unix format, and the file must be located in the root of the cloud path.");
            }
            var fileToAdd = fileToShare.Replace('\\', '/');
            fileToAdd = Context.ZeroKnowledgeProof.EncryptFileName(fileToAdd);
            if (!lines.Contains(fileToAdd))
            {
                lines.Add(fileToAdd);
            }

            var appDataPath = new DirectoryInfo(AppData);
            if (!appDataPath.Exists)
            {
                Util.DirectoryCreate(AppData, Context.Owner, out _);
                appDataPath.Refresh();
                appDataPath.Attributes |= FileAttributes.Hidden;
            }
            File.WriteAllLines(ShareSettingFile, lines);
        }

        /// <summary>
        /// Generate a 10 character pin using the file group guid as the seed
        /// </summary>
        /// <param name="sharingGroup">Group name</param>
        /// <param name="date">Day on which the pin is valid</param>
        /// <returns></returns>
        public string GetPin(string sharingGroup, DateTime? date = null)
        {
            var records = GetRecords(sharingGroup, out string _);
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
        /// <param name="sharingGroup">Group name</param>
        /// <returns>If the pin is valid and not expired it returns true</returns>
        internal List<string> GetPins(string sharingGroup)
        {
            return new List<string>
            {
                GetPin(sharingGroup),
                GetPin(sharingGroup, DateTime.UtcNow.AddDays(-7))
            };
        }

        /// <summary>
        /// Remove a file from a group
        /// </summary>
        /// <param name="sharingGroup">Group name</param>
        /// <param name="toRemove">File to remove</param>
        public void RemoveSharedFile(string sharingGroup, string toRemove)
        {
            var lines = GetRecords(sharingGroup, out string ShareSettingFile);
            lines = lines.FindAll(x => x != toRemove);
            File.WriteAllLines(ShareSettingFile, lines);
        }


        /// <summary>
        /// Generate the file sharing link inherent to the group you have selected.
        /// Give this link to the person with whom you would like to share files belonging to this group!
        /// </summary>
        /// <param name="sharingGroup">Group name</param>
        /// <param name="entryPoint">Proxy entry point</param>
        /// <param name="qr">QR code</param>
        /// <returns>Info about Link and Pin to sharing the files of the group</returns>
        public string GenerateSharingLink(string sharingGroup, Uri entryPoint, string qr)
        {         
            if (entryPoint == null)
                throw new Exception("Missing proxy entry point in QR code");
            
            var entryPointString = entryPoint.ToString();
            new string[] { "server.", "test." }.ToList().ForEach(x =>
            {
                if (entryPointString.StartsWith(x))
                {
                    var proxy = entryPointString.Replace(x, "proxy.");
                    try
                    {
                        if (Dns.GetHostAddresses(proxy).Length > 0)
                            entryPointString = proxy;
                    }
                    catch (Exception)
                    {
                        throw new Exception("Check your internet connection!");
                    }
                }
            });
            var proxyUrl = "http://" + entryPointString + ":5050/proxyinfo";
            var proxyAddress = proxyUrl + "?ping";
            WebClient wc = new WebClient();
            string result = wc.DownloadString(proxyAddress);
            if (result != "ok")
                throw new Exception("The encrypted proxy is unreachable, or the cloud does not have the proxy!");
            proxyUrl += "?qr=" + qr;
            return "The link to access shared files is: " + proxyUrl + Environment.NewLine + "The pin is: " + Context.Share.GetPin(sharingGroup) + Environment.NewLine + "Attention: Provide links and pins separately using different communication systems!";
        }
    }
}
