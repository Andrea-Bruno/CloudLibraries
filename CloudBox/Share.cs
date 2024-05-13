using CloudSync;
using EncryptedMessaging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

namespace CloudBox
{
    /// <summary>
    /// A set of features useful for file sharing. These functions allow you to share files to those who do not have an account in the cloud, using the encrypted web interface and creating groups of files
    /// </summary>
    static public class Share
    {
      
        /// <summary>
        /// Generate the file sharing link inherent to the group you have selected.
        /// Give this link to the person with whom you would like to share files belonging to this group!
        /// </summary>
        /// <returns></returns>
        public static string GenerateSharingLink(CloudBox cloudBox = null, string qr = null)
        {
            if (cloudBox.IsServer)
            {
                throw new Exception("QR parameter omitted!");
            }
            qr = cloudBox?.Context.SecureStorage.Values.Get("QR", null);
            if (qr == null)
                qr = cloudBox?.Context.SecureStorage.Values.Get("ServerPublicKey", null);
            if (qr == null)
                throw new Exception("You must first connect this client to the cloud!");
            if (!CloudBox.SolveQRCode(qr, out string entryPoint, out _, out _))
                throw new Exception("Invalid QR code!");
            if (entryPoint == null)
                throw new Exception("Missing proxy entry point in QR code");
            new string[] { "server.", "test." }.ToList().ForEach(x =>
            {
                if (entryPoint.StartsWith(x))
                {
                    var proxy = entryPoint.Replace(x, "proxy.");
                    try
                    {
                        if (Dns.GetHostAddresses(proxy).Length > 0)
                            entryPoint = proxy;
                    }
                    catch (Exception)
                    {
                        throw new Exception("Check your internet connection!");
                    }
                }
            });
            var proxyUrl = "http://" + entryPoint + ":5050/proxyinfo";
            var proxyAddress = proxyUrl + "?ping";
            System.Net.WebClient wc = new WebClient();
            string result = wc.DownloadString(proxyAddress);
            if (result != "ok")
                throw new Exception("The encrypted proxy is unreachable, or the cloud does not have the proxy!");
            proxyUrl += "?qr=" + qr;
            return "The link to access shared files is: " + proxyUrl + Environment.NewLine + "The pin is: " + Environment.NewLine + "Attention: Provide links and pins using different communication systems!";
        }
    }
}
