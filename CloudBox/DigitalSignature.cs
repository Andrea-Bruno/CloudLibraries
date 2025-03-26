using CloudSync;
using NBitcoin;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
namespace CloudBox
{
    /// <summary>
    /// Class that represents the digital signature on a file
    /// </summary>
    public class DigitalSignature
    {
        /// <summary>
        /// Empty constructor for deserialization purposes
        /// </summary>
        public DigitalSignature()
        {

        }

        /// <summary>
        /// Initiator that creates a digital signature of a document
        /// </summary>
        /// <param name="privateKey">Private key to sign the document</param>
        /// <param name="scopeOfSignature">The reason (the intentions), of whoever affixes the signature</param>
        /// <param name="fullFileName">The full path of the file (may be omitted if the file is specified in binary format). If this parameter is specified, then the digital signature will be automatically saved on disk (in the same path as the file to be signed)</param>
        /// <param name="file">The file in binary format on which to sign (optional, if omitted the full path of the file must be specified)</param>
        public DigitalSignature(byte[] privateKey, Scope scopeOfSignature, string fullFileName = null, byte[] file = null)
        {
            var key = new Key(privateKey);
            var publicKey = key.PubKey;
            PublicKey = publicKey.ToHex();
            var hash = file != null ? Hash256(file) : HashFile(fullFileName);
            Hash = hash.ToHex();
            var json = Json("http://api.blockcypher.com/v1/btc/main");
            json.TryGetValue("previous_url", out var jsonPreviusUrl);
            json = Json((string)jsonPreviusUrl);
            json.TryGetValue("prev_block_url", out jsonPreviusUrl);
            json = Json((string)jsonPreviusUrl);
            json.TryGetValue("prev_block_url", out jsonPreviusUrl);
            json = Json((string)jsonPreviusUrl);
            json.TryGetValue("prev_block_url", out jsonPreviusUrl);
            json = Json((string)jsonPreviusUrl);
            json.TryGetValue("hash", out var hashBlock);
            BlockchainHashBlock = (string)hashBlock;
            var blockchainHashBlock = BlockchainHashBlock.HexToBytes();
            ScopeOfSignature = scopeOfSignature;
            var signBase = new byte[] { Version }.Concat(publicKey.ToBytes()).Concat(hash).Concat(blockchainHashBlock).Concat([(byte)ScopeOfSignature]).ToArray();
            var hashBase = new uint256(Hash256(signBase));
            var signature = key.Sign(hashBase);
            Signature = signature.ToDER().ToHex();
            if (file == null)
            {
                var jsonSign = Save();
                File.WriteAllText(fullFileName + FileExtension(), jsonSign);
            }
        }

        /// <summary>
        /// The timestamp of the blockchain block (It is proof that the digital signature may have been placed in a more recent period than this date)
        /// </summary>
        /// <returns>Date time literal</returns>
        public DateTime BlockTime()
        {
            var json = Json("http://api.blockcypher.com/v1/btc/main/blocks/" + BlockchainHashBlock);
            json.TryGetValue("time", out var time);
            return (DateTime)time;
        }

        /// <summary>
        /// Digital signature version (format of digital signature)
        /// </summary>
        public byte Version = 0;
        /// <summary>
        /// Public key of the signer (hex format)
        /// </summary>
        public string PublicKey;
        /// <summary>
        /// Hash 256 of file (hex format)
        /// </summary>
        public string Hash;
        /// <summary>
        /// Hash of a recent block of the blockchain (hex format) to prove the existence of the file after a certain time (the closure of the block)
        /// </summary>
        public string BlockchainHashBlock;
        /// <summary>
        /// The reason why the signature was affixed
        /// </summary>
        public Scope ScopeOfSignature;
        /// <summary>
        /// Signature hex format (computed from the concatenation of all the above data, in the order as they appear, in binary format)
        /// </summary>
        public string Signature;

        /// <summary>
        /// Convert a json string into a digital signature object
        /// </summary>
        /// <param name="json"></param>
        /// <returns>Digital signature object</returns>
        public static DigitalSignature Load(string json)
        {
            var jsonDynamic = JsonConvert.DeserializeObject<DigitalSignature>(json);
            return jsonDynamic;
        }

        /// <summary>
        /// Convert a Digital signature object to json text format
        /// </summary>
        /// <returns>Json text</returns>
        public string Save()
        {
            var json = JsonConvert.SerializeObject(this);
            return json;
        }

        /// <summary>
        /// Validate the digital signature
        /// </summary>
        /// <param name="file"></param>
        /// <param name="fullFileName">The corresponding file In which the digital signature was placed</param>
        /// <returns>True if the digital signature is correct (not forged)</returns>
        public bool Validate(byte[] file = null, string fullFileName = null)
        {
            var hash = file != null ? Hash256(file) : HashFile(fullFileName);
            if (Hash != hash.ToHex())
                return false;
            var signBase = new byte[] { Version }.Concat(PublicKey.HexToBytes()).Concat(hash).Concat(BlockchainHashBlock.HexToBytes()).Concat([(byte)ScopeOfSignature]).ToArray();
            var hashBase = new uint256(Hash256(signBase));
            var publicKey = new PubKey(PublicKey.HexToBytes());
            return publicKey.Verify(hashBase, Signature.HexToBytes());
        }

        /// <summary>
        /// User ID of the person who affixed the signature
        /// </summary>
        /// <returns></returns>
        public ulong UserId()
        {
            return BitConverter.ToUInt64(Hash256(PublicKey.HexToBytes()), 0);
        }

        /// <summary>
        /// File extension with digital signature in the format .userId.sign.
        /// The digital signature file has the same name as the document file, plus this extension in addition.
        /// </summary>
        /// <returns>File extension</returns>
        public string FileExtension()
        {
            return "." + UserId() + ".sign";
        }

        private static readonly Dictionary<string, Tuple<DateTime, string>> JsonCache = [];

        private Dictionary<string, object> Json(string url)
        {
            string json = null;

            if (JsonCache.TryGetValue(url, out Tuple<DateTime, string> cache))
            {
                if (cache.Item1.AddMinutes(10) >= DateTime.UtcNow)
                    json = cache.Item2;
            }
            if (json == null)
            {
                using (WebClient wc = new WebClient())
                {
                    json = wc.DownloadString(url);
                }
                JsonCache[url] = new Tuple<DateTime, string>(DateTime.UtcNow, json);
            }
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
        }

        /// <summary>
        /// Compute hash 256
        /// </summary>
        /// <param name="data">Data base of hashing</param>
        /// <returns>Hash 256</returns>
        public static byte[] Hash256(byte[] data)
        {
            using SHA256 sha256Hash = SHA256.Create();
            // ComputeHash - returns byte array  
            return sha256Hash.ComputeHash(data);
        }

        /// <summary>
        /// Compute hash 256
        /// </summary>
        /// <param name="fileName">File name (full name, with path)</param>
        /// <returns>Hash 256</returns>
        public static byte[] HashFile(string fileName)
        {
            byte[] result;
            var sha = new SHA256CryptoServiceProvider();
            using (FileStream fs = File.OpenRead(fileName))
            {
                result = sha.ComputeHash(fs);
            }
            return result;
        }
        /// <summary>
        /// Valid reasons for signing (purpose of signing)
        /// </summary>
        public enum Scope : byte
        {
            /// <summary>
            /// Sign the document and I accept
            /// </summary>
            Accept,
            /// <summary>
            /// The document has been submitted to me but I do not approve it
            /// </summary>
            Reject,
            /// <summary>
            /// I have viewed the document without accepting or rejecting it
            /// </summary>
            Viewed,
        }

        /// <summary>
        /// Public key of the signer (base 64 format)
        /// </summary>
        [JsonIgnore]
        public string PublicKeyBase64
        {
            get
            {
                return Bytes.HexToBytes(PublicKey).ToBase64();
            }
        }

        /// <summary>
        /// Use date and time to set unix time stamp
        /// </summary>
        /// <param name="timeStamp"></param>
        public void SetTimestamp(DateTime timeStamp)
        {
            UnixTimeStamp = timeStamp.ToUnixTimestamp();
        }

        /// <summary>
        /// Timestamp self-declaration (optional)
        /// </summary>
        public int? UnixTimeStamp;
    }
}
