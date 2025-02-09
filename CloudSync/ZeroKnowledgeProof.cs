using Blake2Fast;
using NBitcoin.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CloudSync
{
    internal class ZeroKnowledgeProof
    {
        /// <summary>
        /// Initializes the instance that is responsible for providing Zero Knowledge Proof support
        /// </summary>
        /// <param name="context">Sync context</param>
        /// <param name="encryptionMasterKey">Used for zero knowledge proof, meaning files will be sent encrypted with keys derived from this, and once received, if encrypted, they will be decrypted.</param>
        internal ZeroKnowledgeProof(Sync context, byte[] encryptionMasterKey)
        {
            Context = context;
            lock (Util.Sha256) // ComputeHash in one case has generate StackOverFlow error, i try to fix by lock the instance
                FilenameObfuscationKey = Util.Hash256(encryptionMasterKey); // 32 bytes
            EncryptionMasterKey = Blake2b.ComputeHash(encryptionMasterKey.Concat(FilenameObfuscationKey)); // 64 bytes
        }
        Sync Context;

        /// <summary>
        /// Do not use directly, use DerivedEncryptionKey instead
        /// </summary>
        private byte[] EncryptionMasterKey;

        /// <summary>
        /// 32 bytes of cryptographic key used to obfuscate file names
        /// </summary>
        internal byte[] FilenameObfuscationKey;

        internal byte[] DerivedEncryptionKey(FileInfo file)
        {
            var relativeName = file.CloudRelativeUnixFullName(Context);
            var bytes = relativeName.GetBytes();
            var len = BitConverter.GetBytes((ulong)bytes.Length);
            var date = file.UnixLastWriteTimestamp().GetBytes();
            var concat = new byte[len.Length + bytes.Length + date.Length + EncryptionMasterKey.Length];
            var offset = 0;
            Buffer.BlockCopy(bytes, 0, concat, offset, bytes.Length);
            offset += bytes.Length;
            Buffer.BlockCopy(len, 0, concat, offset, len.Length);
            offset += len.Length;
            Buffer.BlockCopy(date, 0, concat, offset, date.Length);
            offset += date.Length;
            Buffer.BlockCopy(EncryptionMasterKey, 0, concat, offset, EncryptionMasterKey.Length);
            return Blake2b.ComputeHash(concat);
        }

        /// <summary>
        /// Encrypts or decrypts a file using a key derived from recursive hashing and XOR.
        /// This method processes data in 8-byte (64-bit) blocks and computes the hash every 8 cycles.
        /// </summary>
        /// <param name="inputFile">The input file to process.</param>
        /// <param name="outputFile">The output file to store the result.</param>
        /// <param name="key">The encryption/decryption key.</param>
        public static void EncryptFile(FileInfo inputFile, string outputFile, byte[] key)
        {
            // Validate parameters
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));
            if (key == null || key.Length != 64)
                throw new ArgumentException("Key must be 64 bytes.", nameof(key));

            // Block size (8 bytes for ulong)
            const int blockSize = 8;

            // Number of cycles before recomputing the hash
            const int cyclesPerHash = 8; // Optimized for Blake2b 64 bit

            // Buffers for input and output data
            byte[] inputBuffer = new byte[blockSize];
            byte[] outputBuffer = new byte[blockSize];

            // Initialize the seal and current key using Blake2b
            byte[] sealt = Blake2b.ComputeHash(key);
            byte[] currentKey = Blake2b.ComputeHash(sealt);

            using (FileStream inputStream = inputFile.OpenRead())
            using (FileStream outputStream = File.Create(outputFile))
            {
                int cycleCounter = 0;
                int bytesRead;
                while ((bytesRead = inputStream.Read(inputBuffer, 0, blockSize)) > 0)
                {
                    // Convert the input buffer and current key to ulong for XOR operation
                    ulong inputBlock = BitConverter.ToUInt64(inputBuffer, 0);
                    ulong keyBlock = BitConverter.ToUInt64(currentKey, cycleCounter * blockSize);

                    // Perform XOR on 8-byte blocks
                    ulong outputBlock = inputBlock ^ keyBlock;

                    // Convert the result back to bytes
                    byte[] outputBytes = BitConverter.GetBytes(outputBlock);
                    Array.Copy(outputBytes, outputBuffer, bytesRead);

                    // Write the processed data to the output file
                    outputStream.Write(outputBuffer, 0, bytesRead);

                    // Update the cycle counter
                    cycleCounter++;

                    // Recompute the hash every 8 cycles
                    if (cycleCounter >= cyclesPerHash)
                    {
                        currentKey = Blake2b.ComputeHash(sealt, currentKey);
                        cycleCounter = 0;
                    }
                }
            }
        }


        /// <summary>
        /// Decrypts a file using a key derived from recursive hashing and XOR.
        /// This method processes data in 8-byte (64-bit) blocks and computes the hash every 8 cycles.
        /// </summary>
        /// <param name="inputFile">The encrypted file to decrypt.</param>
        /// <param name="outputFile">The output file to store the decrypted file.</param>
        /// <param name="key">The encryption/decryption key.</param>
        public static void DecryptFile(FileInfo inputFile, string outputFile, byte[] key) => EncryptFile(inputFile, outputFile, key);


        private const int IvSize = 16; // AES block size (128 bits)
        private const CipherMode EncryptionMode = CipherMode.CFB;

        public static string EncryptFullFileName(string fullFileName, byte[] key)
        {
            var result = new List<string>();
            var parts = fullFileName.Split(new char[] { '/', '\\' });
            foreach (var part in parts)
            {
                result.Add(EncryptFullFileName(part, key));
            }
            return string.Join('/', result);
        }

        /// <summary>
        /// Encrypts a filename while preserving format constraints
        /// </summary>
        /// <param name="fileName">Valid input filename</param>
        /// <param name="key">Encryption key (must be valid AES key length: 16, 24, or 32 bytes)</param>
        /// <returns>Encrypted filename with preserved leading dot and valid format</returns>
        public static string EncryptFileName(string fileName, byte[] key)
        {
            if (string.IsNullOrEmpty(fileName))
                return fileName;
            bool hasLeadingDot = fileName.StartsWith('.');
            string namePart = hasLeadingDot ? fileName[1..] : fileName;

            byte[] nameBytes = Encoding.UTF8.GetBytes(namePart);
            byte[] iv = GenerateSecureIV();
            byte[] encryptedBytes = PerformEncryption(nameBytes, key, iv);

            string encoded = Base64UrlEncode(iv.Concat(encryptedBytes).ToArray());
            return FormatEncryptedFilename(encoded, hasLeadingDot);
        }

        /// <summary>
        /// Decrypts an encrypted filename back to original
        /// </summary>
        /// <param name="encryptedFileName">Encrypted filename</param>
        /// <param name="key">Original encryption key</param>
        /// <returns>Original decrypted filename</returns>
        public static string DecryptFileName(string encryptedFileName, byte[] key)
        {
            if (string.IsNullOrEmpty(encryptedFileName))
                return encryptedFileName;
            bool hasLeadingDot = encryptedFileName.StartsWith('.');
            string encodedPart = hasLeadingDot ? encryptedFileName[1..] : encryptedFileName;

            byte[] combined = Base64UrlDecode(encodedPart);
            ValidateCombinedData(combined);

            byte[] iv = combined.Take(IvSize).ToArray();
            byte[] ciphertext = combined.Skip(IvSize).ToArray();

            byte[] decryptedBytes = PerformDecryption(ciphertext, key, iv);
            return FormatDecryptedFilename(decryptedBytes, hasLeadingDot);
        }

        private static byte[] GenerateSecureIV()
        {
            using var rng = RandomNumberGenerator.Create();
            byte[] iv = new byte[IvSize];
            rng.GetBytes(iv);
            return iv;
        }

        private static byte[] PerformEncryption(byte[] data, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = EncryptionMode;
            aes.Padding = PaddingMode.None;

            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        private static byte[] PerformDecryption(byte[] ciphertext, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = EncryptionMode;
            aes.Padding = PaddingMode.None;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }

        private static string FormatEncryptedFilename(string encoded, bool hasLeadingDot)
        {
            // Ensure valid filename by removing any potential trailing spaces
            string trimmed = encoded.TrimEnd(' ');
            return hasLeadingDot
                ? $".{trimmed}"
                : trimmed;
        }

        private static string FormatDecryptedFilename(byte[] decryptedBytes, bool hasLeadingDot)
        {
            string namePart = Encoding.UTF8.GetString(decryptedBytes);
            return hasLeadingDot
                ? $".{namePart}"
                : namePart;
        }

        private static void ValidateCombinedData(byte[] combined)
        {
            if (combined.Length < IvSize)
            {
                throw new ArgumentException("Invalid encrypted data format");
            }
        }

        private static string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }

        private static byte[] Base64UrlDecode(string input)
        {
            string incoming = input
                .Replace('-', '+')
                .Replace('_', '/');

            switch (input.Length % 4)
            {
                case 2: incoming += "=="; break;
                case 3: incoming += "="; break;
            }

            return Convert.FromBase64String(incoming);
        }
    }
}

