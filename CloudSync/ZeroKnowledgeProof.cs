using Blake2Fast;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        internal byte[] DerivedEncryptionKey(FileInfo file, uint unixLastWriteTimestamp = default)
        {
            unixLastWriteTimestamp = unixLastWriteTimestamp != default ? unixLastWriteTimestamp : file.UnixLastWriteTimestamp();
            var relativeName = file.CloudRelativeUnixFullName(Context);
            var bytes = relativeName.GetBytes();
            var len = BitConverter.GetBytes((ulong)bytes.Length);
            var date = unixLastWriteTimestamp.GetBytes();
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
        private static void EncryptFile(FileInfo inputFile, string outputFile, byte[] key)
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

            // Initialize the seal and current key using Blake2b
            byte[] sealt = Blake2b.ComputeHash(key);
            byte[] currentKey = Blake2b.ComputeHash(sealt);

            using FileStream inputStream = inputFile.OpenRead();
            using FileStream outputStream = File.Create(outputFile);
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

                // Write the processed data to the output file
                outputStream.Write(outputBytes, 0, bytesRead);

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

        /// <summary>
        /// Decrypts a file using a key derived from recursive hashing and XOR.
        /// This method processes data in 8-byte (64-bit) blocks and computes the hash every 8 cycles.
        /// </summary>
        /// <param name="inputFile">The encrypted file to decrypt.</param>
        /// <param name="outputFile">The output file to store the decrypted file.</param>
        /// <param name="key">The encryption/decryption key.</param>
        private static void DecryptFile(FileInfo inputFile, string outputFile, byte[] key) => EncryptFile(inputFile, outputFile, key);

        /// <summary>
        /// Encrypts or decrypts a file using a key derived from recursive hashing and XOR.
        /// This method processes data in 8-byte (64-bit) blocks and computes the hash every 8 cycles.
        /// </summary>
        /// <param name="inputFile">The input file to process.</param>
        /// <param name="outputFile">The output file to store the result.</param>
        public void EncryptFile(FileInfo inputFile, string outputFile)
        {
            EncryptFile(inputFile, outputFile, DerivedEncryptionKey(inputFile));
        }

        /// <summary>
        /// Encrypts or decrypts a chunk of data at a specific byte offset within a file stream.
        /// This allows individual file chunks to be encrypted independently while maintaining
        /// consistency with the full-file <see cref="EncryptFile(FileInfo, string)"/> encryption,
        /// enabling seekable access to the XOR stream cipher at any file position.
        /// The operation is symmetric: applying it twice returns the original data.
        /// </summary>
        /// <param name="data">The chunk data to encrypt or decrypt.</param>
        /// <param name="file">The source file, used to derive the per-file encryption key.</param>
        /// <param name="byteOffset">The byte offset of this chunk within the original file stream.</param>
        /// <returns>The encrypted (or decrypted) chunk data of the same length as the input.</returns>
        public byte[] EncryptChunk(byte[] data, FileInfo file, long byteOffset)
        {
            return EncryptChunk(data, DerivedEncryptionKey(file), byteOffset);
        }

        /// <summary>
        /// Encrypts or decrypts a chunk of data starting at the specified byte offset within the key stream.
        /// Seeks to the correct position in the XOR key stream before processing so that chunks
        /// can be encrypted individually and remain consistent with full-file encryption.
        /// </summary>
        /// <param name="data">The chunk data to process.</param>
        /// <param name="key">The 64-byte encryption key.</param>
        /// <param name="byteOffset">The byte offset of the chunk within the file stream.</param>
        /// <returns>The processed chunk data.</returns>
        private static byte[] EncryptChunk(byte[] data, byte[] key, long byteOffset)
        {
            if (data == null || data.Length == 0)
                return data;
            if (key == null || key.Length != 64)
                throw new ArgumentException("Key must be 64 bytes.", nameof(key));

            // Block size (8 bytes for ulong)
            const int blockSize = 8;

            // Number of cycles before recomputing the hash
            const int cyclesPerHash = 8;

            // Initialize the seal and key stream using Blake2b (same as EncryptFile)
            byte[] sealt = Blake2b.ComputeHash(key);
            byte[] currentKey = Blake2b.ComputeHash(sealt);

            // Seek to the correct position in the key stream for this chunk's byte offset.
            // This requires iterating through hash cycles sequentially; for very large files
            // the seek cost grows linearly with the chunk position. In practice, the chunk size
            // is 1 MB so seek cost for a given file is bounded by file_size / (blockSize * cyclesPerHash).
            long startBlock = byteOffset / blockSize;
            long hashCycle = startBlock / cyclesPerHash;
            int cycleCounter = (int)(startBlock % cyclesPerHash);

            for (long i = 0; i < hashCycle; i++)
                currentKey = Blake2b.ComputeHash(sealt, currentKey);

            byte[] inputBuffer = new byte[blockSize];
            byte[] result = new byte[data.Length];

            for (int i = 0; i < data.Length; i += blockSize)
            {
                int bytesAvailable = Math.Min(blockSize, data.Length - i);

                // Zero-pad the input buffer, then copy available bytes
                Array.Clear(inputBuffer, 0, blockSize);
                Buffer.BlockCopy(data, i, inputBuffer, 0, bytesAvailable);

                // Perform XOR on 8-byte blocks
                ulong inputBlock = BitConverter.ToUInt64(inputBuffer, 0);
                ulong keyBlock = BitConverter.ToUInt64(currentKey, cycleCounter * blockSize);
                ulong outputBlock = inputBlock ^ keyBlock;

                byte[] outputBytes = BitConverter.GetBytes(outputBlock);
                Buffer.BlockCopy(outputBytes, 0, result, i, bytesAvailable);

                cycleCounter++;
                if (cycleCounter >= cyclesPerHash)
                {
                    currentKey = Blake2b.ComputeHash(sealt, currentKey);
                    cycleCounter = 0;
                }
            }

            return result;
        }

        /// <summary>
        /// Decrypts a file using a key derived from recursive hashing and XOR.
        /// This method processes data in 8-byte (64-bit) blocks and computes the hash every 8 cycles.
        /// </summary>
        /// <param name="inputFile">The encrypted file to decrypt.</param>
        /// <param name="outputFile">The output file to store the decrypted file.</param>
        public void DecryptFile(FileInfo inputFile, string outputFile)
        {
            DecryptFile(inputFile, outputFile, DerivedEncryptionKey(new FileInfo(outputFile), inputFile.UnixLastWriteTimestamp()));
        }


        public string EncryptFullFileName(string fullFileName) => EncryptFullFileName(fullFileName, FilenameObfuscationKey);

        public static string EncryptFullFileName(string fullFileName, byte[] key)
        {
            var result = new List<string>();
            var parts = fullFileName.Split(['/', '\\']);
            var clearFolder = false;
            foreach (var part in parts)
            {
                if (Util.SpecialDirectories.Contains(part))
                    clearFolder = true;
                result.Add(clearFolder ? part : EncryptFileName(part, key));
            }
            return string.Join('/', result);
        }

        public string DecryptFullFileName(string fullFileName) => DecryptFullFileName(fullFileName, FilenameObfuscationKey);

        public static string DecryptFullFileName(string fullFileName, byte[] key)
        {
            var result = new List<string>();
            var parts = fullFileName.Split(['/', '\\']);
            var clearFolder = false;
            foreach (var part in parts)
            {
                if (Util.SpecialDirectories.Contains(part))
                    clearFolder = true;
                result.Add(clearFolder ? part : DecryptFileName(part, key));
            }
            return string.Join('/', result);
        }

        public string EncryptFileName(string fullFileName) => EncryptFileName(fullFileName, FilenameObfuscationKey);


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
            var encryptName = PerformEncrtptText(namePart, key);
            return hasLeadingDot ? "." : "" + encryptName + EncryptFileNameEndChar;
        }

        public string DecryptFileName(string fullFileName) => DecryptFileName(fullFileName, FilenameObfuscationKey);


        /// <summary>
        /// Decrypts an encrypted filename back to original
        /// </summary>
        /// <param name="encryptedFileName">Encrypted filename</param>
        /// <param name="key">Original encryption key</param>
        /// <returns>Original decrypted filename</returns>
        public static string DecryptFileName(string encryptedFileName, byte[] key)
        {
            if (!encryptedFileName.EndsWith(EncryptFileNameEndChar))
                return encryptedFileName;
            else
                encryptedFileName = encryptedFileName[..^1]; // Remove last char
            if (string.IsNullOrEmpty(encryptedFileName))
                return encryptedFileName;
            bool hasLeadingDot = encryptedFileName.StartsWith('.');
            string encodedPart = hasLeadingDot ? encryptedFileName[1..] : encryptedFileName;
            var namePart = PerformDecryptText(encodedPart, key);
            return hasLeadingDot ? "." : "" + namePart;
        }

        public const char EncryptFileNameEndChar = '⁇';

        private const string Set256Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĹĺĻļĽľŁłŃńŅņŇňŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžǍǎǏǐǑǒǓǔǕǖǗ";

        private static string PerformEncrtptText(string text, byte[] key)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            var masterKey = key.Concat([(byte)bytes.Length]);
            var masc = new byte[0];
            do
            {
                masterKey = Blake2b.ComputeHash(masterKey);
                masc = masc.Concat(masterKey);
            } while (masc.Length < bytes.Length);
            var result = new StringBuilder(bytes.Length);
            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];
                result.Append(Set256Chars[b ^ masc[i]]);
            }
            return result.ToString();
        }
        private static Dictionary<char, byte> DecryptHelper = null;
        private static string PerformDecryptText(string text, byte[] key)
        {
            lock (Set256Chars)
            {
                if (DecryptHelper == null)
                {
                    var helper = new Dictionary<char, byte>();
                    var len = Set256Chars.ToCharArray().Length;
                    for (int i = 0; i < len; i++)
                    {
                        helper.Add(Set256Chars[i], (byte)i);
                    }
                    DecryptHelper = helper;
                }
            }
            var bytes = new byte[text.Length];
            var masterKey = key.Concat([(byte)bytes.Length]);
            var masc = new byte[0];
            do
            {
                masterKey = Blake2b.ComputeHash(masterKey);
                masc = masc.Concat(masterKey);
            } while (masc.Length < bytes.Length);
            for (int i = 0; i < bytes.Length; i++)
            {
                var b = DecryptHelper[text[i]];
                var m = masc[i];
                bytes[i] = (byte)(b ^ m);
            }
            return Encoding.UTF8.GetString(bytes);
        }
    }
}

