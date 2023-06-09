using System;

namespace CloudBox
{
    /// <summary>
    /// A powerful encryption type, which can be implemented easily on 32-bit JavaScript platforms
    /// Encryption algorithm oriented to JavaScript and C#, allows fast and secure encryption and decryption, works with any size of keys and data.
    /// </summary>
    public static class EncryptionXorAB
    {
        /// <summary>
        /// Encrypt a data package with a key
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="data">Data</param>
        /// <returns></returns>
        public static byte[] Encryp(byte[] key, byte[] data)
        {
            var k = (byte[])key.Clone();
            var length = data.Length;
            var newsize = (int)Math.Ceiling(length / 8d) * 8;
            var dt = new byte[newsize];
            Array.Copy(data, dt, length);
            if (k.Length < 4)
                Array.Resize(ref k, 4);
            Array.Copy(BitConverter.GetBytes(length ^ BitConverter.ToInt32(k, 0)), 0, k, 0, 4);
            var result = new byte[dt.Length];
            for (var i = 0; i < dt.Length; i += 8)
            {
                var p = i % k.Length / 8;
                if (p == 0)
                {
                    k = FastHash256(k);
                }
                var part = BitConverter.GetBytes(BitConverter.ToUInt64(dt, i) ^ BitConverter.ToUInt64(k, p * 8));
                Array.Copy(part, 0, result, i, 8);
            }
            Array.Resize(ref result, length);
            return result;
        }

        /// <summary>
        /// Decrypts a data packet with a key used for encryption
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="encryptedData">Encrypted data</param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] key, byte[] encryptedData)
        {
            return Encryp(key, encryptedData);
        }

        /// <summary>
        /// Fast hashing algorithm that is easy to implement in JavaScript and C#, and works well even on 32-bit systems
        /// </summary>
        /// <param name="data">Data package object of the computation</param>
        /// <returns>Hash256 data</returns>
        public static byte[] FastHash256(byte[] data)
        {
            var dl = data.Length;
            var newLength = (int)Math.Ceiling(data.Length / 32d) * 32;
            var bytes = new byte[newLength];
            Array.Copy(data, bytes, dl);
            var p0 = 0b01010101_01010101_01010101_01010101;
            var p1 = 0b00110011_00110011_00110011_00110011;
            var p2 = 0b00100100_10010010_00100100_10010010;
            var p3 = 0b00011100_01110001_11000111_00011100;
            var p4 = p0 ^ -1;
            var p5 = p1 ^ -1;
            var p6 = p2 ^ -1;
            var p7 = p3 ^ -1;
            //int x = (bl * 1103515245 + 12345) & 0x7fffffff;
            var x = dl ^ 0x55555555;
            x ^= x << (1 + dl % 30);
            x ^= 0x55555555;
            x ^= x >> (1 + dl % 29);

            for (var i = 0; i < bytes.Length; i += 32)
            {
                var v0 = BitConverter.ToInt32(bytes, i);
                var v1 = BitConverter.ToInt32(bytes, i + 4);
                var v2 = BitConverter.ToInt32(bytes, i + 8);
                var v3 = BitConverter.ToInt32(bytes, i + 12);
                var v4 = BitConverter.ToInt32(bytes, i + 16);
                var v5 = BitConverter.ToInt32(bytes, i + 20);
                var v6 = BitConverter.ToInt32(bytes, i + 24);
                var v7 = BitConverter.ToInt32(bytes, i + 28);
                x ^= (v0 ^ v1 ^ v2 ^ v3 ^ v4 ^ v5 ^ v6 ^ v7);
                x ^= 0x55555555;
                x ^= x << (1 + x % 28);
                x ^= 0x55555555;
                x ^= x >> (1 + x % 29);
                x ^= 0x55555555;
                x ^= x << (1 + x % 30);
                p0 ^= v0 ^ x;
                p1 ^= v1 ^ x;
                p2 ^= v2 ^ x;
                p3 ^= v3 ^ x;
                p4 ^= v4 ^ x;
                p5 ^= v5 ^ x;
                p6 ^= v6 ^ x;
                p7 ^= v7 ^ x;
            }
            var result = new byte[32];
            Array.Copy(BitConverter.GetBytes(p0), 0, result, 0, 4);
            Array.Copy(BitConverter.GetBytes(p1), 0, result, 4, 4);
            Array.Copy(BitConverter.GetBytes(p2), 0, result, 8, 4);
            Array.Copy(BitConverter.GetBytes(p3), 0, result, 12, 4);
            Array.Copy(BitConverter.GetBytes(p4), 0, result, 16, 4);
            Array.Copy(BitConverter.GetBytes(p5), 0, result, 20, 4);
            Array.Copy(BitConverter.GetBytes(p6), 0, result, 24, 4);
            Array.Copy(BitConverter.GetBytes(p7), 0, result, 28, 4);
            return result;
        }
    }
}
