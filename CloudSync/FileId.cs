using System;
using System.IO;

namespace CloudSync
{

    public struct FileId : IEquatable<FileId>
    {
        public byte[] Bytes { get; }

        public readonly ulong HashFile => BitConverter.ToUInt64(Bytes, 0);
        public readonly uint UnixLastWriteTimestamp => BitConverter.ToUInt32(Bytes, 8);
       
        public FileId(byte[] bytes)
        {
            if (bytes.Length != 12)
                throw new ArgumentException("Array must be exactly 12 bytes long.");

            Bytes = bytes;
        }
        public static FileId GetFileId(byte[] bytes) => new FileId(bytes); 
        public FileId(ulong hash, uint unixLastWriteTimestamp)
        {
            Bytes = BitConverter.GetBytes(hash).Concat(BitConverter.GetBytes(unixLastWriteTimestamp));
        }
        public static FileId GetFileId(ulong hash, uint unixLastWriteTimestamp) => new FileId(hash, unixLastWriteTimestamp);

        public FileId(FileSystemInfo file, Sync context)
        {
            var hash =  Util.HashFileName(file, context);
            uint unixLastWriteTimestamp = file.UnixLastWriteTimestamp();
            Bytes = BitConverter.GetBytes(hash).Concat(BitConverter.GetBytes(unixLastWriteTimestamp));
        }
        public static FileId GetFileId(FileSystemInfo file, Sync context) => new FileId(file, context);

        public bool Equals(FileId other)
        {
            if (Bytes.Length != other.Bytes.Length)
                return false;

            for (int i = 0; i < Bytes.Length; i++)
            {
                if (Bytes[i] != other.Bytes[i])
                    return false;
            }
            return true;
        }

        public override bool Equals(object obj)
        {
            return obj is FileId other && Equals(other);
        }

        public override int GetHashCode()
        {
            int hash = 17;
            foreach (var b in Bytes)
            {
                hash = hash * 31 + b;
            }
            return hash;
        }

        public static bool operator ==(FileId left, FileId right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(FileId left, FileId right)
        {
            return !left.Equals(right);
        }
    }

}
