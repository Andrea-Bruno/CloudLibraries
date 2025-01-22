using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace CloudSync
{

    public struct FileId : IEquatable<FileId>
    {
        public byte[] Bytes { get; }

        public ulong HashFile => BitConverter.ToUInt64(Bytes, 0);
        public uint UnixLastWriteTimestamp => BitConverter.ToUInt32(Bytes, 8);
       
        public FileId(byte[] bytes)
        {
            if (bytes.Length != 12)
                throw new ArgumentException("Array must be exactly 12 bytes long.");

            Bytes = bytes;
        }
        public FileId(ulong hash, uint unixLastWriteTimestamp)
        {
            Bytes = BitConverter.GetBytes(hash).Concat(BitConverter.GetBytes(unixLastWriteTimestamp));
        }

        public FileId(string fullFileName, Sync context)
        {
            var file = new FileInfo(fullFileName);
            var hash =  Util.HashFileName(file, context);
            uint unixLastWriteTimestamp = file.UnixLastWriteTimestamp();
            Bytes = BitConverter.GetBytes(hash).Concat(BitConverter.GetBytes(unixLastWriteTimestamp));
        }

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
