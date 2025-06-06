using System;
using System.Diagnostics;
using System.IO;

namespace CloudSync
{
    // Represents a file identifier with a unique hash and timestamp.
    public struct FileId : IEquatable<FileId>
    {
        // Byte array storing the file ID information.
        public byte[] Bytes { get; }

        // Extracts the first 8 bytes as a hash identifier.
        public readonly ulong HashFile => BitConverter.ToUInt64(Bytes, 0);

        // Extracts the next 4 bytes as a UNIX last write timestamp.
        public readonly uint UnixLastWriteTimestamp => BitConverter.ToUInt32(Bytes, 8);

        // Determines if the file is a directory based on timestamp.
        public readonly bool IsDirectory => UnixLastWriteTimestamp == default;

        // Determines if the file is a regular file (not a directory).
        public readonly bool IsFile => UnixLastWriteTimestamp != default;

        // Constructor accepting a byte array and validating its length.
        public FileId(byte[] bytes)
        {
            if (bytes.Length != 12)
                throw new ArgumentException("Array must be exactly 12 bytes long.");

            Bytes = bytes;
#if DEBUG
            Check(); // Debug check for consistency.
#endif
        }

        // Factory method to create a FileId instance from a byte array.
        public static FileId GetFileId(byte[] bytes) => new FileId(bytes);

        // Constructor initializing FileId with hash and timestamp.
        public FileId(ulong hash, uint unixLastWriteTimestamp)
        {
            Bytes = BitConverter.GetBytes(hash).Concat(BitConverter.GetBytes(unixLastWriteTimestamp));
#if DEBUG
            Check(); // Debug check for consistency.
#endif
        }

        // Constructor for creating a FileId from a file system object.
        public FileId(FileSystemInfo file, Sync context)
        {
            var hash = Util.HashFileName(file, context);
            uint unixLastWriteTimestamp = file.UnixLastWriteTimestamp();
            Bytes = BitConverter.GetBytes(hash).Concat(BitConverter.GetBytes(unixLastWriteTimestamp));
#if DEBUG
            Check(); // Debug check for consistency.
#endif
        }

#if DEBUG
        // Debug method to verify the integrity of the file identifier.
        private bool Check()
        {
            if (IsDirectory != ((HashFile & 1UL) == 1)) // Check if the directory bit is set
            {
                Debugger.Break(); // Directory flag does not match the hash file type.
                return false;
            }

            return true;
        }
#endif

        // Factory method to create a FileId from hash and timestamp.
        public static FileId GetFileId(ulong hash, uint unixLastWriteTimestamp) => new FileId(hash, unixLastWriteTimestamp);

        // Factory method to create a FileId from a FileSystemInfo object.
        public static FileId GetFileId(FileSystemInfo file, Sync context) => new FileId(file, context);

        // Determines if two FileId instances are equal.
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

        // Overrides Equals method for object comparison.
        public override bool Equals(object obj)
        {
            return obj is FileId other && Equals(other);
        }

        // Computes a hash code for the FileId.
        public override int GetHashCode()
        {
            return (int)(BitConverter.ToUInt32(Bytes, 0) ^
                         BitConverter.ToUInt32(Bytes, 4) ^
                         BitConverter.ToUInt32(Bytes, 8));
        }

        // Equality operator for FileId comparison.
        public static bool operator ==(FileId left, FileId right)
        {
            return left.Equals(right);
        }

        // Inequality operator for FileId comparison.
        public static bool operator !=(FileId left, FileId right)
        {
            return !left.Equals(right);
        }
    }
}
