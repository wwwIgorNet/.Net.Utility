using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace DotNet.Utility
{
    public static class SecureStringExtension
    {
#if DEBUG
        public static string AsString(this SecureString secureString)
        {
            return new System.Net.NetworkCredential(string.Empty, secureString).Password;
        }
#endif

        public static byte[] GetSHA256(this SecureString ss)
        {
            using (var pinedByteArray = ss.GetPinnedByteArray())
            {
                using (var crypt = new SHA256Managed())
                {
                    return crypt.ComputeHash(pinedByteArray.Bytes);
                }
            }
        }

        public static bool IsEqualTo(this SecureString s1, SecureString s2)
        {
            if (s1 != null && s2 != null)
            {
                if (s1.Length != s2.Length)
                {
                    return false;
                }

                byte[] s1Bytes = null;
                byte[] s2Bytes = null;
                try
                {
                    return Enumerable.SequenceEqual(s1.GetByteEnumerator(Encoding.Unicode), s2.GetByteEnumerator(Encoding.Unicode));
                }
                finally
                {
                    if (s1Bytes != null)
                    {
                        for (int i = 0; i < s1Bytes.Length; i++)
                        {
                            s1Bytes[i] = 0;
                        }
                    }

                    if (s2Bytes != null)
                    {
                        for (int i = 0; i < s2Bytes.Length; i++)
                        {
                            s2Bytes[i] = 0;
                        }
                    }
                }
            }
            else
            {
                return false;
            }
        }

        public static SecureString Create(byte[] bytes, Encoding encoding = null)
        {
            return Create(bytes, 0, bytes.Length);
        }
        public static SecureString Create(byte[] bytes, int index, int count, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            SecureString secureString = new SecureString();
            char[] chars = null;
            GCHandle? charsPin = null;
            try
            {
                int length = encoding.GetCharCount(bytes, index, count);
                chars = new char[length];
                charsPin = GCHandle.Alloc(chars, GCHandleType.Pinned);
                encoding.GetChars(bytes, index, count, chars, 0);
                foreach (var c in chars)
                {
                    secureString.AppendChar(c);
                }
            }
            finally
            {
                if (chars != null)
                {
                    Array.Clear(chars, 0, chars.Length);
                }
                charsPin?.Free();
            }

            return secureString;
        }

        public static IEnumerable<char> GetCharEnumerator(this SecureString secureString)
        {
            using (var pinned = secureString.GetPinnedCharArray())
            {
                foreach (var c in pinned.Chars)
                {
                    yield return c;
                }
            }
        }
        public static IEnumerable<byte> GetByteEnumerator(this SecureString secureString, Encoding encoding = null)
        {
            using (var pinned = secureString.GetPinnedByteArray(encoding))
            {
                foreach (var b in pinned.Bytes)
                {
                    yield return b;
                }
            }
        }

        public static PinnedByteArray GetPinnedByteArray(this SecureString secureString, Encoding encoding = null)
        {
            return new PinnedByteArray(secureString, encoding);
        }
        public static PinnedCharArray GetPinnedCharArray(this SecureString secureString)
        {
            return new PinnedCharArray(secureString);
        }

        public class PinnedByteArray : PinnedBase
        {
            private readonly Encoding encoding;
            private readonly SecureString secureString;
            private byte[] _bytes = null;
            protected GCHandle? bytesPin = null;

            public PinnedByteArray(SecureString secureString)
              : this(secureString, Encoding.UTF8)
            { }

            public PinnedByteArray(SecureString secureString, Encoding encoding)
            {
                this.secureString = secureString ?? throw new ArgumentNullException(nameof(secureString));
                this.encoding = encoding ?? Encoding.UTF8;
            }

            public byte[] Bytes
            {
                get
                {
                    if (disposed)
                        throw new ObjectDisposedException(nameof(PinnedByteArray));

                    return ToByteArray();
                }
            }

            protected override void Free()
            {
                if (_bytes != null)
                {
                    Array.Clear(_bytes, 0, _bytes.Length);
                }

                bytesPin?.Free();
            }

            private byte[] ToByteArray()
            {
                if (_bytes == null)
                {
                    using (var pinned = secureString.GetPinnedCharArray())
                    {
                        char[] chars = pinned.Chars;
                        int lenght = encoding.GetByteCount(chars);
                        _bytes = new byte[lenght];
                        bytesPin = GCHandle.Alloc(_bytes, GCHandleType.Pinned);
                        encoding.GetBytes(chars, 0, chars.Length, _bytes, 0);
                    }
                }

                return _bytes;
            }
        }

        public class PinnedCharArray : PinnedBase
        {
            private readonly SecureString secureString;
            private char[] _chars = null;
            private GCHandle? charsPin = null;

            public PinnedCharArray(SecureString secureString)
            {
                this.secureString = secureString ?? throw new ArgumentNullException(nameof(secureString));
            }

            public char[] Chars
            {
                get
                {
                    if (disposed)
                        throw new ObjectDisposedException(nameof(PinnedCharArray));

                    return GetCharsArray();
                }
            }


            [HandleProcessCorruptedStateExceptions]
            private char[] GetCharsArray()
            {
                if (_chars == null)
                {
                    IntPtr bstr = IntPtr.Zero;
                    byte[] unicodeBytes = null;
                    GCHandle? unicodeBytesPin = null;
                    try
                    {
                        bstr = Marshal.SecureStringToBSTR(secureString);
                        int length = Marshal.ReadInt32(bstr, -4);
                        unicodeBytes = new byte[length];
                        unicodeBytesPin = GCHandle.Alloc(unicodeBytes, GCHandleType.Pinned);
                        Marshal.Copy(bstr, unicodeBytes, 0, length);

                        _chars = new char[Encoding.Unicode.GetCharCount(unicodeBytes)];
                        charsPin = GCHandle.Alloc(_chars, GCHandleType.Pinned);

                        Encoding.Unicode.GetChars(unicodeBytes, 0, unicodeBytes.Length, _chars, 0);
                    }
                    catch (AccessViolationException ex)
                    {
                        throw new Exception("Access violation exception.", ex);
                    }
                    finally
                    {
                        if (unicodeBytes != null)
                        {
                            Array.Clear(unicodeBytes, 0, unicodeBytes.Length);
                        }
                        unicodeBytesPin?.Free();
                        if (bstr != IntPtr.Zero)
                        {
                            Marshal.ZeroFreeBSTR(bstr);
                        }
                    }
                }

                return _chars;
            }

            protected override void Free()
            {
                if (_chars != null)
                {
                    Array.Clear(_chars, 0, _chars.Length);
                }

                charsPin?.Free();
            }
        }

        public abstract class PinnedBase : IDisposable
        {
            protected abstract void Free();

            // Flag: Has Dispose already been called?
            protected bool disposed = false;

            // Public implementation of Dispose pattern callable by consumers.
            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }

            // Protected implementation of Dispose pattern.
            protected virtual void Dispose(bool disposing)
            {
                if (disposed)
                    return;

                if (disposing)
                {
                    // Free any other managed objects here.
                    //
                }

                Free();
                // Free any unmanaged objects here.
                //
                disposed = true;
            }

            ~PinnedBase()
            {
                Dispose(false);
            }
        }
    }
}

