using MoreNet.Foundation;
using System;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace MoreNet.Cryptography
{
    /// <summary>
    /// Detector for format of RSA key.
    /// </summary>
    public static class RSAKeyFormatDetector
    {
        /// <summary>
        /// Detect the format of valid private key.
        /// The method would not handle invalid private key, so if input invalid <paramref name="privateKey"/>,
        /// will throw exception or return unexpected result.
        /// </summary>
        /// <param name="privateKey">Valid private key.</param>
        /// <returns>The private key foramt.</returns>
        public static RSAPrivateKeyForamt DetectPrivateKeyFormat(string privateKey)
        {
            Argument.ShouldNotEmpty(privateKey, nameof(privateKey));

            if (TryFromBase64String(privateKey, out var bytes))
            {
                switch (bytes[7])
                {
                    case 0x30:
                        return RSAPrivateKeyForamt.Pkcs8;
                    case 0x02:
                        return RSAPrivateKeyForamt.Pkcs1;
                    default:
                        return RSAPrivateKeyForamt.None;
                }
            }

            if (TryParseXml(privateKey, out var xDocument))
            {
                return RSAPrivateKeyForamt.Xml;
            }

            return RSAPrivateKeyForamt.None;
        }

        /// <summary>
        /// Detect the format of valid public key.
        /// The method would not handle invalid private key, so if input invalid <paramref name="publicKey"/>,
        /// will throw exception or return unexpected result.
        /// </summary>
        /// <param name="publicKey">Valid public key.</param>
        /// <returns>The public key foramt.</returns>
        public static RSAPublicKeyForamt DetectRSAPublicKeyForamt(string publicKey)
        {
            Argument.ShouldNotEmpty(publicKey, nameof(publicKey));

            if (TryFromBase64String(publicKey, out var bytes))
            {
                // TODO: I don't know why, try to do some research to explain it.
                if (bytes[0] == 0x30)
                {
                    // Length of data size.
                    // If the value > 0b1000_0000, the last 7 bits indicate the length of data to indicate data size;
                    // otherwise, it is the data size.
                    // For instance:
                    // 0b1000_0001 means the content of next 1 byte is for data size,
                    // 0b1000_0002 means the content of next 2 bytes is for data size,
                    // 0b0100_1000 means the value is for data size (72 bytes)
                    var lengthOfDataSize = bytes[1];
                    int length = 0;
                    if (lengthOfDataSize > 0b1000_0000)
                    {
                        length = lengthOfDataSize - 0b1000_0000;
                    }

                    // The index of first byte of data.
                    // Skip first 2 bytes and length, +1 for next byte, and -1 for zero-based index.
                    var dataIndex = (2 + length + 1) - 1;

                    switch (bytes[dataIndex])
                    {
                        case 0x02:
                            return RSAPublicKeyForamt.Pkcs1;
                        case 0x30:
                            return RSAPublicKeyForamt.SubjectPublicKeyInfo;
                        default:
                            return RSAPublicKeyForamt.None;
                    }
                }
            }

            if (TryParseXml(publicKey, out var xDocument))
            {
                return RSAPublicKeyForamt.Xml;
            }

            return RSAPublicKeyForamt.None;
        }

        private static bool TryParseXml(string text, out XDocument xDocument)
        {
            try
            {
                xDocument = XDocument.Parse(text);
            }
            catch (XmlException)
            {
                xDocument = null;
                return false;
            }

            return true;
        }

        private static bool TryFromBase64String(string s, out byte[] base64Bytes)
        {
#if NETSTANDARD2_1_OR_GREATER
            var bytes = new Span<byte>(new byte[s.Length]);
            if (Convert.TryFromBase64String(s, bytes, out var count))
            {
                base64Bytes = bytes[0..count].ToArray();
                return true;
            }
#else
            var isValidBase64 = (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
            if (isValidBase64)
            {
                base64Bytes = Convert.FromBase64String(s);
                return true;
            }
#endif

            base64Bytes = null;
            return false;
        }
    }
}
