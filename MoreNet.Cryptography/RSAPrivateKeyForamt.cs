using System;

namespace MoreNet.Cryptography
{
    /// <summary>
    /// Format of private key for RSA.
    /// </summary>
    [Flags]
    public enum RSAPrivateKeyForamt
    {
        /// <summary>
        /// Unknown.
        /// </summary>
        None = 0,

        /// <summary>
        /// Xml.
        /// </summary>
        Xml = 1,

        /// <summary>
        /// Pkcs1.
        /// </summary>
        Pkcs1 = 2,

        /// <summary>
        /// Pkcs8.
        /// </summary>
        Pkcs8 = 4,
    }
}
