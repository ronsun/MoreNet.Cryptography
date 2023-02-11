using System;

namespace MoreNet.Cryptography
{
    /// <summary>
    /// Format of public key for RSA.
    /// </summary>
    [Flags]
    public enum RSAPublicKeyForamt
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
        /// X.509 SubjectPublicKeyInfo structure after decryption (SPKI).
        /// </summary>
        SubjectPublicKeyInfo = 4,
    }
}
