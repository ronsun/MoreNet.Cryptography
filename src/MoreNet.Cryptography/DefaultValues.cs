using System.Security.Cryptography;
using System.Text;

namespace MoreNet.Cryptography
{
    /// <summary>
    /// Default values.
    /// </summary>
    internal static class DefaultValues
    {
        /// <summary>
        /// Default <see cref="System.Text.Encoding"/>.
        /// </summary>
        internal static readonly Encoding Encoding = Encoding.UTF8;

        /// <summary>
        /// Default <see cref="HashAlgorithmName"/>.
        /// </summary>
        internal static readonly HashAlgorithmName HashAlgorithmName = HashAlgorithmName.SHA1;

        /// <summary>
        /// Default <see cref="RSASignaturePadding"/>.
        /// </summary>
        internal static readonly RSASignaturePadding RSASignaturePadding = RSASignaturePadding.Pkcs1;
    }
}
