using System.Security.Cryptography;
using System.Text;

namespace MoreNet.Cryptography
{
    internal static class DefaultValues
    {
        internal static readonly Encoding Encoding = Encoding.UTF8;

        internal static readonly HashAlgorithmName HashAlgorithmName = HashAlgorithmName.SHA1;

        internal static readonly RSASignaturePadding RSASignaturePadding = RSASignaturePadding.Pkcs1;
    }
}
