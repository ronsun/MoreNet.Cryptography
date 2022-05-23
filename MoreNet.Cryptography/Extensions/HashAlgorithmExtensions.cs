using MoreNet.Cryptography.Assertion;
using System;
using System.Security.Cryptography;
using System.Text;

namespace MoreNet.Cryptography.Extensions
{
    /// <summary>
    /// Extension methods for HashAlgorithm.
    /// </summary>
    public static class HashAlgorithmExtensions
    {
        /// <summary>
        /// CompteHash and convert result to hex string without charactor '-'.
        /// </summary>
        /// <param name="hash">The instance of HashAlgorithm. </param>
        /// <param name="plaintext">Plaintext, usd UTF-8 as default encoding. </param>
        /// <returns>Hashed string.</returns>
        public static string ComputeHashToHex(this HashAlgorithm hash, string plaintext)
        {
            return ComputeHashToHex(hash, plaintext, DefaultValues.Encoding);
        }

        /// <summary>
        /// CompteHash and convert result to hex string without charactor '-'.
        /// </summary>
        /// <param name="hash">The instance of HashAlgorithm. </param>
        /// <param name="plaintext">Plaintext. </param>
        /// <param name="plaintextEncoding">Encoding of plaintext.</param>
        /// <returns>Hashed string.</returns>
        public static string ComputeHashToHex(this HashAlgorithm hash, string plaintext, Encoding plaintextEncoding)
        {
            Argument.ShouldNotEmpty(plaintextEncoding, nameof(plaintextEncoding));

            return ComputeHashToHex(hash, plaintextEncoding.GetBytes(plaintext));
        }

        /// <summary>
        /// CompteHash and convert result to hex string without charactor '-'.
        /// </summary>
        /// <param name="hash">The instance of HashAlgorithm. </param>
        /// <param name="plaintextBytes">Plaintext in byte array. </param>
        /// <returns>Hashed string.</returns>
        public static string ComputeHashToHex(this HashAlgorithm hash, byte[] plaintextBytes)
        {
            Argument.ShouldNotEmpty(hash, nameof(hash));

            byte[] ciphertextBytes = hash.ComputeHash(plaintextBytes);

#if NETSTANDARD2_1_OR_GREATER
            var hex = BitConverter.ToString(ciphertextBytes).Replace("-", string.Empty, default);
#else
            var hex = BitConverter.ToString(ciphertextBytes).Replace("-", string.Empty);
#endif
            return hex;
        }
    }
}
