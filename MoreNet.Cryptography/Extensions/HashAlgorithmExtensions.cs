using System.Text;

namespace System.Security.Cryptography
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
            return ComputeHashToHex(hash, plaintext, Encoding.UTF8);
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
            byte[] ciphertextBytes = hash.ComputeHash(plaintextBytes);

            return BitConverter.ToString(ciphertextBytes).Replace("-", string.Empty);
        }
    }
}
