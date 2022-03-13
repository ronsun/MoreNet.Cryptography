using MoreNet.Cryptography;
using System.IO;
using System.Text;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Extension methods for <see cref="SymmetricAlgorithm"/>.
    /// </summary>
    public static class SymmetricAlgorithmExtensions
    {
        /// <summary>
        /// Encrypt to base64 string.
        /// </summary>
        /// <param name="symmetric">The instance of SymmetricAlgorithm. </param>
        /// <param name="plaintext">The plaintext string by UTF-8 encoding. </param>
        /// <returns>Ciphertext. </returns>
        public static string EncryptToBase64(this SymmetricAlgorithm symmetric, string plaintext)
        {
            return EncryptToBase64(symmetric, plaintext, DefaultValues.Encoding);
        }

        /// <summary>
        /// Encrypt to base64 string.
        /// </summary>
        /// <param name="symmetric">The instance of SymmetricAlgorithm. </param>
        /// <param name="plaintext">The plaintext string. </param>
        /// <param name="plaintextEncoding">Encoding of plaintext. </param>
        /// <returns>Ciphertext. </returns>
        public static string EncryptToBase64(this SymmetricAlgorithm symmetric, string plaintext, Encoding plaintextEncoding)
        {
            if (plaintextEncoding == null)
            {
                throw new ArgumentNullException(nameof(plaintextEncoding));
            }

            return EncryptToBase64(symmetric, plaintextEncoding.GetBytes(plaintext));
        }

        /// <summary>
        /// Encrypt to base64 string.
        /// </summary>
        /// <param name="symmetric">The instance of SymmetricAlgorithm. </param>
        /// <param name="plaintextBytes">The plaintext in byte array. </param>
        /// <returns>Ciphertext. </returns>
        public static string EncryptToBase64(this SymmetricAlgorithm symmetric, byte[] plaintextBytes)
        {
            var ciphertextBytes = Encrypt(symmetric, plaintextBytes);
            return Convert.ToBase64String(ciphertextBytes);
        }

        /// <summary>
        /// Encrypt.
        /// </summary>
        /// <param name="symmetric">The instance of SymmetricAlgorithm. </param>
        /// <param name="plaintextBytes">The plaintext in byte array. </param>
        /// <returns>Ciphertext bytes. </returns>
        public static byte[] Encrypt(this SymmetricAlgorithm symmetric, byte[] plaintextBytes)
        {
            if (symmetric == null)
            {
                throw new ArgumentNullException(nameof(symmetric));
            }

            if (plaintextBytes == null)
            {
                throw new ArgumentNullException(nameof(plaintextBytes));
            }

            MemoryStream ms = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(ms, symmetric.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Decrypt from base64 string.
        /// </summary>
        /// <param name="symmetric">The instance of SymmetricAlgorithm. </param>
        /// <param name="ciphertext">The ciphertext string. </param>
        /// <returns>Plaintext. </returns>
        public static string DecryptFromBase64(this SymmetricAlgorithm symmetric, string ciphertext)
        {
            return DecryptFromBase64(symmetric, ciphertext, DefaultValues.Encoding);
        }

        /// <summary>
        /// Decrypt from base64 string.
        /// </summary>
        /// <param name="symmetric">The instance of SymmetricAlgorithm. </param>
        /// <param name="ciphertext">The ciphertext string. </param>
        /// <param name="plaintextEncoding">Encoding of plaintext. </param>
        /// <returns>Plaintext. </returns>
        public static string DecryptFromBase64(this SymmetricAlgorithm symmetric, string ciphertext, Encoding plaintextEncoding)
        {
            if (plaintextEncoding == null)
            {
                throw new ArgumentNullException(nameof(plaintextEncoding));
            }

            var ciphertextBytes = Convert.FromBase64String(ciphertext);
            var plaintextBytes = Decrypt(symmetric, ciphertextBytes);
            return plaintextEncoding.GetString(plaintextBytes);
        }

        /// <summary>
        /// Decrypt.
        /// </summary>
        /// <param name="symmetric">The instance of SymmetricAlgorithm. </param>
        /// <param name="ciphertextBytes">The ciphertext bytes. </param>
        /// <param name="plaintextEncoding">Encoding of plaintext. </param>
        /// <returns>Plaintext. </returns>
        public static string Decrypt(this SymmetricAlgorithm symmetric, byte[] ciphertextBytes, Encoding plaintextEncoding)
        {
            if (plaintextEncoding == null)
            {
                throw new ArgumentNullException(nameof(plaintextEncoding));
            }

            var plaintextBytes = Decrypt(symmetric, ciphertextBytes);
            return plaintextEncoding.GetString(plaintextBytes);
        }

        /// <summary>
        /// Decrypt.
        /// </summary>
        /// <param name="symmetric">The instance of SymmetricAlgorithm. </param>
        /// <param name="ciphertextBytes">The ciphertext bytes.</param>
        /// <returns>Plaintext. </returns>
        public static byte[] Decrypt(this SymmetricAlgorithm symmetric, byte[] ciphertextBytes)
        {
            if (symmetric == null)
            {
                throw new ArgumentNullException(nameof(symmetric));
            }

            if (ciphertextBytes == null)
            {
                throw new ArgumentNullException(nameof(ciphertextBytes));
            }

            MemoryStream ms = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(ms, symmetric.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(ciphertextBytes, 0, ciphertextBytes.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }
    }
}
