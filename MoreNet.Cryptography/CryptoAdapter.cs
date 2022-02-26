using MoreNet.Cryptography.Algorithm;
using System.Security.Cryptography;
using System.Text;

namespace MoreNet.Cryptography
{
    /// <inheritdoc/>
    internal class CryptoAdapter : ICryptoAdapter
    {
        /// <inheritdoc/>
        public string ComputeHashToHex(HashName hashName, string plaintext)
        {
            var algo = CreateAlgorithm(hashName);
            return algo.ComputeHashToHex(plaintext);
        }

        /// <inheritdoc/>
        public string ComputeHashToHex(HashName hashName, string plaintext, Encoding plaintextEncoding)
        {
            var algo = CreateAlgorithm(hashName);
            return algo.ComputeHashToHex(plaintext, plaintextEncoding);
        }

        /// <inheritdoc/>
        public string ComputeHashToHex(HashName hashName, byte[] plaintextBytes)
        {
            var algo = CreateAlgorithm(hashName);
            return algo.ComputeHashToHex(plaintextBytes);
        }

        /// <inheritdoc/>
        public string ComputeKeyedHashToHex(KeyedHashType hashName, string plaintext, string key)
        {
            var keyBytes = DefaultValues.Encoding.GetBytes(key);
            var algo = CreateAlgorithm(hashName, keyBytes);
            return algo.ComputeHashToHex(plaintext);
        }

        /// <inheritdoc/>
        public string ComputeKeyedHashToHex(KeyedHashType hashName, byte[] plaintextBytes, byte[] keyBytes)
        {
            var algo = CreateAlgorithm(hashName, keyBytes);
            return algo.ComputeHashToHex(plaintextBytes);
        }

        /// <inheritdoc/>
        public string EncryptToBase64(SymmetricName symmetricName, string plaintext)
        {
            var algo = CreateAlgorithm(symmetricName);
            return algo.EncryptToBase64(plaintext);
        }

        /// <inheritdoc/>
        public string EncryptToBase64(SymmetricName symmetricName, string plaintext, Encoding plaintextEncoding)
        {
            var algo = CreateAlgorithm(symmetricName);
            return algo.EncryptToBase64(plaintext, plaintextEncoding);
        }

        /// <inheritdoc/>
        public string EncryptToBase64(SymmetricName symmetricName, byte[] plaintextBytes)
        {
            var algo = CreateAlgorithm(symmetricName);
            return algo.EncryptToBase64(plaintextBytes);
        }

        /// <inheritdoc/>
        public byte[] Encrypt(SymmetricName symmetricName, byte[] plaintextBytes)
        {
            var algo = CreateAlgorithm(symmetricName);
            return algo.Encrypt(plaintextBytes);
        }

        /// <inheritdoc/>
        public string DecryptFromBase64(SymmetricName symmetricName, string ciphertext)
        {
            var algo = CreateAlgorithm(symmetricName);
            return algo.DecryptFromBase64(ciphertext);
        }

        /// <inheritdoc/>
        public string DecryptFromBase64(SymmetricName symmetricName, string ciphertext, Encoding plaintextEncoding)
        {
            var algo = CreateAlgorithm(symmetricName);
            return algo.DecryptFromBase64(ciphertext, plaintextEncoding);
        }

        /// <inheritdoc/>
        public string Decrypt(SymmetricName symmetricName, byte[] ciphertextBytes, Encoding plaintextEncoding)
        {
            var algo = CreateAlgorithm(symmetricName);
            return algo.Decrypt(ciphertextBytes, plaintextEncoding);
        }

        /// <inheritdoc/>
        public byte[] Decrypt(SymmetricName symmetricName, byte[] ciphertextBytes)
        {
            var algo = CreateAlgorithm(symmetricName);
            return algo.Decrypt(ciphertextBytes);
        }

        private SymmetricAlgorithm CreateAlgorithm(SymmetricName hashName)
        {
            return (SymmetricAlgorithm)CryptoConfig.CreateFromName(hashName.Name);
        }

        private HashAlgorithm CreateAlgorithm(HashName hashName)
        {
            return (HashAlgorithm)CryptoConfig.CreateFromName(hashName.Name);
        }

        private KeyedHashAlgorithm CreateAlgorithm(KeyedHashType hashName, byte[] keyBytes)
        {
            var algo = (KeyedHashAlgorithm)CryptoConfig.CreateFromName(hashName.Name);
            algo.Key = keyBytes;
            return algo;
        }
    }
}
