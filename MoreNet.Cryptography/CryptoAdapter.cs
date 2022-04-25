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
        public string ComputeKeyedHashToHex(KeyedHashName hashName, string plaintext, string key)
        {
            var keyBytes = DefaultValues.Encoding.GetBytes(key);
            var algo = CreateAlgorithm(hashName, keyBytes);
            return algo.ComputeHashToHex(plaintext);
        }

        /// <inheritdoc/>
        public string ComputeKeyedHashToHex(KeyedHashName hashName, byte[] plaintextBytes, byte[] keyBytes)
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

        /// <inheritdoc/>
        public string RSAEncryptChunksToBase64(string plaintext, RSAEncryptionPadding padding)
        {
            var algo = CreateRSA();
            return algo.EncryptChunksToBase64(plaintext, padding);
        }

        /// <inheritdoc/>
        public byte[] RSAEncryptChunks(byte[] plaintextBytes, RSAEncryptionPadding padding)
        {
            var algo = CreateRSA();
            return algo.EncryptChunks(plaintextBytes, padding);
        }

        /// <inheritdoc/>
        public string RSADecryptChunksFromBase64(string ciphertext, RSAEncryptionPadding padding)
        {
            var algo = CreateRSA();
            return algo.DecryptChunksFromBase64(ciphertext, padding);
        }

        /// <inheritdoc/>
        public byte[] RSADecryptChunks(byte[] ciphertextBytes, RSAEncryptionPadding padding)
        {
            var algo = CreateRSA();
            return algo.DecryptChunks(ciphertextBytes, padding);
        }

        /// <inheritdoc/>
        public string RSASignDataToBase64(string data)
        {
            var algo = CreateRSA();
            return algo.SignDataToBase64(data);
        }

        /// <inheritdoc/>
        public string RSASignDataToBase64(string data, Encoding encoding, HashAlgorithmName hashAlgoName, RSASignaturePadding padding)
        {
            var algo = CreateRSA();
            return algo.SignDataToBase64(data, encoding, hashAlgoName, padding);
        }

        /// <inheritdoc/>
        public bool RSAVerifyDataFromBase64(string data, string signature)
        {
            var algo = CreateRSA();
            return algo.VerifyDataFromBase64(data, signature);
        }

        /// <inheritdoc/>
        public bool RSAVerifyDataFromBase64(string data, Encoding dataEncoding, string signature, HashAlgorithmName hashAlgoName, RSASignaturePadding padding)
        {
            var algo = CreateRSA();
            return algo.VerifyDataFromBase64(data, dataEncoding, signature, hashAlgoName, padding);
        }

        private HashAlgorithm CreateAlgorithm(HashName hashName)
        {
            return (HashAlgorithm)CryptoConfig.CreateFromName(hashName.Name);
        }

        private KeyedHashAlgorithm CreateAlgorithm(KeyedHashName hashName, byte[] keyBytes)
        {
            var algo = (KeyedHashAlgorithm)CryptoConfig.CreateFromName(hashName.Name);
            algo.Key = keyBytes;
            return algo;
        }

        private SymmetricAlgorithm CreateAlgorithm(SymmetricName symmetricName)
        {
            return (SymmetricAlgorithm)CryptoConfig.CreateFromName(symmetricName.Name);
        }

        private RSA CreateRSA()
        {
            return (RSA)CryptoConfig.CreateFromName(AsymmetricName.RSA.Name);
        }
    }
}
