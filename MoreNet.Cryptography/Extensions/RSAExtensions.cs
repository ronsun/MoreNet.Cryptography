using System.Collections.Generic;
using System.Linq;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Extensions for <see cref="RSA"/>.
    /// </summary>
    public static class RSAExtensions
    {
        private static Dictionary<RSAEncryptionPadding, int> _offsetDictionary = new Dictionary<RSAEncryptionPadding, int>
        {
            [RSAEncryptionPadding.Pkcs1] = 11,
            [RSAEncryptionPadding.OaepSHA1] = 42,
            [RSAEncryptionPadding.OaepSHA256] = 66,
            [RSAEncryptionPadding.OaepSHA384] = 98,
            [RSAEncryptionPadding.OaepSHA512] = 130,
        };

        /// <summary>
        /// Encrypt. If plaintext longer than key size, will slice and encrypt all of chunks.
        /// </summary>
        /// <param name="rsa"><see cref="RSA"/>.</param>
        /// <param name="plaintextBytes">Plaintext bytes.</param>
        /// <param name="padding"><see cref="RSAEncryptionPadding"/>.</param>
        /// <returns>Ciphertext in bytes.</returns>
        public static byte[] EncryptChunks(this RSA rsa, byte[] plaintextBytes, RSAEncryptionPadding padding)
        {
            var size = (rsa.KeySize / 8) - _offsetDictionary[padding];
            return Chunk(plaintextBytes, size)
                    .Select(chunk => rsa.Encrypt(chunk, padding))
                    .SelectMany(r => r)
                    .ToArray();
        }

        /// <summary>
        /// Decrypt. If plaintext longer than key size, will slice and decrypt all of chunks.
        /// </summary>
        /// <param name="rsa"><see cref="RSA"/>.</param>
        /// <param name="ciphertextBytes">Ciphertext bytes.</param>
        /// <param name="padding"><see cref="RSAEncryptionPadding"/>.</param>
        /// <returns>Plaintext in bytes.</returns>
        public static byte[] DecryptChunks(this RSA rsa, byte[] ciphertextBytes, RSAEncryptionPadding padding)
        {
            var size = rsa.KeySize / 8;
            return Chunk(ciphertextBytes, size)
                .Select(chunk => rsa.Decrypt(chunk, padding))
                .SelectMany(r => r)
                .ToArray();
        }

        private static IEnumerable<byte[]> Chunk(byte[] source, int size)
        {
            int index = 0;
            bool hasNext = source.Any();
            while (hasNext)
            {
                byte[] current = source.Skip(index++ * size).Take(size).ToArray();
                hasNext = current.Length == size;
                if (current.Any())
                {
                    yield return current;
                }
            }
        }
    }
}
