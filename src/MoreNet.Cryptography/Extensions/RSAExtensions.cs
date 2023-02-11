using MoreNet.Foundation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MoreNet.Cryptography.Extensions
{
    /// <summary>
    /// Extensions for <see cref="RSA"/>.
    /// </summary>
    public static class RSAExtensions
    {
        private static readonly Dictionary<RSAEncryptionPadding, int> _offsetDictionary = new Dictionary<RSAEncryptionPadding, int>
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
        /// <param name="plaintext">Plaintext in UTF-8.</param>
        /// <param name="padding"><see cref="RSAEncryptionPadding"/>.</param>
        /// <returns>Ciphertext in base64 string.</returns>
        public static string EncryptChunksToBase64(this RSA rsa, string plaintext, RSAEncryptionPadding padding)
        {
            var plaintextBytes = DefaultValues.Encoding.GetBytes(plaintext);
            var ciphertextBytes = EncryptChunks(rsa, plaintextBytes, padding);
            return Convert.ToBase64String(ciphertextBytes);
        }

        /// <summary>
        /// Encrypt. If plaintext longer than key size, will slice and encrypt all of chunks.
        /// </summary>
        /// <param name="rsa"><see cref="RSA"/>.</param>
        /// <param name="plaintextBytes">Plaintext bytes.</param>
        /// <param name="padding"><see cref="RSAEncryptionPadding"/>.</param>
        /// <returns>Ciphertext in bytes.</returns>
        public static byte[] EncryptChunks(this RSA rsa, byte[] plaintextBytes, RSAEncryptionPadding padding)
        {
            Argument.ShouldNotEmpty(rsa, nameof(rsa));

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
        /// <param name="ciphertext">Ciphertext in base64 string.</param>
        /// <param name="padding"><see cref="RSAEncryptionPadding"/>.</param>
        /// <returns>Plaintext in UFT-8.</returns>
        public static string DecryptChunksFromBase64(this RSA rsa, string ciphertext, RSAEncryptionPadding padding)
        {
            var ciphertextBytes = Convert.FromBase64String(ciphertext);
            var plaintextBytes = DecryptChunks(rsa, ciphertextBytes, padding);
            return DefaultValues.Encoding.GetString(plaintextBytes);
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
            Argument.ShouldNotEmpty(rsa, nameof(rsa));

            var size = rsa.KeySize / 8;
            return Chunk(ciphertextBytes, size)
                .Select(chunk => rsa.Decrypt(chunk, padding))
                .SelectMany(r => r)
                .ToArray();
        }

        /// <summary>
        /// Sign data to base64 string.
        /// </summary>
        /// <param name="rsa"><see cref="RSA"/>.</param>
        /// <param name="data">Plaintext in UTF-8.</param>
        /// <returns>Ciphertext in base64 string.</returns>
        public static string SignDataToBase64(this RSA rsa, string data)
        {
            return SignDataToBase64(rsa, data, DefaultValues.Encoding, DefaultValues.HashAlgorithmName, DefaultValues.RSASignaturePadding);
        }

        /// <summary>
        /// Sign data to base64 string.
        /// </summary>
        /// <param name="rsa"><see cref="RSA"/>.</param>
        /// <param name="data">Plaintext in UTF-8.</param>
        /// <param name="encoding"><see cref="Encoding"/>.</param>
        /// <param name="hashAlgoName"><see cref="HashAlgorithmName"/>.</param>
        /// <param name="padding"><see cref="RSASignaturePadding"/>.</param>
        /// <returns>Signature in base64 string.</returns>
        public static string SignDataToBase64(this RSA rsa, string data, Encoding encoding, HashAlgorithmName hashAlgoName, RSASignaturePadding padding)
        {
            Argument.ShouldNotEmpty(encoding, nameof(encoding));
            Argument.ShouldNotEmpty(rsa, nameof(rsa));

            var dataBytes = encoding.GetBytes(data);
            var signatureBytes = rsa.SignData(dataBytes, hashAlgoName, padding);
            return Convert.ToBase64String(signatureBytes);
        }

        /// <summary>
        /// Verify data from base64 string.
        /// </summary>
        /// <param name="rsa"><see cref="RSA"/>.</param>
        /// <param name="data">Plaintext in UTF-8.</param>
        /// <param name="signature">Signature in base64 string.</param>
        /// <returns>Is <paramref name="data"/> valid.</returns>
        /// <remarks>
        /// <see cref="HashAlgorithmName"/> default to <see cref="HashAlgorithmName.SHA1"/>.
        /// <see cref="RSASignaturePadding"/> default to <see cref="RSASignaturePadding.Pkcs1"/>.
        /// </remarks>
        public static bool VerifyDataFromBase64(this RSA rsa, string data, string signature)
        {
            return VerifyDataFromBase64(rsa, data, DefaultValues.Encoding, signature, DefaultValues.HashAlgorithmName, DefaultValues.RSASignaturePadding);
        }

        /// <summary>
        /// Verify data from base64 string.
        /// </summary>
        /// <param name="rsa"><see cref="RSA"/>.</param>
        /// <param name="data">Plaintext.</param>
        /// <param name="dataEncoding">Encoding of plaintext.</param>
        /// <param name="signature">Signature in base64 string.</param>
        /// <param name="hashAlgoName"><see cref="HashAlgorithmName"/>.</param>
        /// <param name="padding"><see cref="RSASignaturePadding"/>.</param>
        /// <returns>Is <paramref name="data"/> valid.</returns>
        public static bool VerifyDataFromBase64(this RSA rsa, string data, Encoding dataEncoding, string signature, HashAlgorithmName hashAlgoName, RSASignaturePadding padding)
        {
            Argument.ShouldNotEmpty(dataEncoding, nameof(dataEncoding));
            Argument.ShouldNotEmpty(rsa, nameof(rsa));

            var dataBytes = dataEncoding.GetBytes(data);
            var signatureBytes = Convert.FromBase64String(signature);
            return rsa.VerifyData(dataBytes, signatureBytes, hashAlgoName, padding);
        }

#if NETSTANDARD2_1_OR_GREATER

        /// <summary>
        /// Import private key with detected format <see cref="RSAPrivateKeyForamt"/>.
        /// </summary>
        /// <param name="rsa"><see cref="RSA"/>.</param>
        /// <param name="privateKey">Valid private key.</param>
        public static void ImportPrivateKey(this RSA rsa, string privateKey)
        {
            Argument.ShouldNotEmpty(rsa, nameof(rsa));
            Argument.ShouldNotEmpty(privateKey, nameof(privateKey));

            var format = RSAKeyFormatDetector.DetectPrivateKeyFormat(privateKey);
            switch (format)
            {
                case RSAPrivateKeyForamt.Xml:
                    rsa.FromXmlString(privateKey);
                    break;

                case RSAPrivateKeyForamt.Pkcs1:
                    var pcks1Bytes = Convert.FromBase64String(privateKey);
                    rsa.ImportRSAPrivateKey(pcks1Bytes, out int _);
                    break;

                case RSAPrivateKeyForamt.Pkcs8:
                    var pcks8Bytes = Convert.FromBase64String(privateKey);
                    rsa.ImportPkcs8PrivateKey(pcks8Bytes, out int _);
                    break;

                case RSAPrivateKeyForamt.None:
                default:
                    throw new ArgumentException("Unknown format of private key");
            }
        }

        /// <summary>
        /// Import public key with detected format <see cref="RSAPublicKeyForamt"/>.
        /// </summary>
        /// <param name="rsa"><see cref="RSA"/>.</param>
        /// <param name="publicKey">Valid public key.</param>
        public static void ImportPublicKey(this RSA rsa, string publicKey)
        {
            Argument.ShouldNotEmpty(rsa, nameof(rsa));
            Argument.ShouldNotEmpty(publicKey, nameof(publicKey));

            var format = RSAKeyFormatDetector.DetectRSAPublicKeyForamt(publicKey);
            switch (format)
            {
                case RSAPublicKeyForamt.Xml:
                    rsa.FromXmlString(publicKey);
                    break;

                case RSAPublicKeyForamt.Pkcs1:
                    var pcks1Bytes = Convert.FromBase64String(publicKey);
                    rsa.ImportRSAPublicKey(pcks1Bytes, out int _);
                    break;

                case RSAPublicKeyForamt.SubjectPublicKeyInfo:
                    var pcks8Bytes = Convert.FromBase64String(publicKey);
                    rsa.ImportSubjectPublicKeyInfo(pcks8Bytes, out int _);
                    break;

                case RSAPublicKeyForamt.None:
                default:
                    throw new ArgumentException("Unknown format of public key");
            }
        }
#endif

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
