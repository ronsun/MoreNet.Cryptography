﻿using MoreNet.Foundation;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MoreNet.Cryptography.Extensions
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
            Argument.ShouldNotNull(plaintext, nameof(plaintext));
            Argument.ShouldNotNull(plaintextEncoding, nameof(plaintextEncoding));

            var plaintextEncodingBytes = plaintextEncoding.GetBytes(plaintext);
            return EncryptToBase64(symmetric, plaintextEncodingBytes);
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
            Argument.ShouldNotNull(symmetric, nameof(symmetric));
            Argument.ShouldNotNull(plaintextBytes, nameof(plaintextBytes));

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
            Argument.ShouldNotNull(ciphertext, nameof(ciphertext));
            Argument.ShouldNotNull(plaintextEncoding, nameof(plaintextEncoding));

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
            Argument.ShouldNotNull(ciphertextBytes, nameof(ciphertextBytes));
            Argument.ShouldNotNull(plaintextEncoding, nameof(plaintextEncoding));

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
            Argument.ShouldNotNull(symmetric, nameof(symmetric));
            Argument.ShouldNotNull(ciphertextBytes, nameof(ciphertextBytes));

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
