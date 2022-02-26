using MoreNet.Cryptography.Algorithm;
using System.Text;

namespace MoreNet.Cryptography
{
    /// <summary>
    /// Crypto adapter.
    /// </summary>
    public interface ICryptoAdapter
    {
        /// <summary>
        /// Compute hash to Hex.
        /// </summary>
        /// <param name="hashName"><see cref="HashName"/>.</param>
        /// <param name="plaintext">Plaintext in <see cref="DefaultValues.Encoding"/>.</param>
        /// <returns>Hash in hex.</returns>
        string ComputeHashToHex(HashName hashName, string plaintext);

        /// <summary>
        /// Compute hash to Hex.
        /// </summary>
        /// <param name="hashName"><see cref="HashName"/>.</param>
        /// <param name="plaintext">Plaintext.</param>
        /// <param name="plaintextEncoding">Encoding of plaintext.</param>
        /// <returns>Hash in hex.</returns>
        string ComputeHashToHex(HashName hashName, string plaintext, Encoding plaintextEncoding);

        /// <summary>
        /// Compute hash to Hex.
        /// </summary>
        /// <param name="hashName"><see cref="HashName"/>.</param>
        /// <param name="plaintextBytes">Plaintext in byte array.</param>
        /// <returns>Hash in hex.</returns>
        string ComputeHashToHex(HashName hashName, byte[] plaintextBytes);

        /// <summary>
        /// Compute heyed hash to Hex.
        /// </summary>
        /// <param name="hashName"><see cref="HashName"/>.</param>
        /// <param name="plaintext">Plaintext in <see cref="DefaultValues.Encoding"/>.</param>
        /// <param name="key">Key in <see cref="DefaultValues.Encoding"/>.</param>
        /// <returns>Hash in hex.</returns>
        string ComputeKeyedHashToHex(KeyedHashType hashName, string plaintext, string key);

        /// <summary>
        /// Compute heyed hash to Hex.
        /// </summary>
        /// <param name="hashName"><see cref="HashName"/>.</param>
        /// <param name="plaintextBytes">Plaintext in byte array.</param>
        /// <param name="keyBytes">Key in byte array.</param>
        /// <returns>Hash in hex.</returns>
        string ComputeKeyedHashToHex(KeyedHashType hashName, byte[] plaintextBytes, byte[] keyBytes);

        /// <summary>
        /// Encrypt to base64 string.
        /// </summary>
        /// <param name="symmetricName"><see cref="SymmetricName"/>.</param>
        /// <param name="plaintext">Plaintext in <see cref="DefaultValues.Encoding"/>.</param>
        /// <returns>Ciphertext in base64.</returns>
        string EncryptToBase64(SymmetricName symmetricName, string plaintext);

        /// <summary>
        /// Encrypt to base64 string.
        /// </summary>
        /// <param name="symmetricName"><see cref="SymmetricName"/>.</param>
        /// <param name="plaintext">Plaintext.</param>
        /// <param name="plaintextEncoding">Encoding of <paramref name="plaintext"/>.</param>
        /// <returns>Ciphertext in base64 string.</returns>
        string EncryptToBase64(SymmetricName symmetricName, string plaintext, Encoding plaintextEncoding);

        /// <summary>
        /// Encrypt to base64 string.
        /// </summary>
        /// <param name="symmetricName"><see cref="SymmetricName"/>.</param>
        /// <param name="plaintextBytes">Plaintext in byte array.</param>
        /// <returns>Ciphertext in base64 string.</returns>
        string EncryptToBase64(SymmetricName symmetricName, byte[] plaintextBytes);

        /// <summary>
        /// Encrypt to base64 string.
        /// </summary>
        /// <param name="symmetricName"><see cref="SymmetricName"/>.</param>
        /// <param name="plaintextBytes">Plaintext in byte array.</param>
        /// <returns>Ciphertext.</returns>
        byte[] Encrypt(SymmetricName symmetricName, byte[] plaintextBytes);

        /// <summary>
        /// Decrypt from base64 string.
        /// </summary>
        /// <param name="symmetricName"><see cref="SymmetricName"/>.</param>
        /// <param name="ciphertext">Ciphertext in <see cref="DefaultValues.Encoding"/>.</param>
        /// <returns>Plaintext in <see cref="DefaultValues.Encoding"/>.</returns>
        string DecryptFromBase64(SymmetricName symmetricName, string ciphertext);

        /// <summary>
        /// Decrypt from base64 string.
        /// </summary>
        /// <param name="symmetricName"><see cref="SymmetricName"/>.</param>
        /// <param name="ciphertext">Ciphertext in <see cref="DefaultValues.Encoding"/>.</param>
        /// <param name="plaintextEncoding">Encoding of plaintext.</param>
        /// <returns>Plaintext.</returns>
        string DecryptFromBase64(SymmetricName symmetricName, string ciphertext, Encoding plaintextEncoding);

        /// <summary>
        /// Decrypt.
        /// </summary>
        /// <param name="symmetricName"><see cref="SymmetricName"/>.</param>
        /// <param name="ciphertextBytes">Ciphertext in byte array.</param>
        /// <param name="plaintextEncoding">Encoding of plaintext.</param>
        /// <returns>Plaintext in <see cref="DefaultValues.Encoding"/>.</returns>
        string Decrypt(SymmetricName symmetricName, byte[] ciphertextBytes, Encoding plaintextEncoding);

        /// <summary>
        /// Decrypt.
        /// </summary>
        /// <param name="symmetricName"><see cref="SymmetricName"/>.</param>
        /// <param name="ciphertextBytes">Ciphertext in byte array.</param>
        /// <returns>Plaintext.</returns>
        byte[] Decrypt(SymmetricName symmetricName, byte[] ciphertextBytes);
    }
}
