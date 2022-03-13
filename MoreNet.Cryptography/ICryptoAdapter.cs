using MoreNet.Cryptography.Algorithm;
using System.Security.Cryptography;
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

        /// <summary>
        /// Encrypt. If plaintext longer than key size, will slice and encrypt all of chunks.
        /// </summary>
        /// <param name="plaintext">Plaintext in UTF-8.</param>
        /// <param name="padding"><see cref="RSAEncryptionPadding"/>.</param>
        /// <returns>Ciphertext in base64 string.</returns>
        string RSAEncryptChunksToBase64(string plaintext, RSAEncryptionPadding padding);

        /// <summary>
        /// Encrypt. If plaintext longer than key size, will slice and encrypt all of chunks.
        /// </summary>
        /// <param name="plaintextBytes">Plaintext bytes.</param>
        /// <param name="padding"><see cref="RSAEncryptionPadding"/>.</param>
        /// <returns>Ciphertext in bytes.</returns>
        byte[] RSAEncryptChunks(byte[] plaintextBytes, RSAEncryptionPadding padding);

        /// <summary>
        /// Decrypt. If plaintext longer than key size, will slice and decrypt all of chunks.
        /// </summary>
        /// <param name="ciphertext">Ciphertext in base64 string.</param>
        /// <param name="padding"><see cref="RSAEncryptionPadding"/>.</param>
        /// <returns>Plaintext in UFT-8.</returns>
        string RSADecryptChunksFromBase64(string ciphertext, RSAEncryptionPadding padding);

        /// <summary>
        /// Decrypt. If plaintext longer than key size, will slice and decrypt all of chunks.
        /// </summary>
        /// <param name="ciphertextBytes">Ciphertext bytes.</param>
        /// <param name="padding"><see cref="RSAEncryptionPadding"/>.</param>
        /// <returns>Plaintext in bytes.</returns>
        byte[] RSADecryptChunks(byte[] ciphertextBytes, RSAEncryptionPadding padding);

        /// <summary>
        /// Sign data to base64 string.
        /// </summary>
        /// <param name="data">Plaintext in UTF-8.</param>
        /// <returns>Ciphertext in base64 string.</returns>
        string RSASignDataToBase64(string data);

        /// <summary>
        /// Sign data to base64 string.
        /// </summary>
        /// <param name="data">Plaintext in UTF-8.</param>
        /// <param name="encoding"><see cref="Encoding"/>.</param>
        /// <param name="hashAlgoName"><see cref="HashAlgorithmName"/>.</param>
        /// <param name="padding"><see cref="RSASignaturePadding"/>.</param>
        /// <returns>Signature in base64 string.</returns>
        string RSASignDataToBase64(string data, Encoding encoding, HashAlgorithmName hashAlgoName, RSASignaturePadding padding);

        /// <summary>
        /// Verify data from base64 string.
        /// </summary>
        /// <param name="data">Plaintext in UTF-8.</param>
        /// <param name="signature">Signature in base64 string.</param>
        /// <returns>Is <paramref name="data"/> valid.</returns>
        /// <remarks>
        /// <see cref="HashAlgorithmName"/> default to <see cref="HashAlgorithmName.SHA1"/>.
        /// <see cref="RSASignaturePadding"/> default to <see cref="RSASignaturePadding.Pkcs1"/>.
        /// </remarks>
        bool RSAVerifyDataFromBase64(string data, string signature);

        /// <summary>
        /// Verify data from base64 string.
        /// </summary>
        /// <param name="data">Plaintext.</param>
        /// <param name="dataEncoding">Encoding of plaintext.</param>
        /// <param name="signature">Signature in base64 string.</param>
        /// <param name="hashAlgoName"><see cref="HashAlgorithmName"/>.</param>
        /// <param name="padding"><see cref="RSASignaturePadding"/>.</param>
        /// <returns>Is <paramref name="data"/> valid.</returns>
        bool RSAVerifyDataFromBase64(string data, Encoding dataEncoding, string signature, HashAlgorithmName hashAlgoName, RSASignaturePadding padding);
    }
}
