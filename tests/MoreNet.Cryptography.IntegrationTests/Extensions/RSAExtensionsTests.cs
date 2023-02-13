using FluentAssertions;
using MoreNet.Cryptography.Extensions;
using NUnit.Framework;
using System.Collections;
using System.Linq;
using System.Text;

namespace System.Security.Cryptography.IntegrationTests
{
    [TestFixture()]
    public class RSAExtensionsTests
    {
#if NETCOREAPP3_1_OR_GREATER
        [Test()]
        [TestCaseSource(nameof(EncryptDecryptTestCaseSource_EncryptAndDecryptCorrectly))]
        public void EncryptDecryptTest_Base64_EncryptAndDecryptCorrectly(
            int stubPalintextSizeInByte,
            RSAEncryptionPadding stubPadding,
            string stubPublicKey,
            string stubPrivateKey)
        {
            // arrange
            var stubPlaintext = string.Empty.PadLeft(stubPalintextSizeInByte, 'a');
            var stubEncryptRSA = CreateRSAWithPublicKey(stubPublicKey);
            var stubDecryptRSA = CreateRSAWithPrivateKey(stubPrivateKey);

            // act
            var ciphertext = stubEncryptRSA.EncryptChunksToBase64(stubPlaintext, stubPadding);
            var actualPlaintextBytes = stubDecryptRSA.DecryptChunksFromBase64(ciphertext, stubPadding);

            // assert
            actualPlaintextBytes.Should().BeEquivalentTo(stubPlaintext);
        }

        [Test()]
        [TestCaseSource(nameof(EncryptDecryptTestCaseSource_EncryptAndDecryptCorrectly))]
        public void EncryptDecryptTest_EncryptAndDecryptCorrectly(
            int stubPalintextSizeInByte,
            RSAEncryptionPadding stubPadding,
            string stubPublicKey,
            string stubPrivateKey)
        {
            // arrange
            var stubPlaintextBytes = Enumerable.Range(0, stubPalintextSizeInByte).Select(r => byte.MaxValue).ToArray();
            var stubEncryptRSA = CreateRSAWithPublicKey(stubPublicKey);
            var stubDecryptRSA = CreateRSAWithPrivateKey(stubPrivateKey);

            // act
            var ciphertext = stubEncryptRSA.EncryptChunks(stubPlaintextBytes, stubPadding);
            var actualPlaintextBytes = stubDecryptRSA.DecryptChunks(ciphertext, stubPadding);

            // assert
            actualPlaintextBytes.Should().BeEquivalentTo(stubPlaintextBytes);
        }

        [Test()]
        [TestCaseSource(nameof(SignDataVerifySignTestCaseSource_Base64_SimpleScenario))]
        public void SignDataVerifySignTest_Base64_SimpleScenario(
            string stubPublicKey,
            string stubPrivateKey)
        {
            // arrange
            var stubPlaintext = "a";
            var stubSignRSA = CreateRSAWithPrivateKey(stubPrivateKey);
            var stubVerifyRSA = CreateRSAWithPublicKey(stubPublicKey);

            // act
            var ciphertext = stubSignRSA.SignDataToBase64(stubPlaintext);
            var actualIsValid = stubVerifyRSA.VerifyDataFromBase64(stubPlaintext, ciphertext);

            // assert
            actualIsValid.Should().BeTrue();
        }

        private static IEnumerable SignDataVerifySignTestCaseSource_Base64_SimpleScenario()
        {
            foreach (var key in RSATestData.OpensslRSA.Values)
            {
                yield return new TestCaseData(key.Pkcs1PublicKey, key.Pkcs1PrivateKey);
            }
        }

        [Test()]
        [TestCaseSource(nameof(SignDataVerifySignTestCaseSource_VerifyCorrectly))]
        public void SignDataVerifySignTest_Base64(
            Encoding stubEncoding,
            HashAlgorithmName stubHashAlgorithmName,
            RSASignaturePadding stubPadding,
            string stubPublicKey,
            string stubPrivateKey)
        {
            // arrange
            var stubPlaintext = "a";
            var stubSignRSA = CreateRSAWithPrivateKey(stubPrivateKey);
            var stubVerifyRSA = CreateRSAWithPublicKey(stubPublicKey);

            // act
            var ciphertext = stubSignRSA.SignDataToBase64(stubPlaintext, stubEncoding, stubHashAlgorithmName, stubPadding);
            var actualIsValid = stubVerifyRSA.VerifyDataFromBase64(stubPlaintext, stubEncoding, ciphertext, stubHashAlgorithmName, stubPadding);

            // assert
            actualIsValid.Should().BeTrue();
        }

        private static IEnumerable EncryptDecryptTestCaseSource_EncryptAndDecryptCorrectly()
        {
            // 64 bytes (512 bits) - 11 bytes (padding size of Pkcs1), edge case and 1 byte longer scenario
            var length512 = RSATestData.OpensslRSA[512];
            yield return new TestCaseData(64 - 11, RSAEncryptionPadding.Pkcs1, length512.Pkcs1PublicKey, length512.Pkcs1PrivateKey);
            yield return new TestCaseData(64 - 11 + 1, RSAEncryptionPadding.Pkcs1, length512.Pkcs1PublicKey, length512.Pkcs1PrivateKey);

            // 64 bytes (512 bits) - 42 bytes (padding size of OaepSHA1), edge case and 1 byte longer scenario
            yield return new TestCaseData(64 - 42, RSAEncryptionPadding.OaepSHA1, length512.Pkcs1PublicKey, length512.Pkcs1PrivateKey);
            yield return new TestCaseData(64 - 42 + 1, RSAEncryptionPadding.OaepSHA1, length512.Pkcs1PublicKey, length512.Pkcs1PrivateKey);

            // 128 bytes (1024 bits) - 66 bytes (padding size of OaepSHA256), edge case and 1 byte longer scenario
            var length1024 = RSATestData.OpensslRSA[1024];
            yield return new TestCaseData(128 - 66, RSAEncryptionPadding.OaepSHA256, length1024.Pkcs1PublicKey, length1024.Pkcs1PrivateKey);
            yield return new TestCaseData(128 - 66 + 1, RSAEncryptionPadding.OaepSHA256, length1024.Pkcs1PublicKey, length1024.Pkcs1PrivateKey);

            // 128 bytes (1024 bits) - 98 bytes (padding size of OaepSHA384), edge case and 1 byte longer scenario
            yield return new TestCaseData(128 - 98, RSAEncryptionPadding.OaepSHA384, length1024.Pkcs1PublicKey, length1024.Pkcs1PrivateKey);
            yield return new TestCaseData(128 - 98 + 1, RSAEncryptionPadding.OaepSHA384, length1024.Pkcs1PublicKey, length1024.Pkcs1PrivateKey);

            // 256 bytes (2048 bits) - 130 bytes (padding size of OaepSHA512), edge case and 1 byte longer scenario
            var length2048 = RSATestData.OpensslRSA[2048];
            yield return new TestCaseData(256 - 130, RSAEncryptionPadding.OaepSHA512, length2048.Pkcs1PublicKey, length2048.Pkcs1PrivateKey);
            yield return new TestCaseData(256 - 130 + 1, RSAEncryptionPadding.OaepSHA512, length2048.Pkcs1PublicKey, length2048.Pkcs1PrivateKey);
        }

        private static IEnumerable SignDataVerifySignTestCaseSource_VerifyCorrectly()
        {
            var encodings = new[] { Encoding.UTF8, Encoding.Unicode };
            var hashNames = new[] { HashAlgorithmName.SHA1, HashAlgorithmName.SHA256 };
            var rsaPaddings = new[] { RSASignaturePadding.Pkcs1 };

            var length512 = RSATestData.OpensslRSA[512];
            var length1024 = RSATestData.OpensslRSA[1024];
            var length2048 = RSATestData.OpensslRSA[2048];

            foreach (var encoding in encodings)
                foreach (var hashName in hashNames)
                    foreach (var rsaPadding in rsaPaddings)
                    {
                        yield return new TestCaseData(encoding, hashName, rsaPadding, length512.Pkcs1PublicKey, length512.Pkcs1PrivateKey);
                        yield return new TestCaseData(encoding, hashName, rsaPadding, length1024.Pkcs1PublicKey, length1024.Pkcs1PrivateKey);
                        yield return new TestCaseData(encoding, hashName, rsaPadding, length2048.Pkcs1PublicKey, length2048.Pkcs1PrivateKey);
                    }
        }

        private RSA CreateRSAWithPublicKey(string publicKey)
        {
            var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out int _);
            return rsa;
        }

        private RSA CreateRSAWithPrivateKey(string privateKey)
        {
            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out int _);
            return rsa;
        }
#endif
    }
}
