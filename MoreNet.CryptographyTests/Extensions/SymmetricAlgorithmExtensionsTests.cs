using FluentAssertions;
using NUnit.Framework;
using System.Collections;
using System.Text;

namespace System.Security.Cryptography.IntegrationTests
{
    [TestFixture()]
    public class SymmetricAlgorithmExtensionsTests
    {
        [Test()]
        [TestCaseSource(nameof(EncryptToBase64TestCaseSource_EncryptAndDecryptCorrectly))]
        public void EncryptToBase64Test_WithPlaintextString_EncryptAndDecryptCorrectly(SymmetricAlgorithm stubEncryptor, SymmetricAlgorithm stubDecryptor)
        {
            // arrange
            string stubPlaintext = "a";

            // act
            string actualCiphertext = stubEncryptor.EncryptToBase64(stubPlaintext);
            string actualPlaintext = stubDecryptor.DecryptFromBase64(actualCiphertext);

            // assert
            actualPlaintext.Should().Be(stubPlaintext);
        }

        [Test()]
        [TestCaseSource(nameof(EncryptToBase64TestCaseSource_EncryptAndDecryptCorrectly))]
        public void EncryptToBase64Test_WithPlaintextStringAndEncoding_EncryptAndDecryptCorrectly(SymmetricAlgorithm stubEncryptor, SymmetricAlgorithm stubDecryptor)
        {
            // arrange
            string stubPlaintext = "a";
            Encoding stubEncoding = Encoding.ASCII;

            // act
            string actualCiphertext = stubEncryptor.EncryptToBase64(stubPlaintext, stubEncoding);
            string actualPlaintext = stubDecryptor.DecryptFromBase64(actualCiphertext, stubEncoding);

            // assert
            actualPlaintext.Should().Be(stubPlaintext);
        }

        [Test()]
        [TestCaseSource(nameof(EncryptToBase64TestCaseSource_EncryptAndDecryptCorrectly))]
        public void EncryptToBase64Test_WithPlaintextBytes_EncryptAndDecryptCorrectly(SymmetricAlgorithm stubEncryptor, SymmetricAlgorithm stubDecryptor)
        {
            // arrange
            string stubPlaintext = "a";
            byte[] stubPlaintextBytes = Encoding.UTF8.GetBytes(stubPlaintext);

            // act
            string actualCiphertext = stubEncryptor.EncryptToBase64(stubPlaintextBytes);
            string actualPlaintext = stubDecryptor.DecryptFromBase64(actualCiphertext);

            // assert
            actualPlaintext.Should().Be(stubPlaintext);
        }

        [Test()]
        [TestCaseSource(nameof(EncryptToBase64TestCaseSource_EncryptAndDecryptCorrectly))]
        public void EncryptTest_WithPlaintextBytes_EncryptAndDecryptCorrectly(SymmetricAlgorithm stubEncryptor, SymmetricAlgorithm stubDecryptor)
        {
            // arrange
            string stubPlaintext = "a";
            byte[] stubPlaintextBytes = Encoding.UTF8.GetBytes(stubPlaintext);

            // act
            byte[] actualCiphertextBytes = stubEncryptor.Encrypt(stubPlaintextBytes);
            byte[] actualPlaintextBytes = stubDecryptor.Decrypt(actualCiphertextBytes);

            // assert
            actualPlaintextBytes.Should().BeEquivalentTo(stubPlaintextBytes);
        }

        private static IEnumerable EncryptToBase64TestCaseSource_EncryptAndDecryptCorrectly()
        {
            yield return new TestCaseData(
                    new AesCryptoServiceProvider()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(128),
                    },
                    new AesCryptoServiceProvider()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(128),
                    }
                );

            yield return new TestCaseData(
                    new DESCryptoServiceProvider()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(64)
                    },
                    new DESCryptoServiceProvider()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(64)
                    }
                );

            yield return new TestCaseData(
                    new RC2CryptoServiceProvider()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(64)
                    },
                    new RC2CryptoServiceProvider()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(64)
                    }
                );

            yield return new TestCaseData(
                    new RijndaelManaged()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(128),
                    },
                    new RijndaelManaged()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(128),
                    }
                );

            yield return new TestCaseData(
                    new TripleDESCryptoServiceProvider()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(192)
                    },
                    new TripleDESCryptoServiceProvider()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(192)
                    }
                );
#if NET462 || NET47|| NET471 || NET472 || NET48
            yield return new TestCaseData(
                    new TripleDESCng()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(192)
                    },
                    new TripleDESCng()
                    {
                        Mode = CipherMode.ECB,
                        Key = GenerateKey(192)
                    }
                );
#endif
        }

        private static byte[] GenerateKey(int bits)
        {
            int bytes = bits / 8;
            var key = new byte[bytes];
            new Random(0).NextBytes(key);
            return key;
        }
    }
}