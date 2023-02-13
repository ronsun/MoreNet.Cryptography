using FluentAssertions;
using NSubstitute;
using NUnit.Framework;
using System;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

namespace MoreNet.Cryptography.Extensions.Tests
{
    [TestFixture()]
    public partial class RSAExtensionsTests
    {
        [Test()]
        [TestCaseSource(nameof(TestCaseSource_AllMethods_InputNullRSA_ThrowExpectedException))]
        public void Test_AllMethods_InputNullRSA_ThrowExpectedException(Action stubAction)
        {
            // arrange

            // act

            // assert
            stubAction.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable TestCaseSource_AllMethods_InputNullRSA_ThrowExpectedException()
        {
            RSA target = null;
            string stubPlaintext = string.Empty;
            string stubCiphertext = string.Empty;
            byte[] stubPlaintextBytes = new byte[] { };
            RSAEncryptionPadding stubRSAEncryptionPadding = RSAEncryptionPadding.Pkcs1;
            RSASignaturePadding stubRSASignaturePadding = RSASignaturePadding.Pkcs1;
            Encoding stubPlaintextEncoding = Encoding.UTF8;
            HashAlgorithmName stubHashAlgorithmName = HashAlgorithmName.SHA1;

            Action stubAction = null;

            stubAction = () => target.EncryptChunksToBase64(stubPlaintext, stubRSAEncryptionPadding);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.EncryptChunks(stubPlaintextBytes, stubRSAEncryptionPadding);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.DecryptChunksFromBase64(stubCiphertext, stubRSAEncryptionPadding);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.DecryptChunks(stubPlaintextBytes, stubRSAEncryptionPadding);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.SignDataToBase64(stubPlaintext);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.SignDataToBase64(stubPlaintext, stubPlaintextEncoding, stubHashAlgorithmName, stubRSASignaturePadding);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.VerifyDataFromBase64(stubPlaintext, stubCiphertext);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.VerifyDataFromBase64(stubPlaintext, stubPlaintextEncoding, stubCiphertext, stubHashAlgorithmName, stubRSASignaturePadding);
            yield return new TestCaseData(stubAction);


#if NETCOREAPP3_1_OR_GREATER

            string stubPrivateKey = "MIIBOgIBAAJBAMTRmyHCakZccDa3v3xDwHGUmhaBTep7XqnzOfAfXu9/N+8430kEN5XeSp6xqOh/Ajs67wbk8VRBGeHtWBpWm1kCAwEAAQJANwMXR1Jd/hisTL8DSKpvSc/tWcj+jEG7belMEm/SS0JXTQdm7pcheUmEZnVvuw1K+nlxNb6YjscGGL/iV4P3AQIhAP8/uE29asszvgW3qF5/7z82puzsFGnM3pIJ9ZpknhSRAiEAxWXe0ZSSEkrinUhkBAzB4HsquPghahPe5hise48d3kkCIQD3b6LPob6kC5261yYdrbGUuvsok1balWJxebwgFkf0MQIgDc3U6iUQnfTcqhEQ5XOa7z7NuwenForzMHYTQcS9WvkCIE/XKkWwC+J7ETkxnGRqR6mpaQhFXU3uoSvw0F83BXQZ";
            string stubPublicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMTRmyHCakZccDa3v3xDwHGUmhaBTep7XqnzOfAfXu9/N+8430kEN5XeSp6xqOh/Ajs67wbk8VRBGeHtWBpWm1kCAwEAAQ==";

            stubAction = () => target.ImportPrivateKey(stubPrivateKey);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.ImportPublicKey(stubPublicKey);
            yield return new TestCaseData(stubAction);
#endif

        }

        [Test()]
        [TestCaseSource(nameof(EncryptChunksToBase64TestCaseSource_InputNullArguments_ThrowExpectedException))]
        public void EncryptChunksToBase64Test_InputNullArguments_ThrowExpectedException(
            string stubPlaintext,
            RSAEncryptionPadding stubRSAEncryptionPadding
            )
        {
            // arrange
            var target = Substitute.For<RSA>();

            // act
            Action action = () => target.EncryptChunksToBase64(stubPlaintext, stubRSAEncryptionPadding);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable EncryptChunksToBase64TestCaseSource_InputNullArguments_ThrowExpectedException()
        {
            string stubPlaintext = null;
            RSAEncryptionPadding stubRSAEncryptionPadding = null;

            stubPlaintext = null;
            stubRSAEncryptionPadding = RSAEncryptionPadding.Pkcs1;
            yield return new TestCaseData(stubPlaintext, stubRSAEncryptionPadding);

            stubPlaintext = string.Empty;
            stubRSAEncryptionPadding = null;
            yield return new TestCaseData(stubPlaintext, stubRSAEncryptionPadding);
        }

        [Test()]
        [TestCaseSource(nameof(EncryptChunksTestCaseSource_InputNullArguments_ThrowExpectedException))]
        public void EncryptChunksTest_InputNullArguments_ThrowExpectedException(
            byte[] stubPlaintextBytes,
            RSAEncryptionPadding stubRSAEncryptionPadding
            )
        {
            // arrange
            var target = Substitute.For<RSA>();

            // act
            Action action = () => target.EncryptChunks(stubPlaintextBytes, stubRSAEncryptionPadding);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable EncryptChunksTestCaseSource_InputNullArguments_ThrowExpectedException()
        {
            byte[] stubPlaintextBytes = null;
            RSAEncryptionPadding stubRSAEncryptionPadding = null;

            stubPlaintextBytes = null;
            stubRSAEncryptionPadding = RSAEncryptionPadding.Pkcs1;
            yield return new TestCaseData(stubPlaintextBytes, stubRSAEncryptionPadding);

            stubPlaintextBytes = new byte[] { };
            stubRSAEncryptionPadding = null;
            yield return new TestCaseData(stubPlaintextBytes, stubRSAEncryptionPadding);
        }

        [Test()]
        [TestCaseSource(nameof(DecryptChunksFromBase64TestCaseSource_InputNullArguments_ThrowExpectedException))]
        public void DecryptChunksFromBase64Test_InputNullArguments_ThrowExpectedException(
            string stubCiphertext,
            RSAEncryptionPadding stubRSAEncryptionPadding
            )
        {
            // arrange
            var target = Substitute.For<RSA>();

            // act
            Action action = () => target.DecryptChunksFromBase64(stubCiphertext, stubRSAEncryptionPadding);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable DecryptChunksFromBase64TestCaseSource_InputNullArguments_ThrowExpectedException()
        {
            string stubCiphertext = null;
            RSAEncryptionPadding stubRSAEncryptionPadding = null;

            stubCiphertext = null;
            stubRSAEncryptionPadding = RSAEncryptionPadding.Pkcs1;
            yield return new TestCaseData(stubCiphertext, stubRSAEncryptionPadding);

            stubCiphertext = string.Empty;
            stubRSAEncryptionPadding = null;
            yield return new TestCaseData(stubCiphertext, stubRSAEncryptionPadding);
        }

        [Test()]
        [TestCaseSource(nameof(DecryptChunksTestCaseSource_InputNullArguments_ThrowExpectedException))]
        public void DecryptChunksTest_InputNullArguments_ThrowExpectedException(
            byte[] stubCiphertextBytes,
            RSAEncryptionPadding stubRSAEncryptionPadding
            )
        {
            // arrange
            var target = Substitute.For<RSA>();

            // act
            Action action = () => target.DecryptChunks(stubCiphertextBytes, stubRSAEncryptionPadding);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable DecryptChunksTestCaseSource_InputNullArguments_ThrowExpectedException()
        {
            byte[] stubCiphertextBytes = null;
            RSAEncryptionPadding stubRSAEncryptionPadding = null;

            stubCiphertextBytes = null;
            stubRSAEncryptionPadding = RSAEncryptionPadding.Pkcs1;
            yield return new TestCaseData(stubCiphertextBytes, stubRSAEncryptionPadding);

            stubCiphertextBytes = new byte[] { };
            stubRSAEncryptionPadding = null;
            yield return new TestCaseData(stubCiphertextBytes, stubRSAEncryptionPadding);
        }

        [Test()]
        public void SignDataToBase64Test_WithData_InputNullData_ThrowExpectedException()
        {
            // arrange
            string stubData = null;
            var target = Substitute.For<RSA>();

            // act
            Action action = () => target.SignDataToBase64(stubData);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [Test()]
        [TestCaseSource(nameof(SignDataToBase64TestCaseSource_WithAllArguments_InputNullArguments_ThrowExpectedException))]
        public void SignDataToBase64Test_WithAllArguments_InputNullArguments_ThrowExpectedException(
            string stubData,
            Encoding stubEncoding,
            RSASignaturePadding stubRSASignaturePadding
            )
        {
            // arrange
            var target = Substitute.For<RSA>();
            HashAlgorithmName stubHashAlgorithmName = default;

            // act
            Action action = () => target.SignDataToBase64(stubData, stubEncoding, stubHashAlgorithmName, stubRSASignaturePadding);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable SignDataToBase64TestCaseSource_WithAllArguments_InputNullArguments_ThrowExpectedException()
        {
            string stubData = null;
            Encoding stubEncoding = null;
            RSASignaturePadding stubRSASignaturePadding = null;

            stubData = null;
            stubEncoding = Encoding.UTF8;
            stubRSASignaturePadding = RSASignaturePadding.Pkcs1;
            yield return new TestCaseData(stubData, stubEncoding, stubRSASignaturePadding);

            stubData = string.Empty;
            stubEncoding = null;
            stubRSASignaturePadding = RSASignaturePadding.Pkcs1;
            yield return new TestCaseData(stubData, stubEncoding, stubRSASignaturePadding);

            stubData = string.Empty;
            stubEncoding = Encoding.UTF8;
            stubRSASignaturePadding = null;
            yield return new TestCaseData(stubData, stubEncoding, stubRSASignaturePadding);
        }

        [Test()]
        [TestCaseSource(nameof(VerifyDataFromBase64TestCaseSource_WithDataAndSignature_InputNullArguments_ThrowExpectedException))]
        public void VerifyDataFromBase64Test_WithDataAndSignature_InputNullArguments_ThrowExpectedException(
            string stubData,
            string stubSignature
            )
        {
            // arrange
            var target = Substitute.For<RSA>();

            // act
            Action action = () => target.VerifyDataFromBase64(stubData, stubSignature);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable VerifyDataFromBase64TestCaseSource_WithDataAndSignature_InputNullArguments_ThrowExpectedException()
        {
            string stubData = null;
            string stubSignature = null;

            stubData = null;
            stubSignature = string.Empty;
            yield return new TestCaseData(stubData, stubSignature);

            stubData = string.Empty;
            stubSignature = null;
            yield return new TestCaseData(stubData, stubSignature);
        }

        [Test()]
        [TestCaseSource(nameof(VerifyDataFromBase64TestCaseSource_WithAllArguments_InputNullArguments_ThrowExpectedException))]
        public void VerifyDataFromBase64Test_WithAllArguments_InputNullArguments_ThrowExpectedException(
            string stubData,
            Encoding stubEncoding,
            string stubSignature,
            RSASignaturePadding stubRSASignaturePadding
            )
        {
            // arrange
            var target = Substitute.For<RSA>();
            HashAlgorithmName stubHashAlgorithmName = default;

            // act
            Action action = () => target.VerifyDataFromBase64(stubData, stubEncoding, stubSignature, stubHashAlgorithmName, stubRSASignaturePadding);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable VerifyDataFromBase64TestCaseSource_WithAllArguments_InputNullArguments_ThrowExpectedException()
        {
            string stubData = null;
            Encoding stubEncoding = null;
            string stubSignature = null;
            RSASignaturePadding stubRSASignaturePadding = null;

            stubData = null;
            stubEncoding = Encoding.UTF8;
            stubSignature = string.Empty;
            stubRSASignaturePadding = RSASignaturePadding.Pkcs1;
            yield return new TestCaseData(stubData, stubEncoding, stubSignature, stubRSASignaturePadding);

            stubData = string.Empty;
            stubEncoding = null;
            stubSignature = string.Empty;
            stubRSASignaturePadding = RSASignaturePadding.Pkcs1;
            yield return new TestCaseData(stubData, stubEncoding, stubSignature, stubRSASignaturePadding);

            stubData = string.Empty;
            stubEncoding = Encoding.UTF8;
            stubSignature = null;
            stubRSASignaturePadding = RSASignaturePadding.Pkcs1;
            yield return new TestCaseData(stubData, stubEncoding, stubSignature, stubRSASignaturePadding);

            stubData = string.Empty;
            stubEncoding = Encoding.UTF8;
            stubSignature = string.Empty;
            stubRSASignaturePadding = null;
            yield return new TestCaseData(stubData, stubEncoding, stubSignature, stubRSASignaturePadding);
        }

#if NETCOREAPP3_1_OR_GREATER

        [TestCase]
        public void ImportPrivateKeyTest_InputNullPrivateKey_ThrowExpectedException()
        {
            // arrange
            string stubPrivateKey = null;
            var target = Substitute.For<RSA>();

            // act
            Action action = () => target.ImportPrivateKey(stubPrivateKey);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestCase]
        public void ImportPrivateKeyTest_InputEmptyPrivateKey_ThrowExpectedException()
        {
            // arrange
            string stubPrivateKey = string.Empty;
            var target = Substitute.For<RSA>();

            // act
            Action action = () => target.ImportPrivateKey(stubPrivateKey);

            // assert
            action.Should().ThrowExactly<ArgumentException>();
        }

        [TestCase]
        public void ImportPublicKeyTest_InputNullPublicKey_ThrowExpectedException()
        {
            // arrange
            string stubPublidKey = null;
            var target = Substitute.For<RSA>();

            // act
            Action action = () => target.ImportPublicKey(stubPublidKey);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestCase]
        public void ImportPublicKeyTest_InputEmptyPublicKey_ThrowExpectedException()
        {
            // arrange
            string stubPublicKey = string.Empty;
            var target = Substitute.For<RSA>();

            // act
            Action action = () => target.ImportPublicKey(stubPublicKey);

            // assert
            action.Should().ThrowExactly<ArgumentException>();
        }
#endif
    }
}