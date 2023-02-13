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
    public partial class SymmetricAlgorithmExtensionsTests
    {
        [Test()]
        [TestCaseSource(nameof(TestCaseSource_AllMethods_InputNullSymmetricAlgorithm_ThrowExpectedException))]
        public void Test_AllMethods_InputNullSymmetricAlgorithm_ThrowExpectedException(Action stubAction)
        {
            // arrange

            // act

            // assert
            stubAction.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable TestCaseSource_AllMethods_InputNullSymmetricAlgorithm_ThrowExpectedException()
        {
            SymmetricAlgorithm target = null;
            string stubPlaintext = string.Empty;
            string stubCiphertext = string.Empty;
            byte[] stubPlaintextBytes = new byte[] { };
            byte[] stubCiphertextBytes = new byte[] { };
            Encoding stubPlaintextEncoding = Encoding.UTF8;

            Action stubAction = null;

            stubAction = () => target.EncryptToBase64(stubPlaintextBytes);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.EncryptToBase64(stubPlaintext);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.EncryptToBase64(stubPlaintext, stubPlaintextEncoding);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.Encrypt(stubPlaintextBytes);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.DecryptFromBase64(stubCiphertext);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.DecryptFromBase64(stubCiphertext, stubPlaintextEncoding);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.Decrypt(stubCiphertextBytes);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.Decrypt(stubCiphertextBytes, stubPlaintextEncoding);
            yield return new TestCaseData(stubAction);
        }

        [Test()]
        public void EncryptToBase64Test_WithPlaintext_InputNullArguments_ThrowExpectedException()
        {
            // arrange
            string stubPlaintext = null;
            var target = Substitute.For<SymmetricAlgorithm>();

            // act
            Action action = () => target.EncryptToBase64(stubPlaintext);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [Test()]
        [TestCaseSource(nameof(EncryptToBase64TestCaseSource_WithPlaintextAndPlaintextEncoding_InputNullArguments_ThrowExpectedException))]
        public void EncryptToBase64Test_WithPlaintextAndPlaintextEncoding_InputNullArguments_ThrowExpectedException(
            string stubPlaintext,
            Encoding stubPlaintextEncoding
            )
        {
            // arrange
            var target = Substitute.For<SymmetricAlgorithm>();

            // act
            Action action = () => target.EncryptToBase64(stubPlaintext, stubPlaintextEncoding);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable EncryptToBase64TestCaseSource_WithPlaintextAndPlaintextEncoding_InputNullArguments_ThrowExpectedException()
        {
            string stubPlaintext = null;
            Encoding stubPlaintextEncoding = null;

            stubPlaintext = null;
            stubPlaintextEncoding = Encoding.UTF8;
            yield return new TestCaseData(stubPlaintext, stubPlaintextEncoding);

            stubPlaintext = string.Empty;
            stubPlaintextEncoding = null;
            yield return new TestCaseData(stubPlaintext, stubPlaintextEncoding);
        }

        [Test()]
        public void EncryptToBase64Test_WithPlaintextBytes_InputNullArguments_ThrowExpectedException()
        {
            // arrange
            byte[] stubPlaintextBytes = null;
            var target = Substitute.For<SymmetricAlgorithm>();

            // act
            Action action = () => target.EncryptToBase64(stubPlaintextBytes);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [Test()]
        public void EncryptTest_WithPlaintextBytes_InputNullArguments_ThrowExpectedException()
        {
            // arrange
            byte[] stubPlaintextBytes = null;
            var target = Substitute.For<SymmetricAlgorithm>();

            // act
            Action action = () => target.Encrypt(stubPlaintextBytes);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [Test()]
        public void DecryptFromBase64Test_WithCiphertext_InputNullArguments_ThrowExpectedException()
        {
            // arrange
            string stubCiphertext = null;
            var target = Substitute.For<SymmetricAlgorithm>();

            // act
            Action action = () => target.DecryptFromBase64(stubCiphertext);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [Test()]
        [TestCaseSource(nameof(DecryptFromBase64TestCaseSource_WithCiphertextAndPlaintextEncoding_InputNullArguments_ThrowExpectedException))]
        public void DecryptFromBase64Test_WithCiphertextAndPlaintextEncoding_InputNullArguments_ThrowExpectedException(
            string stubCipertext,
            Encoding stubPlaintextEncoding
            )
        {
            // arrange
            var target = Substitute.For<SymmetricAlgorithm>();

            // act
            Action action = () => target.DecryptFromBase64(stubCipertext, stubPlaintextEncoding);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable DecryptFromBase64TestCaseSource_WithCiphertextAndPlaintextEncoding_InputNullArguments_ThrowExpectedException()
        {
            string stubCiphertext = null;
            Encoding stubPlaintextEncoding = null;

            stubCiphertext = null;
            stubPlaintextEncoding = Encoding.UTF8;
            yield return new TestCaseData(stubCiphertext, stubPlaintextEncoding);

            stubCiphertext = string.Empty;
            stubPlaintextEncoding = null;
            yield return new TestCaseData(stubCiphertext, stubPlaintextEncoding);
        }

        [Test()]
        [TestCaseSource(nameof(DecryptTestCaseSource_WithCipertextBytesAndPlaintextEncoding_InputNullArguments_ThrowExpectedException))]
        public void DecryptTest_WithCipertextBytesAndPlaintextEncoding_InputNullArguments_ThrowExpectedException(
            byte[] stubCipertextBytes,
            Encoding stubPlaintextEncoding
            )
        {
            // arrange
            var target = Substitute.For<SymmetricAlgorithm>();

            // act
            Action action = () => target.Decrypt(stubCipertextBytes, stubPlaintextEncoding);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable DecryptTestCaseSource_WithCipertextBytesAndPlaintextEncoding_InputNullArguments_ThrowExpectedException()
        {
            byte[] stubCiphertextBytes = null;
            Encoding stubPlaintextEncoding = null;

            stubCiphertextBytes = null;
            stubPlaintextEncoding = Encoding.UTF8;
            yield return new TestCaseData(stubCiphertextBytes, stubPlaintextEncoding);

            stubCiphertextBytes = new byte[] { };
            stubPlaintextEncoding = null;
            yield return new TestCaseData(stubCiphertextBytes, stubPlaintextEncoding);
        }

        [Test()]
        public void DecryptTest_WithCiphertextBytes_InputNullArguments_ThrowExpectedException()
        {
            // arrange
            byte[] stubCiphertext = null;
            var target = Substitute.For<SymmetricAlgorithm>();

            // act
            Action action = () => target.Decrypt(stubCiphertext);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }
    }
}