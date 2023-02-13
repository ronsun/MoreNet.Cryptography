using FluentAssertions;
using MoreNet.Cryptography.Extensions;
using NSubstitute;
using NUnit.Framework;
using System.Collections;
using System.Text;

namespace System.Security.Cryptography.UnitTests
{
    [TestFixture()]
    public partial class HashAlgorithmExtensionsTests
    {
        [Test()]
        [TestCaseSource(nameof(TestCaseSource_AllMethods_InputNullHashAlgorithm_ThrowExpectedException))]
        public void Test_AllMethods_InputNullHashAlgorithm_ThrowExpectedException(Action stubAction)
        {
            // arrange

            // act

            // assert
            stubAction.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable TestCaseSource_AllMethods_InputNullHashAlgorithm_ThrowExpectedException()
        {
            HashAlgorithm target = null;
            string stubPlaintext = string.Empty;
            Encoding stubPlaintextEncoding = Encoding.UTF8;
            byte[] stubPlaintextBytes = new byte[] { };

            Action stubAction = null;

            stubAction = () => target.ComputeHashToHex(stubPlaintext);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.ComputeHashToHex(stubPlaintext, stubPlaintextEncoding);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.ComputeHashToHex(stubPlaintextBytes);
            yield return new TestCaseData(stubAction);
        }

        [Test()]
        public void ComputeHashToHexTest_WithPlaintextString_InputNullPlaintext_ThrowExpectedException()
        {
            // arrange
            HashAlgorithm target = Substitute.For<HashAlgorithm>();
            string stubPlaintext = null;

            // act
            Action action = () => target.ComputeHashToHex(stubPlaintext);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [Test()]
        public void ComputeHashToHexTest_WithPlaintextBytes_InputNullPlaintextBytes_ThrowExpectedException()
        {
            // arrange
            HashAlgorithm target = Substitute.For<HashAlgorithm>();
            byte[] stubPlaintextBytes = null;

            // act
            Action action = () => target.ComputeHashToHex(stubPlaintextBytes);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [Test()]
        [TestCaseSource(nameof(ComputeHashToHexTestCaseSource_WithPlaintextAndPlaintextEncoding_InputNullArguments_ThrowExpectedException))]
        public void ComputeHashToHexTest_WithPlaintextAndPlaintextEncoding_InputNullArguments_ThrowExpectedException(
            string stubPlaintext,
            Encoding stubPlaintextEncoding
            )
        {
            // arrange
            HashAlgorithm target = Substitute.For<HashAlgorithm>();

            // act
            Action action = () => target.ComputeHashToHex(stubPlaintext, stubPlaintextEncoding);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable ComputeHashToHexTestCaseSource_WithPlaintextAndPlaintextEncoding_InputNullArguments_ThrowExpectedException()
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
    }
}