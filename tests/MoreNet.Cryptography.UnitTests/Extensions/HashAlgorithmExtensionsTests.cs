using FluentAssertions;
using MoreNet.Cryptography.Extensions;
using NUnit.Framework;
using System.Collections;
using System.Text;

namespace System.Security.Cryptography.Extensions.UnitTests
{
    [TestFixture()]
    public partial class HashAlgorithmExtensionsTests
    {
        [Test()]
        [TestCaseSource(nameof(ComputeHashToHexTestCaseSource_WithPlaintext_ReturnExpected))]
        public void ComputeHashToHexTest_WithPlaintextString_ReturnExpected(HashAlgorithm target, string stubPlaintext, string expected)
        {
            // arrange

            // act
            string actual = target.ComputeHashToHex(stubPlaintext);

            // assert
            actual.Should().Be(expected);
        }

        [Test()]
        [TestCaseSource(nameof(ComputeHashToHexTestCaseSource_WithPlaintext_ReturnExpected))]
        public void ComputeHashToHexTest_WithPlaintextBytes_ReturnExpected(HashAlgorithm target, string stubPlaintext, string expected)
        {
            // arrange
            var stubPlaintextBytes = Encoding.UTF8.GetBytes(stubPlaintext);

            // act
            string actual = target.ComputeHashToHex(stubPlaintextBytes);

            // assert
            actual.Should().Be(expected);
        }

        private static IEnumerable ComputeHashToHexTestCaseSource_WithPlaintext_ReturnExpected()
        {
            byte[] hmacKeyBytes = Encoding.UTF8.GetBytes("a");
            string stubPlaintext = "a";

            // CryptoServiceProvider
            yield return new TestCaseData(new MD5CryptoServiceProvider(), stubPlaintext, "0CC175B9C0F1B6A831C399E269772661");
            yield return new TestCaseData(new SHA1CryptoServiceProvider(), stubPlaintext, "86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8");
            yield return new TestCaseData(new SHA256CryptoServiceProvider(), stubPlaintext, "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB");
            yield return new TestCaseData(new SHA384CryptoServiceProvider(), stubPlaintext, "54A59B9F22B0B80880D8427E548B7C23ABD873486E1F035DCE9CD697E85175033CAA88E6D57BC35EFAE0B5AFD3145F31");
            yield return new TestCaseData(new SHA512CryptoServiceProvider(), stubPlaintext, "1F40FC92DA241694750979EE6CF582F2D5D7D28E18335DE05ABC54D0560E0F5302860C652BF08D560252AA5E74210546F369FBBBCE8C12CFC7957B2652FE9A75");

            // hmac series
            yield return new TestCaseData(new HMACMD5(hmacKeyBytes), stubPlaintext, "06F30DC9049F859EA0CCB39FDC8FD5C2");
            yield return new TestCaseData(new HMACSHA1(hmacKeyBytes), stubPlaintext, "3902ED847FF28930B5F141ABFA8B471681253673");
            yield return new TestCaseData(new HMACSHA256(hmacKeyBytes), stubPlaintext, "3ECF5388E220DA9E0F919485DEB676D8BEE3AEC046A779353B463418511EE622");
            yield return new TestCaseData(new HMACSHA384(hmacKeyBytes), stubPlaintext, "724C212553F366248BC76017E812C8ACC85B94FEC2F396C2A925BCC2571F7AB29FEDEE6B3B3013BBF9DE7B89549D5A69");
            yield return new TestCaseData(new HMACSHA512(hmacKeyBytes), stubPlaintext, "FC8C80E6B943CD07ECCECF01BC6038BAE68EBB6FA2E1E62B44753D7C177AF7A46B089DF349A19F7622A22312C76906CA9C984E1446D3AB86A98FDFA1425341C5");
#if NET462 || NET47|| NET471 || NET472 || NET48
            yield return new TestCaseData(new HMACRIPEMD160(hmacKeyBytes), stubPlaintext, "ECB2E5CA0EEFFD84F5566B5DE1D037EF1F9689EF");
#endif

            // managed series
            yield return new TestCaseData(new SHA1Managed(), stubPlaintext, "86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8");
            yield return new TestCaseData(new SHA256Managed(), stubPlaintext, "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB");
            yield return new TestCaseData(new SHA384Managed(), stubPlaintext, "54A59B9F22B0B80880D8427E548B7C23ABD873486E1F035DCE9CD697E85175033CAA88E6D57BC35EFAE0B5AFD3145F31");
            yield return new TestCaseData(new SHA512Managed(), stubPlaintext, "1F40FC92DA241694750979EE6CF582F2D5D7D28E18335DE05ABC54D0560E0F5302860C652BF08D560252AA5E74210546F369FBBBCE8C12CFC7957B2652FE9A75");
#if NET462 || NET47|| NET471 || NET472 || NET48
            yield return new TestCaseData(new RIPEMD160Managed(), stubPlaintext, "0BDC9D2D256B3EE9DAAE347BE6F4DC835A467FFE");
#endif

#if NET462 || NET47|| NET471 || NET472 || NET48
            // cng series
            yield return new TestCaseData(new MD5Cng(), stubPlaintext, "0CC175B9C0F1B6A831C399E269772661");
            yield return new TestCaseData(new SHA1Cng(), stubPlaintext, "86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8");
            yield return new TestCaseData(new SHA256Cng(), stubPlaintext, "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB");
            yield return new TestCaseData(new SHA384Cng(), stubPlaintext, "54A59B9F22B0B80880D8427E548B7C23ABD873486E1F035DCE9CD697E85175033CAA88E6D57BC35EFAE0B5AFD3145F31");
            yield return new TestCaseData(new SHA512Cng(), stubPlaintext, "1F40FC92DA241694750979EE6CF582F2D5D7D28E18335DE05ABC54D0560E0F5302860C652BF08D560252AA5E74210546F369FBBBCE8C12CFC7957B2652FE9A75");
#endif
        }

        [Test()]
        [TestCaseSource(nameof(ComputeHashToHexTestCaseSource_WithPlaintextAndPlaintextEncoding_ReturnExpected))]
        public void ComputeHashToHexTest_WithPlaintextAndPlaintextEncoding_ReturnExpected(
            HashAlgorithm target,
            string stubPlaintext,
            Encoding stubPlaintextEncoding,
            string expected)
        {
            // arrange

            // act
            string actual = target.ComputeHashToHex(stubPlaintext, stubPlaintextEncoding);

            // assert
            actual.Should().Be(expected);
        }

        private static IEnumerable ComputeHashToHexTestCaseSource_WithPlaintextAndPlaintextEncoding_ReturnExpected()
        {
            byte[] hmacKeyBytes = Encoding.UTF8.GetBytes("a");
            string stubPlaintext = "a";
            Encoding stubPlaintextEncoding = Encoding.Unicode;

            // CryptoServiceProvider
            yield return new TestCaseData(new MD5CryptoServiceProvider(), stubPlaintext, stubPlaintextEncoding, "4144E195F46DE78A3623DA7364D04F11");
            yield return new TestCaseData(new SHA1CryptoServiceProvider(), stubPlaintext, stubPlaintextEncoding, "0A04B971B03DA607CE6C455184037B660CA89F78");
            yield return new TestCaseData(new SHA256CryptoServiceProvider(), stubPlaintext, stubPlaintextEncoding, "FFE9AAEAA2A2D5048174DF0B80599EF0197EC024C4B051BC9860CFF58EF7F9F3");
            yield return new TestCaseData(new SHA384CryptoServiceProvider(), stubPlaintext, stubPlaintextEncoding, "DEFB4711C812122BA180A2ECE74CFCD86DD959451CD3BC2AFB672FA8A815CCC2BEE6CCC03816016570D340EC992B0F0C");
            yield return new TestCaseData(new SHA512CryptoServiceProvider(), stubPlaintext, stubPlaintextEncoding, "5C2CA3D50F46ECE6066C53BD1A490CBE5F72D2738AE9417332E91E5C3F75205C639D71A9A41D67D965FA137DDDF439E0AB9443A6EA44915E90D8B5B566D1C076");

            // hmac series
            yield return new TestCaseData(new HMACMD5(hmacKeyBytes), stubPlaintext, stubPlaintextEncoding, "56F5E256045D5F266FC270F8704B1339");
            yield return new TestCaseData(new HMACSHA1(hmacKeyBytes), stubPlaintext, stubPlaintextEncoding, "407AE88963DF8641A8197BF6953FA49C9B9ACAA5");
            yield return new TestCaseData(new HMACSHA256(hmacKeyBytes), stubPlaintext, stubPlaintextEncoding, "25C81056E1D1627790DEB69E7804B77C435585AC252DCB7AC57C58187AF782A9");
            yield return new TestCaseData(new HMACSHA384(hmacKeyBytes), stubPlaintext, stubPlaintextEncoding, "A7BF6548FDBEAEB319D86D48EE17A57443E5BDECE28BBCB14F8DEF94D93E68E60EE26A0999E611964CA0713F7C88DC60");
            yield return new TestCaseData(new HMACSHA512(hmacKeyBytes), stubPlaintext, stubPlaintextEncoding, "BDD6A03D94177BFD7D2E2B2292A4A10C4643403B6EF13B2EE8224E6A1F89081A7D210351BF0CA65CA3486DF6D8955F01C30D1FE0B66984009DDE67F636151405");
#if NET462 || NET47|| NET471 || NET472 || NET48
            yield return new TestCaseData(new HMACRIPEMD160(hmacKeyBytes), stubPlaintext, stubPlaintextEncoding, "014581B92FCDBDDAA587B98CE50E099533C60F96");
#endif

            // managed series
            yield return new TestCaseData(new SHA1Managed(), stubPlaintext, stubPlaintextEncoding, "0A04B971B03DA607CE6C455184037B660CA89F78");
            yield return new TestCaseData(new SHA256Managed(), stubPlaintext, stubPlaintextEncoding, "FFE9AAEAA2A2D5048174DF0B80599EF0197EC024C4B051BC9860CFF58EF7F9F3");
            yield return new TestCaseData(new SHA384Managed(), stubPlaintext, stubPlaintextEncoding, "DEFB4711C812122BA180A2ECE74CFCD86DD959451CD3BC2AFB672FA8A815CCC2BEE6CCC03816016570D340EC992B0F0C");
            yield return new TestCaseData(new SHA512Managed(), stubPlaintext, stubPlaintextEncoding, "5C2CA3D50F46ECE6066C53BD1A490CBE5F72D2738AE9417332E91E5C3F75205C639D71A9A41D67D965FA137DDDF439E0AB9443A6EA44915E90D8B5B566D1C076");
#if NET462 || NET47|| NET471 || NET472 || NET48
            yield return new TestCaseData(new RIPEMD160Managed(), stubPlaintext, stubPlaintextEncoding, "3213D398BB951AA09625539093524FA528848BD0");
#endif

#if NET462 || NET47|| NET471 || NET472 || NET48
            // cng series
            yield return new TestCaseData(new MD5Cng(), stubPlaintext, stubPlaintextEncoding, "4144E195F46DE78A3623DA7364D04F11");
            yield return new TestCaseData(new SHA1Cng(), stubPlaintext, stubPlaintextEncoding, "0A04B971B03DA607CE6C455184037B660CA89F78");
            yield return new TestCaseData(new SHA256Cng(), stubPlaintext, stubPlaintextEncoding, "FFE9AAEAA2A2D5048174DF0B80599EF0197EC024C4B051BC9860CFF58EF7F9F3");
            yield return new TestCaseData(new SHA384Cng(), stubPlaintext, stubPlaintextEncoding, "DEFB4711C812122BA180A2ECE74CFCD86DD959451CD3BC2AFB672FA8A815CCC2BEE6CCC03816016570D340EC992B0F0C");
            yield return new TestCaseData(new SHA512Cng(), stubPlaintext, stubPlaintextEncoding, "5C2CA3D50F46ECE6066C53BD1A490CBE5F72D2738AE9417332E91E5C3F75205C639D71A9A41D67D965FA137DDDF439E0AB9443A6EA44915E90D8B5B566D1C076");
#endif
        }
    }
}