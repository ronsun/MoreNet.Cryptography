using NUnit.Framework;
using System;
using System.Collections;
using System.Security.Cryptography;

namespace MoreNet.Cryptography.Extensions.Tests
{
#if NETCOREAPP3_1_OR_GREATER
    [TestFixture()]
    public class RSAExtensionsTests
    {
        [Test()]
        [TestCaseSource(nameof(ImportPrivateKeyTestCaseSource_ConstantKeys))]
        public void ImportPrivateKeyTest_ConstantKeys(string stubPrivateKey)
        {
            // arrange
            var target = RSA.Create();

            // act
            target.ImportPrivateKey(stubPrivateKey);

            // assert
            Assert.Pass();
        }

        private static IEnumerable ImportPrivateKeyTestCaseSource_ConstantKeys()
        {
            foreach (var key in RSATestData.OpensslRSA.Values)
            {
                yield return new TestCaseData(key.Pkcs1PrivateKey);
                yield return new TestCaseData(key.Pkcs8PrivateKey);
                yield return new TestCaseData(key.XmlPrivateKey);
            }
        }

        [Test()]
        [TestCaseSource(nameof(ImportPrivateKeyTestCaseSource_NETGeneratedKeys))]
        public void ImportPrivateKeyTest_NETGeneratedKeys(string stubPrivateKey)
        {
            // arrange
            var target = RSA.Create();

            // act
            target.ImportPrivateKey(stubPrivateKey);

            // assert
            Assert.Pass();
        }

        private static IEnumerable ImportPrivateKeyTestCaseSource_NETGeneratedKeys()
        {
            var keyLengths = new int[] { 512, 1024, 2048, 3072, 4096, 7680, 15360 };
            foreach (var length in keyLengths)
            {
                yield return new TestCaseData(Convert.ToBase64String(RSA.Create(length).ExportRSAPrivateKey()));
                yield return new TestCaseData(Convert.ToBase64String(RSA.Create(length).ExportPkcs8PrivateKey()));
                yield return new TestCaseData(RSA.Create(length).ToXmlString(true));
            }
        }

        [Test()]
        [TestCaseSource(nameof(ImportPublicKeyTestCaseSource_ConstantKeys))]
        public void ImportPublicKeyTest_ConstantKeys(string stubPublic)
        {
            // arrange
            var target = RSA.Create();

            // act
            target.ImportPublicKey(stubPublic);

            // assert
            Assert.Pass();
        }

        private static IEnumerable ImportPublicKeyTestCaseSource_ConstantKeys()
        {
            foreach (var key in RSATestData.OpensslRSA.Values)
            {
                yield return new TestCaseData(key.Pkcs1PublicKey);
                yield return new TestCaseData(key.SubjectPublicKeyInfo);
                yield return new TestCaseData(key.XmlPublicKey);
            }
        }


        [Test()]
        [TestCaseSource(nameof(ImportPublicKeyTestCaseSource_NETGeneratedKeys))]
        public void ImportPublicKeyTest_NETGeneratedKeys(string stubPublic)
        {
            // arrange
            var target = RSA.Create();

            // act
            target.ImportPublicKey(stubPublic);

            // assert
            Assert.Pass();
        }

        private static IEnumerable ImportPublicKeyTestCaseSource_NETGeneratedKeys()
        {
            var keyLengths = new int[] { 512, 1024, 2048, 3072, 4096, 7680, 15360 };
            foreach (var length in keyLengths)
            {
                yield return new TestCaseData(Convert.ToBase64String(RSA.Create(length).ExportRSAPublicKey()));
                yield return new TestCaseData(Convert.ToBase64String(RSA.Create(length).ExportSubjectPublicKeyInfo()));
                yield return new TestCaseData(RSA.Create(length).ToXmlString(false));
            }
        }
    }
#endif
}