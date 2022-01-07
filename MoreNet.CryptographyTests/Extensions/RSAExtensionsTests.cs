#if NETCOREAPP3_1_OR_GREATER

using FluentAssertions;
using NUnit.Framework;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace System.Security.Cryptography.IntegrationTests
{
    [TestFixture()]
    public class RSAExtensionsTests
    {
        private const string PublicKey512 = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAI32qtivsOn59tIjehhHe3guZ0yEY/RhHHHzmiPJJ0Nx2CpSdQPJvjS/+e6PO7scYkojJ+0PY6CC602FNbzQxlcCAwEAAQ==";
        private const string PrivateKey512 = "MIIBOgIBAAJBAI32qtivsOn59tIjehhHe3guZ0yEY/RhHHHzmiPJJ0Nx2CpSdQPJvjS/+e6PO7scYkojJ+0PY6CC602FNbzQxlcCAwEAAQJAUoj0byJGAuIWw7lohLEacZbY672Ut0G2XfG4zdFnCGhK+krt+3VaXWnrKGftDuNJpSjMvWMEqqC90q2r7mVpwQIhANJuzQQMLgXFuDQbevNjds+U+On57UGtYVXpogBV2lNHAiEArLRRvrOCy3usWlJJLThEgnVmiYj6UQ0K+nw5+J+X3HECIBr/TB4w0da7vx4wSF3hbOTE4ApkniPG8q3rA3W3jgMRAiAtItNaa7/7Pk9FK8xELTh6gARUXaBOHoKIBH+CIvOlgQIhAMmRVbmWYKEJTNWfawscIBwlOCsCtVnNgNIHVxox/ln0";

        private const string PublicKey1024 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtiPuJ2+WCF4TvPhlNJtoQVtiF+fsSiO0EX4kkUAg3IGHThT3orncuJgweiQLqSPCg8S/NSx25ob+gczCm/R79rXzLK+RG/RICv1L/8IVqOBl/SvND0hIbJYzN1qaAi+phKHk6ccwdXEo1RrKPCeE2W/+lsmvd8tqgtQrvLf616QIDAQAB";
        private const string PrivateKey1024 = "MIICWwIBAAKBgQCtiPuJ2+WCF4TvPhlNJtoQVtiF+fsSiO0EX4kkUAg3IGHThT3orncuJgweiQLqSPCg8S/NSx25ob+gczCm/R79rXzLK+RG/RICv1L/8IVqOBl/SvND0hIbJYzN1qaAi+phKHk6ccwdXEo1RrKPCeE2W/+lsmvd8tqgtQrvLf616QIDAQABAoGAS3vJRmcTRuoqFdLiOJAMzIyqNGTPVHmg94UC53u0hx4bz2Em076H8tfz75hTX0uI98jRrS/eZy+3ZfiVEh4KSz/nn0z4ugeEX+2FpzkTyoJaDPh/cIp4nil6F89cB6cBX4NWd8h6nEfjzP7EFh9w3kCRRJWrSccQwwcwW165+nECQQDn3IudND+kwlacc8UXZlu/4IFZGwnvBgC0/ABxIfjuX5Pc9ved24vS4j18uc8F6gcxEXJPGHktAlo5ccS0vSrFAkEAv5nzhnYiDM+FLkomqbbl96gFWTZtuMICsfCHezKMhvvLt48zVBWYoriA++/jNp0/8qfSNpilM/SwIH1+JFOg1QJAYBE/P6lwXUGwRS6qkOF2TnAk59iOKx0fmd14CWf8DjhHuZwSSLO4oW3f8BfEsTygMjJ6XE9VldKNs5Nx3zkpyQJATzADlBkS7ZR/CKig3he3Z+nLfBmgs3GLx5sPg31a0xcSFSVcI25hjS8QMA/vKk1HdrShjur7rEN+346+KalemQJAE9uLEzenVAqdiePBDTBwkIvQb0EDBdmBJ+EonsbEtANpg6M6BOcY+ChIjpmL5/EkN8YhGrSZtkVUIlUe+TCqNw==";

        private const string PublicKey2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkASqy594Onb1bboUlPejN5zzGZI9Lv28cD5jnBnB10P5MOLtTHbEvTi8KErxrA3G/XI55SfD+fIpYvaxtPYabDkeaRV5d7VHZEQvHOqF5OHrWrj3ZlpxG1/dmJyvbTsy5YFIVmpjobpAVhS9IMCRB5ZxsjHIBtaL+MYEqd3pstSxxjR73u5l37KT1mMm1tqfobc73SsYwE5v9LFzcnLIHIq6I12u9hmpcWgoe3HRo3ZSVRDXCR7Sq+jnvuVzuuht5XwTGV6IVCK5uxG19KKCesajWOVtg8uxtdSHb2mTvUZJlzvx2GQRy12nKEGthxUi5lD4e6b/vo3qd5L4orqIwIDAQAB";
        private const string PrivateKey2048 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWQBKrLn3g6dvVtuhSU96M3nPMZkj0u/bxwPmOcGcHXQ/kw4u1MdsS9OLwoSvGsDcb9cjnlJ8P58ili9rG09hpsOR5pFXl3tUdkRC8c6oXk4etauPdmWnEbX92YnK9tOzLlgUhWamOhukBWFL0gwJEHlnGyMcgG1ov4xgSp3emy1LHGNHve7mXfspPWYybW2p+htzvdKxjATm/0sXNycsgcirojXa72GalxaCh7cdGjdlJVENcJHtKr6Oe+5XO66G3lfBMZXohUIrm7EbX0ooJ6xqNY5W2Dy7G11IdvaZO9RkmXO/HYZBHLXacoQa2HFSLmUPh7pv++jep3kviiuojAgMBAAECggEBAJKeadlUIBBoBVdTCviz0TvkJFo1AkKYXg1iA+VEuLWN0eGqFN43jZG9GOw6Su6zrMODII8kD+hEhh9OD6rwtYHF1d8CR7Rus8cLdaqAsF4bYE4RPdVUTMsbE0QiI9gOAvlUJyN5TKXB7wSZ/TGP2plAiNkbun0RU/vg/u/NLky7IzrOHk+5Gorm719m5RA3l8f/7tW62wv6anZemr/MOifuGtdleuYbOT33T7vlhjaGM2b7fvJgcNJ3l4pY29I5FVuIDUVSgl3aUy9VLNuqv+K70l82Psq/N+jvrRYeTa9xJGFxJrKedPJqCbKEZWJIqVT3mq0jFuVi8X26Oul1zMECgYEA0QbMq7iOEH8yxznKfw/HPCfs7rk3vGS3XHgJpJ1oRQSS27g6VYYDGhsQoQRzPbeYDbwrZci9mOO4AeZ2QU/qelZ0I8euBxQpG/mwbcns0h07PYt+ROhIRaJuIPUmmUpSsMUqOz7b2joM3FMqWGBD2hyeTYiI5joQrw19JaYrcQMCgYEAuAPm1qH8Pf8JVX/YAjVdaaztAx7duXU64zrJsIhbj0Zk/QjQfhuwg7vNBXZtz8H+91W3H034J35KcMTiYbi0CO01kflTvc8Pyay5l2kkVImiqUPo5vpm126/RWoMbgnSqfQYh4h9WtATF6H/CZuOf1nByix+RqRE11eM0JsvCGECgYBAGFWqUm09ocNwU8hELhJp39RHX4Q3wKp5MFXEpH/UqhJeTZ+VmgJZfvMabMLpqeJ2U7z6+RMqTqmd641Xeans2ZXDYvd6NDRm36m6ALEdvNjthlixyIhg0e3zLTkoyCGTEuJgSGYiBKrs5JOXhe1IdH4WSEeyURvMkdZONSYdAQKBgCwZc0bYxzSsXDZLTx8oXtymfp6S1RxPBe/S9OcDpr2tZyJk7GJsjF7lsPqwKRzzJwFrX1l3PBNq5rgj1wUIWM0S3BXBpNoGN4hjho7MudIwsfTSu4wvUloqxlgCVDxCymPEheRlR3VuDEVLo21QBFRs1E55X0HauEzLRInxxtHBAoGAb1pOSpmHR2PPEO/RHhxN0+nb0+XuEAUFnsIQ9QsbK6yMzADA9pl3NkswqzA8+K8j9j6aAoiY14KiPs5iRQuNhN0plHNSCorHnhTtoBAAqdBdZ+UapteVxyqR3AD6W1fHxY6voX7+gHGLw94reC4tyHeno5hMMmrobWh4Pp5byKg=";

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
            var stubEncryptRSA = CreateEncryptRSA(stubPublicKey);
            var stubDecryptRSA = CreateDecryptRSA(stubPrivateKey);

            // act
            var ciphertext = stubEncryptRSA.EncryptChunks(stubPlaintextBytes, stubPadding);
            var actualPlaintextBytes = stubDecryptRSA.DecryptChunks(ciphertext, stubPadding);

            // assert
            actualPlaintextBytes.Should().BeEquivalentTo(stubPlaintextBytes);
        }

        private static IEnumerable EncryptDecryptTestCaseSource_EncryptAndDecryptCorrectly()
        {
            // 64 bytes (512 bits) - 11 bytes (padding size of Pkcs1), edge case and 1 byte longer scenario
            yield return new TestCaseData(64 - 11, RSAEncryptionPadding.Pkcs1, PublicKey512, PrivateKey512);
            yield return new TestCaseData(64 - 11 + 1, RSAEncryptionPadding.Pkcs1, PublicKey512, PrivateKey512);

            // 64 bytes (512 bits) - 42 bytes (padding size of OaepSHA1), edge case and 1 byte longer scenario
            yield return new TestCaseData(64 - 42, RSAEncryptionPadding.OaepSHA1, PublicKey512, PrivateKey512);
            yield return new TestCaseData(64 - 42 + 1, RSAEncryptionPadding.OaepSHA1, PublicKey512, PrivateKey512);

            // 128 bytes (1024 bits) - 66 bytes (padding size of OaepSHA256), edge case and 1 byte longer scenario
            yield return new TestCaseData(128 - 66, RSAEncryptionPadding.OaepSHA256, PublicKey1024, PrivateKey1024);
            yield return new TestCaseData(128 - 66 + 1, RSAEncryptionPadding.OaepSHA256, PublicKey1024, PrivateKey1024);

            // 128 bytes (1024 bits) - 98 bytes (padding size of OaepSHA384), edge case and 1 byte longer scenario
            yield return new TestCaseData(128 - 98, RSAEncryptionPadding.OaepSHA384, PublicKey1024, PrivateKey1024);
            yield return new TestCaseData(128 - 98 + 1, RSAEncryptionPadding.OaepSHA384, PublicKey1024, PrivateKey1024);

            // 256 bytes (2048 bits) - 130 bytes (padding size of OaepSHA512), edge case and 1 byte longer scenario
            yield return new TestCaseData(256 - 130, RSAEncryptionPadding.OaepSHA512, PublicKey2048, PrivateKey2048);
            yield return new TestCaseData(256 - 130 + 1, RSAEncryptionPadding.OaepSHA512, PublicKey2048, PrivateKey2048);
        }

        private RSA CreateEncryptRSA(string publicKey)
        {
            var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out int _);
            return rsa;
        }

        private RSA CreateDecryptRSA(string privateKey)
        {
            var rsa = RSA.Create();
            // TODO: I don't know why I should use ImportPkcs8PrivateKey for 2048 key to avoid exception.
            if (privateKey == PrivateKey2048)
            {
                rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out int _);
            }
            else
            {
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out int _);
            }
            return rsa;
        }
    }
}

#endif