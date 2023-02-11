using FluentAssertions;
using NUnit.Framework;

namespace MoreNet.Cryptography.Algorithm.Tests
{
    [TestFixture()]
    public class SymmetricNameTests
    {
        [Test()]
        public void GetHashCodeTest_SameName_ReturnsSameHashCode()
        {
            // arrange
            var expected = SymmetricName.Aes.GetHashCode();

            // act
            var actual = SymmetricName.Aes.GetHashCode();

            // assert
            actual.Should().Be(expected);
        }

        [Test()]
        public void EqualsTest_FromObject()
        {
            // arrange

            // act
            var actual = SymmetricName.Aes.Equals((object)SymmetricName.Aes);

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void EqualsTest_FromIEquatable()
        {
            // arrange

            // act
            var actual = SymmetricName.Aes.Equals(SymmetricName.Aes);

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void EqualsOperatorTest()
        {
            // arrange

            // act
            var actual = SymmetricName.Aes == SymmetricName.Aes;

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void NotEqualsOperatorTest_True()
        {
            // arrange

            // act
            var actual = SymmetricName.Aes != SymmetricName.DES;

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void NotEqualsOperatorTest_False()
        {
            // arrange

            // act
            var actual = SymmetricName.Aes != SymmetricName.Aes;

            // assert
            actual.Should().BeFalse();
        }
    }
}