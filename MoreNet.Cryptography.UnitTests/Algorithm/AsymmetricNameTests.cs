using FluentAssertions;
using NUnit.Framework;

namespace MoreNet.Cryptography.Algorithm.Tests
{
    [TestFixture()]
    public class AsymmetricNameTests
    {
        [Test()]
        public void GetHashCodeTest_SameName_ReturnsSameHashCode()
        {
            // arrange
            var expected = AsymmetricName.RSA.GetHashCode();

            // act
            var actual = AsymmetricName.RSA.GetHashCode();

            // assert
            actual.Should().Be(expected);
        }

        [Test()]
        public void EqualsTest_FromObject()
        {
            // arrange

            // act
            var actual = AsymmetricName.RSA.Equals((object)AsymmetricName.RSA);

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void EqualsTest_FromIEquatable()
        {
            // arrange

            // act
            var actual = AsymmetricName.RSA.Equals(AsymmetricName.RSA);

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void EqualsOperatorTest()
        {
            // arrange

            // act
            var actual = AsymmetricName.RSA == AsymmetricName.RSA;

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void NotEqualsOperatorTest_False()
        {
            // arrange

            // act
            var actual = AsymmetricName.RSA != AsymmetricName.RSA;

            // assert
            actual.Should().BeFalse();
        }
    }
}