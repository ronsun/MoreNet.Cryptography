using FluentAssertions;
using NUnit.Framework;

namespace MoreNet.Cryptography.Algorithm.Tests
{
    [TestFixture()]
    public class KeyedHashNameTests
    {
        [Test()]
        public void GetHashCodeTest_SameName_ReturnsSameHashCode()
        {
            // arrange
            var expected = KeyedHashName.HMACMD5.GetHashCode();

            // act
            var actual = KeyedHashName.HMACMD5.GetHashCode();

            // assert
            actual.Should().Be(expected);
        }

        [Test()]
        public void EqualsTest_FromObject()
        {
            // arrange

            // act
            var actual = KeyedHashName.HMACMD5.Equals((object)KeyedHashName.HMACMD5);

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void EqualsTest_FromIEquatable()
        {
            // arrange

            // act
            var actual = KeyedHashName.HMACMD5.Equals(KeyedHashName.HMACMD5);

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void EqualsOperatorTest()
        {
            // arrange

            // act
            var actual = KeyedHashName.HMACMD5 == KeyedHashName.HMACMD5;

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void NotEqualsOperatorTest_True()
        {
            // arrange

            // act
            var actual = KeyedHashName.HMACMD5 != KeyedHashName.HMACSHA1;

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void NotEqualsOperatorTest_False()
        {
            // arrange

            // act
            var actual = KeyedHashName.HMACMD5 != KeyedHashName.HMACMD5;

            // assert
            actual.Should().BeFalse();
        }
    }
}