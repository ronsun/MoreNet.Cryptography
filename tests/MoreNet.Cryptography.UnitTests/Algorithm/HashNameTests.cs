using FluentAssertions;
using NUnit.Framework;

namespace MoreNet.Cryptography.Algorithm.Tests
{
    [TestFixture()]
    public class HashNameTests
    {
        [Test()]
        public void GetHashCodeTest_SameName_ReturnsSameHashCode()
        {
            // arrange
            var expected = HashName.MD5.GetHashCode();

            // act
            var actual = HashName.MD5.GetHashCode();

            // assert
            actual.Should().Be(expected);
        }

        [Test()]
        public void EqualsTest_FromObject()
        {
            // arrange

            // act
            var actual = HashName.MD5.Equals((object)HashName.MD5);

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void EqualsTest_FromIEquatable()
        {
            // arrange

            // act
            var actual = HashName.MD5.Equals(HashName.MD5);

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void EqualsOperatorTest()
        {
            // arrange

            // act
            var actual = HashName.MD5 == HashName.MD5;

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void NotEqualsOperatorTest_True()
        {
            // arrange

            // act
            var actual = HashName.MD5 != HashName.SHA1;

            // assert
            actual.Should().BeTrue();
        }

        [Test()]
        public void NotEqualsOperatorTest_False()
        {
            // arrange

            // act
            var actual = HashName.MD5 != HashName.MD5;

            // assert
            actual.Should().BeFalse();
        }
    }
}