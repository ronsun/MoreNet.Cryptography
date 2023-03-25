using FluentAssertions;
using NSubstitute;
using NUnit.Framework;
using System;
using System.Security.Cryptography;

namespace MoreNet.Cryptography.Tests
{
    [TestFixture()]
    public partial class RandomValueGeneratorTests
    {
        [Test()]
        public void GetIntTest_InputMinGreaterThanMax_ThrowExpectedException()
        {
            // arrange
            int stubMin = 1;
            int stubMax = 0;
            var stubRandomNumberGenerator = Substitute.For<RandomNumberGenerator>();
            var target = new RandomValueGenerator(stubRandomNumberGenerator);

            // act
            Action action = () => target.GetInt(stubMin, stubMax);

            // assert
            action.Should().ThrowExactly<ArgumentException>();
        }

        [Test()]
        public void GetStringTest_InputLengthOutOfRange_ThrowExpectedException()
        {
            // arrange
            int stubLength = -1;
            var stubDictionary = "a";
            var stubRandomNumberGenerator = Substitute.For<RandomNumberGenerator>();
            var target = new RandomValueGenerator(stubRandomNumberGenerator);

            // act
            Action action = () => target.GetString(stubLength, stubDictionary);

            // assert
            action.Should().ThrowExactly<ArgumentOutOfRangeException>();
        }

        [Test()]
        public void GetStringTest_InputNullDictioanry_ThrowExpectedException()
        {
            // arrange
            int stubLength = 1;
            string stubDictionary = null;
            var stubRandomNumberGenerator = Substitute.For<RandomNumberGenerator>();
            var target = new RandomValueGenerator(stubRandomNumberGenerator);

            // act
            Action action = () => target.GetString(stubLength, stubDictionary);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [Test()]
        public void GetStringTest_InputEmptyDictioanry_ThrowExpectedException()
        {
            // arrange
            int stubLength = 1;
            string stubDictionary = string.Empty;
            var stubRandomNumberGenerator = Substitute.For<RandomNumberGenerator>();
            var target = new RandomValueGenerator(stubRandomNumberGenerator);

            // act
            Action action = () => target.GetString(stubLength, stubDictionary);

            // assert
            action.Should().ThrowExactly<ArgumentException>();
        }
    }
}