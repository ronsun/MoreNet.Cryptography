using FluentAssertions;
using NUnit.Framework;
using System.Security.Cryptography;

namespace MoreNet.Cryptography.IntegrationTests
{
    [TestFixture()]
    public partial class RandomValueGeneratorTests
    {
        [Test()]
        // positive
        [TestCase(1, 2)]
        // negative
        [TestCase(-2, -1)]
        // negative to positive
        [TestCase(-1, 2)]
        public void GetIntTest_ReturnsIntInRange(int stubMin, int stubMax)
        {
            // arrange
            var target = new RandomValueGenerator(RandomNumberGenerator.Create());

            // act
            var actual = target.GetInt(stubMin, stubMax);

            // assert
            actual.Should().BeGreaterThanOrEqualTo(stubMin).And.BeLessThan(stubMax);
        }

        [Test()]
        public void GetIntTest_InputMinEqualsMax_ReturnsMin()
        {
            // arrange
            int stubMin = 0;
            int stubMax = 0;
            var target = new RandomValueGenerator(RandomNumberGenerator.Create());

            // act
            var actual = target.GetInt(stubMin, stubMax);

            // assert
            actual.Should().Be(0);
        }


        [Test()]
        [TestCase(0, "a", "")]
        [TestCase(1, "a", "a")]
        [TestCase(3, "a", "aaa")]
        // text element
        [TestCase(1, "\u0061\u031B", "\u0061\u031B")]
        public void GetStringTest_ReturnsExpectedString(int stubLengh, string stubDictionary, string expected)
        {
            // arrange
            var target = new RandomValueGenerator(RandomNumberGenerator.Create());

            // act
            var actual = target.GetString(stubLengh, stubDictionary);

            // assert
            actual.Should().Be(expected);
        }
    }
}