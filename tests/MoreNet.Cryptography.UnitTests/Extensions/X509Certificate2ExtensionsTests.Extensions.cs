using FluentAssertions;
using NSubstitute;
using NUnit.Framework;
using System;
using System.Collections;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace MoreNet.Cryptography.Extensions.Tests
{
    [TestFixture()]
    public class X509Certificate2ExtensionsTests
    {
        [Test()]
        [TestCaseSource(nameof(TestCaseSource_AllMethods_InputNullX509Certificate2_ThrowExpectedException))]
        public void Test_AllMethods_InputNullX509Certificate2_ThrowExpectedException(Action stubAction)
        {
            // arrange

            // act

            // assert
            stubAction.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable TestCaseSource_AllMethods_InputNullX509Certificate2_ThrowExpectedException()
        {
            X509Certificate2 target = null;
            Assembly stubAssembly = Assembly.GetExecutingAssembly();
            string stubFullName = string.Empty;
            X509KeyStorageFlags stubKeyStorageFlags = default;
            string stubPassword = string.Empty;

            Action stubAction = null;

            stubAction = () => target.Import(stubAssembly, stubFullName, stubKeyStorageFlags);
            yield return new TestCaseData(stubAction);

            stubAction = () => target.Import(stubAssembly, stubFullName, stubPassword);
            yield return new TestCaseData(stubAction);
        }

        [Test()]
        [TestCaseSource(nameof(ImportTestCaseSource_WithAssemblyAndFullNameAndPassword_InputNullArguments_ThrowExpectedException))]
        public void ImportTest_WithAssemblyAndFullNameAndPassword_InputNullArguments_ThrowExpectedException(
            Assembly stubAssembly,
            string stubFullName,
            string stubPassword
            )
        {
            // arrange
            var target = Substitute.For<X509Certificate2>();

            // act
            Action action = () => target.Import(stubAssembly, stubFullName, stubPassword);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable ImportTestCaseSource_WithAssemblyAndFullNameAndPassword_InputNullArguments_ThrowExpectedException()
        {
            Assembly stubAssembly = null;
            string stubFullName = null;
            string stubPassword = null;

            stubAssembly = null;
            stubFullName = string.Empty;
            stubPassword = string.Empty;
            yield return new TestCaseData(stubAssembly, stubFullName, stubPassword);

            stubAssembly = Assembly.GetExecutingAssembly();
            stubFullName = null;
            stubPassword = string.Empty;
            yield return new TestCaseData(stubAssembly, stubFullName, stubPassword);

            stubAssembly = Assembly.GetExecutingAssembly();
            stubFullName = string.Empty;
            stubPassword = null;
            yield return new TestCaseData(stubAssembly, stubFullName, stubPassword);
        }

        [Test()]
        [TestCaseSource(nameof(ImportTestCaseSource_WithAssemblyAndFullNameAndX509KeyStorageFlags_InputNullArguments_ThrowExpectedException))]
        public void ImportTest_WithAssemblyAndFullNameAndX509KeyStorageFlags_InputNullArguments_ThrowExpectedException(
            Assembly stubAssembly,
            string stubFullName
            )
        {
            // arrange
            var target = Substitute.For<X509Certificate2>();
            X509KeyStorageFlags stubX509KeyStorageFlags = default;

            // act
            Action action = () => target.Import(stubAssembly, stubFullName, stubX509KeyStorageFlags);

            // assert
            action.Should().ThrowExactly<ArgumentNullException>();
        }

        public static IEnumerable ImportTestCaseSource_WithAssemblyAndFullNameAndX509KeyStorageFlags_InputNullArguments_ThrowExpectedException()
        {
            Assembly stubAssembly = null;
            string stubFullName = null;

            stubAssembly = null;
            stubFullName = string.Empty;
            yield return new TestCaseData(stubAssembly, stubFullName);

            stubAssembly = Assembly.GetExecutingAssembly();
            stubFullName = null;
            yield return new TestCaseData(stubAssembly, stubFullName);
        }
    }
}