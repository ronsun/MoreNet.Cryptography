using System;

namespace MoreNet.Cryptography.Algorithm
{
    /// <summary>
    /// Name of asymmetric algorithm.
    /// </summary>
    public struct AsymmetricName : IEquatable<AsymmetricName>
    {
        private AsymmetricName(string name)
        {
            Name = name;
        }

        /// <summary>
        /// Gets a <see cref="AsymmetricName" /> representing "RSA".
        /// </summary>
        public static AsymmetricName RSA => new AsymmetricName("System.Security.Cryptography.RSA");

        /// <summary>
        /// Gets the underlying string representation of the algorithm name.
        /// </summary>
        /// <remarks>
        /// May be null or empty to indicate that no hash algorithm is applicable.
        /// </remarks>
        public string Name { get; }

        /// <summary>
        /// Equal operator.
        /// </summary>
        /// <param name="left">Left.</param>
        /// <param name="right">Right.</param>
        /// <returns>Is equal.</returns>
        public static bool operator ==(AsymmetricName left, AsymmetricName right) => left.Equals(right);

        /// <summary>
        /// Not equal operator.
        /// </summary>
        /// <param name="left">Left.</param>
        /// <param name="right">Right.</param>
        /// <returns>Is not equal.</returns>
        public static bool operator !=(AsymmetricName left, AsymmetricName right) => !left.Equals(right);

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is AsymmetricName other && Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode() => HashCode.Combine(this.Name);

        /// <inheritdoc/>
        public bool Equals(AsymmetricName other) => this.Name == other.Name;
    }
}
