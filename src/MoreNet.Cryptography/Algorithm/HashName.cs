using System;

namespace MoreNet.Cryptography.Algorithm
{
    /// <summary>
    /// Name of hash algorithm.
    /// </summary>
    public struct HashName : IEquatable<HashName>
    {
        private HashName(string name)
        {
            Name = name;
        }

        /// <summary>
        /// Gets a <see cref="HashName" /> representing "MD5".
        /// </summary>
        public static HashName MD5 => new HashName("System.Security.Cryptography.MD5");

        /// <summary>
        /// Gets a <see cref="HashName" /> representing "SHA1".
        /// </summary>
        public static HashName SHA1 => new HashName("System.Security.Cryptography.SHA1");

        /// <summary>
        /// Gets a <see cref="HashName" /> representing "SHA256".
        /// </summary>
        public static HashName SHA256 => new HashName("System.Security.Cryptography.SHA256");

        /// <summary>
        /// Gets a <see cref="HashName" /> representing "SHA384".
        /// </summary>
        public static HashName SHA384 => new HashName("System.Security.Cryptography.SHA384");

        /// <summary>
        /// Gets a <see cref="HashName" /> representing "SHA512".
        /// </summary>
        public static HashName SHA512 => new HashName("System.Security.Cryptography.SHA512");

        /// <summary>
        /// Gets a <see cref="HashName" /> representing "RIPEMD160".
        /// </summary>
        public static HashName RIPEMD160 => new HashName("System.Security.Cryptography.RIPEMD160");

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
        public static bool operator ==(HashName left, HashName right) => left.Equals(right);

        /// <summary>
        /// Not equal operator.
        /// </summary>
        /// <param name="left">Left.</param>
        /// <param name="right">Right.</param>
        /// <returns>Is not equal.</returns>
        public static bool operator !=(HashName left, HashName right) => !left.Equals(right);

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is HashName other && Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode() => HashCode.Combine(this.Name);

        /// <inheritdoc/>
        public bool Equals(HashName other) => this.Name == other.Name;
    }
}
