using System;

namespace MoreNet.Cryptography.Algorithm
{
    /// <summary>
    /// Name of keyed hash algorithm.
    /// </summary>
    public struct KeyedHashName : IEquatable<KeyedHashName>
    {
        private KeyedHashName(string name)
        {
            Name = name;
        }

        /// <summary>
        /// Gets a <see cref="KeyedHashName" /> representing "HMACMD5".
        /// </summary>
        public static KeyedHashName HMACMD5 => new KeyedHashName("System.Security.Cryptography.HMACMD5");

        /// <summary>
        /// Gets a <see cref="KeyedHashName" /> representing "HMACRIPEMD160".
        /// </summary>
        public static KeyedHashName HMACRIPEMD160 => new KeyedHashName("System.Security.Cryptography.HMACRIPEMD160");

        /// <summary>
        /// Gets a <see cref="KeyedHashName" /> representing "HMACSHA1".
        /// </summary>
        public static KeyedHashName HMACSHA1 => new KeyedHashName("System.Security.Cryptography.HMACSHA1");

        /// <summary>
        /// Gets a <see cref="KeyedHashName" /> representing "HMACSHA256".
        /// </summary>
        public static KeyedHashName HMACSHA256 => new KeyedHashName("System.Security.Cryptography.HMACSHA256");

        /// <summary>
        /// Gets a <see cref="KeyedHashName" /> representing "HMACSHA384".
        /// </summary>
        public static KeyedHashName HMACSHA384 => new KeyedHashName("System.Security.Cryptography.HMACSHA384");

        /// <summary>
        /// Gets a <see cref="KeyedHashName" /> representing "HMACSHA512".
        /// </summary>
        public static KeyedHashName HMACSHA512 => new KeyedHashName("System.Security.Cryptography.HMACSHA512");

        /// <summary>
        /// Gets a <see cref="KeyedHashName" /> representing "MACTripleDES".
        /// </summary>
        public static KeyedHashName MACTripleDES => new KeyedHashName("System.Security.Cryptography.TripleDES");

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
        public static bool operator ==(KeyedHashName left, KeyedHashName right) => left.Equals(right);

        /// <summary>
        /// Not equal operator.
        /// </summary>
        /// <param name="left">Left.</param>
        /// <param name="right">Right.</param>
        /// <returns>Is not equal.</returns>
        public static bool operator !=(KeyedHashName left, KeyedHashName right) => !(left == right);

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is KeyedHashName other && Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode() => HashCode.Combine(this.Name);

        /// <inheritdoc/>
        public bool Equals(KeyedHashName other) => this.Name == other.Name;
    }
}
