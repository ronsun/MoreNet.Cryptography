using System;

namespace MoreNet.Cryptography
{
    public struct KeyedHashType : IEquatable<KeyedHashType>
    {
        /// <summary>
        /// Gets a <see cref="KeyedHashType" /> representing "HMACMD5".
        /// </summary>
        public static KeyedHashType HMACMD5 => new KeyedHashType("System.Security.Cryptography.HMACMD5");

        /// <summary>
        /// Gets a <see cref="KeyedHashType" /> representing "HMACRIPEMD160".
        /// </summary>
        public static KeyedHashType HMACRIPEMD160 => new KeyedHashType("System.Security.Cryptography.HMACRIPEMD160");

        /// <summary>
        /// Gets a <see cref="KeyedHashType" /> representing "HMACSHA1".
        /// </summary>
        public static KeyedHashType HMACSHA1 => new KeyedHashType("System.Security.Cryptography.HMACSHA1");

        /// <summary>
        /// Gets a <see cref="KeyedHashType" /> representing "HMACSHA256".
        /// </summary>
        public static KeyedHashType HMACSHA256 => new KeyedHashType("System.Security.Cryptography.HMACSHA256");

        /// <summary>
        /// Gets a <see cref="KeyedHashType" /> representing "HMACSHA384".
        /// </summary>
        public static KeyedHashType HMACSHA384 => new KeyedHashType("System.Security.Cryptography.HMACSHA384");

        /// <summary>
        /// Gets a <see cref="KeyedHashType" /> representing "HMACSHA512".
        /// </summary>
        public static KeyedHashType HMACSHA512 => new KeyedHashType("System.Security.Cryptography.HMACSHA512");

        /// <summary>
        /// Gets a <see cref="KeyedHashType" /> representing "MACTripleDES".
        /// </summary>
        public static KeyedHashType MACTripleDES => new KeyedHashType("System.Security.Cryptography.TripleDES");

        /// <summary>
        /// Gets the underlying string representation of the algorithm name.
        /// </summary>
        /// <remarks>
        /// May be null or empty to indicate that no hash algorithm is applicable.
        /// </remarks>
        public string Name { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyedHashType"/> struct.
        /// </summary>
        /// <param name="name">The custom hash algorithm name.</param>
        public KeyedHashType(string name)
        {
            Name = name;
        }

        /// <inheritdoc/>
        public override string ToString() => Name ?? string.Empty;

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is KeyedHashType && Equals((KeyedHashType)obj);

        /// <inheritdoc/>
        public bool Equals(KeyedHashType other) => Name == other.Name;

        /// <inheritdoc/>
        public override int GetHashCode() => Name?.GetHashCode() ?? 0;

        public static bool operator ==(KeyedHashType left, KeyedHashType right) => left.Equals(right);

        public static bool operator !=(KeyedHashType left, KeyedHashType right) => !(left == right);
    }
}
