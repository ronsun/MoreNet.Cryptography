using System;

namespace MoreNet.Cryptography.Algorithm
{
    public struct SymmetricName : IEquatable<SymmetricName>
    {
        /// <summary>
        /// Gets a <see cref="SymmetricName" /> representing "Aes".
        /// </summary>
        public static SymmetricName Aes => new SymmetricName("System.Security.Cryptography.Aes");

        /// <summary>
        /// Gets a <see cref="SymmetricName" /> representing "DES".
        /// </summary>
        public static SymmetricName DES => new SymmetricName("System.Security.Cryptography.DES");

        /// <summary>
        /// Gets a <see cref="SymmetricName" /> representing "Aes".
        /// </summary>
        public static SymmetricName RC2 => new SymmetricName("System.Security.Cryptography.RC2");

        /// <summary>
        /// Gets a <see cref="SymmetricName" /> representing "Aes".
        /// </summary>
        public static SymmetricName Rijndael => new SymmetricName("System.Security.Cryptography.Rijndael");

        /// <summary>
        /// Gets a <see cref="SymmetricName" /> representing "Aes".
        /// </summary>
        public static SymmetricName TripleDES => new SymmetricName("System.Security.Cryptography.TripleDES");

        /// <summary>
        /// Gets the underlying string representation of the algorithm name.
        /// </summary>
        /// <remarks>
        /// May be null or empty to indicate that no hash algorithm is applicable.
        /// </remarks>
        public string Name { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricName"/> struct.
        /// </summary>
        /// <param name="name">The custom hash algorithm name.</param>
        public SymmetricName(string name)
        {
            Name = name;
        }

        /// <inheritdoc/>
        public override string ToString() => Name ?? string.Empty;

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is SymmetricName && Equals((SymmetricName)obj);

        /// <inheritdoc/>
        public bool Equals(SymmetricName other) => Name == other.Name;

        /// <inheritdoc/>
        public override int GetHashCode() => Name?.GetHashCode() ?? 0;

        public static bool operator ==(SymmetricName left, SymmetricName right) => left.Equals(right);

        public static bool operator !=(SymmetricName left, SymmetricName right) => !(left == right);
    }
}
