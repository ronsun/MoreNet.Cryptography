using System;

namespace MoreNet.Cryptography.Algorithm
{
    public struct AsymmetricName : IEquatable<AsymmetricName>
    {
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
        /// Initializes a new instance of the <see cref="AsymmetricName"/> struct.
        /// </summary>
        /// <param name="name">The custom hash algorithm name.</param>
        public AsymmetricName(string name)
        {
            Name = name;
        }

        /// <inheritdoc/>
        public override string ToString() => Name ?? string.Empty;

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is AsymmetricName && Equals((AsymmetricName)obj);

        /// <inheritdoc/>
        public bool Equals(AsymmetricName other) => Name == other.Name;

        /// <inheritdoc/>
        public override int GetHashCode() => Name?.GetHashCode() ?? 0;

        public static bool operator ==(AsymmetricName left, AsymmetricName right) => left.Equals(right);

        public static bool operator !=(AsymmetricName left, AsymmetricName right) => !(left == right);
    }
}
