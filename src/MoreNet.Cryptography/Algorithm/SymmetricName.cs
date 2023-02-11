using System;

namespace MoreNet.Cryptography.Algorithm
{
    /// <summary>
    /// Name of symmertric algorithm.
    /// </summary>
    public struct SymmetricName : IEquatable<SymmetricName>
    {
        private SymmetricName(string name)
        {
            Name = name;
        }

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
        /// Equal operator.
        /// </summary>
        /// <param name="left">Left.</param>
        /// <param name="right">Right.</param>
        /// <returns>Is equal.</returns>
        public static bool operator ==(SymmetricName left, SymmetricName right) => left.Equals(right);

        /// <summary>
        /// Not equal operator.
        /// </summary>
        /// <param name="left">Left.</param>
        /// <param name="right">Right.</param>
        /// <returns>Is not equal.</returns>
        public static bool operator !=(SymmetricName left, SymmetricName right) => !(left == right);

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is SymmetricName other && Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode() => HashCode.Combine(this.Name);

        /// <inheritdoc/>
        public bool Equals(SymmetricName other) => this.Name == other.Name;
    }
}
