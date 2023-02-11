using System;
using System.Security.Cryptography;

namespace MoreNet.Cryptography
{
    /// <inheritdoc/>
    internal class RandomValueGenerator : IRandomValueGenerator
    {
        private readonly RandomNumberGenerator _rng;

        /// <summary>
        /// Initializes a new instance of the <see cref="RandomValueGenerator"/> class.
        /// </summary>
        /// <param name="rng">Injected <see cref="RandomNumberGenerator"/>.</param>
        public RandomValueGenerator(RandomNumberGenerator rng)
        {
            _rng = rng;
        }

        /// <inheritdoc/>
        public string GetAlphabets(int length)
        {
            return GetString(length, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        }

        /// <inheritdoc/>
        public string GetDigits(int length)
        {
            return GetString(length, "0123456789");
        }

        /// <inheritdoc/>
        public string GetAlphanumerics(int length)
        {
            return GetString(length, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        }

        /// <inheritdoc/>
        public string GetString(int length, string dictionary)
        {
            var charArray = new char[length];
            for (int i = 0; i < length; i++)
            {
                var index = GetInt(0, dictionary.Length);
                charArray[i] = dictionary[index];
            }

            return new string(charArray);
        }

        /// <inheritdoc/>
        public int GetInt()
        {
            return GetInt(int.MinValue, int.MaxValue);
        }

        /// <inheritdoc/>
        public int GetInt(int min, int max)
        {
            if (min > max)
            {
                throw new ArgumentException($"{nameof(min)} should not greater than {nameof(max)}");
            }

            if (min == max)
            {
                return min;
            }

            // use Int32 (4 bytes) bacause keyword 'int' is default as Int32
            var nextBytes = new byte[4];
            _rng.GetBytes(nextBytes);

            var range = (long)max - min;
            var shift = BitConverter.ToInt32(nextBytes, 0) % range;

            // shift always between int.MinValue and int.MaxValue, so it's safe convert to int directly
            if (shift < 0)
            {
                return max + (int)shift;
            }

            return min + (int)shift;
        }
    }
}
