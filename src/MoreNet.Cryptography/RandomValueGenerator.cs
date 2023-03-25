using MoreNet.Foundation;
using MoreNet.Foundation.Globalization;
using System;
using System.Security.Cryptography;
using System.Text;

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
            Argument.ShouldInRange(length, 0, int.MaxValue, nameof(length));
            Argument.ShouldNotEmpty(dictionary, nameof(dictionary));

            var textElementDictionary = new TextElementString(dictionary);
            var sb = new StringBuilder();
            for (int i = 0; i < length; i++)
            {
                var index = GetInt(0, textElementDictionary.Length);
                sb.Append(textElementDictionary[index]);
            }

            return sb.ToString();
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

            // Use 4 bytes for Int32.
            var nextBytes = new byte[4];
            _rng.GetBytes(nextBytes);

            var range = (long)max - min;
            var shift = BitConverter.ToInt32(nextBytes, 0) % range;

            // Shift always between int.MinValue and int.MaxValue, so it's safe convert to int directly
            if (shift < 0)
            {
                return max + (int)shift;
            }

            return min + (int)shift;
        }
    }
}
