namespace MoreNet.Cryptography
{
    /// <summary>
    /// Random value generator.
    /// </summary>
    public interface IRandomValueGenerator
    {
        /// <summary>
        /// Get random alphabets to string format, candidate characters are "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".
        /// </summary>
        /// <param name="length">String length.</param>
        /// <returns>Random string.</returns>
        string GetAlphabets(int length);

        /// <summary>
        /// Get random digits to string format, candidate characters are "0123456789".
        /// </summary>
        /// <param name="length">String length.</param>
        /// <returns>Random string.</returns>
        string GetDigits(int length);

        /// <summary>
        /// Get alphanumerics, candidate characters are "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".
        /// </summary>
        /// <param name="length">String length.</param>
        /// <returns>Random string.</returns>
        string GetAlphanumerics(int length);

        /// <summary>
        /// Get random string.
        /// </summary>
        /// <param name="length">String length.</param>
        /// <param name="dictionary">Characters for random, ex: if be "abc", then the all characters in random string should be 'a' or 'b' or 'c'.</param>
        /// <returns>Random string.</returns>
        string GetString(int length, string dictionary);

        /// <summary>
        /// Get random int between <see cref="int.MinValue"/> and <see cref="int.MaxValue"/>.
        /// </summary>
        /// <returns>Random int.</returns>
        int GetInt();

        /// <summary>
        /// Get random int in range, include min but exclude max.
        /// </summary>
        /// <param name="min">Minimum value of range, default: 0.</param>
        /// <param name="max">Maximun valud of range, defalut: int.MaxValue. </param>
        /// <returns>Random int.</returns>
        int GetInt(int min, int max);
    }
}
