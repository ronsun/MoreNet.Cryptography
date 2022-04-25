using System;
using System.Collections;

namespace MoreNet.Cryptography.Assertion
{
    // TODO: migrate to toolkit library

    /// <summary>
    /// Argument assersion.
    /// </summary>
    internal static class Argument
    {
        /// <summary>
        /// Assert argument should not empty.
        /// </summary>
        /// <typeparam name="T">Type of argument.</typeparam>
        /// <param name="arg">Argument.</param>
        /// <param name="argName">Argument name.</param>
        /// <remarks>
        /// Should not be null for reference type.
        /// Should not be empty for <see cref="IEnumerable"/>.
        /// </remarks>
        internal static void ShouldNotEmpty<T>(T arg, string argName)
            where T : class
        {
            if (arg == null)
            {
                throw new ArgumentNullException(argName);
            }

            if (arg is IEnumerable enumerableTarget)
            {
                bool any = false;
                foreach (var item in enumerableTarget)
                {
                    any = true;
                    break;
                }

                if (!any)
                {
                    throw new ArgumentException("Value should not be empty", argName);
                }
            }
        }
    }
}
