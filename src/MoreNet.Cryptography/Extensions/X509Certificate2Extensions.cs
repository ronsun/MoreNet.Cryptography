using MoreNet.Foundation;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace MoreNet.Cryptography.Extensions
{
    /// <summary>
    /// Extension methods for X509Certificate2.
    /// </summary>
    public static class X509Certificate2Extensions
    {
        /// <summary>
        /// Populates an X509Certificate2 object with data from embedded resource in assembly.
        /// </summary>
        /// <param name="cert"><see cref="X509Certificate2"/>.</param>
        /// <param name="assembly">The assembly contain the target embedded resource. </param>
        /// <param name="fullName">Full name of target embedded resource. </param>
        /// <param name="password">Password.</param>
        /// <returns>Current <see cref="X509Certificate2"/>.</returns>
        public static X509Certificate2 Import(
            this X509Certificate2 cert,
            Assembly assembly,
            string fullName,
            string password)
        {
            Argument.ShouldNotEmpty(cert, nameof(cert));
            Argument.ShouldNotEmpty(assembly, nameof(assembly));

            return Import(cert, assembly, fullName, password, default);
        }

        /// <summary>
        /// Populates an X509Certificate2 object with data from embedded resource in assembly.
        /// </summary>
        /// <param name="cert"><see cref="X509Certificate2"/>.</param>
        /// <param name="assembly">The assembly contain the target embedded resource. </param>
        /// <param name="fullName">Full name of target embedded resource. </param>
        /// <param name="keyStorageFlags"><see cref="X509KeyStorageFlags"/>.</param>
        /// <returns>Current <see cref="X509Certificate2"/>.</returns>
        public static X509Certificate2 Import(
            this X509Certificate2 cert,
            Assembly assembly,
            string fullName,
            X509KeyStorageFlags keyStorageFlags)
        {
            Argument.ShouldNotEmpty(cert, nameof(cert));
            Argument.ShouldNotEmpty(assembly, nameof(assembly));

            return Import(cert, assembly, fullName, default, keyStorageFlags);
        }

        private static X509Certificate2 Import(
            this X509Certificate2 cert,
            Assembly assembly,
            string fullName,
            string password,
            X509KeyStorageFlags keyStorageFlags)
        {
            using (Stream certStream = assembly.GetManifestResourceStream(fullName))
            {
                byte[] rawBytes = new byte[certStream.Length];
                for (int index = 0; index < certStream.Length; index++)
                {
                    rawBytes[index] = (byte)certStream.ReadByte();
                }

                if (string.IsNullOrEmpty(password))
                {
                    cert.Import(rawBytes);
                }
                else
                {
                    cert.Import(rawBytes, password, keyStorageFlags);
                }
            }

            return cert;
        }
    }
}