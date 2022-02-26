using MoreNet.Cryptography;
using System.Security.Cryptography;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extensions for <see cref="IServiceCollection"/>.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Add dependencies.
        /// </summary>
        /// <param name="service">The <see cref="IServiceCollection"/> to add the service to.</param>
        /// <returns><see cref="IServiceCollection"/>.</returns>
        public static IServiceCollection AddMoreNetCryptography(this IServiceCollection service)
        {
            service.AddScoped<RandomNumberGenerator, RNGCryptoServiceProvider>();
            service.AddScoped<ICryptoAdapter, CryptoAdapter>();

            return service;
        }
    }
}
