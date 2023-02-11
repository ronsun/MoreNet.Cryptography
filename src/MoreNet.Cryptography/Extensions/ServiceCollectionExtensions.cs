using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;

namespace MoreNet.Cryptography.Extensions
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
