# MoreNet Cryptography

A .NET library that simplifies cryptography tasks and makes `System.Security.Cryptography` easier to use.

## Introduction

This library provides:

- Easy-to-use extension methods for .NET cryptographic classes such as `HashAlgorithm`, `SymmetricAlgorithm`, and `RSA`, which can be applied to their derived classes.
- A high-level interface, `ICryptoAdapter`, for common encryption, decryption, signing, verification, and hashing tasks.
- A simple random value generator, `IRandomValueGenerator`, built on `System.Security.Cryptography.RandomNumberGenerator`. Since `RandomNumberGenerator` provides only basic functionality, this library adds utility methods to make random value generation easier and more convenient.

These features help reduce repetitive code and make cryptographic operations easier in .NET projects.

## Installation

If your .NET project uses Dependency Injection, you can register this library in `Startup.cs`:

```csharp
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        // Add MoreNet Cryptography services
        services.AddMoreNetCryptography();
    }
}
```

## Usage

> **Note: The examples below show basic usage. Additional overloads and related functionality are also available. To explore all available features, use your IDE's auto-completion or review the source code.**

### Using `ICryptoAdapter`

`ICryptoAdapter` is designed for users who are not familiar with `System.Security.Cryptography`. It provides a simple entry point for common cryptographic operations and covers frequently used scenarios.

Once the library is added, you can inject `ICryptoAdapter` into any class and use its methods. Example:

```csharp
public class MyClass
{
    private readonly ICryptoAdapter _cryptoAdapter;

    public MyClass(ICryptoAdapter cryptoAdapter)
    {
        _cryptoAdapter = cryptoAdapter;
    }

    public void MyMethod()
    {
        string hash = _cryptoAdapter.ComputeHashToHex(HashName.MD5, "plaintext");
    }
}
```

### Using `System.Security.Cryptography` Classes Directly

If you need more flexibility, you can still use .NET's cryptographic classes directly. This library provides extension methods to make common tasks simpler.

#### Hash Algorithms

```csharp
using MoreNet.Cryptography.Extensions.HashAlgorithmExtensions;

using (var md5 = new MD5CryptoServiceProvider())
{
    string hash = md5.ComputeHashToHex("plaintext");
}
```

#### Symmetric Encryption

```csharp
using MoreNet.Cryptography.Extensions.SymmetricAlgorithmExtensions;

var aes = new AesCryptoServiceProvider()
{
    Mode = CipherMode.ECB,
    Key = GenerateKey(128)
};

string ciphertext = aes.EncryptToBase64("plaintext");
```

#### RSA

```csharp
using MoreNet.Cryptography.Extensions.RSAExtensions;

using (var rsa = new RSACryptoServiceProvider())
{
    string ciphertext = rsa.EncryptChunksToBase64("plaintext", RSAEncryptionPadding.Pkcs1);
}
```

### Generating Random Values

This library provides `IRandomValueGenerator`, a simple wrapper around `System.Security.Cryptography.RandomNumberGenerator`.

```csharp
public class MyClass
{
    private readonly IRandomValueGenerator _randomValueGenerator;

    public MyClass(IRandomValueGenerator randomValueGenerator)
    {
        _randomValueGenerator = randomValueGenerator;
    }

    public void MyMethod()
    {
        string alphabets = _randomValueGenerator.GetAlphabets(6);
    }
}
```

## Notes

- **Easy to Extend**: This library is designed for convenience. You can continue using `System.Security.Cryptography` classes together with these extension methods.

## Documentation

See the [API documentation](https://ronsun.github.io/MoreNet.Cryptography/api) for the full API reference.
