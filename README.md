# MoreNet Cryptography

A .NET library that improves cryptography functions and makes `System.Security.Cryptography` easier to use.

## Introduction

This library provides:

- Easy-to-use extension methods for .NET cryptographic classes (e.g., `HashAlgorithm`, `SymmetricAlgorithm`, `RSA`) that can be applied to all derived classes of these types.
- A high-level interface, `ICryptoAdapter`, to manage common encryption, decryption, signing, verification, and hashing tasks.
- A simple random value generator (`IRandomValueGenerator`) using `System.Security.Cryptography.RandomNumberGenerator`. Since `RandomNumberGenerator` provides only basic functionality, this library offers additional utility methods to make random value generation easier and more convenient for users.

These features help reduce repetitive code and make cryptographic operations easier in .NET projects.

## Installation

Make sure your .NET project supports Dependency Injection. In an ASP.NET Core application, you can add this library in `Startup.cs`:

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

> **Note: The examples provided here demonstrate basic usage. However, they have additional overloads and related functionalities. To explore all available features, use your IDE's auto-completion or review the source code.**

### Using `ICryptoAdapter`

`ICryptoAdapter` is designed for users who are not familiar with `System.Security.Cryptography`. It provides a simple entry point for common cryptographic operations and includes frequently used scenarios.

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
        string ciphertext = _cryptoAdapter.ComputeHashToHex(HashName.MD5, "plaintext");
    }
}
```

### Using `System.Security.Cryptography` Classes Directly

If you need more flexibility, you can still use .NET's cryptographic classes. This library offers extension methods to make tasks simpler.

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

var aes = new AesCryptoServiceProvider
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

This library provides `IRandomValueGenerator`, a simple wrapper for `System.Security.Cryptography.RandomNumberGenerator`.

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

- **Easy to Extend**: This library is designed for convenience. You can still use `System.Security.Cryptography` classes along with these extension methods.
