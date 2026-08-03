using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Omnetic.JwtGenerator.Tests;

public sealed class JwtGeneratorTest
{
    private const string Kid = "kid-uuid-1";

    [Fact]
    public void ReturnsCompactJwtWithThreeSegments()
    {
        (string privateKey, _) = GenerateRsaKeyPair();

        string token = JwtGenerator.GenerateToken(privateKey, Kid);

        Assert.Equal(3, token.Split('.').Length);
        Assert.DoesNotContain("=", token);
        Assert.DoesNotContain("+", token);
        Assert.DoesNotContain("/", token);
    }

    [Fact]
    public void HeaderUsesRs256AndCarriesTheKid()
    {
        (string privateKey, _) = GenerateRsaKeyPair();

        string token = JwtGenerator.GenerateToken(privateKey, Kid);
        using JsonDocument header = DecodeSegment(token, 0);

        Assert.Equal("RS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal(Kid, header.RootElement.GetProperty("kid").GetString());
    }

    [Fact]
    public void PayloadCarriesServiceAccountClaims()
    {
        (string privateKey, _) = GenerateRsaKeyPair();

        long before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string token = JwtGenerator.GenerateToken(privateKey, Kid, 1800);
        long after = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using JsonDocument payload = DecodeSegment(token, 1);

        Assert.Equal("sa", payload.RootElement.GetProperty("type").GetString());
        Assert.Equal(Kid, payload.RootElement.GetProperty("sub").GetString());
        Assert.False(payload.RootElement.TryGetProperty("typ", out _));

        long issuedAt = payload.RootElement.GetProperty("iat").GetInt64();
        long expiresAt = payload.RootElement.GetProperty("exp").GetInt64();
        Assert.True(issuedAt >= before);
        Assert.True(issuedAt <= after);
        Assert.Equal(issuedAt + 1800, expiresAt);
    }

    [Fact]
    public void DefaultLifetimeIsOneHour()
    {
        (string privateKey, _) = GenerateRsaKeyPair();

        string token = JwtGenerator.GenerateToken(privateKey, Kid);
        using JsonDocument payload = DecodeSegment(token, 1);

        long issuedAt = payload.RootElement.GetProperty("iat").GetInt64();
        long expiresAt = payload.RootElement.GetProperty("exp").GetInt64();
        Assert.Equal(3600L, expiresAt - issuedAt);
    }

    [Fact]
    public void SignatureVerifiesWithMatchingPublicKey()
    {
        (string privateKey, string publicKey) = GenerateRsaKeyPair();

        string token = JwtGenerator.GenerateToken(privateKey, Kid);

        Assert.True(VerifySignature(token, publicKey));
    }

    [Fact]
    public void AcceptsPkcs8FormattedPrivateKey()
    {
        using RSA rsa = RSA.Create(2048);
        string pkcs8PrivateKey = rsa.ExportPkcs8PrivateKeyPem();
        string publicKey = rsa.ExportSubjectPublicKeyInfoPem();

        string token = JwtGenerator.GenerateToken(pkcs8PrivateKey, Kid);

        Assert.True(VerifySignature(token, publicKey));
    }

    [Fact]
    public void SignatureIsRejectedByADifferentPublicKey()
    {
        (string signingPrivate, _) = GenerateRsaKeyPair();
        (_, string otherPublic) = GenerateRsaKeyPair();

        string token = JwtGenerator.GenerateToken(signingPrivate, Kid);

        Assert.False(VerifySignature(token, otherPublic));
    }

    [Fact]
    public void RejectsEmptyPrivateKey()
    {
        Assert.Throws<ArgumentException>(() => JwtGenerator.GenerateToken("", Kid));
    }

    [Fact]
    public void RejectsMalformedPrivateKey()
    {
        Assert.Throws<ArgumentException>(() => JwtGenerator.GenerateToken("not a pem key", Kid));
    }

    [Fact]
    public void RejectsNonRsaPrivateKey()
    {
        Assert.Throws<ArgumentException>(() => JwtGenerator.GenerateToken(GenerateEcPrivateKey(), Kid));
    }

    [Fact]
    public void RejectsPublicKeyPassedAsPrivateKey()
    {
        (_, string publicKey) = GenerateRsaKeyPair();

        Assert.Throws<ArgumentException>(() => JwtGenerator.GenerateToken(publicKey, Kid));
    }

    [Fact]
    public void RejectsRsaKeyShorterThan2048Bits()
    {
        (string privateKey, _) = GenerateRsaKeyPair(1024);

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => JwtGenerator.GenerateToken(privateKey, Kid));
        Assert.Contains("at least 2048 bits", exception.Message);
    }

    [Fact]
    public void ValidatesKidBeforeParsingThePrivateKey()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => JwtGenerator.GenerateToken("not a pem key", ""));
        Assert.Contains("The kid must not be empty.", exception.Message);
    }

    [Fact]
    public void ValidatesLifetimeBeforeParsingThePrivateKey()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => JwtGenerator.GenerateToken("not a pem key", Kid, 3601));
        Assert.Contains("The lifetime must be between 1 and 3600 seconds", exception.Message);
    }

    [Fact]
    public void RejectsEmptyKid()
    {
        (string privateKey, _) = GenerateRsaKeyPair();

        Assert.Throws<ArgumentException>(() => JwtGenerator.GenerateToken(privateKey, ""));
    }

    [Fact]
    public void RejectsLifetimeAboveMaximum()
    {
        (string privateKey, _) = GenerateRsaKeyPair();

        Assert.Throws<ArgumentOutOfRangeException>(() => JwtGenerator.GenerateToken(privateKey, Kid, 3601));
    }

    [Fact]
    public void RejectsNonPositiveLifetime()
    {
        (string privateKey, _) = GenerateRsaKeyPair();

        Assert.Throws<ArgumentOutOfRangeException>(() => JwtGenerator.GenerateToken(privateKey, Kid, 0));
    }

    private static (string PrivateKey, string PublicKey) GenerateRsaKeyPair(int bits = 2048)
    {
        using RSA rsa = RSA.Create(bits);
        return (rsa.ExportRSAPrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
    }

    private static string GenerateEcPrivateKey()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa.ExportPkcs8PrivateKeyPem();
    }

    private static bool VerifySignature(string token, string publicKeyPem)
    {
        string[] segments = token.Split('.');
        byte[] signingInput = Encoding.UTF8.GetBytes($"{segments[0]}.{segments[1]}");
        byte[] signature = Base64UrlDecode(segments[2]);

        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);

        return rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static JsonDocument DecodeSegment(string token, int index)
    {
        string[] segments = token.Split('.');
        return JsonDocument.Parse(Base64UrlDecode(segments[index]));
    }

    private static byte[] Base64UrlDecode(string value)
    {
        string base64 = value.Replace('-', '+').Replace('_', '/');
        base64 = (base64.Length % 4) switch
        {
            2 => base64 + "==",
            3 => base64 + "=",
            _ => base64,
        };

        return Convert.FromBase64String(base64);
    }
}
