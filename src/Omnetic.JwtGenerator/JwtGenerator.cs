using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Omnetic.JwtGenerator;

/// <summary>
/// Generates signed RS256 JWT tokens for authenticating Omnetic DMS Service Account
/// requests against the DMS API.
/// </summary>
public static class JwtGenerator
{
    private const string Algorithm = "RS256";
    private const string TokenType = "sa";
    private const int MaxLifetime = 3600;
    private const int MinKeyBits = 2048;

    /// <summary>
    /// Builds a signed RS256 JWT for authenticating a Service Account against the DMS API.
    /// </summary>
    /// <param name="privateKey">RSA private key in PEM format.</param>
    /// <param name="kid">Key ID; carried in both the JWT header and the <c>sub</c> claim.</param>
    /// <param name="lifetime">Token validity in seconds (1-3600). Defaults to 3600.</param>
    /// <returns>Signed JWT ready for the <c>Authorization: Bearer</c> header.</returns>
    public static string GenerateToken(string privateKey, string kid, int lifetime = MaxLifetime)
    {
        if (string.IsNullOrEmpty(kid))
        {
            throw new ArgumentException("The kid must not be empty.", nameof(kid));
        }

        if (lifetime < 1 || lifetime > MaxLifetime)
        {
            throw new ArgumentOutOfRangeException(
                nameof(lifetime),
                lifetime,
                $"The lifetime must be between 1 and {MaxLifetime} seconds, got {lifetime}.");
        }

        using RSA rsa = ParseRsaPrivateKey(privateKey);

        long issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        byte[] header = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(new { alg = Algorithm, typ = "JWT", kid }));
        byte[] payload = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(new { type = TokenType, sub = kid, iat = issuedAt, exp = issuedAt + lifetime }));

        string signingInput = $"{Base64UrlEncode(header)}.{Base64UrlEncode(payload)}";
        byte[] signature = rsa.SignData(
            Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return $"{signingInput}.{Base64UrlEncode(signature)}";
    }

    private static RSA ParseRsaPrivateKey(string privateKey)
    {
        if (string.IsNullOrEmpty(privateKey))
        {
            throw new ArgumentException("The private key must not be empty.", nameof(privateKey));
        }

        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(privateKey);
        }
        catch (CryptographicException exception)
        {
            // A PEM label matched but the contents are not an RSA key (e.g. an EC key).
            rsa.Dispose();
            throw new ArgumentException("The private key must be an RSA key.", nameof(privateKey), exception);
        }
        catch (ArgumentException exception)
        {
            // No supported PEM was found (garbage text, or an unrecognised label).
            rsa.Dispose();
            throw new ArgumentException(
                "The private key is not a valid PEM-encoded key.", nameof(privateKey), exception);
        }

        try
        {
            // RSA.ImportFromPem also accepts public-key PEMs; a public key has no private
            // material to sign with. Reject it here so callers get an ArgumentException up
            // front rather than a CryptographicException from SignData.
            rsa.ExportPkcs8PrivateKey();
        }
        catch (CryptographicException exception)
        {
            rsa.Dispose();
            throw new ArgumentException(
                "The private key is not a valid PEM-encoded key.", nameof(privateKey), exception);
        }

        if (rsa.KeySize < MinKeyBits)
        {
            rsa.Dispose();
            throw new ArgumentException(
                $"The RSA private key must be at least {MinKeyBits} bits.", nameof(privateKey));
        }

        return rsa;
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
