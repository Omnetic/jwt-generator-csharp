using System;
using System.Globalization;
using System.IO;

namespace Omnetic.JwtGenerator.Examples.GenerateToken;

/// <summary>
/// Sign a Service Account token and print it.
///
/// Usage:
///   dotnet run --project examples/GenerateToken -- &lt;path-to-private-key.pem&gt; &lt;kid&gt; [lifetime]
///
/// The key path and kid may also come from the OMNETIC_SA_KEY_PATH and OMNETIC_SA_KID
/// environment variables. Both the key and the kid are issued on Service Account creation /
/// key rotation.
///
/// This example is deliberately standalone — it repeats the argument handling of
/// examples/CallDmsApi rather than sharing it, so either file can be read, or copied into your
/// own project, on its own.
/// </summary>
internal static class Program
{
    private const string Usage =
        "Usage: dotnet run --project examples/GenerateToken -- <path-to-private-key.pem> <kid> [lifetime]";

    private const string KeyPathVariable = "OMNETIC_SA_KEY_PATH";
    private const string KidVariable = "OMNETIC_SA_KID";

    internal static int Main(string[] args)
    {
        // Empty arguments fall through to the environment, so an omitted `make example`
        // variable behaves the same as passing nothing at all.
        string keyPath = Resolve(args, 0, KeyPathVariable);
        string kid = Resolve(args, 1, KidVariable);

        if (keyPath.Length == 0 || kid.Length == 0)
        {
            Console.Error.WriteLine(Usage);

            return 1;
        }

        int? lifetime = null;
        if (args.Length > 2 && args[2].Length > 0)
        {
            if (!int.TryParse(args[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed))
            {
                Console.Error.WriteLine("The lifetime must be a whole number of seconds.");

                return 1;
            }

            lifetime = parsed;
        }

        if (!File.Exists(keyPath))
        {
            Console.Error.WriteLine(
                $"The private key file {keyPath} does not exist or is not readable.");

            return 1;
        }

        string privateKey;
        try
        {
            privateKey = File.ReadAllText(keyPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Could not read the private key file {keyPath}: {exception.Message}");

            return 1;
        }

        string token;
        try
        {
            // Omitting the lifetime leaves the SDK's own default (3600 s) in charge.
            token = lifetime is null
                ? JwtGenerator.GenerateToken(privateKey, kid)
                : JwtGenerator.GenerateToken(privateKey, kid, lifetime.Value);
        }
        catch (ArgumentException exception)
        {
            // Also catches the ArgumentOutOfRangeException an out-of-range lifetime raises.
            Console.Error.WriteLine($"Could not generate a token: {exception.Message}");

            return 1;
        }

        // Send this as `Authorization: Bearer <token>` on every DMS API request.
        Console.Out.WriteLine(token);

        return 0;
    }

    private static string Resolve(string[] args, int index, string variable)
    {
        string value = args.Length > index ? args[index] : string.Empty;

        return value.Length > 0 ? value : Environment.GetEnvironmentVariable(variable) ?? string.Empty;
    }
}
