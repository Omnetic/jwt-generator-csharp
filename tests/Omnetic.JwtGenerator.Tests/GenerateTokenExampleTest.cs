using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Omnetic.JwtGenerator.Examples.GenerateToken;
using Xunit;

namespace Omnetic.JwtGenerator.Tests;

/// <summary>
/// Smoke tests for examples/GenerateToken — the example ships with the SDK, so its argument
/// handling and exit codes are behavior worth pinning down.
/// </summary>
[Collection(ConsoleExamplesCollection.Name)]
public sealed class GenerateTokenExampleTest : IDisposable
{
    private const string Kid = "kid-uuid-1";
    private const string KeyPathVariable = "OMNETIC_SA_KEY_PATH";
    private const string KidVariable = "OMNETIC_SA_KID";

    private readonly List<string> temporaryKeys = new List<string>();

    public void Dispose()
    {
        foreach (string path in temporaryKeys)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }

        temporaryKeys.Clear();
    }

    [Fact]
    public void PrintsASignedTokenOnStdout()
    {
        ExampleRun result = RunExample(WriteTemporaryKey(), Kid, "600");

        Assert.Equal(0, result.ExitCode);
        Assert.Equal("", result.Stderr);
        Assert.Equal(3, result.Stdout.Trim().Split('.').Length);
    }

    [Fact]
    public void UsesTheSdkDefaultLifetimeWhenTheArgumentIsOmitted()
    {
        ExampleRun result = RunExample(WriteTemporaryKey(), Kid);

        Assert.Equal(0, result.ExitCode);

        using JsonDocument payload = DecodePayload(result.Stdout);
        Assert.Equal(
            3600L,
            payload.RootElement.GetProperty("exp").GetInt64()
                - payload.RootElement.GetProperty("iat").GetInt64());
    }

    [Fact]
    public void PassesAnExplicitLifetimeThroughToTheSdk()
    {
        ExampleRun result = RunExample(WriteTemporaryKey(), Kid, "600");

        Assert.Equal(0, result.ExitCode);

        using JsonDocument payload = DecodePayload(result.Stdout);
        Assert.Equal(
            600L,
            payload.RootElement.GetProperty("exp").GetInt64()
                - payload.RootElement.GetProperty("iat").GetInt64());
    }

    [Fact]
    public void ValidatesTheLifetimeBeforeTouchingTheKeyFile()
    {
        // The spec pins this order: cheap argument checks first, file I/O last.
        ExampleRun result = RunExample("/no/such/key.pem", Kid, "not-a-number");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("whole number of seconds", result.Stderr);
        Assert.DoesNotContain("does not exist or is not readable", result.Stderr);
    }

    [Fact]
    public void FallsBackToTheEnvironmentWhenArgumentsAreEmpty()
    {
        // `make example` always passes both arguments, empty ones included.
        ExampleRun result = RunExample(
            new[] { "", "" },
            environmentKeyPath: WriteTemporaryKey(),
            environmentKid: Kid);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(3, result.Stdout.Trim().Split('.').Length);
    }

    [Fact]
    public void PrintsUsageWithoutArguments()
    {
        ExampleRun result = RunExample();

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("", result.Stdout);
        Assert.Contains("Usage: dotnet run --project examples/GenerateToken", result.Stderr);
    }

    [Fact]
    public void ReportsAKeyPathThatIsNotAReadableFile()
    {
        ExampleRun result = RunExample(Path.GetTempPath(), Kid);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("", result.Stdout);
        Assert.Contains("does not exist or is not readable", result.Stderr);
    }

    [Fact]
    public void ReportsTheSdkValidationMessage()
    {
        ExampleRun result = RunExample(WriteTemporaryKey(), Kid, "9999");

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("", result.Stdout);
        Assert.Contains("The lifetime must be between 1 and 3600 seconds", result.Stderr);
    }

    [Fact]
    public void ReportsALifetimeThatIsNotAWholeNumber()
    {
        ExampleRun result = RunExample(WriteTemporaryKey(), Kid, "not-a-number");

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("", result.Stdout);
        Assert.Contains("whole number of seconds", result.Stderr);
    }

    private static JsonDocument DecodePayload(string stdout)
    {
        string payload = stdout.Trim().Split('.')[1];
        string base64 = payload.Replace('-', '+').Replace('_', '/');
        base64 = (base64.Length % 4) switch
        {
            2 => base64 + "==",
            3 => base64 + "=",
            _ => base64,
        };

        return JsonDocument.Parse(Convert.FromBase64String(base64));
    }

    private static ExampleRun RunExample(params string[] arguments) =>
        RunExample(arguments, null, null);

    private static ExampleRun RunExample(
        string[] arguments,
        string? environmentKeyPath,
        string? environmentKid)
    {
        TextWriter originalOut = Console.Out;
        TextWriter originalError = Console.Error;
        string? originalKeyPath = Environment.GetEnvironmentVariable(KeyPathVariable);
        string? originalKid = Environment.GetEnvironmentVariable(KidVariable);

        using StringWriter output = new StringWriter();
        using StringWriter error = new StringWriter();

        try
        {
            Console.SetOut(output);
            Console.SetError(error);
            // Always set explicitly, so a variable exported in the developer's shell cannot
            // leak into the runs that are meant to have no environment fallback.
            Environment.SetEnvironmentVariable(KeyPathVariable, environmentKeyPath);
            Environment.SetEnvironmentVariable(KidVariable, environmentKid);

            int exitCode = Program.Main(arguments);

            return new ExampleRun(exitCode, output.ToString(), error.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
            Environment.SetEnvironmentVariable(KeyPathVariable, originalKeyPath);
            Environment.SetEnvironmentVariable(KidVariable, originalKid);
        }
    }

    private string WriteTemporaryKey()
    {
        using RSA rsa = RSA.Create(2048);
        string path = Path.Combine(Path.GetTempPath(), $"sa-key-{Guid.NewGuid():N}.pem");
        File.WriteAllText(path, rsa.ExportRSAPrivateKeyPem());
        temporaryKeys.Add(path);

        return path;
    }

    private sealed record ExampleRun(int ExitCode, string Stdout, string Stderr);
}
