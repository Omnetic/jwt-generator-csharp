using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Omnetic.JwtGenerator.Examples.CallDmsApi;
using Xunit;

namespace Omnetic.JwtGenerator.Tests;

/// <summary>
/// Smoke tests for examples/CallDmsApi, covering only the paths that exit before the HTTP
/// request — no test here reaches the network. Each case therefore supplies a key file that is
/// readable but not a valid PEM, so the run fails at signing time, one step after the argument
/// handling under test.
/// </summary>
[Collection(ConsoleExamplesCollection.Name)]
public sealed class CallDmsApiExampleTest : IDisposable
{
    private const string Kid = "kid-uuid-1";
    private const string Url = "https://dms.example.com/endpoint";
    private const string KeyPathVariable = "OMNETIC_SA_KEY_PATH";
    private const string KidVariable = "OMNETIC_SA_KID";
    private const string UrlVariable = "OMNETIC_DMS_API_URL";

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
    public async Task PrintsUsageWhenTheUrlIsMissing()
    {
        ExampleRun result = await RunExampleAsync(WriteUnusableKey(), Kid);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("", result.Stdout);
        Assert.Contains("Usage: dotnet run --project examples/CallDmsApi", result.Stderr);
    }

    [Fact]
    public async Task ReportsAKeyPathThatIsNotAReadableFile()
    {
        ExampleRun result = await RunExampleAsync(Path.GetTempPath(), Kid, Url);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("", result.Stdout);
        Assert.Contains("does not exist or is not readable", result.Stderr);
    }

    [Fact]
    public async Task WarnsWhenTheUrlIsNotHttpsAndStillAttemptsToSign()
    {
        ExampleRun result = await RunExampleAsync(
            WriteUnusableKey(),
            Kid,
            "http://dms.example.com/endpoint");

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("", result.Stdout);
        Assert.Contains("is not HTTPS", result.Stderr);
        // The warning is not fatal: the run proceeds to signing, which is what fails here.
        Assert.Contains("Could not generate a token", result.Stderr);
    }

    [Theory]
    [InlineData("dms.example.com/v1/vehicles")]
    [InlineData("/relative/path")]
    [InlineData("ftp://dms.example.com/v1/vehicles")]
    [InlineData("https://exa mple.com/x")]
    public async Task ReportsAUrlThatIsNotAnAbsoluteHttpUrl(string url)
    {
        ExampleRun result = await RunExampleAsync(WriteUnusableKey(), Kid, url);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("", result.Stdout);
        Assert.Contains("must be an absolute http:// or https:// URL", result.Stderr);
        // Rejected before signing, so no token is minted for a URL that cannot be called.
        Assert.DoesNotContain("Could not generate a token", result.Stderr);
    }

    [Fact]
    public async Task ReportsAnUnreadableKeyBeforeValidatingTheUrl()
    {
        ExampleRun result = await RunExampleAsync(Path.GetTempPath(), Kid, "not-a-url");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("does not exist or is not readable", result.Stderr);
        Assert.DoesNotContain("must be an absolute", result.Stderr);
    }

    [Fact]
    public async Task FallsBackToTheEnvironmentWhenArgumentsAreEmpty()
    {
        // `make example-request` always passes all three arguments, empty ones included.
        ExampleRun result = await RunExampleAsync(
            new[] { "", "", "" },
            environmentKeyPath: WriteUnusableKey(),
            environmentKid: Kid,
            environmentUrl: Url);

        // No usage message means all three values were resolved from the environment.
        Assert.Equal(1, result.ExitCode);
        Assert.DoesNotContain("Usage:", result.Stderr);
        Assert.DoesNotContain("is not HTTPS", result.Stderr);
        Assert.Contains("Could not generate a token", result.Stderr);
    }

    private static Task<ExampleRun> RunExampleAsync(params string[] arguments) =>
        RunExampleAsync(arguments, null, null, null);

    private static async Task<ExampleRun> RunExampleAsync(
        string[] arguments,
        string? environmentKeyPath,
        string? environmentKid,
        string? environmentUrl)
    {
        TextWriter originalOut = Console.Out;
        TextWriter originalError = Console.Error;
        string? originalKeyPath = Environment.GetEnvironmentVariable(KeyPathVariable);
        string? originalKid = Environment.GetEnvironmentVariable(KidVariable);
        string? originalUrl = Environment.GetEnvironmentVariable(UrlVariable);

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
            Environment.SetEnvironmentVariable(UrlVariable, environmentUrl);

            int exitCode = await Program.Main(arguments);

            return new ExampleRun(exitCode, output.ToString(), error.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
            Environment.SetEnvironmentVariable(KeyPathVariable, originalKeyPath);
            Environment.SetEnvironmentVariable(KidVariable, originalKid);
            Environment.SetEnvironmentVariable(UrlVariable, originalUrl);
        }
    }

    /// <summary>
    /// A readable file that is not a valid PEM, so signing fails before any HTTP request.
    /// </summary>
    private string WriteUnusableKey()
    {
        string path = Path.Combine(Path.GetTempPath(), $"sa-key-{Guid.NewGuid():N}.pem");
        File.WriteAllText(path, "not a pem key");
        temporaryKeys.Add(path);

        return path;
    }

    private sealed record ExampleRun(int ExitCode, string Stdout, string Stderr);
}
