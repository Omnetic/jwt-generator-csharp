using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Omnetic.JwtGenerator.Examples.CallDmsApi;
using Xunit;

namespace Omnetic.JwtGenerator.Tests;

/// <summary>
/// Covers examples/CallDmsApi's request path against a loopback listener: the Bearer header it
/// sends and how it maps a response onto stdout and an exit code. That is the whole reason the
/// example exists, so it is pinned here rather than left to manual checking. Nothing leaves the
/// machine — the listener is bound to 127.0.0.1 on an ephemeral port.
/// </summary>
[Collection(ConsoleExamplesCollection.Name)]
public sealed class CallDmsApiRequestTest : IDisposable
{
    private const string Kid = "kid-uuid-1";
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
    public async Task SendsTheSignedTokenAsABearerHeaderAndPrintsTheResponse()
    {
        const string Body = "{\"vehicles\":[{\"id\":1}]}";
        using LoopbackEndpoint endpoint = LoopbackEndpoint.Start(200, "OK", Body);

        ExampleRun result = await RunExampleAsync(WriteTemporaryKey(), Kid, endpoint.Url);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("HTTP 200", result.Stdout);
        Assert.Contains(Body, result.Stdout);

        string request = await endpoint.ReceivedRequest;
        Assert.Contains("Accept: application/json", request, StringComparison.Ordinal);

        string token = BearerToken(request);
        Assert.Equal(3, token.Split('.').Length);

        using JsonDocument payload = JsonDocument.Parse(Base64UrlDecode(token.Split('.')[1]));
        Assert.Equal(Kid, payload.RootElement.GetProperty("sub").GetString());
        Assert.Equal("sa", payload.RootElement.GetProperty("type").GetString());
        // A single request is signed with a short lifetime, not the SDK's 3600 s default.
        Assert.Equal(
            300L,
            payload.RootElement.GetProperty("exp").GetInt64()
                - payload.RootElement.GetProperty("iat").GetInt64());
    }

    [Fact]
    public async Task ExitsNonZeroWhenTheGatewayRejectsTheToken()
    {
        using LoopbackEndpoint endpoint = LoopbackEndpoint.Start(401, "Unauthorized", "{\"error\":\"nope\"}");

        ExampleRun result = await RunExampleAsync(WriteTemporaryKey(), Kid, endpoint.Url);

        Assert.Equal(1, result.ExitCode);
        // The status and body still reach stdout — that is what makes a 401 diagnosable.
        Assert.Contains("HTTP 401", result.Stdout);
        Assert.Contains("nope", result.Stdout);
    }

    [Fact]
    public async Task ReportsAnUnreachableEndpoint()
    {
        // Claim a port, then release it, so the connection is refused rather than hanging.
        string url = LoopbackEndpoint.ReserveUnusedUrl();

        ExampleRun result = await RunExampleAsync(WriteTemporaryKey(), Kid, url);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("", result.Stdout);
        Assert.Contains($"The request to {url} failed:", result.Stderr);
    }

    private static string BearerToken(string request)
    {
        foreach (string line in request.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.StartsWith("Authorization: Bearer ", StringComparison.Ordinal))
            {
                return line["Authorization: Bearer ".Length..].Trim();
            }
        }

        Assert.Fail($"The request carried no `Authorization: Bearer` header:\n{request}");

        return string.Empty;
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

    private static async Task<ExampleRun> RunExampleAsync(string keyPath, string kid, string url)
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
            Environment.SetEnvironmentVariable(KeyPathVariable, null);
            Environment.SetEnvironmentVariable(KidVariable, null);
            Environment.SetEnvironmentVariable(UrlVariable, null);

            int exitCode = await Program.Main(new[] { keyPath, kid, url });

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

    private string WriteTemporaryKey()
    {
        using RSA rsa = RSA.Create(2048);
        string path = Path.Combine(Path.GetTempPath(), $"sa-key-{Guid.NewGuid():N}.pem");
        File.WriteAllText(path, rsa.ExportRSAPrivateKeyPem());
        temporaryKeys.Add(path);

        return path;
    }

    private sealed record ExampleRun(int ExitCode, string Stdout, string Stderr);

    /// <summary>
    /// A one-shot HTTP listener on 127.0.0.1. Hand-rolled on TcpListener so it can bind an
    /// ephemeral port (HttpListener requires a fixed one) and expose the raw request text.
    /// </summary>
    private sealed class LoopbackEndpoint : IDisposable
    {
        private readonly TcpListener listener;

        private LoopbackEndpoint(TcpListener listener, int statusCode, string reason, string body)
        {
            this.listener = listener;
            ReceivedRequest = ServeOnceAsync(listener, statusCode, reason, body);
        }

        public Task<string> ReceivedRequest { get; }

        public string Url => $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/vehicles";

        public static LoopbackEndpoint Start(int statusCode, string reason, string body)
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            return new LoopbackEndpoint(listener, statusCode, reason, body);
        }

        public static string ReserveUnusedUrl()
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();

            return $"http://127.0.0.1:{port}/vehicles";
        }

        public void Dispose() => listener.Stop();

        private static async Task<string> ServeOnceAsync(
            TcpListener listener,
            int statusCode,
            string reason,
            string body)
        {
            using TcpClient client = await listener.AcceptTcpClientAsync();
            await using NetworkStream stream = client.GetStream();

            StringBuilder request = new StringBuilder();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = await stream.ReadAsync(buffer)) > 0)
            {
                request.Append(Encoding.ASCII.GetString(buffer, 0, read));
                if (request.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    break;
                }
            }

            byte[] payload = Encoding.UTF8.GetBytes(body);
            byte[] headers = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {statusCode} {reason}\r\n"
                + "Content-Type: application/json\r\n"
                + $"Content-Length: {payload.Length}\r\n"
                + "Connection: close\r\n\r\n");

            await stream.WriteAsync(headers);
            await stream.WriteAsync(payload);
            await stream.FlushAsync();

            return request.ToString();
        }
    }
}
