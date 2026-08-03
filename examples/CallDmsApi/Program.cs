using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Omnetic.JwtGenerator.Examples.CallDmsApi;

/// <summary>
/// Sign a Service Account token and call a DMS API endpoint with it.
///
/// Usage:
///   dotnet run --project examples/CallDmsApi -- &lt;path-to-private-key.pem&gt; &lt;kid&gt; &lt;url&gt;
///
/// The arguments may also come from the OMNETIC_SA_KEY_PATH, OMNETIC_SA_KID and
/// OMNETIC_DMS_API_URL environment variables. Use the URL of the DMS endpoint your Service
/// Account is allowed to call.
///
/// This example is deliberately standalone — it repeats the argument handling of
/// examples/GenerateToken rather than sharing it, so either file can be read, or copied into
/// your own project, on its own.
/// </summary>
internal static class Program
{
    private const string Usage =
        "Usage: dotnet run --project examples/CallDmsApi -- <path-to-private-key.pem> <kid> <url>";

    private const string KeyPathVariable = "OMNETIC_SA_KEY_PATH";
    private const string KidVariable = "OMNETIC_SA_KID";
    private const string UrlVariable = "OMNETIC_DMS_API_URL";

    /// <summary>A short lifetime is enough for a single request; tokens are cheap to mint.</summary>
    private const int RequestLifetime = 300;

    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    internal static async Task<int> Main(string[] args)
    {
        // Empty arguments fall through to the environment, so an omitted `make example-request`
        // variable behaves the same as passing nothing at all.
        string keyPath = Resolve(args, 0, KeyPathVariable);
        string kid = Resolve(args, 1, KidVariable);
        string url = Resolve(args, 2, UrlVariable);

        if (keyPath.Length == 0 || kid.Length == 0 || url.Length == 0)
        {
            Console.Error.WriteLine(Usage);

            return 1;
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

        // Parse before signing: HttpClient accepts a relative URI here and only fails deep
        // inside SendAsync, which would mint a token and then crash on an unusable URL.
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? requestUri)
            || (requestUri.Scheme != Uri.UriSchemeHttps && requestUri.Scheme != Uri.UriSchemeHttp))
        {
            Console.Error.WriteLine($"The URL {url} must be an absolute http:// or https:// URL.");

            return 1;
        }

        if (requestUri.Scheme != Uri.UriSchemeHttps)
        {
            Console.Error.WriteLine($"Warning: {url} is not HTTPS — the token would travel in plaintext.");
        }

        string token;
        try
        {
            token = JwtGenerator.GenerateToken(privateKey, kid, RequestLifetime);
        }
        catch (ArgumentException exception)
        {
            // Also catches the ArgumentOutOfRangeException an out-of-range lifetime raises.
            Console.Error.WriteLine($"Could not generate a token: {exception.Message}");

            return 1;
        }

        try
        {
            // One short-lived client is fine for a one-shot CLI. In a long-running app, reuse a
            // single HttpClient (or IHttpClientFactory) instead of one per request, and cache the
            // token until it nears its `exp` rather than signing a fresh one every call.
            using HttpClient client = new HttpClient { Timeout = RequestTimeout };
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUri);

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using HttpResponseMessage response = await client.SendAsync(request);
            string body = await response.Content.ReadAsStringAsync();

            Console.Out.WriteLine($"HTTP {(int)response.StatusCode}");
            Console.Out.WriteLine(body);

            // A 401 means the Gateway rejected the token: check that the kid matches the key,
            // that the Service Account is enabled, and that the clock is not skewed.
            return response.IsSuccessStatusCode ? 0 : 1;
        }
        // The URL is already known to be an absolute http(s) URI, so only genuine transport
        // failures and the timeout remain.
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            Console.Error.WriteLine($"The request to {url} failed: {exception.Message}");

            return 1;
        }
    }

    private static string Resolve(string[] args, int index, string variable)
    {
        string value = args.Length > index ? args[index] : string.Empty;

        return value.Length > 0 ? value : Environment.GetEnvironmentVariable(variable) ?? string.Empty;
    }
}
