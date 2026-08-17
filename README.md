# omnetic-jwt-generator-csharp

C#/.NET SDK for generating signed **RS256** JWT tokens used to authenticate Omnetic DMS
**Service Account** requests against the DMS API.

## Requirements

- **.NET 8** (net8.0) for consumers.
- Docker + Docker Compose for local development.

## Usage

```csharp
using Omnetic.JwtGenerator;

string token = JwtGenerator.GenerateToken(privateKey, kid, lifetime: 3600);
// Authorization: Bearer <token>
```

- `privateKey` — RSA private key in PEM format (issued on SA creation / key rotation)
- `kid` — key ID (issued alongside the key)
- `lifetime` — token validity in seconds, optional, default `3600`, max `3600`

`GenerateToken()` builds and RS256-signs a JWT with header
`{"alg":"RS256","typ":"JWT","kid":"<kid>"}` and the claims:

```json
{ "type": "sa", "sub": "<kid>", "iat": "<now>", "exp": "<now + lifetime>" }
```

It throws `ArgumentException` (`ArgumentOutOfRangeException` for `lifetime`) if the `kid` is
empty, `lifetime` is outside `1…3600`, or the private key is empty / not a valid RSA PEM /
shorter than 2048 bits.

## Examples

Two runnable console projects in [`examples/`](examples) — both take the key path, the `kid` and
(for the request example) the endpoint URL as arguments, or from the `OMNETIC_SA_KEY_PATH`,
`OMNETIC_SA_KID` and `OMNETIC_DMS_API_URL` environment variables.

```bash
# Print a signed token (default lifetime 3600 s; optional third argument overrides it)
dotnet run --project examples/GenerateToken -- ./sa-key.pem <kid> 600

# Call a DMS endpoint with a freshly signed token — prints the status and body
dotnet run --project examples/CallDmsApi -- ./sa-key.pem <kid> https://<dms-host>/<endpoint>
```

Via Docker, wrapped by the Makefile (the key must sit inside the repo — that is what gets
mounted; `*.pem` is git-ignored):

```bash
make example         KEY=./sa-key.pem KID=<kid> [LIFETIME=600]
make example-request KEY=./sa-key.pem KID=<kid> URL=https://<dms-host>/<endpoint>
```

The three environment variables are forwarded into the container, so they work as fallbacks for
the `make` targets too.

Pass the path to the key, never the key itself, so no key material lands in your shell history.
`*.pem` is git-ignored, but treat that as a convenience rather than a safeguard — it will not stop
`git add -f`, a key saved under another extension, or a backup of your working tree. For anything
beyond a throwaway key, keep the file outside the repo and bind-mount the directory instead.

Both examples write the token / response to stdout and every diagnostic to stderr, and exit
non-zero on failure (`CallDmsApi` exits `0` on any `2xx`), so they compose in scripts and CI. Use
the `dotnet run` form when piping: `make` echoes its recipe line to stdout, so the `make` wrappers
are for interactive use.

Use the URL of a DMS endpoint your Service Account is allowed to call; the example does not
assume one. A `401` means the Gateway rejected the token — check that the `kid` matches the key,
that the Service Account is enabled, and that the clock is not skewed. `CallDmsApi` signs with a
300 s lifetime — a single request needs no more.

Neither example adds a dependency: `HttpClient` comes from the BCL, like the SDK's signing. Each
is deliberately standalone rather than sharing argument-handling helpers, so a single `Program.cs`
can be read — or copied into your own project — on its own.

## Development

Everything runs inside Docker — no local .NET required.

```bash
make build            # build the dev/test image
make restore          # restore NuGet dependencies
make test             # run the xUnit suite
make format           # auto-fix code style
make format-check     # check code style
make example          # print a signed token (KEY=… KID=… [LIFETIME=…])
make example-request  # call a DMS endpoint with a signed token (KEY=… KID=… URL=…)
make shell            # open a shell in the container
```
