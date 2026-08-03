# omnetic-jwt-generator-csharp

C#/.NET SDK that generates signed **RS256** JWT tokens for authenticating Omnetic DMS
**Service Account (SA)** requests against the DMS API. Distributed to third parties as a
standalone library (v1: consumed from source / git — not published to NuGet).

> **Status:** the SA token generator is implemented — `GenerateToken()` produces an
> RS256-signed JWT (see Public API). The other-language SDKs (PHP/Python/TypeScript) live in
> separate repos.

## Tech Stack

- **Target framework:** **net8.0** (C# `latest`).
- **Runtime dependencies:** none — signing is hand-rolled on the BCL
  (`System.Security.Cryptography` for RS256, `System.Text.Json` for claim encoding).
- **Testing:** xUnit. **Static analysis:** .NET analyzers + nullable reference types, with
  compiler warnings treated as errors (`Directory.Build.props`).
- **Code style:** `dotnet format` driven by `.editorconfig`.
- **Local runtime:** Docker + Docker Compose (.NET 8 SDK image); no local .NET SDK required.

## Layout

```
src/Omnetic.JwtGenerator/JwtGenerator.cs         ← public API; `Omnetic.JwtGenerator` namespace
tests/Omnetic.JwtGenerator.Tests/                ← xUnit suite; `Omnetic.JwtGenerator.Tests` namespace
examples/GenerateToken/Program.cs                ← runnable example: sign a token, print it
examples/CallDmsApi/Program.cs                   ← runnable example: sign a token, call a DMS endpoint
Directory.Build.props                            ← shared strict build settings
Omnetic.JwtGenerator.sln                         ← solution
Dockerfile                                       ← mcr.microsoft.com/dotnet/sdk:8.0
docker-compose.yml                               ← single `dotnet` service, mounts the repo
Makefile                                         ← dev entry points (wrap `docker compose run --rm dotnet …`)
.editorconfig                                    ← code-style config
```

## Development

Everything runs inside Docker — no local .NET required.

```bash
make build            # build the dev/test image
make restore          # restore NuGet dependencies
make test             # run the xUnit suite
make format           # auto-fix code style
make format-check     # verify code style (fails if anything would change)
make example          # run examples/GenerateToken (KEY=… KID=… [LIFETIME=…])
make example-request  # run examples/CallDmsApi (KEY=… KID=… URL=…)
make shell            # open a shell in the container
```

Equivalent without `make`: `docker compose run --rm dotnet <cmd>` (e.g.
`docker compose run --rm dotnet dotnet test`).

## Public API

```csharp
using Omnetic.JwtGenerator;

string token = JwtGenerator.GenerateToken(privateKey, kid, lifetime: 3600);
```

- `privateKey` — RSA private key in **PEM** format (issued on SA creation / key rotation).
- `kid` — key ID (issued alongside the key); becomes the JWT `sub` claim.
- `lifetime` — token validity in seconds, optional, default `3600`, **max `3600`**.
- Returns a signed JWT for the `Authorization: Bearer` header.

The signed token uses **RS256** with header `{"alg":"RS256","typ":"JWT","kid":"<kid>"}`
(the `kid` is carried in **both** the header and the `sub` claim) and these payload claims:

```json
{ "type": "sa", "sub": "<kid>", "iat": "<now>", "exp": "<now + lifetime>" }
```

Validation the SDK enforces (cheap argument checks first, key parsing last): non-empty
`kid`, `1 <= lifetime <= 3600`, non-empty key, valid RSA PEM (private key, not a public key)
of at least 2048 bits. Invalid arguments throw `ArgumentException`
(`ArgumentOutOfRangeException` for `lifetime`).

## Examples

Two runnable console projects under `examples/`, ported from the PHP sibling's `examples/`
directory: `GenerateToken` (sign + print) and `CallDmsApi` (sign + call an endpoint). Both take
the key path, `kid` and (for the request) URL positionally, fall back to `OMNETIC_SA_KEY_PATH` /
`OMNETIC_SA_KID` / `OMNETIC_DMS_API_URL` when an argument is empty, write results to stdout and
diagnostics to stderr, and exit non-zero on failure.

Each exposes `internal static Main` returning an exit code (not top-level statements) with
`InternalsVisibleTo` for the test project, so the xUnit suite drives them in process with the
console redirected — no subprocess, and **no test contacts an external host** (the request-path
tests use a `TcpListener` on `127.0.0.1`). All example test classes share the
`ConsoleExamples` collection with `DisableParallelization = true`; that flag is required, since
console and environment state are process-global. Both projects are in the solution, so
`make test` / `make format-check` gate them too.

`CallDmsApi` parses the URL with `Uri.TryCreate(…, UriKind.Absolute, …)` and rejects any
non-`http(s)` scheme *before* signing. Do not drop that: `HttpClient` treats a scheme-less string
as a relative URI and throws `InvalidOperationException` from inside `SendAsync`, which is not an
`HttpRequestException` and would crash the example after a token had already been minted.

They stay dependency-free (`HttpClient` is BCL) and deliberately standalone: the duplicated
argument handling is intentional, so either `Program.cs` reads on its own.

## Conventions

- Nullable reference types enabled; compiler warnings are errors.
- Types are `sealed`/`static` unless extension is a deliberate part of the API.
- Explicit `using` directives (implicit usings disabled).
- Signing goes through the BCL (`RSA` + `System.Text.Json`); no third-party JWT library.
- Every public behavior gets an xUnit test; `make test` and `make format-check` must stay green.

## Context

- Jira: **T20-127460** ("[BE] JWT Generator SDK — C#, Python, TypeScript, PHP").
- Tokens must pass Gateway validation — **UC10 in T20-120653**. The claim shape and RS256
  algorithm above are the contract; do not diverge from them.
- The token-type claim is **`type`** (value `sa`), per the gateway contract (DEV-2012,
  confirmed in MR !13706). The legacy `typ` payload claim is deprecated — do **not** emit it,
  even though UC10's older example still shows `typ`.
- Sibling SDKs (separate repos): `omnetic-jwt-generator-php`,
  `omnetic-jwt-generator-python`, `omnetic-jwt-generator-typescript`.
