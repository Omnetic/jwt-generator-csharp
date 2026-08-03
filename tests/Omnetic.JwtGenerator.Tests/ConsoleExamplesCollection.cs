using Xunit;

namespace Omnetic.JwtGenerator.Tests;

/// <summary>
/// Groups the example tests into one non-parallel collection. They drive the examples in
/// process, and both the redirected console and the environment variables the examples read
/// are process-global state.
///
/// DisableParallelization is required, not decorative: xUnit already serialises tests *within*
/// a collection, but without this flag the collection still runs in parallel with the other
/// collections in this assembly, and a concurrent test observing the redirected Console fails.
/// Removing it makes this suite flaky.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ConsoleExamplesCollection
{
    public const string Name = "ConsoleExamples";
}
