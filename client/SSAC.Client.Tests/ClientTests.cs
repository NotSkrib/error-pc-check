using System.Security.Cryptography;
using System.Text;
using SSAC.Client;
using Xunit;

namespace SSAC.Client.Tests;

public class OptionsTests
{
    [Fact]
    public void Parse_reads_key_endpoint_pin_flags()
    {
        var o = Options.Parse(["--key", "abc123", "--endpoint", "http://localhost:54321/functions/v1/", "--pin", "PIN"]);
        Assert.NotNull(o);
        Assert.Equal("abc123", o!.Key);
        Assert.Equal("http://localhost:54321/functions/v1", o.Endpoint); // trailing slash trimmed
        Assert.Equal("PIN", o.Pin);
    }

    [Fact]
    public void Parse_accepts_bare_positional_key_and_defaults_endpoint()
    {
        var o = Options.Parse(["deadbeef"]);
        Assert.NotNull(o);
        Assert.Equal("deadbeef", o!.Key);
        Assert.Equal(AppInfo.DefaultEndpoint, o.Endpoint);
    }

    [Fact]
    public void Parse_returns_null_on_help()
        => Assert.Null(Options.Parse(["--help"]));
}

public class SeverityTests
{
    [Fact]
    public void Worst_picks_highest()
        => Assert.Equal(Severity.Critical,
            SeverityX.Worst([Severity.Info, Severity.Critical, Severity.Low]));

    [Fact]
    public void Wire_is_lowercase()
        => Assert.Equal("critical", Severity.Critical.Wire());

    [Fact]
    public void Counts_group_by_severity()
    {
        var ctx = new ScanContext((_, _, _, _) => Task.CompletedTask);
        ctx.Add(new Finding("m", Severity.Low, "a", ""));
        ctx.Add(new Finding("m", Severity.Low, "b", ""));
        ctx.Add(new Finding("m", Severity.High, "c", ""));
        var c = ctx.Counts();
        Assert.Equal(2, c["low"]);
        Assert.Equal(1, c["high"]);
        Assert.Equal(Severity.High, ctx.Verdict);
    }
}

public class IngestSigningTests
{
    // Mirrors the check in supabase/functions/ingest/index.ts: hex(HMAC_SHA256(key, body)).
    [Fact]
    public void Hmac_hex_is_64_lowercase_hex()
    {
        const string key = "test-key";
        const string body = "{\"action\":\"describe\"}";
        var sig = Convert.ToHexString(
            new HMACSHA256(Encoding.UTF8.GetBytes(key)).ComputeHash(Encoding.UTF8.GetBytes(body)))
            .ToLowerInvariant();

        Assert.Equal(64, sig.Length);
        Assert.Matches("^[0-9a-f]{64}$", sig);
    }
}
