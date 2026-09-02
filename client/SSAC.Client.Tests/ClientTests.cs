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

public class ForensicsHelpersTests
{
    [Fact]
    public void Rot13_round_trips()
        => Assert.Equal(@"C:\Users\x\vape.exe", Forensics.Rot13(Forensics.Rot13(@"C:\Users\x\vape.exe")));

    [Fact]
    public void Rot13_decodes_userassist_style_name()
        => Assert.Equal("hello", Forensics.Rot13("uryyb"));

    [Fact]
    public void FromFileTimeLe_parses_known_value()
    {
        var dto = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var bytes = BitConverter.GetBytes(dto.ToFileTime());
        var parsed = Forensics.FromFileTimeLe(bytes);
        Assert.NotNull(parsed);
        Assert.Equal(dto.UtcDateTime, parsed!.Value.UtcDateTime);
    }

    [Fact]
    public void FromFileTimeLe_rejects_zero()
        => Assert.Null(Forensics.FromFileTimeLe(new byte[8]));

    [Theory]
    [InlineData(@"\Device\HarddiskVolume3\Windows\System32\cmd.exe", @"C:\Windows\System32\cmd.exe")]
    [InlineData(@"\??\C:\x\y.exe", @"C:\x\y.exe")]
    public void NormalizeNtPath_maps_device_and_dos_prefixes(string input, string expected)
        => Assert.Equal(expected, Forensics.NormalizeNtPath(input));

    [Fact]
    public void LooksLikeCheat_is_case_insensitive_substring()
    {
        Assert.True(Forensics.LooksLikeCheat(@"C:\Users\bob\Downloads\Vape_V4.exe"));
        Assert.False(Forensics.LooksLikeCheat(@"C:\Windows\explorer.exe"));
    }

    [Fact]
    public void CheatHints_cover_general_injection_tooling()
    {
        Assert.True(Forensics.LooksLikeCheat("Xenos64.exe"));
        Assert.True(Forensics.LooksLikeCheat("Extreme Injector v3.exe"));
        Assert.True(Forensics.LooksLikeCheat("hwid-spoofer.exe"));
        Assert.True(Forensics.LooksLikeCheat("aimbot.dll"));
    }

    [Fact]
    public void VulnerableDrivers_are_lowercase_sys_names()
    {
        Assert.Contains("rtcore64.sys", Forensics.VulnerableDrivers);
        Assert.All(Forensics.VulnerableDrivers, d => Assert.Equal(d.ToLowerInvariant(), d));
        Assert.All(Forensics.VulnerableDrivers, d => Assert.EndsWith(".sys", d));
    }
}

public class ParserTests
{
    [Fact]
    public void ShimCache_parse_extracts_path_after_10ts_signature()
    {
        var path = @"C:\temp\doomsday.exe";
        var pb = Encoding.Unicode.GetBytes(path);
        var buf = new List<byte>();
        buf.AddRange("10ts"u8.ToArray());        // signature (+0)
        buf.AddRange(new byte[4]);               // unknown   (+4)
        buf.AddRange(new byte[4]);               // cacheEntrySize (+8)
        buf.AddRange(BitConverter.GetBytes((ushort)pb.Length)); // pathLen (+12)
        buf.AddRange(pb);                        // path (+14)
        buf.AddRange(new byte[16]);              // trailing

        var hits = ShimCacheModule.Parse(buf.ToArray());
        Assert.Contains(hits, h => h.Path == path && h.Exe == "doomsday.exe");
    }

    [Fact]
    public void RecycleBin_parse_v2_record()
    {
        var path = @"C:\Users\x\AppData\Roaming\.minecraft\mods\vape.jar";
        var pchars = path.Length + 1; // incl NUL
        var deleted = new DateTimeOffset(2026, 2, 1, 12, 0, 0, TimeSpan.Zero);

        var b = new List<byte>();
        b.AddRange(BitConverter.GetBytes(2L));                 // version
        b.AddRange(BitConverter.GetBytes(12345L));             // size
        b.AddRange(BitConverter.GetBytes(deleted.ToFileTime()));
        b.AddRange(BitConverter.GetBytes(pchars));             // char count
        b.AddRange(Encoding.Unicode.GetBytes(path + "\0"));

        var rec = RecycleBinModule.ParseIBytes(b.ToArray());
        Assert.NotNull(rec);
        Assert.Equal(path, rec!.Value.Path);
        Assert.Equal(12345L, rec.Value.Size);
        Assert.Equal(deleted.UtcDateTime, rec.Value.Deleted!.Value.UtcDateTime);
    }
}

public class CorrelationTests
{
    private static ScanContext Ctx() => new((_, _, _, _) => Task.CompletedTask);

    [Fact]
    public async Task Cheat_name_across_two_artifacts_is_flagged()
    {
        var ctx = Ctx();
        ctx.NoteExecution("doomsday.exe", @"C:\x\doomsday.exe", "bam", DateTimeOffset.UtcNow);
        ctx.NoteExecution("doomsday.exe", @"C:\x\doomsday.exe", "userassist", DateTimeOffset.UtcNow);

        await new CorrelationModule().RunAsync(ctx, default);

        Assert.Contains(ctx.Findings, f =>
            f.Module == "correlation" && f.Severity >= Severity.High && f.Title.Contains("across"));
    }

    [Fact]
    public async Task EasyAntiCheat_is_not_flagged_as_a_cheat()
    {
        var ctx = Ctx();
        ctx.NoteExecution("easyanticheat_eos_setup.exe", null, "bam", DateTimeOffset.UtcNow);
        ctx.NoteExecution("easyanticheat_eos_setup.exe", null, "userassist", DateTimeOffset.UtcNow);

        await new CorrelationModule().RunAsync(ctx, default);

        Assert.DoesNotContain(ctx.Findings, f => f.Title.Contains("easyanticheat", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Execution_without_prefetch_when_wiped_flags_cleanup()
    {
        var ctx = Ctx();
        ctx.Signals.Add("prefetch:empty");
        ctx.NoteExecution("someapp.exe", null, "bam", DateTimeOffset.UtcNow);

        await new CorrelationModule().RunAsync(ctx, default);

        Assert.Contains(ctx.Findings, f =>
            f.Module == "correlation" && f.Title.Contains("Prefetch wiped"));
    }

    [Fact]
    public async Task Missing_prefetch_is_not_flagged_when_prefetch_was_merely_unreadable()
    {
        var ctx = Ctx();
        ctx.Signals.Add("prefetch:unreadable");
        ctx.NoteExecution("someapp.exe", null, "bam", DateTimeOffset.UtcNow);

        await new CorrelationModule().RunAsync(ctx, default);

        Assert.DoesNotContain(ctx.Findings, f => f.Title.Contains("Prefetch file is missing"));
    }
}

public class SignatureDbTests
{
    [Fact]
    public void Embedded_db_loads_with_signatures()
    {
        var db = SignatureDb.Embedded();
        Assert.NotEqual("0", db.Version);
        Assert.True(db.Signatures.Count >= 10);
    }

    [Fact]
    public void Filename_matcher_identifies_meteor()
    {
        var db = SignatureDb.Embedded();
        var t = new MatchTarget();
        t.FileNames.Add("meteor-client-1.21-0.5.8.jar");
        var hits = db.Match(t);
        Assert.Contains(hits, h => h.Signature.Id == "meteor-client" && h.Confidence >= h.Signature.MinConfidence);
    }

    [Fact]
    public void Log_regex_matcher_identifies_wurst()
    {
        var db = SignatureDb.Embedded();
        var t = new MatchTarget();
        t.LogText.Add("[12:00:00] [main/INFO]: Starting Wurst Client v7.45");
        Assert.Contains(db.Match(t), h => h.Signature.Id == "wurst-client");
    }

    [Fact]
    public void Below_min_confidence_does_not_hit()
    {
        var db = SignatureDb.Embedded();
        var t = new MatchTarget();
        t.Strings.Add("com/example/KillAura"); // weight 1, generic sig needs 3
        Assert.DoesNotContain(db.Match(t), h => h.Signature.Id == "generic-killaura-strings");
    }

    [Fact]
    public void Newest_prefers_higher_version_and_survives_garbage()
    {
        var embedded = SignatureDb.Embedded();
        var newer = $"{{\"version\":\"9999.12.31\",\"updated\":\"x\",\"signatures\":[]}}";
        Assert.Equal("9999.12.31", SignatureDb.Newest(newer).Version);
        Assert.Equal(embedded.Version, SignatureDb.Newest("not json at all").Version);
        Assert.Equal(embedded.Version, SignatureDb.Newest(null).Version);
    }

    [Fact]
    public void Regexes_in_embedded_db_all_compile()
    {
        var db = SignatureDb.Embedded();
        foreach (var s in db.Signatures)
            foreach (var m in s.Matchers.Where(m => m.Kind.EndsWith("regex")))
                _ = new System.Text.RegularExpressions.Regex(m.Value); // throws on bad pattern
    }
}
