using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SSAC.Client;

// Known-cheat signature DB + matcher (docs/phase-0-design.md §7).
// The client carries an embedded seed and, at scan start, tries to fetch a
// newer copy from the public `signatures` Edge Function. Whichever has the
// higher `version` string wins; the version used is recorded in the report.

public sealed record Matcher(string Kind, string Value, int Weight);

public sealed record Signature(
    string Id, string Name, string Family, string Type,
    string SeverityHint, int MinConfidence, IReadOnlyList<Matcher> Matchers,
    IReadOnlyList<string> References)
{
    public Severity Hint => SeverityHint?.ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        _ => Severity.High,
    };
}

public sealed record SignatureHit(Signature Signature, int Confidence, IReadOnlyList<string> MatchedOn);

/// <summary>Evidence collected from one Minecraft instance, fed to the matcher.</summary>
public sealed class MatchTarget
{
    public List<string> FileNames { get; } = [];   // mod / version jar names
    public List<string> Strings { get; } = [];     // jar entry names, config file names
    public List<string> LogText { get; } = [];     // log file contents (chunked)
    public List<string> Hashes { get; } = [];      // sha256 hex of mod jars
}

public sealed class SignatureDb
{
    public string Version { get; }
    public string Updated { get; }
    public IReadOnlyList<Signature> Signatures { get; }

    /// <summary>True if any matcher needs a file hash — lets collectors skip hashing otherwise.</summary>
    public bool NeedsHashes { get; }

    private SignatureDb(string version, string updated, IReadOnlyList<Signature> sigs)
    {
        (Version, Updated, Signatures) = (version, updated, sigs);
        NeedsHashes = sigs.Any(s => s.Matchers.Any(m => m.Kind == "file_hash"));
    }

    public static SignatureDb Embedded()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("ssac-signatures.json")
            ?? throw new InvalidOperationException("embedded ssac-signatures.json missing");
        using var r = new StreamReader(s);
        return Parse(r.ReadToEnd());
    }

    /// <summary>Returns the newer of the embedded seed and an optionally-fetched JSON string.</summary>
    public static SignatureDb Newest(string? fetchedJson)
    {
        var embedded = Embedded();
        if (string.IsNullOrWhiteSpace(fetchedJson)) return embedded;
        try
        {
            var fetched = Parse(fetchedJson);
            return string.CompareOrdinal(fetched.Version, embedded.Version) > 0 ? fetched : embedded;
        }
        catch { return embedded; }
    }

    public static SignatureDb Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var sigs = new List<Signature>();
        foreach (var e in root.GetProperty("signatures").EnumerateArray())
        {
            var matchers = e.GetProperty("matchers").EnumerateArray()
                .Select(m => new Matcher(
                    m.GetProperty("kind").GetString() ?? "",
                    m.GetProperty("value").GetString() ?? "",
                    m.TryGetProperty("weight", out var w) ? w.GetInt32() : 1))
                .ToList();
            var refs = e.TryGetProperty("references", out var rr)
                ? rr.EnumerateArray().Select(x => x.GetString() ?? "").ToList()
                : [];
            sigs.Add(new Signature(
                e.GetProperty("id").GetString() ?? "",
                e.GetProperty("name").GetString() ?? "",
                e.TryGetProperty("family", out var f) ? f.GetString() ?? "" : "",
                e.TryGetProperty("type", out var t) ? t.GetString() ?? "mod" : "mod",
                e.TryGetProperty("severity_hint", out var sh) ? sh.GetString() ?? "high" : "high",
                e.TryGetProperty("min_confidence", out var mc) ? mc.GetInt32() : 1,
                matchers, refs));
        }
        return new SignatureDb(
            root.TryGetProperty("version", out var v) ? v.GetString() ?? "0" : "0",
            root.TryGetProperty("updated", out var u) ? u.GetString() ?? "" : "",
            sigs);
    }

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    public List<SignatureHit> Match(MatchTarget target)
    {
        var hits = new List<SignatureHit>();
        foreach (var sig in Signatures)
        {
            var score = 0;
            var matchedOn = new List<string>();
            foreach (var m in sig.Matchers)
            {
                if (MatcherFires(m, target))
                {
                    score += m.Weight;
                    matchedOn.Add($"{m.Kind}:{Trunc(m.Value)}");
                }
            }
            if (score >= sig.MinConfidence)
                hits.Add(new SignatureHit(sig, score, matchedOn));
        }
        return hits;
    }

    private static bool MatcherFires(Matcher m, MatchTarget t)
    {
        try
        {
            switch (m.Kind)
            {
                case "file_hash":
                    return t.Hashes.Any(h => string.Equals(h, m.Value, StringComparison.OrdinalIgnoreCase));
                case "file_name_regex":
                {
                    var re = new Regex(m.Value, RegexOptions.CultureInvariant, RegexTimeout);
                    return t.FileNames.Any(re.IsMatch);
                }
                case "log_regex":
                {
                    var re = new Regex(m.Value, RegexOptions.CultureInvariant, RegexTimeout);
                    return t.LogText.Any(re.IsMatch);
                }
                case "string":
                    return t.Strings.Any(s => s.Contains(m.Value, StringComparison.OrdinalIgnoreCase))
                        || t.LogText.Any(s => s.Contains(m.Value, StringComparison.OrdinalIgnoreCase));
                default:
                    return false;
            }
        }
        catch (RegexMatchTimeoutException) { return false; }
        catch (ArgumentException) { return false; } // bad regex in a fetched DB
    }

    private static string Trunc(string s) => s.Length > 48 ? s[..48] + "…" : s;
}
