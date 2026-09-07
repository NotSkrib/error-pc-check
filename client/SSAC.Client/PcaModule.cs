using System.Globalization;

namespace SSAC.Client;

/// <summary>
/// Program Compatibility Assistant history (Windows 10 20H2+ / Windows 11).
/// `%WINDIR%\appcompat\pca\PcaAppLaunchDic.txt` records every GUI program launch
/// with a last-run time; `PcaGeneralDb0/1.txt` additionally logs abnormal
/// process exits. It is a plain-text execution artifact that survives some
/// anti-forensics aimed at Prefetch, and it feeds the correlation engine
/// (docs/phase-0-design.md §8, T5).
/// </summary>
public sealed class PcaModule : IScanModule
{
    public string Name => "pca";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);

        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "appcompat", "pca");
        var launchDic = Path.Combine(dir, "PcaAppLaunchDic.txt");
        var generalDbs = new[]
        {
            Path.Combine(dir, "PcaGeneralDb0.txt"),
            Path.Combine(dir, "PcaGeneralDb1.txt"),
        };

        if (!File.Exists(launchDic) && !generalDbs.Any(File.Exists))
        {
            ctx.Add(new Finding(Name, Severity.Info, "Program Compatibility Assistant history not available",
                "This Windows build does not keep a PCA launch history (added in Windows 10 20H2).",
                SortKey: 26));
            await ctx.ModuleDone(Name, 0);
            return;
        }

        ctx.Signals.Add("pca:present");
        var flagged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seen = 0;

        seen += ParseLaunchDic(ctx, launchDic, flagged, ct);
        foreach (var db in generalDbs)
            seen += ParseGeneralDb(ctx, db, flagged, ct);

        await ctx.Log(Name, $"{seen} PCA execution record(s)");
        await ctx.ModuleDone(Name, 0);
    }

    private static int ParseLaunchDic(ScanContext ctx, string path, HashSet<string> flagged, CancellationToken ct)
    {
        if (!File.Exists(path)) return 0;
        var n = 0;
        foreach (var line in ReadLines(path))
        {
            ct.ThrowIfCancellationRequested();
            var bar = line.LastIndexOf('|');
            if (bar <= 0) continue;
            var exe = line[..bar].Trim();
            var when = ParseWhen(line[(bar + 1)..].Trim());
            Consider(ctx, exe, when, "", flagged);
            n++;
        }
        return n;
    }

    private static int ParseGeneralDb(ScanContext ctx, string path, HashSet<string> flagged, CancellationToken ct)
    {
        if (!File.Exists(path)) return 0;
        var n = 0;
        foreach (var line in ReadLines(path))
        {
            ct.ThrowIfCancellationRequested();
            var f = line.Split('\t');
            if (f.Length < 3) continue;
            var exe = f.FirstOrDefault(x => x.TrimEnd().EndsWith(".exe", StringComparison.OrdinalIgnoreCase))?.Trim();
            if (string.IsNullOrEmpty(exe)) continue;
            var when = f.Select(ParseWhen).FirstOrDefault(w => w is not null);
            var note = f.FirstOrDefault(x =>
                x.Contains("abnormal", StringComparison.OrdinalIgnoreCase)
                || x.Contains("compatibility", StringComparison.OrdinalIgnoreCase)
                || x.Contains("stopped working", StringComparison.OrdinalIgnoreCase)) ?? "";
            Consider(ctx, exe, when, note, flagged);
            n++;
        }
        return n;
    }

    private static void Consider(ScanContext ctx, string exe, DateTimeOffset? when, string note, HashSet<string> flagged)
    {
        if (string.IsNullOrWhiteSpace(exe)) return;
        var name = Forensics.FileName(exe);
        // Feed the correlation engine regardless; only cheat-named launches are
        // worth a finding on their own (installers run from Downloads constantly).
        ctx.NoteExecution(name, exe, "pca", when);

        if (Forensics.LooksLikeCheat(name) && flagged.Add(exe.ToLowerInvariant()))
            ctx.Add(new Finding("pca", Severity.High,
                $"PCA recorded a cheat-named program running: {name}",
                $"Windows' Program Compatibility Assistant logged '{exe}' executing on this machine{(when is { } w ? $" (last {w:u})" : "")}.",
                new { path = exe, last_run = when?.ToString("u"), note }, SortKey: 5));
    }

    private static DateTimeOffset? ParseWhen(string s)
    {
        s = s.Trim();
        if (s.Length < 6) return null;
        if (DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var dto))
            return dto;
        if (DateTimeOffset.TryParse(s, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out dto))
            return dto;
        if (long.TryParse(s, out var ft) && ft > 0)
            return Forensics.FromFileTimeUtc(ft);
        return null;
    }

    private static IEnumerable<string> ReadLines(string path)
    {
        string[] lines;
        try { lines = File.ReadAllLines(path); } // BOM-detected; PCA files are UTF-16LE
        catch { yield break; }
        foreach (var l in lines)
            if (!string.IsNullOrWhiteSpace(l))
                yield return l;
    }
}
