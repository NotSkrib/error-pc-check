using System.Text;
using Microsoft.Win32;

namespace SSAC.Client;

// ===========================================================================
// Phase 3 — out-of-instance forensic collectors (docs/phase-0-design.md §8).
// User-privilege modules first, then admin ones (which degrade to
// "module_unavailable" without elevation), then the correlation engine.
// Everything here is inside the §4.1 allowlist: program-execution artifacts
// only, never document/message/credential contents.
// ===========================================================================

/// <summary>C:\Windows\Prefetch\*.pf — evidence of execution + wipe detection (T7).</summary>
public sealed class PrefetchModule : IScanModule
{
    public string Name => "prefetch";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        string[] files;
        try { files = Directory.Exists(dir) ? Directory.GetFiles(dir, "*.pf") : []; }
        catch (UnauthorizedAccessException)
        {
            ctx.Signals.Add("prefetch:unreadable");
            ctx.Add(new Finding(Name, Severity.Info, "Prefetch not readable",
                "Could not read the Prefetch folder — re-run the tool as administrator for execution history and wipe detection.",
                SortKey: 1));
            await ctx.ModuleDone(Name, 0);
            return;
        }

        var enabled = PrefetchEnabled();
        if (files.Length == 0)
        {
            ctx.Signals.Add("prefetch:empty");
            ctx.Add(new Finding(Name, enabled ? Severity.Medium : Severity.Low,
                enabled ? "Prefetch folder is empty" : "Prefetch is disabled and empty",
                enabled
                    ? "Prefetch is enabled but contains no .pf files. On a normally-used PC this usually means it was cleared — a common anti-forensic step before a screenshare."
                    : "Prefetch is disabled system-wide, so absence of .pf files is expected. Worth noting it limits execution history.",
                new { dir, enabled }, SortKey: 2));
            await ctx.ModuleDone(Name, 0);
            return;
        }

        int cheaty = 0;
        foreach (var f in files)
        {
            ct.ThrowIfCancellationRequested();
            var stem = Path.GetFileNameWithoutExtension(f);
            var dash = stem.LastIndexOf('-');
            var exe = dash > 0 ? stem[..dash] : stem;
            DateTimeOffset when;
            try { when = File.GetLastWriteTime(f); } catch { continue; }
            ctx.NoteExecution(exe, null, "prefetch", when);
            if (Forensics.LooksLikeCheat(exe))
            {
                cheaty++;
                ctx.Add(new Finding(Name, Severity.High, $"Prefetch shows a suspicious program ran: {exe}",
                    "A Prefetch file indicates this executable was run on this PC.",
                    new { exe, prefetch = Path.GetFileName(f), lastRun = when }, when, SortKey: 10));
            }
        }

        await ctx.Log(Name, $"{files.Length} .pf files, {cheaty} suspicious");
        await ctx.ModuleDone(Name, 0);
    }

    private static bool PrefetchEnabled()
    {
        using var k = Forensics.Open(RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
        var v = k?.GetValue("EnablePrefetcher");
        return v is null || (v is int i && i != 0);
    }
}

/// <summary>BAM/DAM — per-user execution + timestamp, keyed by SID.</summary>
public sealed class BamModule : IScanModule
{
    public string Name => "bam";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        var sid = Forensics.CurrentUserSid();
        string[] roots =
        [
            $@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{sid}",
            $@"SYSTEM\CurrentControlSet\Services\bam\UserSettings\{sid}",
        ];

        var found = 0;
        foreach (var root in roots)
        {
            using var k = Forensics.Open(RegistryHive.LocalMachine, root);
            if (k is null) continue;
            foreach (var (name, val) in Forensics.Values(k))
            {
                ct.ThrowIfCancellationRequested();
                if (val is not byte[] b || b.Length < 8) continue;
                var when = Forensics.FromFileTimeLe(b);
                var path = Forensics.NormalizeNtPath(name);
                var exe = Forensics.FileName(path);
                if (string.IsNullOrEmpty(exe)) continue;
                found++;
                ctx.NoteExecution(exe, path, "bam", when);
                if (Forensics.LooksLikeCheat(exe) || Forensics.LooksLikeCheat(path))
                    ctx.Add(new Finding(Name, Severity.High, $"BAM shows a suspicious program ran: {exe}",
                        "The Background Activity Moderator recorded this executable running under the current user account.",
                        new { path, lastRun = when }, when, SortKey: 10));
            }
        }

        await ctx.Log(Name, found == 0 ? "no BAM entries for this user" : $"{found} BAM entries");
        if (found == 0)
            ctx.Add(new Finding(Name, Severity.Info, "No BAM history",
                "BAM has no entries for this user. Possible on a fresh profile, or if it was cleared.", SortKey: 3));
        await ctx.ModuleDone(Name, 0);
    }
}

/// <summary>UserAssist — GUI-launched program run counts + last-exec time (ROT13 value names).</summary>
public sealed class UserAssistModule : IScanModule
{
    public string Name => "userassist";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        using var ua = Forensics.Open(RegistryHive.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
        var count = 0;
        foreach (var guid in ua?.GetSubKeyNames() ?? [])
        {
            using var ck = ua!.OpenSubKey($@"{guid}\Count");
            foreach (var (name, val) in Forensics.Values(ck))
            {
                ct.ThrowIfCancellationRequested();
                var path = Forensics.Rot13(name);
                if (path.StartsWith("UEME_", StringComparison.OrdinalIgnoreCase)) continue;
                var exe = Forensics.FileName(path);
                if (string.IsNullOrEmpty(exe)) continue;
                int runs = 0;
                DateTimeOffset? last = null;
                if (val is byte[] b && b.Length >= 68)
                {
                    runs = BitConverter.ToInt32(b, 4);
                    last = Forensics.FromFileTimeLe(b.AsSpan(60, 8));
                }
                count++;
                ctx.NoteExecution(exe, path, "userassist", last);
                if (Forensics.LooksLikeCheat(path))
                    ctx.Add(new Finding(Name, Severity.High, $"UserAssist shows a suspicious program was launched: {exe}",
                        "The current user launched this program from Explorer.",
                        new { path, runs, lastRun = last }, last, SortKey: 10));
            }
        }
        await ctx.Log(Name, $"{count} UserAssist entries");
        await ctx.ModuleDone(Name, 0);
    }
}

/// <summary>AppCompatCache (ShimCache) — best-effort path extraction from the Win10/11 blob.</summary>
public sealed class ShimCacheModule : IScanModule
{
    public string Name => "shimcache";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        using var k = Forensics.Open(RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache");
        if (k?.GetValue("AppCompatCache") is not byte[] blob || blob.Length < 16)
        {
            ctx.Add(new Finding(Name, Severity.Info, "ShimCache not readable",
                "The AppCompatCache value is missing or unreadable without elevation.", SortKey: 3));
            await ctx.ModuleDone(Name, 0);
            return;
        }

        var hits = Parse(blob);
        var flagged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (path, exe) in hits)
        {
            ctx.NoteExecution(exe, path, "shimcache", null);
            if (Forensics.LooksLikeCheat(path) && flagged.Add(exe))
                ctx.Add(new Finding(Name, Severity.Medium, $"ShimCache references a suspicious program: {exe}",
                    "The application-compatibility cache lists this executable. ShimCache entries do not prove execution but do prove the file was present.",
                    new { path }, SortKey: 12));
        }
        await ctx.Log(Name, $"{hits.Count} cached paths");
        await ctx.ModuleDone(Name, 0);
    }

    /// <summary>
    /// Scan for "10ts" entry signatures and pull the UTF-16 path.
    /// Win10/11 entry: "10ts"(4) unknown(4) cacheEntrySize(4) pathLen(2) path(pathLen) ...
    /// so pathLen is at sig+12 and the path at sig+14.
    /// </summary>
    public const int ShimPathLenOffset = 12;

    public static List<(string Path, string Exe)> Parse(byte[] b)
    {
        var outp = new List<(string, string)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sig = "10ts"u8.ToArray();
        for (var i = 0; i + ShimPathLenOffset + 2 < b.Length; i++)
        {
            if (b[i] != sig[0] || b[i + 1] != sig[1] || b[i + 2] != sig[2] || b[i + 3] != sig[3]) continue;
            try
            {
                var pathLen = BitConverter.ToUInt16(b, i + ShimPathLenOffset);
                var start = i + ShimPathLenOffset + 2;
                if (pathLen is 0 or > 1024 || pathLen % 2 != 0 || start + pathLen > b.Length) continue;
                var path = Encoding.Unicode.GetString(b, start, pathLen).TrimEnd('\0');
                if (!IsSanePath(path) || !seen.Add(path)) continue;
                outp.Add((path, Forensics.FileName(path)));
            }
            catch { /* skip malformed entry */ }
        }
        return outp;
    }

    private static bool IsSanePath(string p)
        => p.Length is > 3 and < 260
           && p.Contains('\\')
           && p.All(c => c >= ' ' && c != '�');
}

/// <summary>RunMRU, TypedPaths, Run keys, MUICache — lightweight registry sweep.</summary>
public sealed class RegistryArtifactsModule : IScanModule
{
    public string Name => "registry";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        var seen = 0;

        // MUICache: exe path -> friendly name; the path side is evidence the file was run.
        string[] muiKeys =
        [
            @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\MuiCache",
        ];
        var muiSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var mk in muiKeys)
        {
            using var k = Forensics.Open(RegistryHive.CurrentUser, mk);
            foreach (var (rawName, _) in Forensics.Values(k))
            {
                if (!rawName.Contains('\\')) continue;
                // MUICache value names are "<exe path>.FriendlyAppName" / ".ApplicationCompany".
                var path = rawName;
                foreach (var suf in new[] { ".FriendlyAppName", ".ApplicationCompany" })
                    if (path.EndsWith(suf, StringComparison.OrdinalIgnoreCase)) path = path[..^suf.Length];
                if (!muiSeen.Add(path)) continue;
                seen++;
                var exe = Forensics.FileName(path);
                ctx.NoteExecution(exe, path, "muicache", null);
                if (Forensics.LooksLikeCheat(path))
                    ctx.Add(new Finding(Name, Severity.Medium, $"MUICache references a suspicious program: {exe}",
                        "This executable was run at least once by the current user.", new { path }, SortKey: 12));
            }
        }

        // RunMRU + TypedPaths: strings the user typed into Run / Explorer.
        foreach (var (hive, sub) in new[]
        {
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"),
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"),
        })
        {
            using var k = Forensics.Open(hive, sub);
            foreach (var (n, v) in Forensics.Values(k))
            {
                if (v is not string s || n == "MRUList") continue;
                seen++;
                if (Forensics.LooksLikeCheat(s))
                    ctx.Add(new Finding(Name, Severity.Medium, "Suspicious Run / typed path",
                        "A value the user typed into the Run box or address bar matches known cheat naming.",
                        new { value = s }, SortKey: 14));
            }
        }

        // Autostart (loader persistence — T5).
        foreach (var (hive, sub) in new[]
        {
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        })
        {
            using var k = Forensics.Open(hive, sub);
            foreach (var (n, v) in Forensics.Values(k))
            {
                if (v is not string s) continue;
                seen++;
                if (Forensics.LooksLikeCheat(s) || Forensics.LooksLikeCheat(n))
                    ctx.Add(new Finding(Name, Severity.High, $"Suspicious autostart entry: {n}",
                        "A program set to start with Windows matches known cheat / injector naming.",
                        new { name = n, command = s }, SortKey: 8));
            }
        }

        await ctx.Log(Name, $"{seen} registry artifacts scanned");
        await ctx.ModuleDone(Name, 0);
    }
}

/// <summary>Recycle Bin $I records — deleted .jar/.exe/.dll (T7).</summary>
public sealed class RecycleBinModule : IScanModule
{
    public string Name => "recycle-bin";
    public bool RequiresElevation => false;
    private static readonly string[] Exts = [".jar", ".exe", ".dll"];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        var bins = new List<string>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType != DriveType.Fixed) continue;
            var p = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
            if (Directory.Exists(p)) bins.Add(p);
        }

        var count = 0;
        foreach (var bin in bins)
        {
            IEnumerable<string> sidDirs;
            try { sidDirs = Directory.EnumerateDirectories(bin); } catch { continue; }
            foreach (var sd in sidDirs)
            {
                IEnumerable<string> iFiles;
                try { iFiles = Directory.EnumerateFiles(sd, "$I*"); } catch { continue; }
                foreach (var i in iFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var rec = ParseI(i);
                    if (rec is null) continue;
                    var (origPath, size, deleted) = rec.Value;
                    var ext = Path.GetExtension(origPath).ToLowerInvariant();
                    if (!Exts.Contains(ext)) continue;
                    count++;

                    var lower = origPath.ToLowerInvariant();
                    var inMods = lower.Contains(@"\.minecraft\mods\") || lower.Contains(@"\mods\");
                    var cheat = Forensics.LooksLikeCheat(origPath);
                    var sev = (cheat, inMods) switch
                    {
                        (true, _) => Severity.Critical,
                        (_, true) when ext == ".jar" => Severity.High,
                        _ => Severity.Medium,
                    };
                    ctx.NoteExecution(Forensics.FileName(origPath), origPath, "recycle-bin", null);
                    ctx.Add(new Finding(Name, sev, $"Deleted {ext} in the Recycle Bin: {Forensics.FileName(origPath)}",
                        inMods
                            ? "A mod/jar was deleted from a Minecraft mods folder and is sitting in the Recycle Bin."
                            : "An executable/library was deleted and is in the Recycle Bin.",
                        new { origPath, sizeBytes = size, deletedAt = deleted }, deleted, SortKey: cheat ? 1 : 15));
                }
            }
        }

        await ctx.Log(Name, $"{count} deleted jar/exe/dll in recycle bins");
        await ctx.ModuleDone(Name, 0);
    }

    /// <summary>$I format: v1 (fixed 260-char path) and v2 (length-prefixed).</summary>
    public static (string Path, long Size, DateTimeOffset? Deleted)? ParseI(string file)
    {
        byte[] b;
        try { b = File.ReadAllBytes(file); } catch { return null; }
        return ParseIBytes(b);
    }

    public static (string Path, long Size, DateTimeOffset? Deleted)? ParseIBytes(byte[] b)
    {
        if (b.Length < 24) return null;
        var version = BitConverter.ToInt64(b, 0);
        var size = BitConverter.ToInt64(b, 8);
        var deleted = Forensics.FromFileTimeLe(b.AsSpan(16, 8));
        string path;
        if (version == 2)
        {
            if (b.Length < 28) return null;
            var chars = BitConverter.ToInt32(b, 24);
            var bytes = chars * 2;
            if (bytes <= 0 || 28 + bytes > b.Length) return null;
            path = Forensics.Utf16(b.AsSpan(28, bytes));
        }
        else // v1
        {
            var span = b.AsSpan(24, Math.Min(520, b.Length - 24));
            path = Forensics.Utf16(span);
        }
        return string.IsNullOrWhiteSpace(path) ? null : (path, size, deleted);
    }
}

/// <summary>PSReadLine history — manual download / injection / AV-tamper commands.</summary>
public sealed class PowerShellHistoryModule : IScanModule
{
    public string Name => "powershell-history";
    public bool RequiresElevation => false;

    /// <summary>Shared with <see cref="PowerShellEventLogModule"/> so both the typed-history
    /// check and the script-block-logging check flag the same command patterns.</summary>
    internal static readonly (string Needle, Severity Sev, string Why)[] Rules =
    [
        ("disablerealtimemonitoring", Severity.High, "disables Windows Defender real-time protection"),
        ("add-mppreference", Severity.High, "adds a Windows Defender exclusion"),
        ("-javaagent", Severity.High, "launches Java with an instrumentation agent"),
        ("inject", Severity.High, "references process injection"),
        ("invoke-expression", Severity.High, "pipes downloaded content into Invoke-Expression — the classic fetch-and-run pattern"),
        ("| iex", Severity.High, "pipes downloaded content into iex — the classic fetch-and-run pattern"),
        ("invoke-webrequest", Severity.Medium, "downloads a file"),
        ("invoke-restmethod", Severity.Medium, "downloads a file"),
        ("iwr ", Severity.Medium, "downloads a file"),
        ("irm ", Severity.Medium, "downloads a file"),
        ("certutil -urlcache", Severity.Medium, "downloads a file via certutil"),
        ("bitsadmin /transfer", Severity.Medium, "downloads a file via bitsadmin"),
        ("curl ", Severity.Low, "downloads a file"),
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
        if (!File.Exists(path))
        {
            await ctx.Log(Name, "no PSReadLine history");
            await ctx.ModuleDone(Name, 0);
            return;
        }

        string[] lines;
        try { lines = File.ReadAllLines(path); } catch { await ctx.ModuleDone(Name, 0); return; }
        var hits = 0;
        foreach (var raw in lines)
        {
            var line = raw.ToLowerInvariant();
            foreach (var (needle, sev, why) in Rules)
            {
                if (!line.Contains(needle)) continue;
                hits++;
                var s = Forensics.LooksLikeCheat(line) && sev < Severity.High ? Severity.High : sev;
                ctx.Add(new Finding(Name, s, "PowerShell command of interest",
                    $"A command in PowerShell history {why}.",
                    new { command = raw.Length > 300 ? raw[..300] : raw }, SortKey: 16));
                break;
            }
        }
        await ctx.Log(Name, $"{lines.Length} history lines, {hits} of interest");
        await ctx.ModuleDone(Name, 0);
    }
}

/// <summary>PowerShell Script Block Logging (event 4104) — catches the same command
/// patterns as <see cref="PowerShellHistoryModule"/>, but from commands that never touch
/// PSReadLine's history file: hidden/non-interactive invocations
/// (<c>powershell -WindowStyle Hidden -Command "irm ... | iex"</c>), scripts run via
/// <c>-File</c>, or history that was cleared after the fact. Needs Script Block Logging
/// enabled (Group Policy / registry) to have anything to read — degrades gracefully
/// otherwise.</summary>
public sealed class PowerShellEventLogModule : IScanModule
{
    public string Name => "powershell-eventlog";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        try
        {
            var q = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                "Microsoft-Windows-PowerShell/Operational",
                System.Diagnostics.Eventing.Reader.PathType.LogName,
                "*[System[(EventID=4104)]]");
            using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(q);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var n = 0; var hits = 0;
            for (var e = reader.ReadEvent(); e is not null && n < 5000; e = reader.ReadEvent(), n++)
            {
                ct.ThrowIfCancellationRequested();
                string desc;
                try { desc = e.FormatDescription() ?? ""; } catch { continue; }
                if (desc.Length == 0) continue;
                var line = desc.ToLowerInvariant();
                foreach (var (needle, sev, why) in PowerShellHistoryModule.Rules)
                {
                    if (!line.Contains(needle)) continue;
                    var snippet = desc.Length > 300 ? desc[..300] : desc;
                    if (!seen.Add(snippet)) break; // same script block logged more than once
                    hits++;
                    var s = Forensics.LooksLikeCheat(line) && sev < Severity.High ? Severity.High : sev;
                    ctx.Add(new Finding(Name, s, "PowerShell script block of interest",
                        $"A PowerShell Script Block Logging event (4104) {why}. This is captured even for hidden or "
                        + "non-interactive invocations that never touch PSReadLine history.",
                        new { time = e.TimeCreated, snippet }, e.TimeCreated, SortKey: 16));
                    break;
                }
            }
            await ctx.Log(Name, $"{n} script-block events, {hits} of interest");
        }
        catch (Exception ex)
        {
            ctx.Add(new Finding(Name, Severity.Info, "PowerShell script-block log not available",
                "Could not read the Microsoft-Windows-PowerShell/Operational event log — Script Block Logging may "
                + "not be enabled (Group Policy), or the log is inaccessible.",
                new { error = ex.GetType().Name }, SortKey: 20));
        }
        await ctx.ModuleDone(Name, 0);
    }
}

// ---- admin-only (degrade gracefully) --------------------------------------

/// <summary>Amcache.hve — needs an offline registry-hive parser (Phase 3b).</summary>
public sealed class AmcacheModule : IScanModule
{
    public string Name => "amcache";
    public bool RequiresElevation => true;
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        ctx.Add(new Finding(Name, Severity.Info, "Amcache not analysed",
            "Amcache.hve parsing (program hashes + first-run times, needed for the strongest anti-forensic correlation) is not implemented yet — Phase 3b.",
            SortKey: 20));
        await ctx.ModuleDone(Name, 0);
    }
}

/// <summary>$MFT — needs raw NTFS parsing (Phase 3b).</summary>
public sealed class MftModule : IScanModule
{
    public string Name => "mft";
    public bool RequiresElevation => true;
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        ctx.Add(new Finding(Name, Severity.Info, "$MFT not analysed",
            "Raw $MFT parsing (deleted-file records + timestomp detection) is not implemented yet — Phase 3b.",
            SortKey: 20));
        await ctx.ModuleDone(Name, 0);
    }
}

/// <summary>Security 4688 process-creation events — best effort, usually needs admin + audit policy on.</summary>
public sealed class EventLogModule : IScanModule
{
    public string Name => "eventlog";
    public bool RequiresElevation => true;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        try
        {
            var q = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                "Security", System.Diagnostics.Eventing.Reader.PathType.LogName,
                "*[System[(EventID=4688)]]");
            using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(q);
            var n = 0; var cheaty = 0;
            for (var e = reader.ReadEvent(); e is not null && n < 5000; e = reader.ReadEvent(), n++)
            {
                ct.ThrowIfCancellationRequested();
                string desc;
                try { desc = e.FormatDescription() ?? ""; } catch { continue; }
                if (Forensics.LooksLikeCheat(desc))
                {
                    cheaty++;
                    ctx.Add(new Finding(Name, Severity.High, "Process-creation event names a suspicious program",
                        "A Windows Security log entry (4688) references known cheat naming.",
                        new { time = e.TimeCreated }, e.TimeCreated, SortKey: 10));
                }
            }
            await ctx.Log(Name, $"{n} 4688 events, {cheaty} suspicious");
        }
        catch (Exception ex)
        {
            ctx.Add(new Finding(Name, Severity.Info, "Security event log not available",
                "Could not read Security 4688 events (needs elevation and process-creation auditing enabled).",
                new { error = ex.GetType().Name }, SortKey: 20));
        }
        await ctx.ModuleDone(Name, 0);
    }
}

/// <summary>Reasons over everything the other collectors gathered (the headline T7 capability).</summary>
public sealed class CorrelationModule : IScanModule
{
    public string Name => "correlation";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);

        var bySource = ctx.Executions
            .GroupBy(e => e.Name)
            .Select(g => (Name: g.Key, Sources: g.Select(x => x.Source).Distinct().ToArray(),
                          When: g.Select(x => x.When).Where(w => w is not null).Max()))
            .ToList();

        var prefetchWiped = ctx.Signals.Contains("prefetch:empty");
        var prefetchUnreadable = ctx.Signals.Contains("prefetch:unreadable");
        var usnDeletedPf = ctx.Signals.Contains("usn:deleted-pf");
        // We can only reason about "missing" Prefetch files if Prefetch was actually readable.
        var canReasonAboutMissingPf = !prefetchUnreadable && (prefetchWiped || usnDeletedPf);

        const int MaxDetailFindings = 15;
        var missingPf = new List<string>();

        foreach (var g in bySource)
        {
            var hasPrefetch = g.Sources.Contains("prefetch");
            var otherSources = g.Sources.Where(s => s != "prefetch").ToArray();
            var cheat = Forensics.LooksLikeCheat(g.Name);

            // Executed (per BAM/UserAssist/ShimCache/MUICache) but no Prefetch file for it,
            // on a system where Prefetch is readable and shows signs of tampering.
            if (canReasonAboutMissingPf && !hasPrefetch && otherSources.Length > 0)
            {
                if (missingPf.Count < MaxDetailFindings)
                {
                    var sev = cheat ? Severity.Critical : (usnDeletedPf ? Severity.High : Severity.Medium);
                    ctx.Add(new Finding(Name, sev,
                        $"Execution recorded for '{g.Name}' but its Prefetch file is missing",
                        $"'{g.Name}' shows as executed in {string.Join(", ", otherSources)}, but there is no matching Prefetch file"
                        + (prefetchWiped ? " and the Prefetch folder appears wiped" : "")
                        + (usnDeletedPf ? " and the USN journal shows .pf files were deleted" : "")
                        + ". This pattern is consistent with deliberate cleanup.",
                        new { name = g.Name, sources = otherSources, lastRun = g.When }, g.When, SortKey: 0));
                }
                missingPf.Add(g.Name);
            }

            // Same cheaty name from two or more independent artifacts.
            if (cheat && g.Sources.Length >= 2)
                ctx.Add(new Finding(Name, Severity.High,
                    $"'{g.Name}' matches known cheat naming across {g.Sources.Length} artifacts",
                    $"Independent Windows artifacts ({string.Join(", ", g.Sources)}) all reference '{g.Name}'.",
                    new { name = g.Name, sources = g.Sources, lastRun = g.When }, g.When, SortKey: 1));
        }

        if (missingPf.Count > MaxDetailFindings)
            ctx.Add(new Finding(Name, Severity.High,
                $"{missingPf.Count} programs have execution records with no Prefetch file",
                "Many programs show as executed in other artifacts but have no Prefetch entry, on a system where Prefetch shows signs of tampering.",
                new { examples = missingPf.Take(30) }, SortKey: 0));

        if (prefetchWiped && !prefetchUnreadable && ctx.Executions.Any(e => e.Source != "prefetch"))
            ctx.Add(new Finding(Name, Severity.High, "Prefetch wiped but other execution history survives",
                "The Prefetch folder is empty, yet BAM / UserAssist / ShimCache still hold execution records. Selectively clearing Prefetch is a known anti-forensic step.",
                new { survivingSources = ctx.Executions.Select(e => e.Source).Distinct() }, SortKey: 1));

        await ctx.Log(Name, $"correlated {ctx.Executions.Count} execution records across {bySource.Count} programs");
        await ctx.ModuleDone(Name, 0);
    }
}
