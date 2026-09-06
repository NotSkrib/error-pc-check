using Microsoft.Data.Sqlite;

namespace SSAC.Client;

/// <summary>
/// Reads the browser download history (the `downloads` table only — never
/// browsing history, form data or cookies) from Chromium browsers and Firefox,
/// and flags downloads of known cheat clients / from cheat sites. Catches things
/// that were downloaded and then deleted from the Downloads folder.
/// </summary>
public sealed class BrowserDownloadsModule : IScanModule
{
    public string Name => "browser-downloads";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var total = 0;

        // Chromium: <User Data>\<Profile>\History  -> downloads(target_path, tab_url, start_time)
        string[] chromiumRoots =
        [
            Path.Combine(local, @"Google\Chrome\User Data"),
            Path.Combine(local, @"Microsoft\Edge\User Data"),
            Path.Combine(local, @"BraveSoftware\Brave-Browser\User Data"),
            Path.Combine(local, @"Chromium\User Data"),
            Path.Combine(roaming, @"Opera Software\Opera Stable"),
        ];
        foreach (var root in chromiumRoots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var db in FindDbs(root, "History"))
                total += ScanChromium(ctx, db, ct);
        }

        // Firefox: <Profiles>\<profile>\places.sqlite  -> downloaded resources
        var ffRoot = Path.Combine(roaming, @"Mozilla\Firefox\Profiles");
        if (Directory.Exists(ffRoot))
            foreach (var db in FindDbs(ffRoot, "places.sqlite"))
                total += ScanFirefox(ctx, db, ct);

        await ctx.Log(Name, $"{total} download records inspected");
        await ctx.ModuleDone(Name, 0);
    }

    private static IEnumerable<string> FindDbs(string root, string name)
    {
        var hits = new List<string>();
        try
        {
            if (name.Contains('.'))
                hits.AddRange(Directory.EnumerateFiles(root, name, SearchOption.AllDirectories));
            else
                foreach (var dir in Directory.EnumerateDirectories(root))
                {
                    var p = Path.Combine(dir, name);
                    if (File.Exists(p)) hits.Add(p);
                }
        }
        catch { /* ignore */ }
        return hits;
    }

    /// <summary>
    /// Open the DB read-only IN PLACE — no copy to %TEMP%. `mode=ro&immutable=1`
    /// lets SQLite read a file the browser has open without taking any locks.
    /// Reading it where it lives (not staging a copy in temp) avoids the classic
    /// infostealer IOC that AV heuristics pattern-match on.
    /// </summary>
    private static SqliteConnection? OpenCopy(string dbPath)
    {
        try
        {
            var fileUri = "file:///" + dbPath.Replace('\\', '/').Replace(" ", "%20") + "?mode=ro&immutable=1";
            var c = new SqliteConnection($"Data Source={fileUri};Cache=Private");
            c.Open();
            return c;
        }
        catch { return null; }
    }

    private static int ScanChromium(ScanContext ctx, string db, CancellationToken ct)
    {
        using var c = OpenCopy(db);
        if (c is null) return 0;
        var n = 0;
        try
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText =
                "SELECT target_path, IFNULL(tab_url,''), IFNULL(referrer,''), start_time " +
                "FROM downloads ORDER BY start_time DESC LIMIT 5000";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                ct.ThrowIfCancellationRequested();
                n++;
                var path = r.GetString(0);
                var url = r.GetString(1);
                var referrer = r.GetString(2);
                var when = ChromeTime(r.IsDBNull(3) ? 0 : r.GetInt64(3));
                Consider(ctx, db, path, url, referrer, when);
            }
        }
        catch { /* schema drift / not a downloads db */ }
        return n;
    }

    private static int ScanFirefox(ScanContext ctx, string db, CancellationToken ct)
    {
        using var c = OpenCopy(db);
        if (c is null) return 0;
        var n = 0;
        try
        {
            using var cmd = c.CreateCommand();
            // Downloaded file destinations live in moz_annos; the source URL is on moz_places.
            cmd.CommandText =
                "SELECT IFNULL(p.url,''), IFNULL(a.content,''), p.last_visit_date " +
                "FROM moz_annos a JOIN moz_places p ON p.id = a.place_id " +
                "JOIN moz_anno_attributes t ON t.id = a.anno_attribute_id " +
                "WHERE t.name = 'downloads/destinationFileURI' LIMIT 5000";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                ct.ThrowIfCancellationRequested();
                n++;
                var url = r.GetString(0);
                var dest = Uri.TryCreate(r.GetString(1), UriKind.Absolute, out var u) ? u.LocalPath : r.GetString(1);
                var when = r.IsDBNull(2) ? (DateTimeOffset?)null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(2) / 1000);
                Consider(ctx, db, dest, url, "", when);
            }
        }
        catch { /* older firefox / no downloads annos */ }
        return n;
    }

    private static void Consider(ScanContext ctx, string db, string targetPath, string url, string referrer, DateTimeOffset? when)
    {
        var name = Forensics.FileName(targetPath);
        var hay = $"{name} {url} {referrer}";
        if (!Forensics.IsCheatDownload(hay)) return;

        var browser = db.Contains("Edge") ? "Edge" : db.Contains("Brave") ? "Brave"
            : db.Contains("Firefox") ? "Firefox" : db.Contains("Opera") ? "Opera" : "Chrome";
        var ext = Path.GetExtension(name).ToLowerInvariant();
        if (ext is ".exe" or ".jar" or ".dll") ctx.NoteExecution(name, targetPath, "browser-download", when);

        ctx.Add(new Finding("browser-downloads", Severity.High,
            $"Cheat client downloaded: {name}",
            $"{browser} download history shows this file was downloaded" +
            (string.IsNullOrEmpty(url) ? "." : $" from {Shorten(url)}."),
            new { file = name, target = targetPath, url, referrer, downloadedAt = when }, when, SortKey: 2));
    }

    private static DateTimeOffset? ChromeTime(long micros)
    {
        if (micros <= 0) return null;
        try { return new DateTimeOffset(1601, 1, 1, 0, 0, 0, TimeSpan.Zero).AddMicroseconds(micros); }
        catch { return null; }
    }

    private static string Shorten(string url)
        => url.Length <= 80 ? url : url[..80] + "…";
}
