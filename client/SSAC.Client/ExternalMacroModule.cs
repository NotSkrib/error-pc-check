using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SSAC.Client;

/// <summary>
/// Catches an <b>external</b> macro / PvP client running alongside the game even
/// when its file has been renamed. A renamed .exe still keeps its embedded PE
/// version info (ProductName / FileDescription / CompanyName) and usually its
/// window title, so we match on those rather than just the filename. Also flags
/// AutoHotkey / AutoIt runtimes (the usual crystal / mace macro engines) and
/// loose .ahk / .au3 scripts. (docs/phase-0-design.md T6, and zenithmacros.store
/// as the worked example.)
/// </summary>
public sealed class ExternalMacroModule : IScanModule
{
    public string Name => "external-macro";
    public bool RequiresElevation => false;

    // Strong: a hit anywhere (window title or version info) is a finding on its own.
    private static readonly string[] StrongTerms =
    [
        "autoclicker", "auto clicker", "triggerbot", "trigger bot", "killaura", "kill aura",
        "aimassist", "aim assist", "aimbot", "auto crystal", "autocrystal", "hit crystal",
        "anchor macro", "double anchor", "safe anchor", "crystal aura", "crystal pvp",
        "mace macro", "totem macro", "no recoil", "norecoil", "reach hack", "ghost client",
        "external pvp", "pvp macro", "pvp client", "scaffold macro", "velocity macro",
        "zenith macros", "zenith macro", "autohotkey", "autoit",
    ];

    // Weak: only a finding when the process is also unsigned and outside Program Files.
    private static readonly string[] WeakTerms = ["macro", "clicker", "pvp cheat", "cheat client"];

    // CompanyName values that mean "leave it alone" for the weak checks.
    private static readonly string[] GoodVendors =
    [
        "microsoft", "google", "mozilla", "valve", "discord inc", "spotify", "nvidia",
        "advanced micro devices", "intel", "epic games", "riot games", "logitech", "corsair",
        "razer", "steelseries", "apple inc", "adobe", "dropbox", "oracle", "amazon",
        "moonsworth", "overwolf", "obs project", "streamlabs", "blizzard", "electronic arts",
    ];

    private static readonly string[] KnownGoodNames =
    [
        "explorer", "javaw", "java", "steam", "steamwebhelper", "discord", "spotify",
        "chrome", "firefox", "msedge", "opera", "brave", "obs64", "obs32", "nvcontainer",
        "lunarclient", "badlion", "prismlauncher", "modrinth", "curseforge", "feather",
        "logioverlay", "logi_", "code", "svchost", "runtimebroker", "textinputhost",
    ];

    private static readonly string[] UserDirParts =
    [
        "\\downloads\\", "\\desktop\\", "\\appdata\\local\\temp\\", "\\temp\\", "\\tmp\\",
        "\\appdata\\roaming\\", "\\documents\\", "\\public\\", "\\onedrive\\", "\\music\\",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);

        var titlesByPid = WindowTitlesByPid();
        var flagged = 0;

        foreach (var p in Process.GetProcesses())
        {
            ct.ThrowIfCancellationRequested();
            int pid;
            string name, path = "";
            try
            {
                pid = p.Id;
                name = p.ProcessName;
                path = p.MainModule?.FileName ?? "";
            }
            catch { continue; }

            var lname = name.ToLowerInvariant();
            if (KnownGoodNames.Any(g => lname.Contains(g))) continue;
            var lpath = path.ToLowerInvariant();

            titlesByPid.TryGetValue(pid, out var titles);
            var (desc, product, company, comments) = VersionInfo(path);
            if (GoodVendors.Any(v => company.Contains(v))) continue;

            var haystack = string.Join("  ",
                new[] { name, titles ?? "", desc, product, company, comments }
                .Where(s => !string.IsNullOrWhiteSpace(s)))
                .ToLowerInvariant();

            var strong = StrongTerms.FirstOrDefault(haystack.Contains);
            var signed = path.Length > 0 && Authenticode.IsSigned(path);
            var inUserDir = UserDirParts.Any(lpath.Contains);

            if (strong is not null)
            {
                ctx.Signals.Add("external-macro:running");
                ctx.NoteExecution(name, path, "live-process", DateTimeOffset.Now);
                ctx.Add(new Finding(Name, Severity.High,
                    $"External macro / cheat program running: {name}.exe",
                    $"A running program's window title or embedded details contain “{strong}”. "
                    + "This is how an external macro (renamed or not) shows up while the game is open.",
                    new { pid, name, path, matched = strong, signed, window = Clip(titles, 200), product, company },
                    SortKey: 1));
                flagged++;
                continue;
            }

            if (!signed && inUserDir)
            {
                var weak = WeakTerms.FirstOrDefault(haystack.Contains);
                if (weak is not null)
                {
                    ctx.Add(new Finding(Name, Severity.Medium,
                        $"Unsigned program with “{weak}” in its name / window: {name}.exe",
                        "An unsigned program running from a user folder describes itself with a macro-ish term. Worth a manual look.",
                        new { pid, name, path, matched = weak, window = Clip(titles, 200), product, company },
                        SortKey: 11));
                    flagged++;
                }
            }
        }

        flagged += ScanScripts(ctx);

        await ctx.Log(Name, $"{flagged} suspicious program(s) / script(s)");
        await ctx.ModuleDone(Name, 0);
    }

    private static int ScanScripts(ScanContext ctx)
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var roots = new[]
        {
            Path.Combine(home, "Downloads"), Path.Combine(home, "Desktop"),
            Path.Combine(home, "Documents"), home, Path.Combine(roaming, ".minecraft"),
        };
        var hits = new List<string>();
        foreach (var r in roots)
        {
            if (!Directory.Exists(r)) continue;
            foreach (var pat in new[] { "*.ahk", "*.au3" })
            {
                try { hits.AddRange(Directory.EnumerateFiles(r, pat, SearchOption.TopDirectoryOnly)); }
                catch { /* skip */ }
            }
        }
        var n = 0;
        foreach (var f in hits.Distinct(StringComparer.OrdinalIgnoreCase).Take(25))
        {
            ctx.NoteExecution(Path.GetFileName(f), f, "script-file", File.GetLastWriteTime(f));
            ctx.Add(new Finding("external-macro", Severity.Medium,
                $"Macro script on disk: {Path.GetFileName(f)}",
                "An AutoHotkey / AutoIt script — the usual engine for crystal / mace / clicker macros.",
                new { path = f, modified = File.GetLastWriteTime(f).ToString("u") }, SortKey: 12));
            n++;
        }
        return n;
    }

    private static (string Desc, string Product, string Company, string Comments) VersionInfo(string path)
    {
        try
        {
            if (path.Length == 0 || !File.Exists(path)) return ("", "", "", "");
            var v = FileVersionInfo.GetVersionInfo(path);
            return (v.FileDescription ?? "", v.ProductName ?? "",
                    (v.CompanyName ?? "").ToLowerInvariant(), v.Comments ?? "");
        }
        catch { return ("", "", "", ""); }
    }

    private static Dictionary<int, string> WindowTitlesByPid()
    {
        var map = new Dictionary<int, string>();
        try
        {
            EnumWindows((h, _) =>
            {
                try
                {
                    if (!IsWindowVisible(h)) return true;
                    var len = GetWindowTextLength(h);
                    if (len <= 0) return true;
                    var sb = new StringBuilder(len + 1);
                    GetWindowText(h, sb, sb.Capacity);
                    _ = GetWindowThreadProcessId(h, out var pid);
                    var t = sb.ToString();
                    if (t.Length == 0) return true;
                    map[pid] = map.TryGetValue(pid, out var e) ? e + " | " + t : t;
                }
                catch { /* skip a window */ }
                return true;
            }, IntPtr.Zero);
        }
        catch { /* EnumWindows unavailable */ }
        return map;
    }

    private static string Clip(string? s, int max)
        => string.IsNullOrEmpty(s) ? "" : s.Length <= max ? s : s[..max] + "…";

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr p);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] private static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr h, StringBuilder sb, int max);
    [DllImport("user32.dll")] private static extern int GetWindowThreadProcessId(IntPtr h, out int pid);
}
