using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace SSAC.Client;

/// <summary>
/// General (non-Minecraft) cheat indicators: cheat/injection tooling on disk or
/// having run, boot flags that weaken code-integrity, and kernel drivers of the
/// kind cheats load via BYOVD. Reads program-execution artifacts + top-level
/// file names in the usual download/temp locations only (docs/phase-0-design.md
/// §4.1) — never file contents in user folders.
/// </summary>
public sealed class GeneralCheatModule : IScanModule
{
    public string Name => "general-cheats";
    public bool RequiresElevation => false;

    private static readonly Regex[] NameRules =
    [
        new(@"\b(aimbot|triggerbot|wall ?hack|no ?recoil|spinbot|rage ?bot)\b", RegexOptions.IgnoreCase),
        new(@"(dll[- ]?inject|injector|xenos|extreme ?injector|reclass\.net)", RegexOptions.IgnoreCase),
        new(@"(cheat ?engine|hwid ?spoofer|perm ?spoofer|\bspoofer\b|unknowncheats)", RegexOptions.IgnoreCase),
        new(@"(fling ?trainer|wemod|cheat ?happens|[-_ ]trainer\.exe|[-_ ]unlocker\.exe)", RegexOptions.IgnoreCase),
        new(@"\besp\.(dll|exe)$", RegexOptions.IgnoreCase),
    ];
    private static readonly string[] ScanExts = [".exe", ".dll", ".sys", ".ahk"];
    private const int MaxFilesPerZone = 4000;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);

        ScanBootFlags(ctx);
        ScanDrivers(ctx, ct);
        ScanCheatEngineReg(ctx);
        var files = ScanDropZones(ctx, ct);

        await ctx.Log(Name, $"{files} candidate files scanned in download/temp zones");
        await ctx.ModuleDone(Name, 0);
    }

    // ---- boot integrity flags (test signing / no integrity checks / kernel debug) ----
    private static void ScanBootFlags(ScanContext ctx)
    {
        string outp;
        try
        {
            var psi = new ProcessStartInfo("bcdedit", "/enum {current}")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return;
            outp = p.StandardOutput.ReadToEnd();
            p.WaitForExit(4000);
        }
        catch { return; } // no bcdedit / not permitted

        var norm = Regex.Replace(outp, @"\s+", " ").ToLowerInvariant();
        void Flag(string needle, string title, string why, Severity sev)
        {
            if (norm.Contains(needle))
                ctx.Add(new Finding("general-cheats", sev, title, why, new { source = "bcdedit" }, SortKey: 3));
        }
        Flag("testsigning yes", "Windows test signing is ON",
            "The `testsigning` boot flag is enabled, which lets unsigned kernel drivers load. Common for kernel-level cheats.", Severity.High);
        Flag("nointegritychecks yes", "Kernel integrity checks are OFF",
            "The `nointegritychecks` boot flag is enabled — driver signature enforcement is disabled.", Severity.High);
        Flag("debug yes", "Kernel debugging is enabled",
            "The `debug` boot flag is enabled. Legitimate for driver developers, but also used to run/hide cheat drivers.", Severity.Medium);
    }

    // ---- kernel driver service entries: BYOVD names, or driver images in user/temp paths ----
    private static void ScanDrivers(ScanContext ctx, CancellationToken ct)
    {
        using var services = Forensics.Open(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services");
        if (services is null) return;

        foreach (var svcName in services.GetSubKeyNames())
        {
            ct.ThrowIfCancellationRequested();
            using var k = services.OpenSubKey(svcName);
            if (k is null) continue;
            if (k.GetValue("Type") is not int type || (type != 1 && type != 2)) continue; // kernel / file-system driver
            var image = (k.GetValue("ImagePath") as string ?? "").Trim('"');
            var basename = Forensics.FileName(image.Replace("\\SystemRoot", "").Replace("\\??\\", ""));
            var lb = basename.ToLowerInvariant();

            if (Forensics.VulnerableDrivers.Contains(lb))
            {
                ctx.NoteExecution(basename, image, "driver-service", null);
                ctx.Add(new Finding("general-cheats", Severity.High,
                    $"Known abusable kernel driver registered: {basename}",
                    "This driver is on the BYOVD (bring-your-own-vulnerable-driver) list frequently used by cheats to gain kernel access.",
                    new { service = svcName, image }, SortKey: 2));
                continue;
            }

            var li = image.ToLowerInvariant();
            if (li.Contains(@"\temp\") || li.Contains(@"\downloads\") || li.Contains(@"\desktop\")
                || li.Contains(@"\appdata\local\temp\") || li.Contains(@"\users\public\"))
            {
                ctx.NoteExecution(basename, image, "driver-service", null);
                ctx.Add(new Finding("general-cheats", Severity.Medium,
                    $"Kernel driver registered from a user/temp path: {basename}",
                    "A driver service points at a driver image in a temp / downloads / desktop folder. Some monitoring tools (CPU-Z, MSI Afterburner) do this legitimately; kernel cheats also do. Worth confirming what it is.",
                    new { service = svcName, image }, SortKey: 6));
            }
            else if (Forensics.LooksLikeCheat(lb))
            {
                ctx.Add(new Finding("general-cheats", Severity.Medium,
                    $"Driver service with suspicious name: {svcName}",
                    "A driver service name matches known cheat / injection tooling.",
                    new { service = svcName, image }, SortKey: 6));
            }
        }
    }

    private static void ScanCheatEngineReg(ScanContext ctx)
    {
        using var ce = Forensics.Open(RegistryHive.CurrentUser, @"Software\Cheat Engine");
        if (ce is not null)
            ctx.Add(new Finding("general-cheats", Severity.Medium, "Cheat Engine settings key present",
                "HKCU\\Software\\Cheat Engine exists — Cheat Engine has been run on this account.",
                new { key = @"HKCU\Software\Cheat Engine" }, SortKey: 8));
    }

    // ---- file names (NOT contents) in the usual drop zones ----
    private int ScanDropZones(ScanContext ctx, CancellationToken ct)
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] zones =
        [
            Path.Combine(home, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath(),
        ];

        var scanned = 0;
        var flagged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var zone in zones.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(zone)) continue;
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(zone, "*", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = 2,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System,
                });
            }
            catch { continue; }

            foreach (var f in files)
            {
                if (scanned++ > MaxFilesPerZone * zones.Length) break;
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (!ScanExts.Contains(ext)) continue;
                var nm = Path.GetFileName(f);

                var rule = NameRules.FirstOrDefault(r => r.IsMatch(nm)) is not null;
                var hint = Forensics.LooksLikeCheat(nm);
                if (!rule && !hint) continue;
                if (!flagged.Add(f)) continue;

                DateTimeOffset? mtime = null;
                try { mtime = File.GetLastWriteTime(f); } catch { }
                if (ext is ".exe" or ".dll") ctx.NoteExecution(nm, f, "drop-zone", null);

                var sev = ext == ".sys" ? Severity.High : (rule ? Severity.High : Severity.Medium);
                ctx.Add(new Finding("general-cheats", sev,
                    $"Cheat-tool file present: {nm}",
                    $"A {ext} file whose name matches known cheat / injection tooling is in {Shorten(Path.GetDirectoryName(f) ?? "")}.",
                    new { path = f, modified = mtime }, mtime, SortKey: rule ? 4 : 10));
            }
        }
        return scanned;
    }

    private static string Shorten(string p)
    {
        var parts = p.Split('\\');
        return parts.Length <= 3 ? p : "…\\" + string.Join('\\', parts[^2..]);
    }
}
