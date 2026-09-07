using System.Text;
using Microsoft.Win32;

namespace SSAC.Client;

/// <summary>Shared parsing helpers for the Phase 3 out-of-instance forensic collectors.</summary>
public static class Forensics
{
    /// <summary>Substrings that make an executed / deleted file worth flagging (T1, T5, T6, general cheats).</summary>
    public static readonly string[] CheatHints =
    [
        // known Minecraft client families (distinctive names only)
        "vape", "doomsday", "prestige", "entropy", "novoline", "liquidbounce",
        "wurstclient", "meteorclient", "nightware", "nursultan", "slinky",
        "horion", "fate client", "fateinjector", "zephyr",
        "zenith client", "zenithclient", "zenith macro", "zenith macros",
        "zenithmacro", "zenithmacros", "zenithware", "zenith ghost", "zenith.exe",
        // generic cheat / injection tooling
        "injector", "inject-helper", "dll-inject", "dllinject", "xenos", "guidedhacking",
        "extremeinjector", "processhacker", "reclass", "cheatengine", "cheat engine",
        "unknowncheats", "hwid spoofer", "hwidspoofer", "permspoofer", "spoofer",
        "aimbot", "triggerbot", "wallhack", "norecoil", "no-recoil", "bhop",
        "killaura", "aimassist", "autoclicker", "autoclick", "ghostclient",
        "x-ray", "xray-", "-xray", "esp-", "-esp.dll",
        // game trainers / unlockers (lower confidence — often single-player, but still cheat tooling)
        "wemod", "fling trainer", "flingtrainer", "cheathappens", "trainer.exe", "unlocker.exe",
    ];

    /// <summary>Legitimate software whose name would otherwise trip a hint (e.g. "cheat" in "EasyAntiCheat").</summary>
    private static readonly string[] Allowlist =
    [
        "easyanticheat", "anticheat", "battleye", "vanguard", "ricochet",
        "moonsworth", "com.moonsworth", "lunarclient", "faithful",
        "systeminformer", "system informer", // legit sysadmin fork of Process Hacker
    ];

    /// <summary>Domains that host Minecraft / game cheats — matched against browser download URLs.</summary>
    public static readonly string[] CheatDomains =
    [
        "vape.gg", "liquidbounce.net", "wurstclient.net", "meteorclient.com", "rusherhack.org",
        "impactclient.net", "prestigeclient.vip", "sigmaclient.info", "futureclient.net",
        "novoline.", "nightware.", "aristois.net", "doomsdayclient", "entropy.", "nursultan",
        "unknowncheats.me", "guidedhacking.com", "cheatengine.org", "wemod.com",
        "zenithmacros.", "zenithmacros.store", "zenith-macros.", "zenithclient.",
    ];

    public static bool IsCheatDownload(string urlOrPath)
    {
        var l = (urlOrPath ?? "").ToLowerInvariant();
        return CheatDomains.Any(d => l.Contains(d)) || LooksLikeCheat(l);
    }

    /// <summary>Kernel drivers commonly abused by cheats via BYOVD (bring-your-own-vulnerable-driver).</summary>
    public static readonly string[] VulnerableDrivers =
    [
        "rtcore64.sys", "gdrv.sys", "gdrv2.sys", "iqvw64e.sys", "winio64.sys", "winio.sys",
        "winring0x64.sys", "winring0.sys", "dbutil_2_3.sys", "dbutildrv2.sys", "capcom.sys",
        "asrdrv10.sys", "atillk64.sys", "nvoclock.sys", "phymemx64.sys", "physmem.sys",
        "kprocesshacker.sys", "procexp152.sys", "speedfan.sys", "hw64.sys",
    ];

    public static bool LooksLikeCheat(string s)
    {
        var l = s.ToLowerInvariant();
        if (Allowlist.Any(a => l.Contains(a))) return false;
        return CheatHints.Any(h => l.Contains(h));
    }

    public static Severity CheatSeverity(string s) => LooksLikeCheat(s) ? Severity.High : Severity.Info;

    // ---- time ----
    public static DateTimeOffset? FromFileTimeUtc(long filetime)
    {
        if (filetime <= 0) return null;
        try { return DateTimeOffset.FromFileTime(filetime); }
        catch { return null; }
    }

    public static DateTimeOffset? FromFileTimeLe(ReadOnlySpan<byte> b)
        => b.Length < 8 ? null : FromFileTimeUtc(BitConverter.ToInt64(b));

    // ---- ROT13 (UserAssist value names) ----
    public static string Rot13(string s)
    {
        var a = s.ToCharArray();
        for (var i = 0; i < a.Length; i++)
        {
            var c = a[i];
            if (c is >= 'a' and <= 'z') a[i] = (char)('a' + (c - 'a' + 13) % 26);
            else if (c is >= 'A' and <= 'Z') a[i] = (char)('A' + (c - 'A' + 13) % 26);
        }
        return new string(a);
    }

    // ---- paths ----
    /// <summary>\Device\HarddiskVolume2\x -> C:\x  (best effort; falls back to the input).</summary>
    public static string NormalizeNtPath(string p)
    {
        if (string.IsNullOrEmpty(p)) return p;
        var m = System.Text.RegularExpressions.Regex.Match(p, @"^\\Device\\HarddiskVolume\d+\\(.*)$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (m.Success) return "C:\\" + m.Groups[1].Value; // volume->letter mapping is Phase 3b
        if (p.StartsWith(@"\??\")) return p[4..];
        if (p.StartsWith(@"\\?\")) return p[4..];
        return p;
    }

    public static string FileName(string path)
    {
        try { return Path.GetFileName(path.Replace('/', '\\')); }
        catch { return path; }
    }

    // ---- registry ----
    public static RegistryKey? Open(RegistryHive hive, string subKey, RegistryView view = RegistryView.Registry64)
    {
        try
        {
            using var b = RegistryKey.OpenBaseKey(hive, view);
            return b.OpenSubKey(subKey);
        }
        catch { return null; }
    }

    public static IEnumerable<(string Name, object? Value)> Values(RegistryKey? k)
    {
        if (k is null) yield break;
        string[] names;
        try { names = k.GetValueNames(); }
        catch { yield break; }
        foreach (var n in names)
        {
            object? v = null;
            try { v = k.GetValue(n); }
            catch { /* skip unreadable */ }
            yield return (n, v);
        }
    }

    public static string CurrentUserSid()
    {
        try { return System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? ""; }
        catch { return ""; }
    }

    // ---- utf-16 span reader ----
    public static string Utf16(ReadOnlySpan<byte> b)
    {
        var s = Encoding.Unicode.GetString(b);
        var nul = s.IndexOf('\0');
        return nul >= 0 ? s[..nul] : s;
    }
}
