using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;

namespace SSAC.Client;

public enum Severity { Clean, Info, Low, Medium, High, Critical }

public static class SeverityX
{
    public static string Wire(this Severity s) => s.ToString().ToLowerInvariant();
    public static Severity Worst(IEnumerable<Severity> xs)
    {
        var w = Severity.Clean;
        foreach (var s in xs) if (s > w) w = s;
        return w;
    }
}

public sealed record Finding(
    string Module, Severity Severity, string Title, string Description,
    object? Evidence = null, DateTimeOffset? OccurredAt = null, int SortKey = 0);

/// <summary>One "this program ran" data point from a forensic artifact.</summary>
public sealed record ExecEvidence(string Name, string? Path, string Source, DateTimeOffset? When);

/// <summary>Accumulates findings and forwards progress to a sink (the ingest client + UI).</summary>
public sealed class ScanContext(Func<string, string?, string, int?, Task> progress)
{
    private readonly List<Finding> _findings = [];
    public IReadOnlyList<Finding> Findings => _findings;

    // Locked: a module abandoned by the per-module timeout may still be running
    // on a threadpool thread when the main loop moves on.
    public void Add(Finding f) { lock (_findings) _findings.Add(f); }

    // Shared execution-evidence bag: collectors add entries, CorrelationModule reasons over them.
    private readonly List<ExecEvidence> _exec = [];
    public IReadOnlyList<ExecEvidence> Executions => _exec;
    public void NoteExecution(string name, string? path, string source, DateTimeOffset? when)
        => _exec.Add(new ExecEvidence(name.Trim().ToLowerInvariant(), path, source, when));

    /// <summary>Cross-module hints, e.g. "prefetch:empty", "usn:deleted-pf". Read by CorrelationModule.</summary>
    public HashSet<string> Signals { get; } = [];

    public Task ModuleStart(string module, int pct) => progress("module_start", module, $"scanning {module}", pct);
    public Task ModuleDone(string module, int pct) => progress("module_done", module, $"{module} done", pct);
    public Task Log(string module, string message) => progress("log", module, message, null);

    public Severity Verdict => SeverityX.Worst(_findings.Select(f => f.Severity).DefaultIfEmpty(Severity.Info));

    public Dictionary<string, int> Counts()
    {
        var d = new Dictionary<string, int>();
        foreach (var f in _findings)
        {
            var k = f.Severity.Wire();
            d[k] = d.GetValueOrDefault(k) + 1;
        }
        return d;
    }
}

public interface IScanModule
{
    string Name { get; }
    /// <summary>True if this module needs admin and does not have it — still runs, emits module_unavailable.</summary>
    bool RequiresElevation { get; }
    Task RunAsync(ScanContext ctx, CancellationToken ct);
}

// ---------------------------------------------------------------------------
// MVP modules. Phase 3/4 add the real forensic collectors (Prefetch, USN,
// $MFT, .minecraft, signature DB, correlation). These three prove the pipeline
// and are all inside the docs/phase-0-design.md §4.1 "always" allowlist.
// ---------------------------------------------------------------------------

public sealed class EnvironmentModule : IScanModule
{
    public string Name => "environment";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 10);
        var env = Probe();

        if (env.DebuggerPresent)
            ctx.Add(new Finding(Name, Severity.Medium, "Debugger attached to the scan tool",
                "A debugger is attached to this client. Results from this run may have been tampered with.",
                new { env.DebuggerPresent }));

        if (env.IsVm)
            ctx.Add(new Finding(Name, Severity.Info, "Running inside a virtual machine",
                "This PC appears to be a virtual machine. A staff member should confirm this is the machine used to play.",
                new { env.IsVm }));

        var uptimeMin = env.UptimeSeconds / 60;
        if (uptimeMin < 5)
            ctx.Add(new Finding(Name, Severity.Low, "System was rebooted moments ago",
                $"Windows has only been running for {uptimeMin} minute(s). A reboot immediately before a screenshare can clear volatile evidence.",
                new { env.UptimeSeconds }));

        await ctx.Log(Name, $"Windows {env.OsBuild}, up {uptimeMin} min, vm={env.IsVm}, elevated={env.Elevated}");
        await ctx.ModuleDone(Name, 20);
    }

    public static EnvironmentPayload Probe() => new()
    {
        OsBuild = Environment.OSVersion.VersionString,
        UptimeSeconds = (long)(Environment.TickCount64 / 1000),
        IsVm = LooksLikeVm(),
        DebuggerPresent = Debugger.IsAttached || NativeDebuggerPresent(),
        ClientHashOk = SelfIntegrity.Verify(),
        ClientSha256 = SelfIntegrity.Sha256() ?? "",
        ParentProcess = ParentProcessName(),
        Elevated = IsElevated(),
    };

    /// <summary>Name of the process that launched us — "explorer" for a double-click,
    /// a shell / launcher name otherwise. Recorded so staff can see how it was started.</summary>
    private static string ParentProcessName()
    {
        try
        {
            using var s = new System.Management.ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {Environment.ProcessId}");
            foreach (var o in s.Get())
            {
                var ppid = Convert.ToInt32(o["ParentProcessId"]);
                try { return Process.GetProcessById(ppid).ProcessName; }
                catch { return ppid.ToString(); }
            }
        }
        catch { /* WMI unavailable */ }
        return "";
    }

    public static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static bool LooksLikeVm()
    {
        try
        {
            using var s = new System.Management.ManagementObjectSearcher(
                "SELECT Manufacturer, Model FROM Win32_ComputerSystem");
            foreach (var o in s.Get())
            {
                var m = ($"{o["Manufacturer"]} {o["Model"]}").ToLowerInvariant();
                if (m.Contains("vmware") || m.Contains("virtualbox") || m.Contains("kvm") ||
                    m.Contains("qemu") || m.Contains("hyper-v") || m.Contains("virtual machine"))
                    return true;
            }
        }
        catch { /* WMI unavailable — treat as unknown */ }
        return false;
    }

    [DllImport("kernel32.dll")] private static extern bool IsDebuggerPresent();
    private static bool NativeDebuggerPresent()
    {
        try { return IsDebuggerPresent(); } catch { return false; }
    }
}

public sealed class ProcessListModule : IScanModule
{
    public string Name => "processes";
    public bool RequiresElevation => false;

    // Known external autoclicker / macro binaries (docs/phase-0-design.md T6).
    private static readonly string[] AutoClickerNames =
        ["opautoclicker", "autoclicker", "gsautoclicker", "opautoclick", "mouseclicker",
         "autohotkey", "xmouse"];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 30);
        int total = 0, unsigned = 0;

        foreach (var p in Process.GetProcesses())
        {
            ct.ThrowIfCancellationRequested();
            total++;
            string name, path = "";
            try
            {
                name = p.ProcessName;
                path = p.MainModule?.FileName ?? "";
            }
            catch { continue; }

            var lname = name.ToLowerInvariant();
            if (AutoClickerNames.Any(a => lname.Contains(a)))
                ctx.Add(new Finding(Name, Severity.Medium, $"Possible autoclicker running: {name}",
                    "A process whose name matches known autoclicker / macro software is running.",
                    new { name, path, pid = p.Id }, SortKey: 5));

            // Any running process whose name / path matches known cheat tooling
            // (e.g. an external macro like Zenith Macros running alongside the game).
            if (Forensics.LooksLikeCheat(lname) || (path.Length > 0 && Forensics.LooksLikeCheat(path)))
            {
                ctx.NoteExecution(name, path, "live-process", DateTimeOffset.Now);
                ctx.Add(new Finding(Name, Severity.High, $"Cheat-named program running: {name}",
                    "A process whose name matches known cheat / macro tooling is running right now.",
                    new { name, path, pid = p.Id }, SortKey: 1));
            }

            if (!string.IsNullOrEmpty(path) && !Authenticode.IsSigned(path))
            {
                unsigned++;
                if (lname is "javaw" or "java")
                    ctx.Add(new Finding(Name, Severity.Low, "Unsigned Java runtime",
                        "The running Java process has no valid digital signature. Common for some launchers, but worth noting.",
                        new { name, path }, SortKey: 3));
            }
        }

        await ctx.Log(Name, $"{total} processes, {unsigned} unsigned");
        await ctx.ModuleDone(Name, 60);
    }
}

public static class Authenticode
{
    public static bool IsSigned(string path)
    {
        try
        {
            using var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
            return cert is not null;
        }
        catch { return false; }
    }
}

public static class SelfIntegrity
{
    /// <summary>
    /// SHA-256 of our own on-disk image, lowercase hex, excluding the per-download
    /// key overlay the download function appends (…\nERRSMPKEY[KEY]ERRSMPKEY\n) so
    /// the value is the same for every download of a build. Sent with the report
    /// so staff can confirm it matches the published build. null if unreadable.
    /// </summary>
    public static string? Sha256()
    {
        try
        {
            var path = Environment.ProcessPath;
            if (path is null || !File.Exists(path)) return null;
            using var fs = File.OpenRead(path);

            long hashLen = fs.Length;
            var probe = (int)Math.Min(8192, fs.Length);
            if (probe > 0)
            {
                fs.Seek(-probe, SeekOrigin.End);
                var tail = new byte[probe];
                var got = 0;
                int n;
                while (got < probe && (n = fs.Read(tail, got, probe - got)) > 0) got += n;
                var marker = System.Text.Encoding.ASCII.GetBytes("\nERRSMPKEY[");
                for (var i = got - marker.Length; i >= 0; i--)
                {
                    var hit = true;
                    for (var j = 0; j < marker.Length; j++)
                        if (tail[i + j] != marker[j]) { hit = false; break; }
                    if (hit) { hashLen = fs.Length - (got - i); break; }
                }
            }

            fs.Seek(0, SeekOrigin.Begin);
            using var sha = SHA256.Create();
            var buf = new byte[81920];
            var left = hashLen;
            while (left > 0)
            {
                var r = fs.Read(buf, 0, (int)Math.Min(buf.Length, left));
                if (r <= 0) break;
                sha.TransformBlock(buf, 0, r, null, 0);
                left -= r;
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
        }
        catch { return null; }
    }

    public static bool Verify() => Sha256() is not null;
}
