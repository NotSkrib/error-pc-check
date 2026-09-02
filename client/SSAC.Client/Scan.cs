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

/// <summary>Accumulates findings and forwards progress to a sink (the ingest client + UI).</summary>
public sealed class ScanContext(Func<string, string?, string, int?, Task> progress)
{
    private readonly List<Finding> _findings = [];
    public IReadOnlyList<Finding> Findings => _findings;

    public void Add(Finding f) => _findings.Add(f);

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
        Elevated = IsElevated(),
    };

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

/// <summary>Phase 2 milestone: emits one finding so the end-to-end pipeline is visible in the panel.</summary>
public sealed class PipelineCheckModule : IScanModule
{
    public string Name => "pipeline-check";
    public bool RequiresElevation => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 70);
        ctx.Add(new Finding(Name, Severity.Info, "Client reached the panel",
            "This confirms the client agent uploaded to the panel over a signed channel. Replaced by real detection modules in Phase 3+.",
            new { AppInfo.Version, at = DateTimeOffset.UtcNow }, SortKey: 100));
        await ctx.ModuleDone(Name, 80);
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
    /// <summary>Phase 2 stub: hash our own image and log it. Phase 7 compares to a signed manifest.</summary>
    public static bool Verify()
    {
        try
        {
            var path = Environment.ProcessPath;
            if (path is null || !File.Exists(path)) return false;
            using var fs = File.OpenRead(path);
            _ = Convert.ToHexString(SHA256.HashData(fs));
            return true;
        }
        catch { return false; }
    }
}
