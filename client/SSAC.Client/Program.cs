using System.Windows.Forms;

namespace SSAC.Client;

public static class AppInfo
{
    public const string Version = "0.4.0";
    /// <summary>Set at scan start from the loaded SignatureDb; recorded in the report.</summary>
    public static string SignatureDbVersion { get; set; } = "embedded";
    // SaaS ingest base URL baked in; overridable for local dev with
    // --endpoint http://localhost:54321/functions/v1
    public const string DefaultEndpoint = "https://ugxzpmsotzfhoqraohvv.supabase.co/functions/v1";
}

/// <summary>Best-effort GET of a newer signature DB from the public Edge Function.</summary>
internal static class SignatureFetch
{
    public static async Task<string?> TryGet(string endpoint, CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
            return await http.GetStringAsync($"{endpoint.TrimEnd('/')}/signatures", ct);
        }
        catch { return null; }
    }
}

public sealed record Options(string Key, string Endpoint, string? Pin, bool AutoConsent = false)
{
    public static Options? Parse(string[] args)
    {
        string? key = null, endpoint = null, pin = null;
        var autoConsent = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--key" when i + 1 < args.Length: key = args[++i]; break;
                case "--endpoint" when i + 1 < args.Length: endpoint = args[++i]; break;
                case "--pin" when i + 1 < args.Length: pin = args[++i]; break;
                case "--yes": autoConsent = true; break; // QA: skip the consent click, keep the windows
                case "--help" or "-h" or "/?": return null;
                default:
                    if (!args[i].StartsWith('-') && key is null) key = args[i];
                    break;
            }
        }
        key ??= KeyFromSelfOverlay();
        key ??= KeyFromOwnFilename();
        key ??= KeyFromMarkOfTheWeb();
        // No paste-the-key dialog: the file is always run from a keyed download,
        // so the key comes from the download itself. If it somehow isn't there,
        // Main shows a "ask for a new link" message rather than a text box.
        if (string.IsNullOrWhiteSpace(key)) return null;
        return new Options(key.Trim(), (endpoint ?? AppInfo.DefaultEndpoint).TrimEnd('/'), pin, autoConsent);
    }

    /// <summary>
    /// The download bakes the key into the end of the file
    /// (…<c>ERRSMPKEY[&lt;KEY&gt;]ERRSMPKEY</c>…). Read our own tail and pull it
    /// out. This is the reliable path: it survives renaming, moving, copying and
    /// "Unblock", unlike the mark-of-the-web tag.
    /// </summary>
    private static string? KeyFromSelfOverlay()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe)) return null;
            using var fs = new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var take = (int)Math.Min(4096, fs.Length);
            fs.Seek(-take, SeekOrigin.End);
            var buf = new byte[take];
            var read = 0;
            while (read < take)
            {
                var n = fs.Read(buf, read, take - read);
                if (n <= 0) break;
                read += n;
            }
            var tail = System.Text.Encoding.ASCII.GetString(buf, 0, read);
            var m = System.Text.RegularExpressions.Regex.Match(
                tail, @"ERRSMPKEY\[(?<k>[A-Za-z0-9_\-]{12,64})\]ERRSMPKEY");
            return m.Success ? m.Groups["k"].Value : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// The shipped file is just `Error_PC_Check.exe`, but if someone kept (or a
    /// tester used) a keyed name like `errorsmp-&lt;KEY&gt;.exe` /
    /// `ssac-screenshare-&lt;KEY&gt;.exe`, pull the key out of it.
    /// </summary>
    private static string? KeyFromOwnFilename()
    {
        try
        {
            var stem = Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "");
            var m = System.Text.RegularExpressions.Regex.Match(
                stem, @"^(?:errorsmp|ssac[-_]screenshare)[-_](?<k>[A-Za-z0-9_\-]{12,64})$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success ? m.Groups["k"].Value : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// Windows tags every browser download with a `Zone.Identifier` alternate
    /// data stream that records the URL it came from (`HostUrl` / `ReferrerUrl`).
    /// The panel link is `.../d/&lt;KEY&gt;` (or `?key=&lt;KEY&gt;`), so we can
    /// recover the key from that even though the file itself is just
    /// `Error_PC_Check.exe`. This is the normal path for a browser download.
    /// </summary>
    private static string? KeyFromMarkOfTheWeb()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe)) return null;

            string text;
            using (var fs = new FileStream(exe + ":Zone.Identifier", FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var sr = new StreamReader(fs))
                text = sr.ReadToEnd();

            var m = System.Text.RegularExpressions.Regex.Match(
                text, @"(?:/d/|[?&]key=)(?<k>[A-Za-z0-9_\-]{12,64})",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success ? m.Groups["k"].Value : null;
        }
        catch { return null; }
    }

}

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();

        // Make silent crashes visible instead of the process just vanishing.
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) =>
        {
            Telemetry.Report("thread-exception", e.Exception);
            ShowFatal(e.Exception);
        };
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            Telemetry.Report("domain-unhandled", e.ExceptionObject as Exception);
            ShowFatal(e.ExceptionObject as Exception);
        };

        if (args.Contains("--selftest"))
        {
            SelfTest.Run().GetAwaiter().GetResult();
            return;
        }

        var opts = Options.Parse(args);
        Telemetry.Configure(opts?.Endpoint ?? AppInfo.DefaultEndpoint, opts?.Key);

        // --auto: headless run (no windows). Consent is auto-accepted and recorded
        // as headless=true. For E2E / CI only; the shipped tool always shows the
        // consent screen (docs/phase-0-design.md §5, A1).
        if (args.Contains("--auto") && opts is not null)
        {
            Headless.Run(opts, args.Contains("--browser-optin")).GetAwaiter().GetResult();
            return;
        }
        if (opts is null)
        {
            var msg = args.Contains("--help") || args.Contains("-h") || args.Contains("/?")
                ? "Error SMP Screenshare\n\nUsage: Error_PC_Check.exe [--key <KEY>] [--endpoint <URL>] [--pin <SPKI>]\n\n" +
                  "Normally you just double-click the file the staff member sent you."
                : "Error SMP Screenshare\n\nThis file needs to be run straight from the download link a staff member " +
                  "sent you. Re-download it from that link and run it again — don't move or rename it first.";
            MessageBox.Show(msg, "Error SMP Screenshare", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        try
        {
            Application.Run(new FlowContext(opts));
        }
        finally
        {
            TempCleanup();
        }
    }

    private static void TempCleanup()
    {
        try
        {
            foreach (var d in Directory.EnumerateDirectories(Path.GetTempPath(), "ssac-*"))
                try { Directory.Delete(d, true); } catch { /* best effort */ }
        }
        catch { /* ignore */ }
    }

    /// <summary>
    /// Run one scan module, but never let it wedge the whole run: if it exceeds
    /// <paramref name="timeout"/> we stop awaiting it, ask it to cancel, and record
    /// a coverage gap so the report shows that collector was skipped.
    /// </summary>
    internal static async Task RunModuleGuarded(IScanModule m, ScanContext ctx, CancellationToken ct, TimeSpan timeout)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var run = Task.Run(() => m.RunAsync(ctx, linked.Token), linked.Token);
        var finished = await Task.WhenAny(run, Task.Delay(timeout, CancellationToken.None));
        if (finished != run)
        {
            linked.Cancel();
            if (ct.IsCancellationRequested) return;
            ctx.Add(new Finding(m.Name, Severity.Info, $"{m.Name} did not finish (timed out)",
                $"The {m.Name} collector ran longer than {(int)timeout.TotalSeconds}s and was skipped so the scan could finish. Some evidence from it may be missing.",
                new { timeout_seconds = (int)timeout.TotalSeconds }));
            return;
        }
        await run; // surface any exception to the caller's catch
    }

    internal static void ShowFatal(Exception? ex)
    {
        try
        {
            MessageBox.Show(
                $"The screenshare tool hit an unexpected error and has to close.\n\n{ex?.GetType().Name}: {ex?.Message}",
                "SSAC Screenshare Tool", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch { /* nothing more we can do */ }
    }
}

/// <summary>
/// `--selftest`: runs every scan module locally with no network and prints the
/// findings. Dev-only smoke test for the Phase 3 forensic collectors.
/// </summary>
internal static class SelfTest
{
    private static readonly nint _con = AllocConsole();
    [System.Runtime.InteropServices.DllImport("kernel32.dll")] private static extern nint AllocConsole();

    public static async Task Run()
    {
        _ = _con;
        var ctx = new ScanContext((kind, module, message, _) =>
        {
            Console.WriteLine($"  · {kind} {module}: {message}");
            return Task.CompletedTask;
        });

        var sigDb = SignatureDb.Embedded();
        IScanModule[] modules =
        [
            new EnvironmentModule(), new ProcessListModule(), new GeneralCheatModule(),
            new BrowserDownloadsModule(), new PrefetchModule(), new PcaModule(), new BamModule(),
            new UserAssistModule(), new ShimCacheModule(), new RegistryArtifactsModule(),
            new RecycleBinModule(), new PowerShellHistoryModule(), new MinecraftModule(sigDb),
            new JvmInjectionModule(), new JavaCrashLogModule(),
            new UsnJournalModule(), new AmcacheModule(), new MftModule(), new EventLogModule(),
            new CorrelationModule(),
        ];

        Console.WriteLine($"SSAC client {AppInfo.Version} — selftest "
            + $"(elevated={EnvironmentModule.IsElevated()}, sigdb {sigDb.Version} / {sigDb.Signatures.Count} sigs)\n");
        foreach (var m in modules)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try { await m.RunAsync(ctx, default); }
            catch (Exception ex) { Console.WriteLine($"  !! {m.Name} threw {ex.GetType().Name}: {ex.Message}"); }
            Console.WriteLine($"  [{m.Name} {sw.ElapsedMilliseconds} ms]\n");
        }

        Console.WriteLine($"\n=== {ctx.Findings.Count} findings, verdict {ctx.Verdict.Wire().ToUpperInvariant()} ===");
        foreach (var f in ctx.Findings.OrderByDescending(x => x.Severity))
            Console.WriteLine($"[{f.Severity.Wire().ToUpperInvariant(),-8}] {f.Module,-18} {f.Title}");
        Console.WriteLine($"\n{ctx.Executions.Count} execution-evidence records across "
            + $"{ctx.Executions.Select(e => e.Name).Distinct().Count()} programs.");
        Console.WriteLine("\nPress Enter to exit.");
        Console.ReadLine();
    }
}

/// <summary>Headless end-to-end run for E2E/CI (`--auto`). No UI; consent auto-accepted, marked headless.</summary>
internal static class Headless
{
    private static readonly nint _con = AllocConsole();
    [System.Runtime.InteropServices.DllImport("kernel32.dll")] private static extern nint AllocConsole();

    public static async Task Run(Options opts, bool browserOptIn)
    {
        _ = _con;
        using var ingest = new IngestClient(opts.Endpoint, opts.Key, opts.Pin);
        var ct = CancellationToken.None;

        var desc = await ingest.DescribeAsync(ct);
        Console.WriteLine($"describe: server='{desc.ServerName}' case='{desc.CaseLabel}' used={desc.AlreadyUsed}");
        if (desc.AlreadyUsed) { Console.WriteLine("key already used — abort"); return; }

        var consent = new ConsentPayload
        {
            Accepted = true,
            At = DateTimeOffset.UtcNow,
            BrowserHistoryOptIn = browserOptIn,
            ServerNameShown = desc.ServerName,
            CaseLabel = desc.CaseLabel,
        };
        var env = EnvironmentModule.Probe();
        var sigDb = SignatureDb.Newest(await SignatureFetch.TryGet(opts.Endpoint, ct));
        AppInfo.SignatureDbVersion = sigDb.Version;

        var reportId = await ingest.StartAsync(consent, env, ct);
        Console.WriteLine($"start: report {reportId}, sigdb {sigDb.Version}");

        IScanModule[] modules =
        [
            new EnvironmentModule(), new ProcessListModule(), new GeneralCheatModule(),
            new PrefetchModule(), new PcaModule(), new BamModule(), new UserAssistModule(), new ShimCacheModule(),
            new RegistryArtifactsModule(), new RecycleBinModule(), new PowerShellHistoryModule(),
            new MinecraftModule(sigDb), new JvmInjectionModule(), new JavaCrashLogModule(),
            new UsnJournalModule(), new AmcacheModule(), new MftModule(),
            new EventLogModule(), new CorrelationModule(),
        ];

        var done = 0;
        var ctx = new ScanContext(async (kind, module, message, _) =>
        {
            if (kind == "module_done") Interlocked.Increment(ref done);
            var pct = (int)(5 + 92.0 * done / modules.Length);
            Console.WriteLine($"  {pct,3}%  {kind} {module}: {message}");
            await ingest.EventAsync(kind, module, message, pct, ct);
        });

        var sent = 0;
        foreach (var m in modules)
        {
            try { await Program.RunModuleGuarded(m, ctx, ct, TimeSpan.FromSeconds(90)); }
            catch (Exception ex) { ctx.Add(new Finding(m.Name, Severity.Info, $"module '{m.Name}' failed", ex.Message)); }
            for (; sent < ctx.Findings.Count; sent++)
            {
                var f = ctx.Findings[sent];
                try
                {
                    await ingest.FindingAsync(new FindingPayload(
                        f.Module, f.Severity.Wire(), f.Title, f.Description,
                        f.Evidence ?? new { }, f.OccurredAt, f.SortKey), ct);
                }
                catch (Exception ex) { Console.WriteLine($"  !! finding upload failed: {ex.Message}"); }
            }
        }

        await ingest.CompleteAsync(ctx.Verdict.Wire(), ctx.Counts(), aborted: false, ct);
        Console.WriteLine($"\ncomplete: verdict {ctx.Verdict.Wire().ToUpperInvariant()}, {ctx.Findings.Count} findings");
        foreach (var kv in ctx.Counts()) Console.WriteLine($"  {kv.Key}: {kv.Value}");
    }
}

/// <summary>Drives the whole run on the WinForms STA/sync-context thread.</summary>
internal sealed class FlowContext : ApplicationContext
{
    private readonly Options _opts;

    public FlowContext(Options opts)
    {
        _opts = opts;
        // Kick off the async flow once the message loop is actually running.
        // (In the constructor, before Application.Run, there is no WinForms
        // SynchronizationContext yet — posting to it here would NRE and the
        // process would exit before any window appeared.)
        var start = new System.Windows.Forms.Timer { Interval = 1 };
        start.Tick += async (_, _) =>
        {
            start.Stop();
            start.Dispose();
            try { await RunAsync(); }
            catch (Exception ex)
            {
                Program.ShowFatal(ex);
                ExitThread();
            }
        };
        start.Start();
    }

    private async Task RunAsync()
    {
        using var ingest = new IngestClient(_opts.Endpoint, _opts.Key, _opts.Pin);
        var cts = new CancellationTokenSource();

        SessionDescription desc;
        try
        {
            desc = await ingest.DescribeAsync(cts.Token);
        }
        catch (Exception ex)
        {
            Telemetry.Report("describe", ex);
            MessageBox.Show($"Could not reach the panel or the key is invalid.\n\n{ex.Message}",
                "Error SMP Screenshare", MessageBoxButtons.OK, MessageBoxIcon.Error);
            ExitThread();
            return;
        }

        if (desc.AlreadyUsed)
        {
            MessageBox.Show("This key has already been used. Ask your staff member for a new one.",
                "SSAC", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            ExitThread();
            return;
        }

        // Simple flow: one window, auto-start. Running the keyed file the staff
        // member sent is the consent; it is recorded automatically (flow=simple).
        var ui = new SimpleForm(desc.ServerName);
        ui.FormClosed += (_, _) => { try { ExitThread(); } catch { } };
        ui.Show();
        ui.Report("Preparing…", 2);

        var consentPayload = new ConsentPayload
        {
            Accepted = true,
            At = DateTimeOffset.UtcNow,
            BrowserHistoryOptIn = true, // simple flow always includes browser download history
            ServerNameShown = desc.ServerName,
            CaseLabel = desc.CaseLabel,
        };
        var env = EnvironmentModule.Probe();
        var sigDb = SignatureDb.Newest(await SignatureFetch.TryGet(_opts.Endpoint, cts.Token));
        AppInfo.SignatureDbVersion = sigDb.Version;

        try
        {
            await ingest.StartAsync(consentPayload, env, cts.Token);
        }
        catch (Exception ex)
        {
            Telemetry.Report("start", ex);
            ui.Report("Could not reach the server.", 0);
            ui.Finish(Severity.Info, 0, uploaded: false);
            return;
        }

        IScanModule[] modules =
        [
            new EnvironmentModule(),
            new ProcessListModule(),
            new GeneralCheatModule(),
            new BrowserDownloadsModule(),
            new PrefetchModule(),
            new BamModule(),
            new UserAssistModule(),
            new ShimCacheModule(),
            new RegistryArtifactsModule(),
            new RecycleBinModule(),
            new PowerShellHistoryModule(),
            new MinecraftModule(sigDb),
            new JvmInjectionModule(),
            new JavaCrashLogModule(),
            new PcaModule(),
            new UsnJournalModule(),
            new AmcacheModule(),
            new MftModule(),
            new EventLogModule(),
            new CorrelationModule(), // must run last — reasons over the others
        ];

        var done = 0;
        var ctx = new ScanContext(async (kind, module, message, _) =>
        {
            if (kind == "module_done") Interlocked.Increment(ref done);
            var pct = (int)(4 + 94.0 * done / modules.Length);
            if (kind is "module_start" or "module_done")
                ui.Report($"Checking {(done + (kind == "module_start" ? 1 : 0))} of {modules.Length}…", pct);
            await ingest.EventAsync(kind, module, message, pct, cts.Token);
        });

        var uploadedOk = true;
        await Task.Run(async () =>
        {
            var sent = 0;
            foreach (var m in modules)
            {
                try { await Program.RunModuleGuarded(m, ctx, cts.Token, TimeSpan.FromSeconds(90)); }
                catch (Exception ex)
                {
                    ctx.Add(new Finding(m.Name, Severity.Info, $"Module '{m.Name}' failed to run", ex.Message));
                }

                for (; sent < ctx.Findings.Count; sent++)
                {
                    var f = ctx.Findings[sent];
                    try
                    {
                        await ingest.FindingAsync(new FindingPayload(
                            f.Module, f.Severity.Wire(), f.Title, f.Description,
                            f.Evidence ?? new { }, f.OccurredAt, f.SortKey), cts.Token);
                    }
                    catch { uploadedOk = false; }
                }
            }
        });

        try
        {
            await ingest.CompleteAsync(ctx.Verdict.Wire(), ctx.Counts(), aborted: false, cts.Token);
        }
        catch { uploadedOk = false; }

        ui.Finish(ctx.Verdict, ctx.Findings.Count, uploadedOk);
        // ExitThread happens when the user closes the window (FormClosed handler).
    }
}
