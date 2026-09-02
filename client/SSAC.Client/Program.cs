using System.Windows.Forms;

namespace SSAC.Client;

public static class AppInfo
{
    public const string Version = "0.3.1";
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

public sealed record Options(string Key, string Endpoint, string? Pin)
{
    public static Options? Parse(string[] args)
    {
        string? key = null, endpoint = null, pin = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--key" when i + 1 < args.Length: key = args[++i]; break;
                case "--endpoint" when i + 1 < args.Length: endpoint = args[++i]; break;
                case "--pin" when i + 1 < args.Length: pin = args[++i]; break;
                case "--help" or "-h" or "/?": return null;
                default:
                    if (!args[i].StartsWith('-') && key is null) key = args[i];
                    break;
            }
        }
        key ??= KeyFromOwnFilename();
        key ??= PromptForKey();
        if (string.IsNullOrWhiteSpace(key)) return null;
        return new Options(key.Trim(), (endpoint ?? AppInfo.DefaultEndpoint).TrimEnd('/'), pin);
    }

    /// <summary>
    /// The panel's download link names the file `ssac-screenshare-&lt;KEY&gt;.exe`, so a
    /// suspect can just double-click it. Pull the key back out of our own name.
    /// </summary>
    private static string? KeyFromOwnFilename()
    {
        try
        {
            var stem = Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "");
            var m = System.Text.RegularExpressions.Regex.Match(
                stem, @"^ssac[-_]screenshare[-_](?<k>[A-Za-z0-9_\-]{16,64})$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success ? m.Groups["k"].Value : null;
        }
        catch { return null; }
    }

    private static string? PromptForKey()
    {
        using var f = new Form
        {
            Text = "SSAC Screenshare Tool",
            ClientSize = new System.Drawing.Size(420, 130),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterScreen,
            MaximizeBox = false,
            MinimizeBox = false,
        };
        var lbl = new Label { Text = "Paste the key your staff member gave you:", Dock = DockStyle.Top, Height = 28, Padding = new Padding(10, 8, 10, 0) };
        var box = new TextBox { Dock = DockStyle.Top, Margin = new Padding(10) };
        var ok = new Button { Text = "Continue", Dock = DockStyle.Bottom, Height = 32, DialogResult = DialogResult.OK };
        f.Controls.Add(box);
        f.Controls.Add(lbl);
        f.Controls.Add(ok);
        f.AcceptButton = ok;
        return f.ShowDialog() == DialogResult.OK ? box.Text : null;
    }
}

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();

        if (args.Contains("--selftest"))
        {
            SelfTest.Run().GetAwaiter().GetResult();
            return;
        }

        var opts = Options.Parse(args);

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
            MessageBox.Show(
                "SSAC Screenshare Tool\n\nUsage: ssac-screenshare --key <KEY> [--endpoint <URL>] [--pin <SPKI>]\n\n" +
                "You normally just double-click and paste the key when asked.",
                "SSAC", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
            new PrefetchModule(), new BamModule(),
            new UserAssistModule(), new ShimCacheModule(), new RegistryArtifactsModule(),
            new RecycleBinModule(), new PowerShellHistoryModule(), new MinecraftModule(sigDb),
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
            new PrefetchModule(), new BamModule(), new UserAssistModule(), new ShimCacheModule(),
            new RegistryArtifactsModule(), new RecycleBinModule(), new PowerShellHistoryModule(),
            new MinecraftModule(sigDb), new UsnJournalModule(), new AmcacheModule(), new MftModule(),
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
            try { await m.RunAsync(ctx, ct); }
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
        SynchronizationContext.Current!.Post(async _ => await RunAsync(), null);
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
            MessageBox.Show($"Could not reach the panel or the key is invalid.\n\n{ex.Message}",
                "SSAC", MessageBoxButtons.OK, MessageBoxIcon.Error);
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

        // ---- consent (docs/phase-0-design.md §5) ----
        ConsentResult? consent = null;
        using (var cf = new ConsentForm(desc.ServerName, desc.CaseLabel, desc.SuspectLabel))
        {
            if (cf.ShowDialog() == DialogResult.OK) consent = cf.Result;
        }

        var consentPayload = new ConsentPayload
        {
            Accepted = consent?.Accepted ?? false,
            At = consent?.At ?? DateTimeOffset.UtcNow,
            BrowserHistoryOptIn = consent?.BrowserHistoryOptIn ?? false,
            ServerNameShown = desc.ServerName,
            CaseLabel = desc.CaseLabel,
        };
        var env = EnvironmentModule.Probe();

        // Load the signature DB now so its version is in the report from the start.
        var sigDb = SignatureDb.Newest(await SignatureFetch.TryGet(_opts.Endpoint, cts.Token));
        AppInfo.SignatureDbVersion = sigDb.Version;

        // Record the decision either way; a decline consumes the key and closes the report.
        try
        {
            await ingest.StartAsync(consentPayload, env, cts.Token);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not start the scan.\n\n{ex.Message}", "SSAC",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            ExitThread();
            return;
        }

        if (consent is null or { Accepted: false })
        {
            await ingest.CompleteAsync(Severity.Info.Wire(), new(), aborted: true, cts.Token);
            MessageBox.Show("You declined. Nothing further was scanned. The staff member has been notified.",
                "SSAC", MessageBoxButtons.OK, MessageBoxIcon.Information);
            ExitThread();
            return;
        }

        // ---- scan ----
        var progress = new ProgressForm(desc.ServerName);
        progress.Show();

        IScanModule[] modules =
        [
            new EnvironmentModule(),
            new ProcessListModule(),
            new GeneralCheatModule(),
            new PrefetchModule(),
            new BamModule(),
            new UserAssistModule(),
            new ShimCacheModule(),
            new RegistryArtifactsModule(),
            new RecycleBinModule(),
            new PowerShellHistoryModule(),
            new MinecraftModule(sigDb),
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
            var pct = (int)(5 + 92.0 * done / modules.Length);
            var status = kind switch
            {
                "module_start" => $"Step {Math.Min(done + 1, modules.Length)} of {modules.Length}: {module}",
                "module_done" => $"{Math.Min(done, modules.Length)} of {modules.Length} checks done",
                _ => message,
            };
            progress.Report(status, pct, $"{kind} {module}: {message}");
            await ingest.EventAsync(kind, module, message, pct, cts.Token);
        });

        var uploadedOk = true;
        await Task.Run(async () =>
        {
            var sent = 0;
            foreach (var m in modules)
            {
                try
                {
                    await m.RunAsync(ctx, cts.Token);
                }
                catch (Exception ex)
                {
                    ctx.Add(new Finding(m.Name, Severity.Info, $"Module '{m.Name}' failed to run",
                        ex.Message));
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

        progress.MarkDone();
        await Task.Delay(700);
        progress.Close();
        using (var sf = new SummaryForm(desc.ServerName, ctx.Verdict, ctx.Findings, uploadedOk))
        {
            sf.ShowDialog();
        }

        ExitThread();
    }
}
