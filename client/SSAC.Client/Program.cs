using System.Windows.Forms;

namespace SSAC.Client;

public static class AppInfo
{
    public const string Version = "0.3.0";
    /// <summary>Set at scan start from the loaded SignatureDb; recorded in the report.</summary>
    public static string SignatureDbVersion { get; set; } = "embedded";
    // The product ships with the SaaS ingest base URL baked in; overridable for
    // local dev with --endpoint http://localhost:54321/functions/v1
    public const string DefaultEndpoint = "https://REPLACE-ME.functions.supabase.co";
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
        key ??= PromptForKey();
        if (string.IsNullOrWhiteSpace(key)) return null;
        return new Options(key.Trim(), (endpoint ?? AppInfo.DefaultEndpoint).TrimEnd('/'), pin);
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
            progress.Report(message, pct, $"{kind} {module}: {message}");
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

        progress.Close();
        using (var sf = new SummaryForm(desc.ServerName, ctx.Verdict, ctx.Findings, uploadedOk))
        {
            sf.ShowDialog();
        }

        ExitThread();
    }
}
