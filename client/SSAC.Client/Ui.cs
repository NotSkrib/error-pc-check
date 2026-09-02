using System.Drawing;
using System.Windows.Forms;

namespace SSAC.Client;

/// <summary>
/// Consent screen — docs/phase-0-design.md §5. Branding is deliberately loud so the
/// tool cannot be passed off as something benign (A1). Returns null on cancel.
/// </summary>
public sealed class ConsentForm : Form
{
    private readonly CheckBox _browserOptIn;
    public ConsentResult? Result { get; private set; }

    public ConsentForm(string serverName, string caseLabel, string? suspectLabel)
    {
        Text = $"SSAC Screenshare Tool — {serverName}";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(560, 520);
        BackColor = Color.FromArgb(14, 17, 22);
        ForeColor = Color.Gainsboro;
        Font = new Font("Segoe UI", 9.5f);

        var head = new Label
        {
            Text = $"SSAC Screenshare Tool\n{serverName}",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = Color.White,
            AutoSize = false,
            Dock = DockStyle.Top,
            Height = 64,
            Padding = new Padding(16, 12, 16, 0),
        };

        var body = new Label
        {
            Dock = DockStyle.Top,
            Height = 320,
            Padding = new Padding(16, 8, 16, 8),
            Text =
                $"A staff member of {serverName} has asked you to run a screenshare check " +
                $"(case: {caseLabel}{(suspectLabel is null ? "" : $", for {suspectLabel}")}).\n\n" +
                "WHAT IT READS:\n" +
                "  • Your list of running programs and when they started\n" +
                "  • Your Minecraft folders: mods, version files, logs, launcher settings\n" +
                "    (it does NOT read your account password or login token)\n" +
                "  • Windows records of which programs ran or were deleted recently\n" +
                "  • The Recycle Bin (only .jar, .exe, .dll files)\n\n" +
                "WHAT IT NEVER TOUCHES: your documents, photos, messages, browser history*,\n" +
                "passwords, or anything unrelated to Minecraft.  (*unless you tick the box below)\n\n" +
                "WHAT IT DOES NOT DO: install anything, stay running after it finishes, start\n" +
                "with Windows, or capture your screen or keystrokes. It deletes its own\n" +
                "temporary files when it closes.",
        };

        _browserOptIn = new CheckBox
        {
            Dock = DockStyle.Top,
            Height = 28,
            Padding = new Padding(16, 0, 16, 0),
            Text = "Also check my browser's download history for cheat-client downloads (optional)",
            ForeColor = Color.Gainsboro,
        };

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            Height = 56,
            Padding = new Padding(12),
        };
        var ok = new Button
        {
            Text = "I consent — start the scan",
            AutoSize = true,
            BackColor = Color.White,
            ForeColor = Color.Black,
            Padding = new Padding(10, 6, 10, 6),
        };
        var cancel = new Button { Text = "Cancel", AutoSize = true, Padding = new Padding(10, 6, 10, 6) };
        ok.Click += (_, _) =>
        {
            Result = new ConsentResult(true, DateTimeOffset.UtcNow, _browserOptIn.Checked);
            DialogResult = DialogResult.OK;
            Close();
        };
        cancel.Click += (_, _) => { DialogResult = DialogResult.Cancel; Close(); };
        buttons.Controls.Add(ok);
        buttons.Controls.Add(cancel);

        Controls.Add(buttons);
        Controls.Add(_browserOptIn);
        Controls.Add(body);
        Controls.Add(head);
    }
}

public readonly record struct ConsentResult(bool Accepted, DateTimeOffset At, bool BrowserHistoryOptIn);

/// <summary>Live progress + scrolling log shown while the scan runs.</summary>
public sealed class ProgressForm : Form
{
    private readonly ProgressBar _bar;
    private readonly TextBox _log;
    private readonly Label _status;

    public ProgressForm(string serverName)
    {
        Text = $"SSAC Screenshare Tool — {serverName}";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        ClientSize = new Size(560, 360);
        BackColor = Color.FromArgb(14, 17, 22);
        ForeColor = Color.Gainsboro;
        Font = new Font("Segoe UI", 9.5f);

        _status = new Label { Dock = DockStyle.Top, Height = 28, Padding = new Padding(12, 8, 12, 0), Text = "Starting…" };
        _bar = new ProgressBar { Dock = DockStyle.Top, Height = 20, Style = ProgressBarStyle.Continuous, Margin = new Padding(12) };
        _log = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            BackColor = Color.FromArgb(10, 12, 16),
            ForeColor = Color.Silver,
            Font = new Font("Consolas", 9f),
            BorderStyle = BorderStyle.None,
        };
        var pad = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12) };
        pad.Controls.Add(_log);
        Controls.Add(pad);
        Controls.Add(_bar);
        Controls.Add(_status);
    }

    public void Report(string status, int? pct, string logLine)
    {
        if (IsDisposed) return;
        BeginInvoke(() =>
        {
            _status.Text = status;
            if (pct is int p) _bar.Value = Math.Clamp(p, 0, 100);
            if (!string.IsNullOrEmpty(logLine)) _log.AppendText(logLine + Environment.NewLine);
        });
    }
}

/// <summary>Final summary shown to the suspect — they always see what was sent.</summary>
public sealed class SummaryForm : Form
{
    public SummaryForm(string serverName, Severity verdict, IReadOnlyList<Finding> findings, bool uploaded)
    {
        Text = $"SSAC Screenshare Tool — {serverName}";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        ClientSize = new Size(560, 420);
        BackColor = Color.FromArgb(14, 17, 22);
        ForeColor = Color.Gainsboro;
        Font = new Font("Segoe UI", 9.5f);

        var head = new Label
        {
            Dock = DockStyle.Top,
            Height = 52,
            Padding = new Padding(16, 12, 16, 0),
            Font = new Font("Segoe UI", 12f, FontStyle.Bold),
            ForeColor = Color.White,
            Text = uploaded
                ? $"Scan finished — report sent to {serverName}"
                : "Scan finished — but the report could NOT be sent",
        };

        var list = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            BackColor = Color.FromArgb(10, 12, 16),
            ForeColor = Color.Silver,
            Font = new Font("Consolas", 9f),
            BorderStyle = BorderStyle.None,
            Text = BuildText(verdict, findings),
        };
        var pad = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12) };
        pad.Controls.Add(list);

        var close = new Button { Text = "Close", AutoSize = true, Dock = DockStyle.Right, Padding = new Padding(12, 6, 12, 6) };
        close.Click += (_, _) => Close();
        var foot = new Panel { Dock = DockStyle.Bottom, Height = 48, Padding = new Padding(12) };
        foot.Controls.Add(close);

        Controls.Add(pad);
        Controls.Add(foot);
        Controls.Add(head);
    }

    private static string BuildText(Severity verdict, IReadOnlyList<Finding> findings)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Overall: {verdict.Wire().ToUpperInvariant()}");
        sb.AppendLine("Findings are evidence, not a verdict. A human reviews them.");
        sb.AppendLine();
        if (findings.Count == 0) sb.AppendLine("(no findings)");
        foreach (var f in findings.OrderByDescending(f => f.Severity))
        {
            sb.AppendLine($"[{f.Severity.Wire().ToUpperInvariant()}] {f.Title}");
            sb.AppendLine($"    {f.Description}");
        }
        return sb.ToString();
    }
}
