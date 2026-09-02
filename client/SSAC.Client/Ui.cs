using System.Drawing;
using System.Windows.Forms;

namespace SSAC.Client;

/// <summary>Recorded consent (docs/phase-0-design.md §5). The simple flow records it automatically.</summary>
public readonly record struct ConsentResult(bool Accepted, DateTimeOffset At, bool BrowserHistoryOptIn);

/// <summary>
/// The whole client UI: one small always-on-top window. It auto-starts the scan,
/// shows progress, and switches to a "done" state with a Close button.
/// A one-line disclosure keeps it from looking like something it isn't (A1).
/// </summary>
public sealed class SimpleForm : Form
{
    private readonly ProgressBar _bar;
    private readonly Label _heading;
    private readonly Label _status;
    private readonly Button _close;
    private readonly System.Windows.Forms.Timer _tick = new() { Interval = 1000 };
    private readonly DateTime _started = DateTime.UtcNow;
    private bool _done;

    public SimpleForm(string serverName)
    {
        Text = $"SSAC Screenshare — {serverName}";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        TopMost = true;
        ShowInTaskbar = true;
        ClientSize = new Size(440, 190);
        BackColor = Color.FromArgb(14, 17, 22);
        ForeColor = Color.Gainsboro;
        Font = new Font("Segoe UI", 9.5f);

        _heading = new Label
        {
            Dock = DockStyle.Top,
            Height = 34,
            Padding = new Padding(16, 14, 16, 0),
            Font = new Font("Segoe UI", 12.5f, FontStyle.Bold),
            ForeColor = Color.White,
            Text = "Checking this PC…",
        };
        var disclosure = new Label
        {
            Dock = DockStyle.Top,
            Height = 34,
            Padding = new Padding(16, 2, 16, 0),
            ForeColor = Color.Gray,
            Text = $"Looks for Minecraft cheats and sends a report to {serverName}.\nNothing is installed. This window closes when it's done.",
        };
        _bar = new ProgressBar
        {
            Dock = DockStyle.Top,
            Height = 22,
            Margin = new Padding(16, 8, 16, 8),
            Style = ProgressBarStyle.Continuous,
        };
        _status = new Label { Dock = DockStyle.Top, Height = 22, Padding = new Padding(16, 2, 16, 0), ForeColor = Color.Silver, Text = "Starting…" };
        _close = new Button
        {
            Text = "Close",
            AutoSize = false,
            Size = new Size(90, 30),
            Dock = DockStyle.Right,
            Enabled = false,
            BackColor = Color.White,
            ForeColor = Color.Black,
        };
        _close.Click += (_, _) => Close();
        var foot = new Panel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(16, 8, 16, 8) };
        foot.Controls.Add(_close);

        Controls.Add(foot);
        Controls.Add(_status);
        Controls.Add(_bar);
        Controls.Add(disclosure);
        Controls.Add(_heading);

        _tick.Tick += (_, _) =>
        {
            if (_done) return;
            var e = DateTime.UtcNow - _started;
            _status.Text = $"{_status.Tag ?? "Working…"}   ({(int)e.TotalMinutes}:{e.Seconds:00})";
        };
        _tick.Start();
    }

    /// <summary>Update progress. Call from any thread.</summary>
    public void Report(string status, int? pct)
    {
        if (IsDisposed) return;
        BeginInvoke(() =>
        {
            _status.Tag = status;
            if (pct is int p) _bar.Value = Math.Clamp(p, 0, 100);
        });
    }

    /// <summary>Switch to the finished state and let the user close the window.</summary>
    public void Finish(Severity verdict, int findingCount, bool uploaded)
    {
        if (IsDisposed) return;
        BeginInvoke(() =>
        {
            _done = true;
            _bar.Value = 100;
            _tick.Stop();
            if (uploaded)
            {
                _heading.ForeColor = Color.FromArgb(120, 220, 150);
                _heading.Text = "✓  All done";
                _status.Text = $"Report sent — {findingCount} item(s) flagged, overall {verdict.Wire().ToUpperInvariant()}.";
            }
            else
            {
                _heading.ForeColor = Color.FromArgb(240, 140, 120);
                _heading.Text = "Finished, but the report didn't send";
                _status.Text = "Check the internet connection and ask the staff member for a new link.";
            }
            _close.Enabled = true;
            _close.Focus();
        });
    }
}
