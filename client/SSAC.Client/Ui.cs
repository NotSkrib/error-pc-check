using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace SSAC.Client;

/// <summary>Recorded consent (docs/phase-0-design.md §5). The simple flow records it automatically.</summary>
public readonly record struct ConsentResult(bool Accepted, DateTimeOffset At, bool BrowserHistoryOptIn);

/// <summary>A small rotating arc — the "spinning circle" activity indicator.</summary>
public sealed class Spinner : Control
{
    private readonly System.Windows.Forms.Timer _t = new() { Interval = 33 };
    private float _angle;

    public Spinner()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        Size = new Size(44, 44);
        _t.Tick += (_, _) => { _angle = (_angle + 9f) % 360f; Invalidate(); };
        _t.Start();
    }

    public bool Spinning
    {
        get => _t.Enabled;
        set { _t.Enabled = value; Invalidate(); }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        var pad = 5f;
        var r = new RectangleF(pad, pad, Width - pad * 2, Height - pad * 2);
        using var track = new Pen(Color.FromArgb(28, 255, 255, 255), 3f);
        e.Graphics.DrawEllipse(track, r);
        if (_t.Enabled)
        {
            using var arc = new Pen(Color.FromArgb(0xE5, 0x48, 0x4D), 3f)
            { StartCap = LineCap.Round, EndCap = LineCap.Round };
            e.Graphics.DrawArc(arc, r, _angle, 100f);
        }
        else
        {
            using var done = new Pen(Color.FromArgb(0x37, 0xB2, 0x6A), 3f) { StartCap = LineCap.Round };
            e.Graphics.DrawArc(done, r, -90f, 360f);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _t.Dispose();
        base.Dispose(disposing);
    }
}

/// <summary>
/// The whole client UI: one small always-on-top window. Minimal by request —
/// a heading, a spinner and a progress bar, nothing about which checks run.
/// Auto-starts; switches to a "done" state with a Close button.
/// </summary>
public sealed class SimpleForm : Form
{
    private readonly ProgressBar _bar;
    private readonly Label _heading;
    private readonly Label _sub;
    private readonly Spinner _spinner;
    private readonly Button _close;
    private bool _done;

    public SimpleForm(string serverName)
    {
        Text = $"{serverName} PC Integrity Check";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        TopMost = true;
        ShowInTaskbar = true;
        ClientSize = new Size(380, 214);
        BackColor = Color.FromArgb(0x0C, 0x0D, 0x10);
        ForeColor = Color.Gainsboro;
        Font = new Font("Segoe UI", 9.5f);

        // thin brand accent along the top
        var accent = new Panel { Bounds = new Rectangle(0, 0, 380, 2), BackColor = Color.FromArgb(0xE5, 0x48, 0x4D) };
        Controls.Add(accent);

        _spinner = new Spinner { Location = new Point(168, 30) };

        _heading = new Label
        {
            Bounds = new Rectangle(0, 84, 380, 30),
            TextAlign = ContentAlignment.MiddleCenter,
            Font = new Font("Segoe UI", 13f, FontStyle.Bold),
            ForeColor = Color.White,
            Text = "Scanning",
        };
        _sub = new Label
        {
            Bounds = new Rectangle(0, 114, 380, 20),
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Color.FromArgb(130, 135, 145),
            Text = "Initializing scan…",
        };
        _bar = new ProgressBar
        {
            Bounds = new Rectangle(40, 146, 300, 6),
            Style = ProgressBarStyle.Continuous,
        };
        _close = new Button
        {
            Text = "Close",
            Size = new Size(90, 30),
            Location = new Point(145, 168),
            Enabled = false,
            Visible = false,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(28, 30, 36),
            ForeColor = Color.White,
        };
        _close.FlatAppearance.BorderColor = Color.FromArgb(70, 74, 82);
        _close.Click += (_, _) => Close();

        Controls.Add(_close);
        Controls.Add(_bar);
        Controls.Add(_sub);
        Controls.Add(_heading);
        Controls.Add(_spinner);
    }

    /// <summary>Update progress. The status string is intentionally not shown.</summary>
    public void Report(string status, int? pct)
    {
        _ = status;
        if (IsDisposed) return;
        BeginInvoke(() =>
        {
            if (_done) return;
            if (pct is int p)
            {
                _bar.Value = Math.Clamp(p, 0, 100);
                _sub.Text = p < 12 ? "Initializing scan…" : "Scanning…";
            }
        });
    }

    /// <summary>Switch to the finished state and let the user close the window.</summary>
    public void Finish(Severity verdict, int findingCount, bool uploaded)
    {
        _ = verdict;
        _ = findingCount;
        if (IsDisposed) return;
        BeginInvoke(() =>
        {
            _done = true;
            _spinner.Spinning = false;
            _bar.Value = 100;
            if (uploaded)
            {
                _heading.ForeColor = Color.FromArgb(120, 220, 150);
                _heading.Text = "Scan complete";
                _sub.Text = "You can close this window.";
            }
            else
            {
                _heading.ForeColor = Color.FromArgb(240, 140, 120);
                _heading.Text = "Couldn't finish";
                _sub.Text = "Check your internet and ask for a new link.";
            }
            _close.Visible = true;
            _close.Enabled = true;
            _close.Focus();
        });
    }
}
