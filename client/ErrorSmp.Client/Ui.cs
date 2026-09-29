using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace ErrorSmp.Client;

public readonly record struct ConsentResult(bool Accepted, DateTimeOffset At, bool BrowserHistoryOptIn);

internal static class Palette
{
    public static readonly Color Bg = ColorTranslator.FromHtml("#050A10");
    public static readonly Color Card = ColorTranslator.FromHtml("#0A141E");
    public static readonly Color Brand = ColorTranslator.FromHtml("#0C1824");
    public static readonly Color Border = ColorTranslator.FromHtml("#1E3A4E");
    public static readonly Color BorderHi = ColorTranslator.FromHtml("#2F6F88");
    public static readonly Color Accent = ColorTranslator.FromHtml("#00A8D8");
    public static readonly Color AccentBright = ColorTranslator.FromHtml("#39E5FF");
    public static readonly Color AccentSoft = ColorTranslator.FromHtml("#74E8FF");
    public static readonly Color Text = ColorTranslator.FromHtml("#D8E8F5");
    public static readonly Color Dim = ColorTranslator.FromHtml("#8A97A8");
    public static readonly Color Mut = ColorTranslator.FromHtml("#597086");
    public static readonly Color Ctrl = ColorTranslator.FromHtml("#101824");
    public static readonly Color Success = ColorTranslator.FromHtml("#37B26A");
    public static readonly Color Danger = ColorTranslator.FromHtml("#E5484D");
}

internal static class Geometry
{
    public static GraphicsPath Rounded(Rectangle r, int radius)
    {
        var path = new GraphicsPath();
        int d = radius * 2;
        path.AddArc(r.X, r.Y, d, d, 180, 90);
        path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    public static Region RegionOf(Rectangle r, int radius)
    {
        using var path = Rounded(r, radius);
        return new Region(path);
    }
}

internal static class Drag
{
    [DllImport("user32.dll")] private static extern bool ReleaseCapture();
    [DllImport("user32.dll")] private static extern IntPtr SendMessage(IntPtr hWnd, int msg, int wParam, int lParam);

    private const int WM_NCLBUTTONDOWN = 0xA1;
    private const int HTCAPTION = 0x2;

    public static void Begin(Control anchor)
    {
        var hwnd = anchor.FindForm()?.Handle ?? anchor.Handle;
        ReleaseCapture();
        SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
    }

    public static void Wire(Control c)
    {
        c.MouseDown += (_, e) => { if (e.Button == MouseButtons.Left) Begin(c); };
    }
}

public sealed class Spinner : Control
{
    private readonly System.Windows.Forms.Timer _t = new() { Interval = 33 };
    private float _angle;

    public Spinner()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        Size = new Size(46, 46);
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
        using var track = new Pen(Color.FromArgb(32, 255, 255, 255), 3f);
        e.Graphics.DrawEllipse(track, r);
        if (_t.Enabled)
        {
            using var arc = new Pen(Palette.Accent, 3f)
            { StartCap = LineCap.Round, EndCap = LineCap.Round };
            e.Graphics.DrawArc(arc, r, _angle, 100f);
        }
        else
        {
            using var done = new Pen(Palette.Success, 3f) { StartCap = LineCap.Round };
            e.Graphics.DrawArc(done, r, -90f, 360f);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _t.Dispose();
        base.Dispose(disposing);
    }
}

public sealed class BrandBadge : Control
{
    public BrandBadge()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        Size = new Size(40, 40);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        var r = new Rectangle(1, 1, Width - 3, Height - 3);
        using var fill = new LinearGradientBrush(r, Palette.Brand, Palette.Card, 45f);
        using var path = Geometry.Rounded(r, 10);
        g.FillPath(fill, path);
        using var border = new Pen(Palette.BorderHi, 1f);
        g.DrawPath(border, path);
        using var font = new Font("Segoe UI", 15f, FontStyle.Bold);
        using var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        using var brush = new SolidBrush(Palette.AccentSoft);
        g.DrawString("E", font, brush, new RectangleF(r.X, r.Y, r.Width, r.Height), sf);
    }
}

public sealed class GlowBar : Control
{
    private int _value;

    public int Value
    {
        get => _value;
        set
        {
            var v = Math.Clamp(value, 0, 100);
            if (v == _value) return;
            _value = v;
            Invalidate();
        }
    }

    public GlowBar()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        Height = 8;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        var track = new Rectangle(0, 0, Width - 1, Height - 1);
        using (var tp = Geometry.Rounded(track, track.Height / 2))
        {
            using var tb = new SolidBrush(Palette.Card);
            g.FillPath(tb, tp);
            using var pen = new Pen(Palette.Border, 1f);
            g.DrawPath(pen, tp);
        }
        if (_value <= 0) return;
        var fillW = Math.Max(3, (int)((Width - 4) * _value / 100.0));
        var fill = new Rectangle(2, 2, fillW, Height - 5);
        using var fp = Geometry.Rounded(fill, fill.Height / 2);
        using (var glow = new Pen(Color.FromArgb(80, Palette.AccentSoft), 5f))
            g.DrawPath(glow, fp);
        using var fb = new LinearGradientBrush(fill, Palette.Accent, Palette.AccentBright, 0f);
        g.FillPath(fb, fp);
        using var edge = new Pen(Palette.AccentBright, 1f);
        g.DrawPath(edge, fp);
    }
}

public sealed class PillButton : Control
{
    private bool _hover;

    public PillButton()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        Size = new Size(120, 36);
        Font = new Font("Segoe UI", 10f, FontStyle.Bold);
        Cursor = Cursors.Hand;
    }

    protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hover = false; Invalidate(); base.OnMouseLeave(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        var r = new Rectangle(1, 1, Width - 3, Height - 3);
        using var path = Geometry.Rounded(r, r.Height / 2);
        using (var brush = new SolidBrush(_hover ? Color.FromArgb(0x11, 0xC4, 0xFF) : Palette.Accent))
            g.FillPath(brush, path);
        using (var pen = new Pen(Palette.AccentBright, 1f))
            g.DrawPath(pen, path);
        using var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        using var font = new Font("Segoe UI", 10f, FontStyle.Bold);
        using var tb = new SolidBrush(Color.White);
        g.DrawString(Text, font, tb, new RectangleF(0, 0, Width, Height), sf);
    }
}

public sealed class SimpleForm : Form
{
    private const int RADIUS = 12;
    private readonly GlowBar _bar;
    private readonly Label _heading;
    private readonly Label _sub;
    private readonly Spinner _spinner;
    private readonly PillButton _close;
    private bool _done;

    public SimpleForm(string serverName)
    {
        Text = $"{serverName} Screenshare";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.None;
        MaximizeBox = false;
        MinimizeBox = false;
        TopMost = true;
        ShowInTaskbar = true;
        ClientSize = new Size(400, 252);
        BackColor = Palette.Bg;
        ForeColor = Palette.Text;
        Font = new Font("Segoe UI", 9.5f);
        DoubleBuffered = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);

        var brand = new BrandBadge { Location = new Point(24, 17) };

        _heading = new Label
        {
            Bounds = new Rectangle(74, 14, 302, 26),
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = Color.White,
            BackColor = Palette.Bg,
            Text = "Scanning",
        };
        _sub = new Label
        {
            Bounds = new Rectangle(74, 41, 302, 18),
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI", 10f),
            ForeColor = Palette.Dim,
            BackColor = Palette.Bg,
            Text = "Initializing scan…",
        };

        _spinner = new Spinner { Location = new Point(177, 86) };
        _bar = new GlowBar { Bounds = new Rectangle(24, 164, 352, 8), Value = 0 };

        _close = new PillButton
        {
            Text = "Close",
            Location = new Point(140, 190),
            Size = new Size(120, 36),
            Visible = false,
        };
        _close.Click += (_, _) => Close();

        var footer = new Label
        {
            Bounds = new Rectangle(0, 231, 400, 16),
            TextAlign = ContentAlignment.MiddleCenter,
            Font = new Font("Segoe UI", 9f),
            ForeColor = Palette.Mut,
            BackColor = Palette.Bg,
            Text = $"Error SMP Screenshare · v{AppInfo.Version}",
        };

        Drag.Wire(this);
        Drag.Wire(brand);
        Drag.Wire(_heading);
        Drag.Wire(_sub);
        Drag.Wire(footer);

        Controls.Add(_close);
        Controls.Add(_bar);
        Controls.Add(_spinner);
        Controls.Add(_sub);
        Controls.Add(_heading);
        Controls.Add(brand);
        Controls.Add(footer);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyRegion();
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        ApplyRegion();
    }

    private void ApplyRegion()
    {
        if (ClientSize.Width < 1 || ClientSize.Height < 1) return;
        Region = Geometry.RegionOf(new Rectangle(Point.Empty, ClientSize), RADIUS);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        var rect = new Rectangle(0, 0, ClientSize.Width - 1, ClientSize.Height - 1);
        using (var path = Geometry.Rounded(rect, RADIUS))
        using (var pen = new Pen(Palette.Border, 1f))
            g.DrawPath(pen, path);
        using (var glow = new Pen(Color.FromArgb(120, Palette.Accent), 2f))
        {
            g.DrawLine(glow, 20, 0, ClientSize.Width - 20, 0);
        }
    }

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
                _heading.ForeColor = Palette.Success;
                _heading.Text = "Scan complete";
                _sub.Text = "You can close this window.";
            }
            else
            {
                _heading.ForeColor = Palette.Danger;
                _heading.Text = "Couldn't finish";
                _sub.Text = "Check your internet and ask for a new link.";
            }
            _close.Visible = true;
            _close.Focus();
        });
    }
}