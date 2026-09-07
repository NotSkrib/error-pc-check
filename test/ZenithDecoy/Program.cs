using System.Drawing;
using System.Windows.Forms;

// DETECTION TEST DECOY — does nothing. See ZenithDecoy.csproj header.
// It shows a static fake "macro client" window so the screenshare client's
// external-macro module has something to match on. No timers, no input APIs,
// no game interaction of any kind.

namespace ZenithDecoy;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new DecoyForm());
    }
}

internal sealed class DecoyForm : Form
{
    public DecoyForm()
    {
        // The window title is one of the things ExternalMacroModule reads.
        Text = "Zenith Macros";
        ClientSize = new Size(420, 300);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(0x10, 0x11, 0x16);
        ForeColor = Color.Gainsboro;
        Font = new Font("Segoe UI", 9.5f);

        Controls.Add(new Label
        {
            Text = "Zenith Macros  v1.4.8\nExternal PvP Client\n\n(detection test decoy — inert)",
            Dock = DockStyle.Top,
            Height = 90,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 11f, FontStyle.Bold),
        });

        // Purely cosmetic list — nothing behind these strings.
        Controls.Add(new Label
        {
            Text = "Crystal  •  Sword  •  Mace  •  Cart  •  UHC\n\n"
                 + "Auto Crystal      Hit Crystal      Triggerbot\n"
                 + "Single Anchor     Double Anchor    Safe Anchor\n\n"
                 + "Instance detected: —    Macros suspended",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Color.FromArgb(150, 155, 165),
        });
    }
}
