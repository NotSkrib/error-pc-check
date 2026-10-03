using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace ErrorSmp.Client;

public readonly record struct ConsentResult(bool Accepted, DateTimeOffset At, bool BrowserHistoryOptIn);

internal static class ClientPalette
{
    public static readonly Color Background = Color.FromRgb(27, 13, 31);
    public static readonly Color Surface = Color.FromRgb(37, 19, 43);
    public static readonly Color SurfaceRaised = Color.FromRgb(52, 24, 64);
    public static readonly Color Line = Color.FromArgb(55, 223, 96, 229);
    public static readonly Color Text = Color.FromRgb(245, 243, 249);
    public static readonly Color Muted = Color.FromRgb(184, 157, 190);
    public static readonly Color Quiet = Color.FromRgb(132, 105, 139);
    public static readonly Color Accent = Color.FromRgb(178, 40, 199);
    public static readonly Color AccentBright = Color.FromRgb(235, 92, 239);
    public static readonly Color Success = Color.FromRgb(115, 213, 157);
    public static readonly Color Danger = Color.FromRgb(255, 137, 150);

    public static SolidColorBrush Brush(Color color) => new(color);
}

internal static class ClientFonts
{
    private static readonly Lazy<FontFamily> MinecraftFace = new(LoadMinecraftFace);

    public static FontFamily Minecraft => MinecraftFace.Value;

    private static FontFamily LoadMinecraftFace()
    {
        var fontDirectory = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ErrorSmp", "Fonts");
        Directory.CreateDirectory(fontDirectory);
        ExtractFont("errorsmp-minecraft.ttf", System.IO.Path.Combine(fontDirectory, "Minecraft.ttf"));
        var baseUri = new Uri(System.IO.Path.GetFullPath(fontDirectory) + System.IO.Path.DirectorySeparatorChar, UriKind.Absolute);
        var minecraft = Fonts.GetFontFamilies(baseUri, "./")
            .FirstOrDefault(family => family.FamilyNames.Values.Any(
                name => string.Equals(name, "Minecraft", StringComparison.OrdinalIgnoreCase)));
        return minecraft ?? throw new InvalidOperationException("The bundled Minecraft font could not be loaded.");
    }

    private static void ExtractFont(string resourceName, string destination)
    {
        using var source = typeof(ClientFonts).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"The bundled font {resourceName} is missing.");
        if (File.Exists(destination) && new FileInfo(destination).Length == source.Length) return;
        using var output = File.Create(destination);
        source.CopyTo(output);
    }
}

public sealed class ScanWindow : Window
{
    private readonly TextBlock _status;
    private readonly TextBlock _percent;
    private readonly TextBlock _headline;
    private readonly TextBlock _summary;
    private readonly ProgressBar _progress;
    private readonly Button _close;
    private readonly Button _chromeClose;
    private bool _done;
    private bool _closed;

    public ScanWindow(string serverName)
    {
        Title = $"{serverName} Screenshare";
        Width = 560;
        Height = 340;
        MinWidth = 520;
        MinHeight = 340;
        ResizeMode = ResizeMode.NoResize;
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        ShowInTaskbar = true;
        FontFamily = ClientFonts.Minecraft;
        Foreground = ClientPalette.Brush(ClientPalette.Text);
        Icon = CreateWindowIcon();

        _chromeClose = new Button
        {
            Content = "×",
            Width = 30,
            Height = 28,
            IsEnabled = false,
            ToolTip = "Available when the check is complete",
            Background = Brushes.Transparent,
            Foreground = ClientPalette.Brush(ClientPalette.Muted),
            BorderBrush = Brushes.Transparent,
            FocusVisualStyle = null,
            FontSize = 19,
            Padding = new Thickness(0, -3, 0, 0),
            Cursor = Cursors.Hand,
        };
        _chromeClose.Click += (_, _) => Close();

        var shell = new Border
        {
            CornerRadius = new CornerRadius(14),
            BorderThickness = new Thickness(1),
            BorderBrush = ClientPalette.Brush(Color.FromArgb(86, 185, 66, 195)),
            Background = new LinearGradientBrush(
                Color.FromArgb(252, 39, 18, 46),
                Color.FromArgb(252, 19, 10, 26),
                new Point(0, 0), new Point(1, 1)),
            Effect = new System.Windows.Media.Effects.DropShadowEffect
            {
                Color = Color.FromRgb(8, 6, 13),
                BlurRadius = 28,
                ShadowDepth = 8,
                Opacity = 0.55,
            },
            Padding = new Thickness(1),
            Opacity = 0,
            RenderTransform = new TranslateTransform(0, 8),
        };

        var layout = new Grid();
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var header = BuildHeader(serverName);
        Grid.SetRow(header, 0);
        Grid.SetColumnSpan(header, 2);
        layout.Children.Add(header);

        _headline = new TextBlock
        {
            Text = "Getting things ready",
            FontSize = 22,
            FontWeight = FontWeights.SemiBold,
            Foreground = ClientPalette.Brush(ClientPalette.Text),
            TextWrapping = TextWrapping.Wrap,
        };
        _summary = new TextBlock
        {
            Text = "",
            FontSize = 12,
            Foreground = ClientPalette.Brush(ClientPalette.Muted),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0),
        };
        _status = new TextBlock
        {
            Text = "Starting…",
            FontSize = 12,
            FontWeight = FontWeights.Medium,
            Foreground = ClientPalette.Brush(ClientPalette.Text),
            TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center,
        };
        _percent = new TextBlock
        {
            Text = "Starting",
            FontSize = 12,
            Foreground = ClientPalette.Brush(ClientPalette.AccentBright),
            VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Right,
        };
        _progress = new ProgressBar
        {
            Minimum = 0,
            Maximum = 100,
            Value = 0,
            Height = 8,
            Margin = new Thickness(0, 15, 0, 0),
            Background = ClientPalette.Brush(Color.FromArgb(140, 13, 11, 20)),
            Foreground = ClientPalette.Brush(ClientPalette.Accent),
            BorderThickness = new Thickness(0),
        };

        var statusGrid = new Grid();
        statusGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        statusGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Grid.SetColumn(_status, 0);
        Grid.SetColumn(_percent, 1);
        statusGrid.Children.Add(_status);
        statusGrid.Children.Add(_percent);

        var progressCard = new Border
        {
            Margin = new Thickness(0, 24, 0, 0),
            Padding = new Thickness(16),
            CornerRadius = new CornerRadius(9),
            BorderThickness = new Thickness(1),
            BorderBrush = ClientPalette.Brush(ClientPalette.Line),
            Background = new LinearGradientBrush(
                Color.FromArgb(135, 51, 34, 75),
                Color.FromArgb(100, 25, 18, 38),
                new Point(0, 0), new Point(1, 1)),
            Child = new StackPanel { Children = { statusGrid, _progress } },
        };

        var main = new StackPanel { Margin = new Thickness(36, 24, 36, 14) };
        main.Children.Add(_headline);
        main.Children.Add(_summary);
        main.Children.Add(progressCard);
        Grid.SetRow(main, 1);
        Grid.SetColumnSpan(main, 2);
        layout.Children.Add(main);

        _close = new Button
        {
            Content = "Close",
            Width = 110,
            Height = 36,
            IsEnabled = false,
            Visibility = Visibility.Collapsed,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 0, 36, 18),
            Background = new LinearGradientBrush(ClientPalette.Accent, Color.FromRgb(91, 48, 151), 0),
            Foreground = Brushes.White,
            BorderBrush = ClientPalette.Brush(ClientPalette.AccentBright),
            BorderThickness = new Thickness(1),
            FocusVisualStyle = null,
            FontWeight = FontWeights.SemiBold,
            Cursor = Cursors.Hand,
        };
        _close.Click += (_, _) => Close();
        Grid.SetRow(_close, 2);
        Grid.SetColumn(_close, 1);
        Grid.SetRow(_chromeClose, 0);
        layout.Children.Add(_close);

        var footer = new TextBlock
        {
            Text = "ErrorSmp  ·  Developed by notskrib",
            FontSize = 9,
            Foreground = ClientPalette.Brush(ClientPalette.Quiet),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(36, 0, 0, 0),
        };
        Grid.SetRow(footer, 2);
        Grid.SetColumn(footer, 0);
        layout.Children.Add(footer);

        shell.Child = layout;
        Content = shell;
        var enter = new Storyboard();
        var fade = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(420))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };
        Storyboard.SetTarget(fade, shell);
        Storyboard.SetTargetProperty(fade, new PropertyPath(OpacityProperty));
        enter.Children.Add(fade);
        var slide = new DoubleAnimation(6, 0, TimeSpan.FromMilliseconds(460))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };
        Storyboard.SetTarget(slide, shell);
        Storyboard.SetTargetProperty(slide, new PropertyPath("(UIElement.RenderTransform).(TranslateTransform.Y)"));
        enter.Children.Add(slide);
        Loaded += (_, _) => enter.Begin();
        MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed) DragMove();
        };
        Closing += (_, e) =>
        {
            if (!_done) e.Cancel = true;
        };
        Closed += (_, _) => _closed = true;
    }

    private UIElement BuildHeader(string serverName)
    {
        var header = new Border
        {
            Padding = new Thickness(22, 14, 18, 12),
            BorderBrush = ClientPalette.Brush(Color.FromArgb(35, 255, 255, 255)),
            BorderThickness = new Thickness(0, 0, 0, 1),
            Background = new LinearGradientBrush(
                Color.FromArgb(225, 24, 9, 29),
                Color.FromArgb(232, 16, 8, 22),
                new Point(0, 0), new Point(1, 1)),
        };
        var row = new Grid();
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var dots = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0),
        };
        foreach (var color in new[] { Color.FromRgb(90, 55, 128), Color.FromRgb(113, 68, 159), Color.FromRgb(149, 99, 197), Color.FromRgb(75, 50, 104) })
        {
            dots.Children.Add(new Ellipse
            {
                Width = 7,
                Height = 7,
                Fill = ClientPalette.Brush(color),
                Margin = new Thickness(0, 0, 5, 0),
                VerticalAlignment = VerticalAlignment.Center,
            });
        }

        var mark = new Border
        {
            Width = 62,
            Height = 62,
            Child = CreateBrandMark(),
        };

        var brand = new StackPanel { Margin = new Thickness(5, 1, 0, 0), VerticalAlignment = VerticalAlignment.Center };
        brand.Children.Add(new TextBlock
        {
            Text = "ErrorSmp",
            FontSize = 15,
            FontFamily = ClientFonts.Minecraft,
            FontWeight = FontWeights.Bold,
            Foreground = ClientPalette.Brush(ClientPalette.Text),
            TextTrimming = TextTrimming.CharacterEllipsis,
        });

        var minimize = new Button
        {
            Content = "−",
            Width = 28,
            Height = 28,
            Background = Brushes.Transparent,
            Foreground = ClientPalette.Brush(ClientPalette.Muted),
            BorderBrush = Brushes.Transparent,
            FontSize = 16,
            Padding = new Thickness(0, -4, 0, 0),
            Cursor = Cursors.Hand,
            ToolTip = "Minimize",
        };
        minimize.Click += (_, _) => WindowState = WindowState.Minimized;

        Grid.SetColumn(dots, 0);
        Grid.SetColumn(mark, 1);
        Grid.SetColumn(brand, 2);
        Grid.SetColumn(minimize, 3);
        Grid.SetColumn(_chromeClose, 4);
        row.Children.Add(mark);
        row.Children.Insert(0, dots);
        row.Children.Add(brand);
        row.Children.Add(minimize);
        row.Children.Add(_chromeClose);
        header.Child = row;
        return header;
    }

    private static Image CreateBrandMark()
    {
        using var stream = typeof(ScanWindow).Assembly.GetManifestResourceStream("errorsmp-mark.png")
            ?? throw new InvalidOperationException("The Error SMP logo resource is missing.");
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();
        return new Image
        {
            Source = image,
            Stretch = Stretch.Uniform,
        };
    }

    public void Report(string status, int? pct)
    {
        if (_closed) return;
        Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
        {
            if (_done) return;
            _status.Text = status;
            if (pct is int value)
            {
                AnimateProgress(value);
                _percent.Text = $"{Math.Clamp(value, 0, 100)}%";
                _headline.Text = value < 12 ? "Getting things ready" : "Checking this device";
                _summary.Text = "";
            }
        }));
    }

    public void Finish(Severity verdict, int findingCount, bool uploaded)
    {
        if (_closed) return;
        Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
        {
            _done = true;
            AnimateProgress(100);
            _percent.Text = "Complete";
            _headline.Text = uploaded ? "Check complete" : "Could not send results";
            _headline.Foreground = ClientPalette.Brush(uploaded ? ClientPalette.Success : ClientPalette.Danger);
            _status.Text = uploaded ? "Finished" : "Connection problem";
            _summary.Text = uploaded
                ? $"{findingCount} items recorded"
                : "Check your connection and try again";
            _close.Visibility = Visibility.Visible;
            _close.IsEnabled = true;
            _chromeClose.IsEnabled = true;
            _chromeClose.ToolTip = "Close";
        }));
    }

    private void AnimateProgress(int percentage)
    {
        var animation = new DoubleAnimation(
            _progress.Value,
            Math.Clamp(percentage, 0, 100),
            TimeSpan.FromMilliseconds(420))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };
        _progress.BeginAnimation(ProgressBar.ValueProperty, animation);
    }

    private static ImageSource CreateWindowIcon()
    {
        using var stream = typeof(ScanWindow).Assembly.GetManifestResourceStream("errorsmp-mark.png")
            ?? throw new InvalidOperationException("The Error SMP logo resource is missing.");
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.DecodePixelWidth = 64;
        image.DecodePixelHeight = 64;
        image.EndInit();
        image.Freeze();
        return image;
    }
}
