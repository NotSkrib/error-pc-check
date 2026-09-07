using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;

namespace SSAC.Client;

/// <summary>
/// Live look at the running Java process(es): the JVM command line, the native
/// modules mapped into them, and the parent process. This is the "is it hooked
/// right now" check — the out-of-instance forensic collectors can only infer
/// injection after the fact (docs/phase-0-design.md T1, T2).
/// </summary>
public sealed class JvmInjectionModule : IScanModule
{
    public string Name => "jvm-injection";
    public bool RequiresElevation => false;

    private static readonly string[] AgentFlags =
    [
        "-javaagent:", "-agentpath:", "-agentlib:", "-xrun", "-xbootclasspath/a:",
        "disableattachmechanism", "jdk.attach.allowattachself",
    ];

    // JRE / launcher folders whose unsigned native DLLs are expected.
    private static readonly string[] TrustedDirParts =
    [
        "\\windows\\", "\\program files\\java\\", "\\program files (x86)\\java\\",
        "\\eclipse adoptium\\", "\\eclipse foundation\\", "\\zulu", "\\amazon corretto\\",
        "\\microsoft\\jdk", "\\.jdks\\", "\\jbr\\", "\\jre", "\\jdk", "\\runtime\\",
        "\\.lunarclient\\", "\\.feather\\", "\\.minecraft\\", "\\curseforge\\",
        "\\prismlauncher\\", "\\multimc\\", "\\atlauncher\\", "\\modrinth\\",
    ];

    // User folders where a loose loaded DLL is genuinely out of place. Temp and
    // AppData are deliberately excluded: LWJGL / JNA / sqlite-jdbc / audio codecs
    // legitimately unpack unsigned native libs there for every Java game.
    private static readonly string[] SuspectDirParts =
    [
        "\\downloads\\", "\\desktop\\", "\\documents\\", "\\public\\",
        "\\music\\", "\\videos\\", "\\onedrive\\",
    ];

    // Classpath jars only: these locations are always foreign.
    private static readonly string[] JarSuspectDirParts =
    [
        "\\downloads\\", "\\desktop\\", "\\documents\\", "\\public\\",
        "\\appdata\\local\\temp\\", "\\temp\\", "\\tmp\\",
    ];

    // Native libraries every modern Minecraft / LWJGL launcher ships unsigned.
    private static readonly string[] SafeNativeStems =
    [
        "lwjgl", "glfw", "openal", "jemalloc", "jna", "stb", "opengl", "opengles",
        "vulkan", "freetype", "harfbuzz", "shaderc", "spirv", "tinyfd", "assimp",
        "opus", "lame", "speex", "rnnoise", "libopus", "librnnoise", "libspeex",
        "liblame", "sqlite", "sqlitejdbc", "oshi", "jansi", "zstd", "lz4", "netty",
        "brotli", "imgui", "nativefiledialog", "discord_game_sdk", "steam_api",
        "renderdoc", "yoga", "text2speech", "nvfx",
        // GPU / graphics driver DLLs — Minecraft crashing in one of these is a
        // driver bug, not a cheat.
        "nvoglv", "nvd3d", "nvcuda", "nvapi", "atio6axx", "atioglxx", "aticfx",
        "atig6", "amdxc", "amdvlk", "amdihk", "igd", "igdumd", "ig9icd", "ig11icd",
        "ig75icd", "igvk", "opengl32", "d3d9", "d3d11", "d3d12", "dxgi", "vulkan-1",
        "openglon12", "libglesv2", "libegl",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);

        var javas = Process.GetProcesses()
            .Where(p =>
            {
                try { return p.ProcessName.ToLowerInvariant() is "javaw" or "java"; }
                catch { return false; }
            })
            .ToList();

        if (javas.Count == 0)
        {
            ctx.Add(new Finding(Name, Severity.Info, "No running Java process to inspect",
                "Minecraft (javaw) was not running during the scan, so the live-injection check had nothing to look at.",
                SortKey: 26));
            await ctx.ModuleDone(Name, 0);
            return;
        }

        var cmdlines = ProcessCommandLines();
        var inspected = 0;

        foreach (var p in javas)
        {
            ct.ThrowIfCancellationRequested();
            int pid;
            try { pid = p.Id; }
            catch { continue; }
            inspected++;
            ctx.NoteExecution("javaw", null, "live-process", DateTimeOffset.Now);

            cmdlines.TryGetValue(pid, out var info);
            InspectCommandLine(ctx, pid, info);
            InspectParent(ctx, pid, info);
            InspectModules(ctx, pid, ct);
        }

        await ctx.Log(Name, $"{inspected} java process(es) inspected");
        await ctx.ModuleDone(Name, 0);
    }

    private static void InspectCommandLine(ScanContext ctx, int pid, ProcInfo? info)
    {
        var cmd = info?.CommandLine ?? "";
        if (cmd.Length == 0) return;
        var lc = cmd.ToLowerInvariant();

        var flag = AgentFlags.FirstOrDefault(lc.Contains);
        if (flag is not null)
        {
            ctx.Signals.Add("jvm:agent-live");
            ctx.Add(new Finding("jvm-injection", Severity.High,
                "Running Minecraft was started with a JVM agent",
                $"The live javaw command line contains '{flag.TrimEnd(':')}'. Launch-time and attach injection cheats load exactly this way.",
                new { pid, flag = flag.TrimEnd(':'), command_line = Clip(cmd, 800) }, SortKey: 2));
        }

        // Minecraft classpaths legitimately carry 100+ library jars from launcher
        // folders, so "not under .minecraft" is far too noisy. Only a cheat-named
        // jar, or one loaded from a temp / download / desktop folder, is worth a flag.
        foreach (var jar in ExtractClasspath(cmd))
        {
            var l = jar.ToLowerInvariant();
            if (!l.EndsWith(".jar")) continue;
            var jname = SafeName(jar);
            if (Forensics.LooksLikeCheat(jname))
                ctx.Add(new Finding("jvm-injection", Severity.High,
                    $"Cheat-named .jar on the running Minecraft classpath: {jname}",
                    "javaw has a jar whose name matches known cheat tooling on its classpath.",
                    new { pid, jar }, SortKey: 2));
            else if (JarSuspectDirParts.Any(l.Contains))
                ctx.Add(new Finding("jvm-injection", Severity.Medium,
                    $"Classpath .jar loaded from a user folder: {jname}",
                    "javaw has a .jar on its classpath from a temp / download / desktop location rather than a launcher's own files.",
                    new { pid, jar }, SortKey: 9));
        }
    }

    private static void InspectParent(ScanContext ctx, int pid, ProcInfo? info)
    {
        var parent = info?.ParentName?.ToLowerInvariant();
        if (parent is null) return;
        if (parent is "cmd" or "powershell" or "pwsh" or "wscript" or "cscript"
            or "python" or "python3" or "rundll32" or "regsvr32" or "mshta" or "conhost")
            ctx.Add(new Finding("jvm-injection", Severity.Medium,
                $"Minecraft was launched by {parent}.exe",
                "javaw's parent process is a shell / script host rather than a Minecraft launcher. Worth asking how the game was started.",
                new { pid, parent_pid = info!.ParentPid, parent }, SortKey: 12));
    }

    private static void InspectModules(ScanContext ctx, int pid, CancellationToken ct)
    {
        ProcessModuleCollection mods;
        try { mods = Process.GetProcessById(pid).Modules; }
        catch
        {
            ctx.Add(new Finding("jvm-injection", Severity.Info,
                "Loaded modules of javaw not readable",
                "The scan could not enumerate the DLLs mapped into the running Minecraft process (usually a privilege / integrity-level difference).",
                new { pid }, SortKey: 27));
            return;
        }

        foreach (ProcessModule m in mods)
        {
            ct.ThrowIfCancellationRequested();
            string path;
            try { path = m.FileName ?? ""; }
            catch { continue; }
            var l = path.ToLowerInvariant();
            if (!l.EndsWith(".dll")) continue;

            if (Forensics.LooksLikeCheat(SafeName(path)))
            {
                ctx.Signals.Add("jvm:cheat-module");
                ctx.NoteExecution(SafeName(path), path, "jvm-module", DateTimeOffset.Now);
                ctx.Add(new Finding("jvm-injection", Severity.High,
                    $"Cheat-named DLL mapped into javaw: {SafeName(path)}",
                    "A module whose name matches known cheat tooling is loaded inside the running Minecraft process.",
                    new { pid, module = path }, SortKey: 1));
                continue;
            }

            var suspectDir = SuspectDirParts.Any(l.Contains);
            var trusted = TrustedDirParts.Any(l.Contains);
            if (suspectDir && !trusted && !IsKnownNative(SafeName(path)) && !Authenticode.IsSigned(path))
            {
                ctx.Signals.Add("jvm:unsigned-usermode-module");
                ctx.Add(new Finding("jvm-injection", Severity.Medium,
                    $"Unsigned DLL from a user folder mapped into javaw: {SafeName(path)}",
                    $"javaw has '{path}' loaded — an unsigned library from Downloads / Desktop, not a launcher's files. Native injectors look like this.",
                    new { pid, module = path }, SortKey: 8));
            }
        }
    }

    // ---- helpers ----

    private sealed record ProcInfo(string CommandLine, int ParentPid, string? ParentName);

    private static Dictionary<int, ProcInfo> ProcessCommandLines()
    {
        var byPid = new Dictionary<int, (string Cmd, int Ppid)>();
        var names = new Dictionary<int, string>();
        try
        {
            using var s = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name, CommandLine FROM Win32_Process");
            foreach (ManagementObject o in s.Get())
            {
                try
                {
                    var pid = Convert.ToInt32(o["ProcessId"]);
                    names[pid] = (o["Name"]?.ToString() ?? "").Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
                    byPid[pid] = (o["CommandLine"]?.ToString() ?? "", Convert.ToInt32(o["ParentProcessId"]));
                }
                catch { /* skip a row */ }
            }
        }
        catch { /* WMI unavailable — callers handle the empty map */ }

        return byPid.ToDictionary(
            kv => kv.Key,
            kv => new ProcInfo(kv.Value.Cmd, kv.Value.Ppid,
                names.TryGetValue(kv.Value.Ppid, out var n) ? n : null));
    }

    private static IEnumerable<string> ExtractClasspath(string cmd)
    {
        var m = Regex.Match(cmd, @"(?:-cp|-classpath|--class-path)\s+(""[^""]+""|\S+)",
            RegexOptions.IgnoreCase);
        if (!m.Success) yield break;
        var raw = m.Groups[1].Value.Trim('"');
        foreach (var part in raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            yield return part;
    }

    private static string SafeName(string p)
    {
        try { return Path.GetFileName(p.Replace('/', '\\')); }
        catch { return p; }
    }

    /// <summary>True for game / library native DLLs that legitimately ship unsigned
    /// and unpack to temp (LWJGL, JNA, sqlite-jdbc, audio codecs, …).</summary>
    internal static bool IsKnownNative(string dllName)
    {
        var n = dllName.ToLowerInvariant();
        if (SafeNativeStems.Any(n.Contains)) return true;
        // JNA / sqlite-jdbc etc. extract with a long digit or hex/guid run in the name
        return Regex.IsMatch(n, @"(?:[0-9a-f]{12,}|\d{10,})\.dll$");
    }

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}

/// <summary>
/// Parses JVM fatal-error logs (`hs_err_pid*.log`, `replay_pid*.log`). These
/// persist on disk long after a cheat is removed, so they catch "was injected
/// recently" that a live scan would miss. The <c>Dynamic libraries</c> section
/// lists every native module the crashed JVM had loaded; the <c>VM Arguments</c>
/// line preserves any `-javaagent` / `-agentpath` that was used.
/// </summary>
public sealed class JavaCrashLogModule : IScanModule
{
    public string Name => "java-crash-log";
    public bool RequiresElevation => false;

    private const int MaxLogs = 10;
    private const int MaxBytes = 768 * 1024;
    private static readonly string[] Patterns = ["hs_err_pid*.log", "hs_err_*.log", "replay_pid*.log"];

    // Temp / AppData excluded on purpose — the JVM unpacks legitimate unsigned
    // natives there for every game.
    private static readonly string[] SuspectDirParts =
    [
        "\\downloads\\", "\\desktop\\", "\\documents\\", "\\public\\",
        "\\music\\", "\\videos\\", "\\onedrive\\",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);

        var files = FindLogs().ToList();
        if (files.Count == 0)
        {
            ctx.Add(new Finding(Name, Severity.Info, "No JVM crash logs found",
                "No hs_err_pid*.log files were present in the usual locations.", SortKey: 26));
            await ctx.ModuleDone(Name, 0);
            return;
        }

        var newest = files.Max(File.GetLastWriteTime);
        var days = (int)(DateTime.Now - newest).TotalDays;
        ctx.Add(new Finding(Name, days <= 14 ? Severity.Low : Severity.Info,
            $"{files.Count} JVM crash log(s) on disk (newest {days}d ago)",
            "Minecraft's JVM has crashed and left fatal-error logs. Native injection cheats are a common cause; the logs below are inspected for agents and foreign libraries.",
            new { count = files.Count, newest = newest.ToString("u") }, SortKey: 20));

        foreach (var f in files.Take(MaxLogs))
        {
            ct.ThrowIfCancellationRequested();
            string text;
            try
            {
                using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var buf = new byte[Math.Min(MaxBytes, fs.Length)];
                _ = fs.Read(buf, 0, buf.Length);
                text = System.Text.Encoding.UTF8.GetString(buf);
            }
            catch { continue; }

            Inspect(ctx, f, text);
        }

        await ctx.Log(Name, $"{files.Count} crash log(s), {Math.Min(files.Count, MaxLogs)} parsed");
        await ctx.ModuleDone(Name, 0);
    }

    private void Inspect(ScanContext ctx, string file, string text)
    {
        var name = Path.GetFileName(file);
        var when = File.GetLastWriteTime(file);

        // VM Arguments / java_command lines
        foreach (var line in text.Split('\n'))
        {
            var ll = line.ToLowerInvariant();
            if (!ll.Contains("jvm_args") && !ll.Contains("java_command") && !ll.Contains("vm arguments"))
                continue;
            foreach (var flag in new[] { "-javaagent", "-agentpath", "-agentlib", "-xbootclasspath/a" })
                if (ll.Contains(flag))
                {
                    ctx.Signals.Add("jvm:agent-crashlog");
                    ctx.Add(new Finding(Name, Severity.High,
                        $"Crash log {name} shows Minecraft ran with a JVM agent",
                        $"'{flag}' appears in the recorded VM arguments. The cheat may have been removed since, but it was loaded when this crash happened ({when:u}).",
                        new { file, line = Clip(line.Trim(), 400) }, SortKey: 3));
                    break;
                }
        }

        // Problematic frame — often names the offending native module
        var pf = Regex.Match(text, @"Problematic frame:\s*\r?\n#\s*[Cj]\s+\[([^\]\r\n]+)\]", RegexOptions.IgnoreCase);
        if (pf.Success)
        {
            var frame = pf.Groups[1].Value.Trim();
            var mod = frame.Split('+')[0].Trim();
            if (mod.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                && !IsJreOrWindows(mod) && !JvmInjectionModule.IsKnownNative(mod))
                ctx.Add(new Finding(Name, Forensics.LooksLikeCheat(mod) ? Severity.High : Severity.Medium,
                    $"Crash log {name}: JVM died inside {mod}",
                    $"The problematic frame was '{frame}' — a non-runtime native module. Native cheat code frequently crashes the JVM this way.",
                    new { file, frame }, SortKey: 6));
        }

        // Dynamic libraries section
        var dyn = text.IndexOf("Dynamic libraries:", StringComparison.OrdinalIgnoreCase);
        if (dyn >= 0)
        {
            var section = text[dyn..];
            var end = section.IndexOf("\n\n", StringComparison.Ordinal);
            if (end > 0) section = section[..end];
            foreach (Match m in Regex.Matches(section, @"([A-Za-z]:\\[^\r\n]+?\.dll)", RegexOptions.IgnoreCase))
            {
                var path = m.Groups[1].Value.Trim();
                var pl = path.ToLowerInvariant();
                if (IsJreOrWindows(path)) continue;
                if (Forensics.LooksLikeCheat(Path.GetFileName(path)))
                {
                    ctx.NoteExecution(Path.GetFileName(path), path, "jvm-crashlog", when);
                    ctx.Add(new Finding(Name, Severity.High,
                        $"Crash log {name}: cheat-named DLL was loaded ({Path.GetFileName(path)})",
                        "A module whose name matches known cheat tooling was mapped into the JVM at crash time.",
                        new { file, module = path }, SortKey: 4));
                }
                else if (SuspectDirParts.Any(pl.Contains)
                    && !JvmInjectionModule.IsKnownNative(Path.GetFileName(path))
                    && !Authenticode.IsSigned(path))
                    ctx.Add(new Finding(Name, Severity.Medium,
                        $"Crash log {name}: unsigned DLL from a user folder was loaded",
                        $"'{path}' was mapped into the JVM at crash time — an unsigned library from Downloads / Desktop.",
                        new { file, module = path }, SortKey: 10));
            }
        }
    }

    private static bool IsJreOrWindows(string path)
    {
        var l = path.ToLowerInvariant();
        return l.Contains("\\windows\\") || l.Contains("\\java\\") || l.Contains("\\jdk")
            || l.Contains("\\jre") || l.Contains("\\jbr\\") || l.Contains("adoptium")
            || l.Contains("corretto") || l.Contains("\\zulu") || l.Contains("\\.jdks\\")
            || l.Contains("\\bin\\server\\") || l.Contains("\\runtime\\");
    }

    private static IEnumerable<string> FindLogs()
    {
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetTempPath(), home,
            Path.Combine(home, "Desktop"), Path.Combine(home, "Downloads"),
            Path.Combine(roaming, ".minecraft"),
            Path.Combine(roaming, ".minecraft", "crash-reports"),
            Environment.CurrentDirectory,
        };
        foreach (var inst in MinecraftLocator.Instances())
        {
            roots.Add(inst);
            var parent = Path.GetDirectoryName(inst);
            if (parent is not null) roots.Add(parent);
            roots.Add(Path.Combine(inst, "crash-reports"));
        }

        var hits = new List<string>();
        foreach (var r in roots)
        {
            if (!Directory.Exists(r)) continue;
            foreach (var pat in Patterns)
            {
                try { hits.AddRange(Directory.EnumerateFiles(r, pat, SearchOption.TopDirectoryOnly)); }
                catch { /* skip */ }
            }
        }
        return hits.Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(File.GetLastWriteTime);
    }

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
