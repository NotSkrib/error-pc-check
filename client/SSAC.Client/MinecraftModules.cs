using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace SSAC.Client;

/// <summary>Finds Minecraft instance folders across the common launchers (docs/phase-0-design.md §4.1).</summary>
public static class MinecraftLocator
{
    public static List<string> Instances()
    {
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var found = new List<string>();

        void AddIfInstance(string dir)
        {
            if (!Directory.Exists(dir)) return;
            var probe = new[] { "mods", "versions", "logs", "launcher_profiles.json", "options.txt" };
            if (probe.Any(p => File.Exists(Path.Combine(dir, p)) || Directory.Exists(Path.Combine(dir, p))))
                found.Add(dir);
        }

        AddIfInstance(Path.Combine(roaming, ".minecraft"));
        AddIfInstance(Path.Combine(home, ".lunarclient", "offline", "multiver"));
        AddIfInstance(Path.Combine(home, ".feather", "user-mods"));

        string[] instanceRoots =
        [
            Path.Combine(roaming, "PrismLauncher", "instances"),
            Path.Combine(roaming, "MultiMC", "instances"),
            Path.Combine(roaming, "ATLauncher", "instances"),
            Path.Combine(roaming, "gdlauncher_next", "instances"),
            Path.Combine(home, "curseforge", "minecraft", "Instances"),
        ];
        foreach (var root in instanceRoots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var inst in SafeDirs(root))
            {
                AddIfInstance(inst);
                AddIfInstance(Path.Combine(inst, ".minecraft"));
                AddIfInstance(Path.Combine(inst, "minecraft"));
            }
        }
        return found.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static IEnumerable<string> SafeDirs(string p)
    {
        try { return Directory.EnumerateDirectories(p); } catch { return []; }
    }
}

/// <summary>
/// Inspects each Minecraft instance: mods jars (name + hash + zip entries),
/// version manifests, logs, launcher_profiles.json JVM args, config/ — and runs
/// the known-cheat signature DB over the collected evidence.
/// </summary>
public sealed class MinecraftModule(SignatureDb db) : IScanModule
{
    public string Name => "minecraft";
    public bool RequiresElevation => false;

    private const int MaxInstances = 20;
    private const int MaxTotalJars = 1500;
    private const long MaxJarBytes = 60L * 1024 * 1024;
    private const long MaxLogBytesPerInstance = 2L * 1024 * 1024;
    private long _logBudget = 24L * 1024 * 1024; // aggregate across all instances
    private static readonly string[] AgentFlags = ["-javaagent", "-agentpath", "-agentlib", "disableattachmechanism"];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);
        var instances = MinecraftLocator.Instances()
            .OrderByDescending(InstanceRecency)
            .Take(MaxInstances)
            .ToList();
        if (instances.Count == 0)
        {
            ctx.Add(new Finding(Name, Severity.Info, "No Minecraft install found",
                "None of the common launcher folders contained a Minecraft instance.", SortKey: 25));
            await ctx.ModuleDone(Name, 0);
            return;
        }

        // Dedupe signature hits across instances; report one finding per signature.
        var byId = new Dictionary<string, (SignatureHit Hit, List<string> Instances)>();
        var jarBudget = MaxTotalJars;

        foreach (var inst in instances)
        {
            ct.ThrowIfCancellationRequested();
            await ctx.Log(Name, $"instance: {inst}");
            var target = new MatchTarget();

            var modCount = ScanMods(inst, target, ref jarBudget, ct);
            ScanVersions(ctx, inst, target);
            ScanLogs(inst, target);
            ScanLauncherProfiles(ctx, inst);
            ScanConfig(ctx, inst);

            foreach (var hit in db.Match(target))
            {
                if (byId.TryGetValue(hit.Signature.Id, out var acc))
                {
                    acc.Instances.Add(inst);
                    if (hit.Confidence > acc.Hit.Confidence) byId[hit.Signature.Id] = (hit, acc.Instances);
                }
                else
                {
                    byId[hit.Signature.Id] = (hit, [inst]);
                }
            }
            await ctx.Log(Name, $"  {modCount} mod jar(s) scanned");
        }

        foreach (var (hit, insts) in byId.Values)
        {
            var sev = hit.Confidence >= hit.Signature.MinConfidence + 3
                ? (Severity)Math.Min((int)Severity.Critical, (int)hit.Signature.Hint + 1)
                : hit.Signature.Hint;
            if (hit.Signature.Type == "native")
                ctx.NoteExecution(hit.Signature.Id, insts[0], "minecraft-signature", null);
            ctx.Add(new Finding(Name, sev,
                $"Known cheat detected: {hit.Signature.Name}",
                $"Signature '{hit.Signature.Id}' matched in {insts.Count} Minecraft instance(s) "
                + $"(confidence {hit.Confidence}/{hit.Signature.MinConfidence}).",
                new { hit.Signature.Family, hit.Signature.Type, hit.MatchedOn, instances = insts, hit.Signature.References },
                SortKey: 0));
        }

        await ctx.ModuleDone(Name, 0);
    }

    private static DateTime InstanceRecency(string inst)
    {
        try
        {
            var mods = Path.Combine(inst, "mods");
            var logs = Path.Combine(inst, "logs");
            return new[] { inst, mods, logs }.Where(Directory.Exists)
                .Select(Directory.GetLastWriteTimeUtc).DefaultIfEmpty(DateTime.MinValue).Max();
        }
        catch { return DateTime.MinValue; }
    }

    private int ScanMods(string inst, MatchTarget target, ref int jarBudget, CancellationToken ct)
    {
        var modsDir = Path.Combine(inst, "mods");
        if (!Directory.Exists(modsDir) || jarBudget <= 0) return 0;

        var jars = SafeFiles(modsDir, "*.jar").Take(jarBudget).ToList();
        jarBudget -= jars.Count;

        Parallel.ForEach(jars,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Min(6, Environment.ProcessorCount), CancellationToken = ct },
            jar =>
            {
                var name = Path.GetFileName(jar);
                var entryBlob = new System.Text.StringBuilder();
                var texts = new List<string>();
                string? hash = null;
                try
                {
                    var fi = new FileInfo(jar);
                    if (fi.Length <= MaxJarBytes)
                    {
                        if (db.NeedsHashes)
                            using (var fs = File.OpenRead(jar))
                                hash = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();

                        using var zip = ZipFile.OpenRead(jar);
                        var entryCap = 800;
                        foreach (var entry in zip.Entries)
                        {
                            if (entryCap-- <= 0) break;
                            entryBlob.Append(entry.FullName).Append('\n'); // one blob per jar, not one string per entry
                            var lname = entry.Name.ToLowerInvariant();
                            if (entry.Length is > 0 and < 64 * 1024 &&
                                (lname is "fabric.mod.json" or "mcmod.info" or "mods.toml" or "manifest.mf"
                                 || lname.EndsWith(".mixins.json")))
                            {
                                using var r = new StreamReader(entry.Open());
                                texts.Add(r.ReadToEnd());
                            }
                        }
                    }
                }
                catch { /* corrupt / locked jar — name alone still contributes */ }

                lock (target)
                {
                    target.FileNames.Add(name);
                    if (entryBlob.Length > 0) target.Strings.Add(entryBlob.ToString());
                    target.LogText.AddRange(texts);
                    if (hash is not null) target.Hashes.Add(hash);
                }
            });
        return jars.Count;
    }

    private static void ScanVersions(ScanContext ctx, string inst, MatchTarget target)
    {
        var versionsDir = Path.Combine(inst, "versions");
        if (!Directory.Exists(versionsDir)) return;

        foreach (var vdir in SafeDirs(versionsDir))
        {
            var vname = Path.GetFileName(vdir);
            var json = Path.Combine(vdir, vname + ".json");
            target.FileNames.Add(vname + ".jar");
            if (!File.Exists(json)) continue;
            string text;
            try { text = File.ReadAllText(json); } catch { continue; }

            try
            {
                using var doc = JsonDocument.Parse(text);
                var root = doc.RootElement;
                if (root.TryGetProperty("mainClass", out var mc))
                {
                    var main = mc.GetString() ?? "";
                    if (main.Length > 0 && !main.StartsWith("net.minecraft") && !main.StartsWith("cpw.mods")
                        && !main.StartsWith("net.fabricmc") && !main.StartsWith("org.quiltmc")
                        && !main.Contains("bootstrap"))
                        ctx.Add(new Finding("minecraft", Severity.Medium,
                            $"Custom launch mainClass in version '{vname}'",
                            $"The version manifest uses a non-standard mainClass ({main}).",
                            new { version = vname, mainClass = main }, SortKey: 18));
                }
                var args = text.ToLowerInvariant();
                if (AgentFlags.Any(args.Contains))
                    ctx.Add(new Finding("minecraft", Severity.High,
                        $"JVM agent flag in version manifest '{vname}'",
                        "The version manifest injects a Java agent (-javaagent / -agentpath / -agentlib).",
                        new { version = vname }, SortKey: 6));
            }
            catch { /* not JSON we understand */ }
        }
    }

    private void ScanLogs(string inst, MatchTarget target)
    {
        var logsDir = Path.Combine(inst, "logs");
        if (!Directory.Exists(logsDir)) return;
        long budget = Math.Min(MaxLogBytesPerInstance, Interlocked.Read(ref _logBudget));

        foreach (var f in SafeFiles(logsDir, "*.log").Concat(SafeFiles(logsDir, "*.log.gz"))
                     .OrderByDescending(File.GetLastWriteTimeUtc))
        {
            if (budget <= 0) break;
            try
            {
                string text;
                if (f.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                {
                    using var fs = File.OpenRead(f);
                    using var gz = new GZipStream(fs, CompressionMode.Decompress);
                    using var r = new StreamReader(gz);
                    text = r.ReadToEnd();
                }
                else
                {
                    text = File.ReadAllText(f);
                }
                if (text.Length > budget) text = text[..(int)budget];
                budget -= text.Length;
                Interlocked.Add(ref _logBudget, -text.Length);
                lock (target) target.LogText.Add(text);
            }
            catch { /* skip */ }
        }
    }

    private void ScanLauncherProfiles(ScanContext ctx, string inst)
    {
        var lp = Path.Combine(inst, "launcher_profiles.json");
        if (!File.Exists(lp)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(lp));
            if (!doc.RootElement.TryGetProperty("profiles", out var profiles)) return;
            foreach (var p in profiles.EnumerateObject())
            {
                if (!p.Value.TryGetProperty("javaArgs", out var ja)) continue;
                var args = (ja.GetString() ?? "").ToLowerInvariant();
                var flag = AgentFlags.FirstOrDefault(args.Contains);
                if (flag is not null)
                    ctx.Add(new Finding("minecraft", Severity.High,
                        $"Launcher profile '{p.Name}' injects a Java agent",
                        $"launcher_profiles.json profile '{p.Name}' has JVM args containing '{flag}'. This is how many injection cheats attach at launch.",
                        new { profile = p.Name }, SortKey: 4));
            }
        }
        catch { /* ignore malformed */ }
    }

    private static void ScanConfig(ScanContext ctx, string inst)
    {
        var cfg = Path.Combine(inst, "config");
        if (!Directory.Exists(cfg)) return;
        foreach (var entry in SafeDirs(cfg).Concat(SafeFiles(cfg, "*")))
        {
            var n = Path.GetFileName(entry);
            if (Forensics.LooksLikeCheat(n))
                ctx.Add(new Finding("minecraft", Severity.Medium,
                    $"Suspicious config entry: {n}",
                    "A file or folder under config/ matches known cheat naming.",
                    new { path = entry }, SortKey: 14));
        }
    }

    private static IEnumerable<string> SafeFiles(string p, string pat)
    {
        try { return Directory.EnumerateFiles(p, pat); } catch { return []; }
    }

    private static IEnumerable<string> SafeDirs(string p)
    {
        try { return Directory.EnumerateDirectories(p); } catch { return []; }
    }
}
