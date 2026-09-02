using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SSAC.Client;

/// <summary>
/// NTFS USN change journal reader (docs/phase-0-design.md §8, T7 headline source).
/// Surfaces recent file deletions — especially deleted *.pf and deleted mod jars —
/// which are the clearest sign of anti-forensic cleanup before a screenshare.
/// Needs an elevated volume handle; without it, emits module_unavailable.
/// </summary>
public sealed class UsnJournalModule : IScanModule
{
    public string Name => "usn-journal";
    public bool RequiresElevation => true;

    private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900f4;
    private const uint FSCTL_READ_USN_JOURNAL = 0x000900bb;
    private const uint USN_REASON_FILE_DELETE = 0x00000200;
    private const int MaxRecords = 400_000;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ctx.ModuleStart(Name, 0);

        if (!EnvironmentModule.IsElevated())
        {
            ctx.Add(new Finding(Name, Severity.Info, "USN journal not analysed",
                "Reading the NTFS change journal needs the tool to be run as administrator. Re-run elevated for deletion history (deleted Prefetch files, deleted mod jars).",
                SortKey: 20));
            await ctx.ModuleDone(Name, 0);
            return;
        }

        SafeFileHandle vol;
        try { vol = OpenVolume('C'); }
        catch (Exception ex)
        {
            ctx.Add(new Finding(Name, Severity.Info, "USN journal not readable",
                $"Could not open the C: volume ({ex.GetType().Name}).", SortKey: 20));
            await ctx.ModuleDone(Name, 0);
            return;
        }

        using (vol)
        {
            ulong journalId;
            try
            {
                (journalId, _, _) = QueryJournal(vol);
            }
            catch (Exception ex)
            {
                ctx.Add(new Finding(Name, Severity.Info, "USN journal query failed",
                    $"{ex.GetType().Name}. The journal may be disabled on this volume.", SortKey: 20));
                await ctx.ModuleDone(Name, 0);
                return;
            }

            int deletedPf = 0, deletedJar = 0, total = 0;
            DateTimeOffset? firstPfDelete = null;

            foreach (var (name, reason, ts) in ReadDeletions(vol, journalId, ct))
            {
                if (++total > MaxRecords) break;
                if ((reason & USN_REASON_FILE_DELETE) == 0) continue;

                var lower = name.ToLowerInvariant();
                if (lower.EndsWith(".pf"))
                {
                    deletedPf++;
                    firstPfDelete ??= ts;
                    if (deletedPf <= 20)
                        ctx.Add(new Finding(Name, Severity.High, $"Prefetch file was deleted: {name}",
                            "A .pf file was removed. Deleting Prefetch entries is a common way to hide which programs were run.",
                            new { name, deletedAt = ts }, ts, SortKey: 2));
                }
                else if (lower.EndsWith(".jar") || lower.EndsWith(".exe") || lower.EndsWith(".dll"))
                {
                    var cheat = Forensics.LooksLikeCheat(name);
                    deletedJar++;
                    if (cheat)
                        ctx.Add(new Finding(Name, Severity.Critical, $"Suspicious file deleted: {name}",
                            "A file whose name matches known cheat naming was deleted; the USN journal still records it.",
                            new { name, deletedAt = ts }, ts, SortKey: 0));
                    else if (lower.EndsWith(".jar"))
                        ctx.Add(new Finding(Name, Severity.Medium, $"Jar deleted: {name}",
                            "A .jar file was deleted recently.", new { name, deletedAt = ts }, ts, SortKey: 15));
                }
            }

            if (deletedPf > 0)
            {
                ctx.Signals.Add("usn:deleted-pf");
                if (deletedPf > 20)
                    ctx.Add(new Finding(Name, Severity.Critical, $"{deletedPf} Prefetch files deleted",
                        "A large number of .pf files were deleted according to the change journal — consistent with a bulk Prefetch wipe.",
                        new { count = deletedPf, firstAt = firstPfDelete }, firstPfDelete, SortKey: 0));
            }

            await ctx.Log(Name, $"{total} journal records scanned; {deletedPf} .pf, {deletedJar} jar/exe/dll deletions");
        }

        await ctx.ModuleDone(Name, 0);
    }

    // ---- native ----------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr sec, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle h, uint code,
        byte[]? inBuf, int inSize, byte[] outBuf, int outSize, out int returned, IntPtr overlapped);

    private static SafeFileHandle OpenVolume(char letter)
    {
        const uint GENERIC_READ = 0x80000000;
        const uint FILE_SHARE_RW = 0x00000003;
        const uint OPEN_EXISTING = 3;
        var h = CreateFileW($@"\\.\{letter}:", GENERIC_READ, FILE_SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) throw new IOException($"CreateFile failed ({Marshal.GetLastWin32Error()})");
        return h;
    }

    private static (ulong JournalId, long FirstUsn, long NextUsn) QueryJournal(SafeFileHandle vol)
    {
        var outBuf = new byte[64];
        if (!DeviceIoControl(vol, FSCTL_QUERY_USN_JOURNAL, null, 0, outBuf, outBuf.Length, out _, IntPtr.Zero))
            throw new IOException($"FSCTL_QUERY_USN_JOURNAL failed ({Marshal.GetLastWin32Error()})");
        var journalId = BitConverter.ToUInt64(outBuf, 0);
        var firstUsn = BitConverter.ToInt64(outBuf, 8);
        var nextUsn = BitConverter.ToInt64(outBuf, 16);
        return (journalId, firstUsn, nextUsn);
    }

    private static IEnumerable<(string Name, uint Reason, DateTimeOffset? Ts)> ReadDeletions(
        SafeFileHandle vol, ulong journalId, CancellationToken ct)
    {
        long startUsn = 0;
        var outBuf = new byte[64 * 1024];

        while (!ct.IsCancellationRequested)
        {
            // READ_USN_JOURNAL_DATA_V0 (40 bytes)
            var input = new byte[40];
            BitConverter.GetBytes(startUsn).CopyTo(input, 0);
            BitConverter.GetBytes(USN_REASON_FILE_DELETE).CopyTo(input, 8); // ReasonMask
            BitConverter.GetBytes(0u).CopyTo(input, 12);                    // ReturnOnlyOnClose
            BitConverter.GetBytes(0L).CopyTo(input, 16);                    // Timeout
            BitConverter.GetBytes(0L).CopyTo(input, 24);                    // BytesToWaitFor
            BitConverter.GetBytes(journalId).CopyTo(input, 32);

            if (!DeviceIoControl(vol, FSCTL_READ_USN_JOURNAL, input, input.Length,
                    outBuf, outBuf.Length, out var returned, IntPtr.Zero))
                yield break;
            if (returned <= 8) yield break;

            var next = BitConverter.ToInt64(outBuf, 0);
            var offset = 8;
            while (offset + 60 <= returned)
            {
                var recLen = BitConverter.ToInt32(outBuf, offset);
                if (recLen <= 0 || offset + recLen > returned) break;

                var reason = BitConverter.ToUInt32(outBuf, offset + 40);
                var tsRaw = BitConverter.ToInt64(outBuf, offset + 32);
                var nameLen = BitConverter.ToUInt16(outBuf, offset + 56);
                var nameOff = BitConverter.ToUInt16(outBuf, offset + 58);
                string name = "";
                if (nameOff > 0 && nameLen > 0 && offset + nameOff + nameLen <= returned)
                    name = System.Text.Encoding.Unicode.GetString(outBuf, offset + nameOff, nameLen);

                yield return (name, reason, Forensics.FromFileTimeUtc(tsRaw));
                offset += recLen;
            }

            if (next == startUsn) yield break;
            startUsn = next;
        }
    }
}
