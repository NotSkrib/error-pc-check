# ZenithDecoy — external-macro detection test

**Not a cheat.** `ZenithDecoy` is an inert WinForms program. It has no input
automation, no `SendInput`, no screen capture, no process/memory access and no
game interaction of any kind. It exists only to carry the same *fingerprints* a
real external macro (e.g. `zenithmacros.store`) leaves on a PC, so the
screenshare client's `external-macro` module (`client/SSAC.Client/ExternalMacroModule.cs`)
can be exercised:

- a window titled **"Zenith Macros"**
- PE version info: `ProductName` = "Zenith Macros", `Company` = "Zenith",
  `FileDescription`, `FileVersion` 1.4.8
- unsigned, launched from a user folder, optionally under a renamed filename

## Run

```bash
dotnet publish test/ZenithDecoy/ZenithDecoy.csproj -c Release
P=test/ZenithDecoy/bin/Release/net8.0-windows/win-x64/publish/ZenithDecoy.exe

# rename to something innocuous and run from Downloads (tests rename evasion)
cp "$P" "$USERPROFILE/Downloads/SystemHelper.exe"
printf '; test\n' > "$USERPROFILE/Downloads/crystal-macro.ahk"
"$USERPROFILE/Downloads/SystemHelper.exe" &

# then run a scan (or --selftest) and check the external-macro findings
dotnet client/SSAC.Client/bin/Release/net8.0-windows/win-x64/ssac-screenshare.dll --selftest

# cleanup
taskkill /IM SystemHelper.exe /F
rm "$USERPROFILE/Downloads/SystemHelper.exe" "$USERPROFILE/Downloads/crystal-macro.ahk"
```

## Results (2026-09-07, client 0.4.0)

| Decoy state | `external-macro` verdict |
|---|---|
| renamed file, window "Zenith Macros" | **HIGH** — "External macro / cheat program running: SystemHelper.exe" (window title) |
| renamed file, neutral window title, PE metadata intact | **HIGH** — matched on embedded `ProductName` |
| renamed file, neutral title, **all** version info stripped | not flagged as a process — only the `.ahk` file is (MEDIUM) |
| `crystal-macro.ahk` in Downloads | **MEDIUM** — "Macro script on disk" (always) |

So the module closes the "renamed `.exe`" gap as long as the binary keeps a
recognisable window title **or** its embedded product/company metadata (real
products almost always do). A fully stripped, renamed, metadata-less binary with
a generic window title is still only "an unsigned GUI app from a user folder" —
catching that needs live input-hook / memory inspection (Phase 5).
