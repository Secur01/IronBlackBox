# Changelog

## v1.0.1 — 2026-09-09

**Two false alerts on Windows 10/11 endpoints. If you deployed v1.0.0 to
workstations, you are affected, and neither alert means what it said.**

Both were found the first time the toolkit ran on a client SKU — Windows 11 Pro
build 26200. Every level in `docs/VALIDATION.md` before this release was
measured on Windows Server 2019, which is why neither showed up sooner.

### `Remove-PowerShellV2` reported a PowerShell 2.0 bypass that does not exist

On Windows 11 build 26200 PowerShell 2.0 is gone entirely: no
`MicrosoftWindowsPowerShellV2*` optional feature, no
`HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine` key, no .NET 3.5. But
`powershell.exe -Version 2` there prints *"PowerShell 2.0 has been deprecated.
Using default PowerShell instead."*, runs the command under 5.1, and **exits 0**.

v1.0.0 read that exit code as proof the v2 engine had run and raised:

```
[find] PowerShell 2.0 CAN RUN on this host - ScriptBlock logging can be bypassed
```

An exposure that does not exist, as a finding, two lines above the script's own
correct *"nothing to remove"*. No `-Apply` could clear it, so it was a permanent
exit `1` on every Windows 10/11 host in a fleet.

**What to do:** nothing, beyond updating. The alert was false. If your monitor
recorded exposure on workstations, disregard those records.

**Fixed by** asking the child process what version it is instead of reading its
exit code. A `2` means a v2 engine really ran; a `5` means the switch fell back.
No readable answer is reported as undetermined — never as an exposure, and never
as an all-clear.

### `Enable-VssPreservation` exited 2 on every workstation

A client SKU cannot create a shadow copy storage association. Measured side by
side: `vssadmin` on Windows 11 offers `Resize ShadowStorage` but **not** `Add
ShadowStorage`, while Windows Server 2019 offers both. `Win32_ShadowStorage` is
present on the client with a `Create` method, and `Create` answers **return code
10**, which is not in Microsoft's documented set for it.

v1.0.0 threw on that unmapped code and the run exited `2` — the code
`docs/DEPLOYMENT.md` §2 tells you to alert as a **broken deployment**, on every
workstation, for a capability Windows never offered.

**What to do:** nothing, beyond updating. It was never a deployment fault.

**Fixed by** reporting it as a host limit, which by design does not raise the
exit code, and by saying so before any manifest record is written. The remaining
exit `1` on such a host is the real and clearable *"arm
`Enable-VssSnapshotSchedule`"*. That sibling script is unaffected and completes
its full contract on a client, so the snapshot half of the VSS pair works there
even though the storage half cannot.

### Also in this release

- `docs/DEPLOYMENT.md` gains a section on what these scripts do on Windows 10/11
  workstations, and records that `Enable-WefCollector` modifies a host before
  discovering it is not a collector.
- `docs/VALIDATION.md` records the Windows 11 pass: nine scripts hold a full
  `-Audit` → `-Apply` → `-Apply` → `-Rollback` cycle on build 26200, five
  applied nothing there so the rollback half was not exercised, and two decline
  by design. Older Windows 10 and 11 builds remain unmeasured.
- `verification/facts.json` records both measurements, so neither has to be
  re-derived.

No behaviour changed on Windows Server. Both fixes were re-verified on Server
2019 build 17763 as well as on the client.

## v1.0.0 — 2026-09-08

First public release. 20 scripts in two layers, each with a dated row in
`docs/VALIDATION.md`.
