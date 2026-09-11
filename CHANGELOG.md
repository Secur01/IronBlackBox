# Changelog

## v1.1.0 — 2026-09-10

**If you run `Enable-WefCollector` on a schedule, expect it to start reporting
findings on a collector that read clean under v1.0.1. The findings are true.
This release does not change what the collector does — it changes what the
script is willing to call healthy.**

Nothing else in the toolkit changes behaviour. The other nineteen scripts are
byte-identical apart from their version string.

### `Enable-WefCollector` called a dead collector healthy

Measured on the lab collector on 2026-09-10. Its `-Audit` printed this:

```
328993 event(s) collected, last write 2026-08-30T23:26:44Z
[ ok ] No findings: this host is collecting forwarded events.
```

Ten days without a single forwarded event, read, printed, and then declared
healthy at exit `0`. Every other reading agreed with it: `wecutil gr` said
`RunTimeStatus: Active` and `LastError: 0`, and the collector's own
`Microsoft-Windows-EventCollector/Operational` channel held zero records. A
collector that has silently stopped collecting was indistinguishable from a
working one, and the script whose job is to say otherwise said `[ ok ]`.

The script was not missing the data. It fetched the last-write time, showed it to
a human, and never tested it.

**What to do:** re-run `Enable-WefCollector -Audit` on your collector and read
what it now says. If it reports staleness, the events you think you are
collecting are not arriving, and they have not been for as long as it says.

### Three checks added, all on data the script already read

| Check | New finding when |
|---|---|
| Is anything still arriving? | the newest event in `ForwardedEvents` is older than `-MaxForwardedEventAgeHours` (default **48**, `0` disables) and the channel is not empty |
| Is the channel full? | the `.evtx` is at or over its own `MaximumSizeInBytes` |
| May the collector answer? | the URL ACL on `http://+:5985/wsman/` does not grant `NT SERVICE\Wecsvc` |

The staleness check only fires on a channel that already holds events, so it
reads *"this collector used to work and has stopped"* rather than *"this
collector is new"* — an empty channel already had its own finding. A collector
whose sources are all legitimately offline reads the same way, and the finding
says so and names the parameter to raise.

The full-channel check exists because the lab collector's `ForwardedEvents.evtx`
was measured **4096 bytes over** its own 2 GB maximum in `Circular` mode while
the capacity section passed. That section compares the *configured* cap against
the target and is right to pass — a floor check cannot fail on a full channel —
so the question had to be asked where the runtime size is read.

### The one that would have saved an afternoon

The endpoint check has always proven that the `SubscriptionManager` URL is
*reserved*. It never asked whether the collector service is *allowed to use it*.

On the lab collector the reservation was present, `Wecsvc` and `WinRM` shared one
process so the existing W-1 diagnosis did not apply, and every source still
failed **every** delivery with WS-Man `2150859027` — zero events arriving. The
URL ACL on `http://+:5985/wsman/` granted only `NT SERVICE\WinRM`. This is
Microsoft KB4494462.

Adding `NT SERVICE\Wecsvc` to the ACL produced `EventDelivery completed
successfully` on the next cycle, and **221 events reached the collector from a
Windows 11 client**.

`Enable-WefCollector` now reports this per URL and carries the exact two `netsh`
commands. **It does not run them.** `netsh http add urlacl` rewrites a
machine-wide HTTP reservation that WinRM itself listens on, and this toolkit does
not alter WinRM hosting — the same reason it has never tried to fix W-1.

**What to do:** if the new finding appears, run the two printed commands
deliberately and restart `Wecsvc`. Read them first; they replace an ACL that
WinRM depends on.

### `Enable-WefCollector` no longer modifies a workstation to fail on it

A WEF collector is a role you assign to one host, not a property a host has, so
this script has always done exactly what you asked. On a Windows 11 client that
meant setting `Wecsvc` to Running/Automatic and sizing `ForwardedEvents` to 2 GB
**before** discovering it could not activate the subscription, then exiting `2`
— a host modified for a role it will never hold, and a rollback left facing a
partial apply.

It now reads `ProductType`, and on a client SKU it declines at exit `0` having
changed nothing, naming `Enable-WefClient` as the script you wanted. The gate
sits before the lock and before the manifest, so an `-Apply` on a workstation
writes no run record either. `-Rollback` is exempt: the manifest, not the host's
SKU, is the authority on what this toolkit changed, so a workstation armed by
v1.0.1 can still be undone.

**If a workstation really is your collector, pass `-AllowClientSku`** and the
behaviour is exactly what it was.

**This gate catches only the client case.** On a *server* that is not your
collector, this script still does what you ask. `docs/DEPLOYMENT.md` §4 is still
the place that tells you to scope it deliberately.

### Validation

`docs/VALIDATION.md` gains a Windows 11 domain-member pass: all twenty scripts
through the full contract on a domain-joined Windows 11 Pro client, nine with
real changes applied and restored. Windows Event Forwarding from a client SKU is
now proven end to end, which it was not in v1.0.1.


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
