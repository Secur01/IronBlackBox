# IronBlackBox

[![Atomic Red Team: 19 techniques](https://img.shields.io/badge/Atomic%20Red%20Team-19%20techniques-00AEEF?style=flat-square&labelColor=373637)](docs/ATOMIC-VALIDATION.md)
[![Unarmed host: 11 of 21 leave no trace](https://img.shields.io/badge/unarmed%20host-11%20of%2021%20leave%20no%20trace-FA5A3C?style=flat-square&labelColor=373637)](docs/ATOMIC-VALIDATION.md)
[![Proven on Windows Server 2019](https://img.shields.io/badge/proven%20on-Windows%20Server%202019-146EFA?style=flat-square&labelColor=373637)](docs/VALIDATION.md)

An aircraft black box survives the crash and tells investigators what happened.
IronBlackBox does the same job for a Windows host: turn it on before the
incident, or stay blind during the investigation.

It is a PowerShell toolkit for MSP and DFIR teams, built around two layers you
deploy **before** anything goes wrong — arm the recorder, then protect it from
the crash.

| Folder | Job | Scripts |
|---|---|---|
| `logging-hardening/` | Arm the recorder — turn on the forensic logging Windows leaves off | 11 |
| `anti-tampering/` | Protect the recorder — stop an attacker or a careless tech from switching it back off | 7 |

Reading the recorder *after* the crash is the third layer. It lives in
[`Secur01/IronBlackBox-IR`](https://github.com/Secur01/IronBlackBox-IR) and
stays **private**: publishing the hardening helps defenders, publishing the
collection half publishes the hunt plan.


## Validation status — read this first

**Measured against real attacks, not asserted.** 21 ATT&CK techniques across 8
tactics were executed on a live domain-joined Windows Server, twice — once on a
stock host and once with this toolkit armed, both from the same AMI baseline.
**19 came from Atomic Red Team at a pinned commit; 2 were run by hand** because
those techniques are absent from that commit, and both are marked `(manual)` in
the matrix.
**11 of the 21 leave no trace whatsoever on a stock host.** Armed, 17 carry
evidence attributed by matching the attacker's own command line, and **20 of the
21 are reconstructable from the collected evidence package alone**. The full
per-technique matrix — including what was *not* tested, and the defect the
exercise found in this toolkit — is in
**[docs/ATOMIC-VALIDATION.md](docs/ATOMIC-VALIDATION.md)**.

**All 20 scripts carry a dated row in
[docs/VALIDATION.md](docs/VALIDATION.md)**, the only file in this repository
allowed to say where a script has run. **Six reached L4**, exercised against the
class of host they are actually for: `Enable-IRVisibility`,
`Enable-LegacyAuthAudit`, `Enable-AdObjectAuditing`, `Enable-DnsVisibility`
including its DNS-server half, and both halves of Windows Event Forwarding.
Twelve reached L3 — a full `-Audit` → `-Apply` → `-Apply` → `-Rollback` cycle
with the host restored to its exact baseline. Two are L2: `Test-VisibilityDrift`
and `Test-DefenderPosture` are read-only, so there is no `-Apply` to prove and
L2 is their ceiling. Every script that has an `-Apply` is L3 or better. Read the
row, not this paragraph — the caveats live there.

**Event forwarding is proven end to end, not merely configured.** A collector and
a client were built on two real machines, and **145 events arrived in
`ForwardedEvents`** from the member — with the source listed under `EventSources`
and heartbeating, and WinRM logging `EventDelivery completed successfully`.
Getting there required fixing two defects this toolkit had, which is the point of
running it for real.

Where an effect can be observed, it is observed rather than inferred — 4104 and
4103 events for PowerShell logging, an 8003 for an AppLocker rule, a Sysmon
event ID 1 for a process start, an alert file written five seconds after a log
was cleared. Reading a setting back out of the registry proves only that the
registry holds it, and running these scripts found defects the static gate had
passed in silence: an AppLocker policy that was in the store and never
evaluated, a working Sysmon reported as collecting nothing, a Defender baseline
that absorbed the exclusion it had just flagged.

Per-script state is in [`docs/VALIDATION.md`](docs/VALIDATION.md), which is the
only file allowed to claim a script ran somewhere. **A script with no row there
has never run anywhere.**

**What this does not cover.** One Windows version, one domain, one OS build. It
says nothing about client SKUs or non-English Windows, no EDR was present, and
this toolkit records rather than blocks — nothing here claims an attack was
stopped. Read a script before you run it as SYSTEM on a machine you care about;
they are standalone and written to be read.

## Modes and exit codes

Every script that changes anything has three modes. `Test-VisibilityDrift`
is read-only by design and has `-Audit` only:

- `-Audit` (default) — strictly read-only. Reports current state and what
  `-Apply` would change.
- `-Apply` — makes the change, recording the previous value first.
- `-Rollback` — restores what a prior `-Apply` recorded.

Exit codes are uniform, so an RMM can alert on them without parsing output:

| Code | Meaning |
|---|---|
| `0` | Nothing needs doing, or a successful `-Apply` / `-Rollback` |
| `1` | Something needs doing — RMM-alertable |
| `2` | Execution error, including "not running elevated" |

The trade-off of that uniformity: `1` means **an action exists**, so two classes
of true statement are printed and deliberately kept out of the exit code — host
limits no `-Apply` can clear, and tamper indicators a prior `-Apply` already
reported. Both are named and counted in each script's `Result` section, but an
RMM watching only the exit code will not see them. That is what makes `0` mean
something on a healthy fleet; it also means a human has to read the output at
least once per host. `docs/DESIGN.md` §3.1 is the reasoning.

**`1` means an action exists, not that a condition exists.** That distinction is
what keeps the signal worth having. Some things are simply true of a host and no
run of this toolkit will change them: tamper protection cannot be turned on
without Intune, and a server on NVMe has been measured writing `EnablePrefetcher`
and having Windows remove it again minutes later. Those print as `[limit]`, are
counted separately, and **do not raise the exit code** — because a monitor that
is red on a host forever gets muted, and then it hides the findings that did
matter.

So `[find]` always has a lever behind it: a switch to pass, a file to stage, an
exclusion to remove. `[limit]` has none, and says so. Measured 2026-09-02 on the
armed lab host, across the eighteen scripts in the repository at that date:
eleven exited `0`, and every remaining `1` named something an operator could act
on. The count is left as it was measured rather than restated for the twenty
scripts here now — a number nothing re-ran is not a result.

## Requirements

- Windows PowerShell 5.1 (in-box; no PowerShell 7 dependency).
- Local administrator rights, or SYSTEM via an RMM.
- No module installation — in-box cmdlets and .NET only.

## Disk footprint

Arming forensic logging costs disk, and an MSP deploying to a fleet is entitled
to the number before it deploys. Every figure below is the **configured
ceiling**, measured with `wevtutil gl` and `vssadmin` on a lab host after a full
`-Apply`, not an estimate.

The distinction that matters most: **Windows event channels are circular.** A
channel sized to 2 GB does not grow to 2 GB and keep going — it reaches 2 GB and
begins overwriting its own oldest events. The ceiling is a one-time cost, not a
growth rate. On the measured host every channel below was armed and the actual
`winevt\Logs` directory held **610 MB** of actual data. That measurement predates the
lateral-movement channels in the table below, so the ceiling it was measured against
was 3.2 GB rather than today's 3.6 GB - the point it makes about a ceiling not being
a growth rate is unchanged, and stronger.

| What | Default ceiling | Set by |
|---|---|---|
| `Security` | 2,048 MB | `Enable-IRVisibility` (`-SecurityLogSizeKb`) |
| `Application`, `System` | 256 MB each | `Enable-IRVisibility` (`-OtherLogSizeKb`) |
| `Microsoft-Windows-PowerShell/Operational` | 256 MB | `Enable-IRVisibility` (`-PowerShellChannelSizeBytes`) |
| `Windows PowerShell` | 256 MB | `Enable-IRVisibility` (`-PowerShellChannelSizeBytes`) |
| Firewall logs, 2 profiles | 16 MB each, **doubled** — Windows keeps a `.old` | `Enable-IRVisibility` (`-FirewallLogSizeKb`) |
| `Microsoft-Windows-AppLocker/EXE and DLL` | 128 MB | `Enable-LolbinAudit` (`-AppLockerChannelSizeBytes`) |
| RDP and SMB channels, 5 of them | 64 MB each | `Enable-IRVisibility` (`-LateralMovementChannelSizeBytes`) |
| PowerShell transcripts | **2,048 MB** | `Enable-IRVisibility` (`-TranscriptMaxBytes`) |
| VSS shadow storage | **12% of the volume** | `Enable-VssPreservation` |
| `ForwardedEvents` (collector role only) | 2,048 MB | `Enable-WefCollector` (`-ForwardedEventsSizeMb`) |
| DNS server debug log (DC only) | 256 MB | `Enable-DnsVisibility` (`-DnsServerLogMaxSizeBytes`) |

Channels the toolkit leaves at their Windows defaults — DNS-Client, Task
Scheduler, WMI-Activity, Defender — come to **76 MB** by adding up the four
ceilings measured individually on that host. The four figures are measurements;
the total is arithmetic.

**On a member server, budget roughly 5.6 GB plus 12% of the volume.** That is
about 3.6 GB of circular channels, 2 GB of transcripts, and VSS scaling with
disk size — 9.6 GB on the measured 80 GB volume, but **60 GB on a 500 GB
volume**, which is the figure to check before deploying to a file server. Lower
it with `Enable-VssPreservation -ShadowStoragePercent`.

### Transcripts are the one thing that would otherwise grow forever

PowerShell writes transcripts into `YYYYMMDD` day folders and never removes
them. `Enable-IRVisibility -Apply` therefore registers a daily rotation task
alongside transcription itself:

| Parameter | Default | Effect |
|---|---|---|
| `-TranscriptCompressAfterDays` | `7` | Day folders older than this are zipped (measured 2.7:1 on real transcripts) |
| `-TranscriptKeepDays` | `90` | Archives older than this are deleted |
| `-TranscriptMaxBytes` | `2 GB` | A **backstop**, not the policy |
| `-DisableTranscription` | off | Turns transcription off instead, reversibly |

Today's and yesterday's transcripts are never touched, and nothing is deleted
that could not first be archived.

The backstop **reports rather than absorbs**. If the size cap ever has to evict
a day that is still inside `-TranscriptKeepDays`, it writes a finding saying so,
and `-Audit` raises it as exit `1`:

```
FINDING the size backstop evicted 20260713, only 50 days old, inside the
90-day retention policy. This host generates more transcript volume than
-TranscriptMaxBytes allows, so the REAL retention here is shorter than the
policy says.
```

A silent size cap would quietly turn "we keep 90 days" into a promise the host
cannot honour — and you would find out during an investigation, which is the
worst possible time. This way your RMM tells you first.

### Measuring your own hosts

Ceilings are policy; what a host actually generates is a fact about that host.
There are two different questions and they need two different commands.

**How much history does each channel actually hold?** This is the one that
matters, and the one a ceiling cannot answer. An event log is circular, so the
useful number is the age of its oldest surviving event:

```powershell
'Security','Microsoft-Windows-PowerShell/Operational','Windows PowerShell',
'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
'Microsoft-Windows-SmbClient/Security','Microsoft-Windows-SMBServer/Security',
'Microsoft-Windows-SMBServer/Audit','Microsoft-Windows-AppLocker/EXE and DLL' |
    ForEach-Object {
        $log = Get-WinEvent -ListLog $_ -ErrorAction SilentlyContinue
        $oldest = $null
        try { $oldest = (Get-WinEvent -LogName $_ -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated }
        catch { }
        [pscustomobject]@{
            Channel     = ($_ -replace 'Microsoft-Windows-','')
            CeilingMB   = [math]::Round($log.MaximumSizeInBytes / 1MB)
            UsedMB      = [math]::Round($log.FileSize / 1MB, 1)
            HistoryDays = if ($oldest) { [math]::Round(((Get-Date) - $oldest).TotalDays, 1) } else { 'no events' }
        }
    } | Format-Table -AutoSize
```

Measured on the lab host, and the second row is the point:

```
Channel                                              CeilingMB UsedMB HistoryDays
Security                                                  2048   42.1         2.9
PowerShell/Operational                                     256    256         0.8
Windows PowerShell                                         256    256         1.8
TerminalServices-LocalSessionManager/Operational             1    0.1         2.8
TerminalServices-RemoteConnectionManager/Operational         1    0.1         2.8
SmbClient/Security                                           8    0.1   no events
SMBServer/Security                                           8    0.1   no events
SMBServer/Audit                                              8    0.1   no events
AppLocker/EXE and DLL                                      128    3.1         2.9
```

Both PowerShell channels are **full and hold under two days**, on a host doing
nothing but this project's own testing. `Security` is using 2% of its 2 GB and
holds three days. The three SMB channels have never recorded an event here, which
is why this project will not tell you what they cost on a file server.

A ceiling tells you what a channel is *allowed* to consume. Only `HistoryDays`
tells you whether the window covers the incident you have not had yet — and it is
the only column that gets worse as a host gets busier.

**How much disk is committed?** Note what the first command measures: the
ceiling of **every channel on the host**, not just the ones this toolkit sizes.
On the lab that is 7,390 MB against 960 MB actually on disk, and this toolkit's
own share of that ceiling is the ~3.6 GB in the table above. If your number is
far larger, something other than this toolkit is sizing channels.

```powershell
(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
    Measure-Object -Property MaximumSizeInBytes -Sum).Sum / 1MB

(Get-ChildItem "$env:SystemRoot\System32\winevt\Logs" -File |
    Measure-Object Length -Sum).Sum / 1MB

vssadmin list shadowstorage
```

**How much transcript volume does this host really produce per day?**

```powershell
Get-ChildItem 'C:\ProgramData\IronBlackBox\Transcripts' -Directory |
    Where-Object Name -match '^\d{8}$' |
    ForEach-Object {
        $b = (Get-ChildItem $_.FullName -File -Recurse |
              Measure-Object Length -Sum).Sum
        [pscustomobject]@{ Day = $_.Name; MB = [math]::Round($b / 1MB, 2) }
    } | Sort-Object Day
```

If a host's real daily transcript volume times `-TranscriptKeepDays` exceeds
`-TranscriptMaxBytes`, raise the cap or lower the retention so the two agree —
the rotation task will tell you the same thing, but after the fact.

## Distribution

Two methods, and only two:

1. **Standalone.** Take the `.ps1` files you need and build your own RMM
   components. Read exactly the code that will run before you deploy it.
2. **Release ZIP.** Each release ships the toolkit plus `SHA256SUMS.txt`.
   Extract under `C:\ProgramData\IronBlackBox\`.

There is no bootstrap or downloader, and there will not be one.
`SYSTEM + PowerShell + download + execute` is a pattern EDR products flag, and
correctly — this project will not ask anyone to carve out an exception to their
EDR to solve what is a packaging problem.

### Removing it again

There is no installer, so there is no uninstaller. The undo is per script:
`-Rollback` each one, newest run first, and read
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) §7 first — a rollback can decline on
purpose, and a few changes report `declined-permanent` because this OS cannot
reverse them.

**A fully rolled-back host still has files on it, deliberately.** No script
deletes the toolkit root, and none deletes the `\IronBlackBox\` Task Scheduler
folder it registered its tasks in — `-Rollback` removes the tasks themselves and
nothing more. What is left under `C:\ProgramData\IronBlackBox\`:

| What | Why it is still there |
|---|---|
| `manifest.jsonl` | It is what `-Rollback` reads. It has to outlive the changes, and afterwards it is the record of what was done to the host |
| `Transcripts\` | PowerShell transcripts predating the rollback. A script that deleted evidence it did not write this run would be indefensible |
| The tamper alert log and the handler script | `Deploy-TamperAlerts -Rollback` says it out loud: the alert log is evidence, and a rollback does not delete evidence |

Whether to delete those is your call and your retention policy's, not this
toolkit's — but delete nothing until every script has been rolled back, because
the manifest is the only record of what to restore. One consequence worth
knowing: the root's DACL is applied on every run, so a root left behind on a
decommissioned host is a directory nothing is checking any more.

## Documentation

| File | What it is |
|---|---|
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Pushing this to a fleet: the invocation, the exit codes, the order, the undo |
| [`docs/ARTIFACT-MATRIX.md`](docs/ARTIFACT-MATRIX.md) | Every forensic artifact, and which script arms it, protects it, or collects it |
| [`docs/SCRIPTS.md`](docs/SCRIPTS.md) | Every script, what it is for, and the order to deploy them in |
| [`docs/DESIGN.md`](docs/DESIGN.md) | Conventions, the manifest contract, exit codes |
| [`docs/VALIDATION.md`](docs/VALIDATION.md) | What has actually been proven, and how |
| [`docs/AUTHORING.md`](docs/AUTHORING.md) | How to write one of these, and the traps already paid for |
| [`docs/ATOMIC-VALIDATION.md`](docs/ATOMIC-VALIDATION.md) | 21 ATT&CK techniques measured on a live host, armed and unarmed |

Three shipped files are not documents but are worth knowing about, because they
are what the claims above rest on:

| File | What it is |
|---|---|
| [`verification/facts.json`](verification/facts.json) | The provenance ledger — 98 rows, each carrying where the fact came from and how far it was proven. Every Windows literal in every script (registry path, audit GUID, event ID, SDDL mask) traces to a row here or is marked unverified. One row is marked `RETRACTED`. It is this project's answer to "how do you know?" |
| [`tools/check.ps1`](tools/check.ps1) | The static gate: BOM, AST parse, banned PowerShell 7 syntax, PSScriptAnalyzer, and the helper drift check |
| [`docs/SCRIPT-TEMPLATE.ps1`](docs/SCRIPT-TEMPLATE.ps1) | The helper regions every script copies verbatim. `check.ps1` fails the build on an edited copy, which is what makes 18 standalone scripts agree on what the manifest means |

## Reporting a security issue

**Do not open a public issue for a flaw in these scripts.** They run as SYSTEM,
frequently on domain controllers, so a flaw here is a flaw on every host the
toolkit was deployed to — and a public issue tells those fleets before it tells
the maintainer.

Report it privately through GitHub's private vulnerability reporting on
[`Secur01/IronBlackBox`](https://github.com/Secur01/IronBlackBox): the
repository's **Security** tab, **Report a vulnerability**. Useful to include: the
script, the mode (`-Audit`, `-Apply` or `-Rollback`), what an attacker who
already has a foothold gains, and whether a manifest record is involved.

If that route is not available to you, open an issue that asks for a private
channel and says nothing about the flaw itself. Withholding the details costs a
day; publishing them costs whoever is running this today.

Ordinary bugs, wrong Windows facts and documentation errors are not security
issues — a public issue is the right place for those.

## Contributing

Not open yet — conventions are still being defined.

## License

MIT — see [`LICENSE`](LICENSE).

**Disclaimer.** These scripts modify audit policy, security settings and other
system configuration. They are provided as-is with no warranty. You are
responsible for reviewing and validating every script in your own environment
before running it against any system you care about.
