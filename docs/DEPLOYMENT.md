# Deployment

For the engineer who has to push this to a few hundred endpoints tonight and be
able to sleep afterwards.

Everything below is either derived from the scripts themselves or measured on a
Windows Server 2019 host. Where this project has **not** exercised something, it
says so rather than guessing — `docs/VALIDATION.md` is the only file allowed to
claim a script ran somewhere.

## 1. Invoke through the wrapper, not through `-File`

Use this, and not `powershell.exe -File`:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { & 'C:\ProgramData\IronBlackBox\Enable-IRVisibility.ps1' -Apply; exit $LASTEXITCODE } catch { exit 2 }"
```

**Why it matters.** A parameter that PowerShell rejects at binding time never
reaches the script: the host writes its own error and exits `1`. Your RMM then
records `1` — the alertable state — on a host where nothing ran and nothing was
read. A typo in a component's parameter list looks exactly like a finding.

Measured, both forms, same host:

| Invocation | `-File` | wrapper |
|---|---|---|
| valid, nothing to do | `0` | `0` |
| valid, real findings | `1` | `1` |
| unknown parameter (`-Bogus`) | **`1`** | `2` |
| wrong type (`-SecurityLogSizeKb abc`) | **`1`** | `2` |
| value out of range (`-SecurityLogSizeKb 5`) | `2` | `2` |
| ambiguous (`-Audit -Apply`) | **`1`** | `2` |

The wrapper maps every bad invocation to `2` and leaves a valid run's own exit
code alone. A real `1` still arrives as `1`.

### The quoting trap, if your RMM shells out through PowerShell

The command above is written for a **cmd.exe** parent, which leaves `$` alone. If
the parent process is PowerShell, double quotes make it expand `$LASTEXITCODE`
before the child ever sees it. Measured — this is what actually gets passed:

```
try { & 'C:\...\Enable-IRVisibility.ps1'; exit  } catch { exit 2 }
```

`exit` with no argument. The exit code is silently lost and every host reports
`0`. Use **single quotes on the outside** when the parent is PowerShell:

```powershell
$cmd = 'try { & ''C:\ProgramData\IronBlackBox\Enable-IRVisibility.ps1'' -Apply; exit $LASTEXITCODE } catch { exit 2 }'
Start-Process powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command',$cmd) -Wait
```

## 2. What your monitor should alert on

| Exit | Meaning | Alert? |
|---|---|---|
| `0` | nothing needs doing | no |
| `1` | something needs doing | **yes** |
| `2` | the script could not do its job | **yes**, and differently — this is a broken deployment, not a host finding |

`1` means **an action exists**, not that a condition exists. Conditions no
`-Apply` will ever clear print as `[limit]` and deliberately do not raise the exit
code, because a monitor that is red on a host forever gets muted — and then it
hides the findings that mattered. `docs/DESIGN.md` §3.1 is the contract.

Alert on `2` separately from `1`. A fleet where `2` appears has a staging,
permission or parameter problem, and treating it as "findings" buries it.

### If you were already monitoring `Protect-DefenderConfig` for Defender posture

**Add `Test-DefenderPosture` to your schedule.** Until 2026-09-07,
`Protect-DefenderConfig` reported two unrelated things: whether Defender was
present, running and protecting, and whether an exclusion had appeared since the
baseline. It now reports only the second, and `Test-DefenderPosture` reports the
first.

This one matters more than a rename, because of the direction the change fails
in. A monitor still watching only `Protect-DefenderConfig` does not start
erroring — it starts returning `0` on a host whose real-time protection has been
switched off, and reads as healthy. Nothing in the toolkit can detect that you
have not scheduled the second script. `Protect-DefenderConfig`'s own no-findings
line now says in words that it did not check posture and names the script that
does, which is the only warning available at the point of use.

## 3. Order

Nothing here depends on another script having run first — each one reads the host,
decides, and records its own changes. Four orderings still matter.

1. **`Enable-IRVisibility` first.** It is what everything else protects. A host
   that has not been armed has nothing for `anti-tampering/` to defend and
   nothing for `Test-VisibilityDrift` to compare against.
2. **`Enable-WefCollector` before `Enable-WefClient`.** The collector has to be
   initialised before a source can reach it, and the client's own audit will
   report that it cannot.
3. **`Enable-VssPreservation` before `Enable-VssSnapshotSchedule`.** They were
   one script until 2026-09-07. The first arranges the shadow storage
   association; the second registers the task that writes into it. A task armed
   with no storage area runs on schedule and every snapshot fails, which looks
   like nothing at all in a log. `Enable-VssSnapshotSchedule -Audit` states that
   it does not check the storage area rather than measuring it, because measuring
   it would mean a second copy of the storage logic, and keeping two copies of a
   measurement is how they come to disagree.
4. **`Test-VisibilityDrift` last, then on a schedule.** It reads the manifest
   every other script writes, so it is only as complete as the runs before it.

## 4. Scripts that are not for every host

| Script | Target | On the wrong host |
|---|---|---|
| `Enable-AdObjectAuditing` | domain controllers | detects it and changes nothing |
| `Enable-LegacyAuthAudit` | domain controllers | detects it and changes nothing |
| `Enable-WefCollector` | the one collector | would make every host a collector — scope it deliberately |
| `Enable-Sysmon` | hosts where you have staged the binary and a config | refuses without `-ConfigPath`; it never downloads anything |

The two DC scripts are safe to send fleet-wide — they identify the host role and
decline. `Enable-WefCollector` is not: it does what you ask. Measured on a
Windows 11 client, it set Wecsvc to Running/Automatic and sized
`ForwardedEvents` to 2 GB **before** discovering it could not activate the
subscription, and exited 2. Scope it to the collector.

### On Windows 10/11 workstations

Measured 2026-09-09 on Windows 11 Pro build 26200 — the first client host this
toolkit has run on. Two things behave differently from a server, and both are
worth knowing before a fleet-wide push to workstations:

| Script | On a client SKU |
|---|---|
| `Enable-VssPreservation` | **Cannot create a shadow storage association.** `vssadmin` on a client offers `Resize ShadowStorage` but not `Add ShadowStorage`, so the script reports a `[limit]` and exits 1 on the remaining real finding rather than 2. An association Windows or System Restore already made can still be resized. |
| `Remove-PowerShellV2` | **Nothing to remove.** PowerShell 2.0 is absent from build 26200 entirely — no optional feature, no engine key. The script says so and exits 0. |
| `Enable-WefClient` | Works, and its `-Rollback` needs `-StopWinRmOnRollback` to finish. Without it, it restores everything except WinRM's state and says so: stopping a host's WinRM is not a decision it takes on its own. |

`Enable-VssSnapshotSchedule` is unaffected and completes its full cycle on a
client, so the snapshot half of the VSS pair works there even though the storage
half does not. Older Windows 10 and 11 builds are **not** measured — an MSP
fleet holds several, and `docs/VALIDATION.md` records only build 26200.

## 5. Reboots

**One script needs a restart: `Remove-PowerShellV2`.** It removes a Windows
optional feature, reports `restart pending`, and does not reboot anything itself.
Nothing else in the toolkit requires one.

## 6. What to change per tenant

Defaults are chosen to be safe on a production server, but four are worth a
decision before a fleet-wide push. The disk cost of each is in the README's
**Disk footprint** section.

| Parameter | Default | Decide because |
|---|---|---|
| `Enable-VssPreservation -ShadowStoragePercent` | `12` | it is a percentage of the volume, so 12% of a 500 GB file server is 60 GB |
| `Enable-IRVisibility -SecurityLogSizeKb` | `2097152` (2 GB) | the single biggest disk item; a busy DC fills it faster than you expect |
| `Enable-IRVisibility -TranscriptKeepDays` | `90` | with `-TranscriptMaxBytes` it decides how much history survives; the rotation reports when the two disagree |
| `Enable-IRVisibility -LateralMovementChannelSizeBytes` | `67108864` (64 MB) | five RDP and SMB channels, so 320 MB of new ceiling per host. Windows caps them at 1 MB and 8 MB, and this project could not measure a real event rate for them |
| `-ToolkitRoot` | `C:\ProgramData\IronBlackBox` | change it only with a reason. It is validated, and it is ACL'd to SYSTEM and Administrators on every run |

`Set-TimelineIntegrity` needs `-Force` to change a domain member's time client
type. That is deliberate: taking a host off the domain time hierarchy is not a
default.

## 7. Undoing a fleet-wide deployment

Every `-Apply` records what it changed before changing it, so `-Rollback` is the
undo — per script, per host, newest run first:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { & 'C:\ProgramData\IronBlackBox\Enable-IRVisibility.ps1' -Rollback; exit $LASTEXITCODE } catch { exit 2 }"
```

Three things to know before you rely on it.

- **A rollback can decline, and that is the point.** If the host no longer holds
  what the run set, the script leaves it alone and says so rather than
  overwriting somebody's later change. Those runs stay retryable.
- **Some changes can never be undone**, and they report
  `declined-permanent` rather than pretending. Enlarging a USN journal is
  irreversible on this OS; a shadow storage association this toolkit created
  cannot be removed because `vssadmin delete shadowstorage` is not a documented
  command. `-AbandonRun` lets an operator stop trying on the remainder so the run
  finishes and `Test-VisibilityDrift` stops reporting it.
- **A rollback only writes what the script itself owns.** A manifest record
  naming another volume, another registry key, a file outside the toolkit root or
  a Windows feature this script never touches is declined. That constraint comes
  from the script, not from the record.

## 8. Network, locale, and the things to verify yourself

- **No script opens a socket to fetch anything.** There is no bootstrap and no
  downloader, deliberately: `SYSTEM + PowerShell + download + execute` is a
  pattern EDR products flag, correctly. You stage `Sysmon64.exe` and its config;
  the toolkit verifies the Authenticode signature is Microsoft's, anchored on an
  exact `O=Microsoft Corporation` RDN, before executing it.
  `Set-TimelineIntegrity` reads a clock offset from an NTP peer, and reports
  plainly when it cannot rather than treating silence as success.
- **Locale.** Group and account identities are resolved through well-known SIDs
  rather than names, because `BUILTIN\Administrators` is `Administrateurs` on
  fr-FR Windows. That is a design choice throughout, and it is **unproven**: no
  non-English host has run any of this. If your fleet is not English, pilot it
  and read the output before pushing.
- **Client SKUs.** The lab is Windows Server. Anything that branches on
  `ProductType` — PSv2 feature names, Prefetch keys — is unproven on Windows
  10/11.

### GPO and Intune

**Neither has been exercised by this project**, so what follows is what the
scripts need rather than a procedure that has been run.

The scripts need: SYSTEM or local administrator, a local filesystem path, and an
invocation that preserves the exit code. That fits a GPO computer startup script
and an Intune platform script, and the wrapper in §1 is what makes the exit code
survive either.

Three things to verify on a pilot host before trusting them:

1. That your mechanism actually reports the exit code back, rather than only
   "script ran". Intune platform scripts in particular are worth checking here.
2. That the script file is on a **local** path when it runs. A startup script
   reading from a share depends on the network being up at that point in boot.
3. That the toolkit root's DACL survives. It is applied on every run, so a
   mechanism that recreates the directory with different permissions between
   runs will be reported and repaired — but you want to see that happen once,
   on purpose.

## 9. Staging

Take the `.ps1` files you need and put them somewhere local. Read the code that
will run as SYSTEM before you deploy it — the scripts are standalone with no
module dependencies precisely so that you can.

There is no installer. The toolkit root at `C:\ProgramData\IronBlackBox` is
created on the first `-Apply`, hardened to SYSTEM and Administrators, and holds
the manifest, the transcript directory and any handler scripts the toolkit
schedules. Do not put the `.ps1` files inside it: they are yours to place, and
the root is the toolkit's to own.
