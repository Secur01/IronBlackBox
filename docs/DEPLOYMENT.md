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

### If you were already monitoring `Enable-WefCollector`

**Expect it to go from `0` to `1` on a collector that read clean before v1.1.0,
and believe the `1`.** It now tests three things it used to only print or not ask
at all: whether anything has arrived recently, whether `ForwardedEvents` is at
its own ceiling, and whether the URL ACL lets `Wecsvc` answer a forwarder.

Measured on the lab collector: it printed the newest forwarded event's timestamp
— ten days old — and then `[ ok ] No findings: this host is collecting forwarded
events` at exit `0`, while `wecutil gr` reported `Active` and `LastError: 0`. A
collector that has stopped collecting looked exactly like one that works.

`-MaxForwardedEventAgeHours` (default 48, `0` disables) is the knob. Raise it
only if your sources are legitimately quiet for that long, which on a
subscription that asks for 4624 and 4688 they are not.

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
| `Enable-WefCollector` | the one collector | **declines on a client SKU** since v1.1.0; on a *server* that is not your collector it still does what you ask — scope it deliberately |
| `Enable-Sysmon` | hosts where you have staged the binary and a config | refuses without `-ConfigPath`; it never downloads anything |

The two DC scripts are safe to send fleet-wide — they identify the host role and
decline. **`Enable-WefCollector` is now safe on workstations for the same
reason, and only workstations.** Until v1.1.0 it did whatever you asked:
measured on a Windows 11 client, it set Wecsvc to Running/Automatic and sized
`ForwardedEvents` to 2 GB **before** discovering it could not activate the
subscription, and exited 2 — a host modified for a role it will never hold. It
now reads `ProductType`, declines on a client at exit 0 having changed nothing,
and names `Enable-WefClient` as what you wanted instead. `-AllowClientSku` is
the deliberate opt-in if a workstation really is your collector.

**A collector is a role you assign, not a property a host has**, so that gate
can only catch the client case. On a *server* that is not your collector this
script still does exactly what you ask, and `-Rollback` is exempt from the gate
so a host armed before v1.1.0 can still undo it. Scope it to the collector.

### On Windows 10/11 workstations

Measured 2026-09-09 on Windows 11 Pro build 26200 — the first client host this
toolkit has run on. Two things behave differently from a server, and both are
worth knowing before a fleet-wide push to workstations:

| Script | On a client SKU |
|---|---|
| `Enable-VssPreservation` | **Cannot create a shadow storage association.** `vssadmin` on a client offers `Resize ShadowStorage` but not `Add ShadowStorage`, so the script reports a `[limit]` and exits 1 on the remaining real finding rather than 2. An association Windows or System Restore already made can still be resized. |
| `Remove-PowerShellV2` | **Nothing to remove.** PowerShell 2.0 is absent from build 26200 entirely — no optional feature, no engine key. The script says so and exits 0. |
| `Enable-WefClient` | Works, and its `-Rollback` needs `-StopWinRmOnRollback` to finish. Without it, it restores everything except WinRM's state and says so: stopping a host's WinRM is not a decision it takes on its own. |
| `Enable-LolbinAudit` | **Expect the first `-Apply` to exit 1 and say the policy is not being evaluated.** That is correct, not a defect: the policy is in the store but not yet live. Run `gpupdate /target:computer /force` and re-run `-Apply`; the second run reports `policy proven LIVE` and exits 0. Measured on build 26200, where audit-only rules do evaluate and both `certutil.exe` and `mshta.exe` raised 8003. Do not treat a host as audited until a run says the policy is live. |

`Enable-VssSnapshotSchedule` is unaffected and completes its full cycle on a
client, so the snapshot half of the VSS pair works there even though the storage
half does not. Older Windows 11 builds are **not** measured — an MSP fleet holds several, and
`docs/VALIDATION.md` records only build 26200.

**Windows 10 is out of scope.** It reached end of support in October 2025 and this project does not measure it: no row here covers a Windows 10 host, and none will. That is a decision, not a gap waiting to be filled — if your fleet still runs it, nothing in this repository tells you how these scripts behave there.

**The same build was measured again on 2026-09-10 as a domain member**, all
twenty scripts through the full contract. Nine applied real changes and restored
them, the two domain-controller scripts declined as they should on a member, six
had nothing to do on a client, and `Enable-WefClient` forwarded to a real
collector end to end. Nothing behaved differently from the workgroup pass except
the one thing §4 above already warns about: a domain GPO wins over what these
scripts write.

### On domain-joined hosts, a green `-Apply` is not the proof

**Measured 2026-09-09 on a Server 2019 domain member.** Seven scripts write into
`HKLM:\SOFTWARE\Policies`, which is the Group Policy engine's own registry hive.
On a domain-joined host the engine owns it, so **a domain GPO that sets the same
value wins at the next policy refresh** — unattended, on the background
refresh cycle, with nobody watching.

What was measured, with a GPO that disabled PowerShell ScriptBlock logging:

| | Setting | Was the host actually logging? |
|---|---|---|
| after the GPO applied | `0` | **no** — 0 events |
| after `-Apply` | `1` | yes |
| after the next refresh | `0` | **no** — 0 events again |

The `-Apply` in the middle printed `[ ok ] ... set` and **exited 0**. So on a
domain-joined fleet, a run of zeroes does not mean the fleet is armed.

**What to do about it.** Schedule `Test-VisibilityDrift`. It was measured
catching exactly this — exit 1, naming the value and the script that owns it —
and it is the only thing in the toolkit that can. This is the same reason §2
tells you to schedule `Test-DefenderPosture`: the toolkit reports what it can
see at the moment it runs, and only the drift detector looks at what happened
after.

**Before a fleet-wide push, check your own GPOs** for anything setting PowerShell
logging, audit policy, event log sizing or the Windows Firewall log. If a GPO
sets it, change it there — that is where it will be decided — and let the script
handle what no GPO touches.

Two things that are not obvious, both measured:

- **A routine policy refresh is not itself a hazard.** With no conflicting GPO, a
  forced `gpupdate` left every value the toolkit had written in place.
- **Removing the conflicting GPO does not give you the setting back.** The next
  refresh deleted the value outright rather than restoring the toolkit's — the
  engine cleans up what it stopped managing, and the host was still not logging.
  Re-run the owning script with `-Apply`; that was measured to put the setting
  back, though the run that proved the logging itself came earlier in the same
  sequence, not after this step.

### On the collector: the reservation existing is not permission to use it

**Measured 2026-09-10, and it cost an afternoon.** A source can enumerate a
subscription, appear in `wecutil gr` as `Active` with `LastError: 0`, and then
fail **every** delivery with WS-Man `2150859027` while zero events arrive.

The cause is the URL ACL on `http://+:5985/wsman/`, which by default grants
`NT SERVICE\WinRM` and not `NT SERVICE\Wecsvc` — Microsoft KB4494462. On the lab
collector the `SUBSCRIPTIONMANAGER` reservation was present and the two services
even shared one process, so the existing W-1 diagnosis did not apply, and it
still failed. Adding the Wecsvc SID produced `EventDelivery completed
successfully` on the next cycle and 221 events from a Windows 11 client.

`Enable-WefCollector` reports this per URL from v1.1.0 and prints the exact two
commands. **It does not run them, and neither should you without reading them**
— they replace a machine-wide HTTP reservation that WinRM itself listens on:

```
netsh http delete urlacl url=http://+:5985/wsman/
netsh http add urlacl url=http://+:5985/wsman/ sddl=D:(A;;GX;;;S-1-5-80-569256582-2953403351-2909559716-1301513147-412116970)(A;;GX;;;S-1-5-80-4059739203-877974739-1245631912-527174227-2996563517)
```

Then restart `Wecsvc`. The two SIDs are `NT SERVICE\WinRM` and
`NT SERVICE\Wecsvc`; they are well-known and identical on every Windows host,
which is why they are safe to write literally.

Why the grant was needed on a host where the services shared a process is **not
established** — only that it was, measured in both directions. And the lab's
Server 2019 member forwarded 145 events on 2026-08-27 with the same unfixed ACL,
which is also unexplained. Treat this as a check to run, not a rule to trust.

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
