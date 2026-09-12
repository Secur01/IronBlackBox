# Validation

This is the only file in this repository allowed to claim that a script was
tested. Every other document (README, comment-based help, commit messages)
describes intent, not proof. A script with no row in the table below is
**L0** — absence of a row is not a pass, it is the default, honest state of
an untested script.

Only scripts at **L2 or higher** ship in a tagged release.

## Levels

| Level | Meaning |
|---|---|
| L0 | Written. Nothing proven. |
| L1 | `tools/check.ps1` passes (AST parse + PSScriptAnalyzer, PS 5.1 profile). Proves syntax and API surface — nothing about behaviour on a real Windows host. |
| L2 | `-Audit` ran against the EC2 lab; a before/after diff proved it made zero changes. |
| L3 | `-Apply` ran on the lab, was re-run to confirm idempotence, and `-Rollback` restored the pre-`-Apply` baseline. |
| L4 | Proven on the script's actual real-world target class (e.g. a domain controller, a domain-joined member, a workgroup client SKU) — not just the generic lab image. |

## Known limits of the static gate (L1)

L1 is a useful, cheap filter, but it is not proof of correctness on Windows.
Specifically:

- **PSScriptAnalyzer does not detect an invented cmdlet name.** An unknown
  command name is assumed by PowerShell's parser to be a local function or an
  external executable, so `Get-ThingThatDoesNotExist` passes analysis silently.
- **It does catch invented parameters on real cmdlets** and **invented
  members on real .NET types** (both are checked against loaded type/cmdlet
  metadata), so typos in `-SomeBogusSwitch` on a known cmdlet, or a
  nonexistent `.SomeBogusMethod()` on a known .NET type, are caught.
- **PSScriptAnalyzer exits `0` on a file with parse errors** — it does not
  itself guarantee the file parses. `tools/check.ps1` therefore runs an
  explicit AST parse (`[System.Management.Automation.Language.Parser]::ParseFile()`)
  as a separate, mandatory check, not merely as a PSSA prerequisite.
- **No static gate running on Linux can validate a Windows-side fact**: a
  registry path exists, an event ID is emitted by the component you think
  emits it, an `auditpol` subcategory name is spelled correctly, an SDDL
  string means what you think it means, or a WMI class/namespace exists on
  the target OS. Those require L2+ — an actual run against the lab.

## The release pipeline

**2026-09-08.** `tools/build-release.sh` published a tree containing a `.ps1`
that could not be parsed, and reported it clean. Its substitution for the name of the
authoring-rules document inserted an apostrophe into a single-quoted PowerShell string in
`Enable-WefCollector.ps1`, terminating the string at line 2417. All four of the
build's checks passed it because all four read text and none parsed the
PowerShell.

The build now parses every `.ps1` in the OUTPUT tree, after every substitution,
and refuses if `pwsh` is unavailable rather than skipping the check. Measured:
22 files parsed with 0 errors on the clean tree, and the build refuses with the
exact line-2417 error when the apostrophe is restored.

Independently verified on the published tree for tag readiness: 0 lab or
dev-repo identifiers, 20 scripts, 20 `VALIDATION.md` rows, 0 forbidden OS
claims, 0 internal files leaked, and `tools/check.ps1` PASSES inside the
published tree — which it did not before this fix.

## Windows 11, the first client SKU

**2026-09-09. Windows 11 Pro build 26200, ProductType 1, PS 5.1.26100.9444.** The
first client host any part of this toolkit has ever run on. Until this date
`docs/SCRIPTS.md` recorded client SKU behaviour as unproven because Windows
client licensing is not available on EC2; a guest on the tailnet removed the
blocker.

**Nine scripts completed a full contract cycle** — `-Audit` → `-Apply` →
`-Apply` → `-Rollback` with the host restored — and are L3 on this build:
`Enable-IRVisibility`, `Enable-DnsVisibility`, `Enable-LolbinAudit`,
`Set-TimelineIntegrity`, `Deploy-TamperAlerts`, `Enable-VssSnapshotSchedule`,
`Protect-DefenderConfig`, `Protect-EventLogs`, `Enable-WefClient`.

**Five applied nothing, so the rollback half was never exercised and they are L2
here, not L3**: `Enable-ServerPrefetch` (Prefetch is already on by default on a
client), `Enable-Sysmon` (refuses without `-ConfigPath`, as designed),
`Enable-UsnJournalTracking`, `Protect-ForensicArtifacts`,
`Remove-PowerShellV2`. The harness reports that explicitly rather than counting
a clean run as proof.

**Two declined by design**, which is correct and is not an L3 claim:
`Enable-AdObjectAuditing` and `Enable-LegacyAuthAudit` both answered "Not a
domain controller: nothing in this script applies here. Nothing was changed."

### Effects observed, not just writes — 2026-09-09

The cycles above prove the contract: the scripts write, re-write nothing, and
restore. They do not prove the host then *records* anything, and that gap is why
`docs/AUTHORING.md` carries "never claim an effect you have not observed". Four effects
were measured on this build, each by running a command and reading the event
back:

| Effect | How it was observed | Result |
|---|---|---|
| ScriptBlock logging | ran a marker string through `powershell.exe`, searched `Microsoft-Windows-PowerShell/Operational` | **4104 naming the marker** |
| Transcription | same run, searched the transcript directory | **the marker in a transcript file** |
| Command line on 4688 | ran `cmd.exe /c echo <marker>`, searched the Security log | **4688 carrying the full `Process Command Line`** |
| AppLocker LOLBin audit | ran `certutil.exe` and `mshta.exe` | **8003 for each, naming the image** |

**AppLocker audit is evaluated on Windows 11 Pro.** The effective policy carried
all 18 rules, `Exe=AuditOnly`, and both LOLBins raised 8003. That is measured on
build 26200 with a local policy; it is not a statement about what any edition
licenses, which this project has not verified.

**The first-activation case behaves the same on a client as on a server, and
`Enable-LolbinAudit` caught it by itself.** On the first `-Apply` the policy was
in the local store with `AppIDSvc` running, and `certutil.exe` raised **no**
8003 — so the script raised a finding saying in words that the policy was *not*
being evaluated and naming the remedy. After `gpupdate /target:computer /force`
the re-run reported `policy proven LIVE` and exit 0, and an independent count
outside the script rose from 1 event to 3. This is the check that exists because
an earlier AppLocker policy passed every read-back while not being evaluated;
on a client it fired, and its own remediation path cleared it.

Both scripts were rolled back afterwards and the host was measured back to
`ScriptBlockLogging` absent, 0 local AppLocker rules, `AppIDSvc` Manual.

### Three defects found, all of them shaped the same way

**1. `Remove-PowerShellV2` reported a bypass that does not exist, on every
Windows 11 endpoint.** PowerShell 2.0 is gone from build 26200 — no optional
feature, no `PowerShellEngine` registry key, no .NET 3.5, confirmed three ways.
But `powershell.exe -Version 2` there prints "PowerShell 2.0 has been
deprecated. Using default PowerShell instead.", runs under 5.1 and **exits 0**.
The script read that 0 as proof the engine ran and raised a finding no `-Apply`
could clear. Fixed by asking the child what version it is; see the script's row
above.

**2. `Enable-VssPreservation` exited 2 on every workstation.** Measured side by
side: `vssadmin` on Windows 11 offers `Resize ShadowStorage` but **not** `Add
ShadowStorage`, while Server 2019 offers both. `Win32_ShadowStorage.Create` is
present on the client and answers **return code 10**, which is not in
Microsoft's documented set, so the script threw and the run exited 2 — the code
`docs/DEPLOYMENT.md` §2 tells an MSP to alert as a broken deployment. It is a
capability Windows does not have and no `-Apply` can supply, so it is now a
host limit, out of the exit code, and the remaining exit 1 is the real and
clearable "arm `Enable-VssSnapshotSchedule`". Its sibling passed its full cycle
on the same host, so the snapshot half of the pair works on a client.

**3. `lab/Invoke-LabCycle.sh` produced false failures for the third time.** It
judges the contract by grepping stdout for sentences, and a script that DECLINES
never prints `0 change(s) applied` or `Rollback complete`. Both DC-only scripts
were reported "NOT idempotent" and "rollback did not report completion" while
behaving exactly as documented. Fixed — and the fix had its own defect: treating
"no count line" as a decline also swallowed `Enable-WefCollector`, which set
Wecsvc to Running/Automatic and sized `ForwardedEvents` to 2 GB **and then**
failed `wecutil cs` with 15080 and exited 2. A partial apply is not a decline;
the exit code separates them, since the contract says a decline is 0 or 1.

### The fourth defect: the harness could not pass a rollback its lever

`Enable-WefClient` failed three of six checks, and the script was right every
time. Its `-Rollback` restored two of three changes and DECLINED the third as
retryable, because WinRM had been Stopped before the `-Apply` and stopping a
host's WinRM is not a decision the script takes on its own. Its own output names
the remedy: *"Re-run `-Rollback -StopWinRmOnRollback` to stop it."*

`lab/Invoke-LabCycle.sh` had `--apply-args` and no way to say the same thing to
a rollback, so the full contract of any script whose rollback has a documented
lever could not be exercised. Added, and with it the run reads:

```
[ ok ] apply exit 1        3 change(s) applied
[ ok ] idempotent
[ ok ] rollback exit 0     descriptor restored, value removed,
                           WinRM StartType back to Manual, WinRM stopped
[ ok ] rollback reported complete
[ ok ] second rollback declined to replay
RESULT: 6 passed, 0 failed
```

WinRM ends at `Stopped / Manual`, its exact pre-apply state. The apply's own
exit 1 is a real finding on this host — the forwarding channel is empty because
there is no collector at the test URI — not a contract failure.

### Still open on this host

`Enable-WefCollector` fails to activate a subscription on a client, which is
expected for a host that is not a collector — but it sets Wecsvc to
Running/Automatic and sizes `ForwardedEvents` to 2 GB **before** finding out,
then exits 2. `docs/DEPLOYMENT.md` §4 already says to scope that script to the
collector, and now records what it does on the wrong host. Whether it should
detect the SKU first and decline, as the two DC scripts do, is a design question
and not written up as decided.

`lab/Verify-Facts.ps1` re-measured the mechanically checkable part of
`verification/facts.json` here: **11 confirmed, 1 differs, 6 undeterminable, 80
with no probe written**, later 73 as probes were added. That last number is not a pass — it is the list of
facts that still need a human on this OS, and only its shrinking makes the tool
worth anything.

## Group Policy precedence on a domain-joined host — 2026-09-09

**Server 2019 member of `lab.example`, DomainRole 3.** The one interaction
this project had never exercised: seven scripts write into
`HKLM:\SOFTWARE\Policies`, the Group Policy engine's own hive, and on a
domain-joined host the engine is the owner of record. Nothing had measured what
happens when a domain GPO disagrees.

A GPO was created on the lab DC setting `EnableScriptBlockLogging` to `0`,
security-filtered so that only that one computer account had Apply, which is
what kept it off the DC itself.
Every step ran as SYSTEM through a one-shot scheduled task — the documented
recipe, and how an RMM runs it — and the **effect** was measured at each step by
running a marker string through `powershell.exe` and counting 4104 events naming
it, rather than trusting the registry read-back:

| Step | Registry | 4104 for the marker |
|---|---|---|
| before the GPO applied | `1` | **1** |
| after `gpupdate /target:computer /force` | `0` | **0** |
| after `Enable-IRVisibility -Apply` | `1` | **1** |
| after the next `gpupdate /target:computer /force` | `0` | **0** |
| GPO deleted, then one more refresh | **`<absent>`** | **0** |
| after `Enable-IRVisibility -Apply` again | `1` | not re-measured |

**Three results.**

1. **The GPO wins, and the effect follows it.** This is not only a registry
   value being overwritten — PowerShell stopped writing 4104 and started again,
   twice, in step with the refresh.
2. **The `-Apply` in the middle reported `[ ok ] ScriptBlock logging (event 4104)
   - set` and exited 0.** On a domain-joined fleet a run of zeroes therefore does
   not mean the fleet is armed. Recorded as finding **GP-1** in
   the review log kept in the development repository;
   `docs/DEPLOYMENT.md` §4 now says so at the point an operator plans a push.
3. **`Test-VisibilityDrift` caught it** — exit 1, naming
   `HKLM:\Software\Policies\...\EnableScriptBlockLogging` and the script that
   owns it, *"the value no longer matches what was applied"*. The flagship's
   entire purpose is this case and it works, which is what keeps GP-1 a reporting
   defect rather than a blind spot.

**Two things measured that were not predicted.** A forced refresh with **no**
conflicting GPO left all four watched values in place, so a routine policy cycle
is not itself a hazard. And deleting the conflicting GPO did **not** restore the
toolkit's value — the next refresh removed the value outright and the host was
still not logging, because the engine cleans up what it stopped managing.
Recovery is a re-run of `-Apply`, which put the value back at `1`; the effect
was not re-measured after that step, and the table above says so.

This is a domain-**membership** result, not a SKU result: the mechanism is the
Group Policy engine, which is the same on a workstation.

**Re-measured on a client SKU the same day, and it reproduces exactly.** The
Windows 11 Pro guest was joined to the lab domain — offline domain join, so no
password crossed a command line on a host whose 4688 auditing this toolkit turns
on — and came up `DomainRole 1`, `Test-ComputerSecureChannel` True, SYSVOL
readable by the computer account, `gpupdate` clean, `[adsisearcher]` answering.
Against a GPO filtered to its own computer account the four steps ran identically:
`1` with 1 x 4104, then `0` with **0 x 4104**, then `[ ok ] ScriptBlock logging
(event 4104) - set` at **exit 0**, then `0` with 0 x 4104 — and
`Test-VisibilityDrift` at exit 1 naming the value. GP-1 therefore holds on a
server and on a workstation, and the workgroup results above remain valid for the
workgroup class they were measured on.

One trap surfaced for the third time in this project while doing it:
`Test-ComputerSecureChannel` read **False** over SSH as a *local* account and
True as SYSTEM on the same host, minutes apart. `lab/DOMAIN-LAB.md` documents
why — a local account is not a domain principal — and it still reads as a defect
every time.

## Windows 11 as a domain member — the full cycle, 2026-09-10

**Windows 11 Pro build 26200, `DomainRole 1`, member of the lab domain.** The
workgroup pass above measured a machine that no longer exists in that form, so
all 20 scripts were run through the whole contract again on the joined host —
`-Audit`, `-Apply`, `-Apply`, `-Rollback`, `-Rollback` — by
`lab/Invoke-LabCycle.sh`.

| Outcome | Count | Scripts |
|---|---|---|
| Full contract, real changes applied and restored | **9** | `Enable-IRVisibility`, `Enable-LolbinAudit`, `Enable-DnsVisibility`, `Set-TimelineIntegrity`, `Enable-WefClient`, `Protect-EventLogs`, `Protect-DefenderConfig`, `Enable-VssSnapshotSchedule`, `Deploy-TamperAlerts` |
| Declined by design, correctly | 2 | `Enable-LegacyAuthAudit`, `Enable-AdObjectAuditing` — a domain member is still not a domain controller |
| Applied nothing, so the rollback half was never exercised — **L2 here, not L3** | 6 | `Enable-UsnJournalTracking`, `Enable-ServerPrefetch`, `Enable-Sysmon`, `Remove-PowerShellV2`, `Protect-ForensicArtifacts`, `Enable-VssPreservation` |
| Read-only, no `-Apply` to prove | 2 | `Test-DefenderPosture`, `Test-VisibilityDrift` |
| Not a target for this host | 1 | `Enable-WefCollector` — exits 2 and names defect W-1 itself |

`Enable-WefClient` reached **6 of 6** here, against 3 of 6 on the workgroup pass,
because the harness can now pass `-StopWinRmOnRollback` to a rollback that
documents needing it.

Per script, with the six contract checks each — `-Audit` clean, `-Apply`, second
`-Apply` idempotent, `-Rollback`, rollback reported, second rollback declines:

| Script | | Checks | Reading |
|---|---|---|---|
| `Enable-IRVisibility` | PASS | 6/6 | after draining the manifest, see below |
| `Enable-LolbinAudit` | PASS | 6/6 | real changes applied and restored |
| `Enable-DnsVisibility` | PASS | 6/6 | real changes applied and restored |
| `Enable-UsnJournalTracking` | PASS | 6/6 | nothing to apply — L2 here |
| `Set-TimelineIntegrity` | PASS | 6/6 | real changes, on a domain member this time |
| `Enable-ServerPrefetch` | PASS | 6/6 | Prefetch is already on for a client — L2 |
| `Enable-Sysmon` | PASS | 6/6 | refuses without `-ConfigPath`, by design — L2 |
| `Enable-LegacyAuthAudit` | PASS | 6/6 | declines: a member is not a controller |
| `Enable-AdObjectAuditing` | PASS | 6/6 | declines: same |
| `Enable-WefClient` | PASS | 6/6 | real changes, and forwarding proven below |
| `Enable-WefCollector` | PASS | 6/6 | declines on a client SKU as of v1.1.0 — was **FAIL** 4/6, see below |
| `Remove-PowerShellV2` | PASS | 6/6 | PSv2 absent from build 26200 — L2 |
| `Protect-EventLogs` | PASS | 6/6 | real changes applied and restored |
| `Protect-ForensicArtifacts` | PASS | 6/6 | nothing to apply — L2 |
| `Protect-DefenderConfig` | PASS | 6/6 | real changes applied and restored |
| `Enable-VssPreservation` | PASS | 6/6 | nothing to apply — L2 |
| `Enable-VssSnapshotSchedule` | PASS | 6/6 | real changes applied and restored |
| `Deploy-TamperAlerts` | PASS | 6/6 | real changes applied and restored |
| `Test-DefenderPosture` | PASS | 1/1 | read-only, no `-Apply` to prove |
| `Test-VisibilityDrift` | PASS | 1/1 | read-only, no `-Apply` to prove |

**Originally 19 pass, 1 fail; 20 pass after the fix that failure produced.**
`Enable-WefCollector` failed two checks: `wecutil cs` returns 15080 — the
subscription saves but cannot activate — so the `-Apply` exited 2, and it did so
**after** setting `Wecsvc` to Running/Automatic, leaving the rollback facing a
partial apply. It named defect W-1 in its own output while doing it.

That was the open design question, and it is now decided. From v1.1.0 the script
reads `ProductType` and declines on a client SKU before the lock and before the
manifest, so an `-Apply` on a workstation writes nothing at all — modelled on
how the two controller scripts decline. Re-measured on the same host: audit exit
1 → **0**, apply exit 2 → **0**, and 6 of 6 with the harness reporting *"the
script does not target this host"*. Proven in three states — the client declines,
the client with `-AllowClientSku` behaves exactly as before, and the domain
controller does not decline and passes every check. `-Rollback` is exempt from
the gate, because the manifest and not the host's SKU is the authority on what
this toolkit changed.

A sixth harness defect surfaced writing this table. `Invoke-LabCycle.sh` closed
that run with *"the first `-Apply` changed nothing"* four lines below the script's
own `[ ok ] Wecsvc is now Running and Automatic`. The 2026-09-09 fix had
separated a decline from a partial apply for one flag and left the closing note
reading the old two-state world; there is now a third state that says how much
the apply changed is unknown and points at the script's output instead.

**One cycle failure, and it was the harness judging a host this session had
dirtied.** `Enable-IRVisibility` first reported *"second rollback did not
decline"*. The manifest held 14 records from the GP-1 measurements above, and one
run was in the three-way doctrine's case 3 — the host held neither what the run
set nor what was recorded before it, because a GPO had set the value to `0` and
its deletion had then removed the value entirely. The script declined and stayed
retryable, which is correct. After draining the manifest — one `-AbandonRun` for
the unresolvable run, one clean rollback — the same script scored **6 of 6**. The
fifth false failure from this harness, and the first on a host the tester broke.

## Windows Event Forwarding from a client — proven end to end

**2026-09-10.** With the client domain-joined, `Enable-WefClient` was armed
against the real collector rather than the placeholder URI used in the workgroup
pass. It took two halves and a cause.

Enumeration worked immediately: WinRM logged `Enumeration completed
successfully` and the collector listed the client as an event source. Delivery
failed on every cycle with `EventDelivery failed, error code 2150859027`, and
**three hypotheses were tested and refuted** — the forwarder's channel read
access, `Event Log Readers` membership, and the collector's log being full.

**The cause was the URL ACL on the collector.** `http://+:5985/wsman/` granted
only `NT SERVICE\WinRM`, not `NT SERVICE\Wecsvc`, which is Microsoft KB4494462.
Adding the Wecsvc SID to both `5985` and `5986` made the next cycle log
`EventDelivery completed successfully`, and **221 events reached the collector
from the Windows 11 client, 9 of them naming the marker string the test
generated**, with `LastHeartbeatTime` advancing to the minute. So forwarding from
a client SKU is now proven end to end.

Two things this does not settle, kept rather than smoothed over. The KB
attributes the failure to WinRM and WecSvc running in **separate** `svchost`
processes; on this collector they shared one PID, so why the grant was needed is
not established — only that it was, measured in both directions. And the
Server 2019 member forwarded 145 events on 2026-08-27 with the same unfixed ACL,
which is not explained either.

**What the toolkit learned from it.** `Enable-WefCollector` had two checks that
read the right data and did not test it, and both are now fixed and
mutation-proved:

| Check | Before | After |
|---|---|---|
| Is anything arriving? | printed `last write 2026-08-30`, then `[ ok ] No findings: this host is collecting forwarded events` at exit 0 | new `-MaxForwardedEventAgeHours` (default 48): `has not been written to for 250 hour(s)`, exit 1 |
| Is the channel full? | capacity passed on a `.evtx` **4096 bytes over** its own maximum | reports a channel at or over its own ceiling |
| May Wecsvc use the reserved URL? | not asked — the endpoint check proves the reservation exists | new `Test-WsmanUrlAcl` reports per URL, with the exact `netsh` pair |

The third is the one that would have answered this in a minute instead of an
afternoon.

## Windows Server 2022 — 2026-09-11

**Build 20348, PS 5.1.20348.5499.** The first Server 2022 this toolkit has run
on, measured in two forms on the same day: as a **standalone server** before
promotion, and as the **domain controller of a new forest** after it. The
Server 2019 lab that produced every earlier L4 row was retired the same day; an
AMI of its controller is kept, and `lab/DOMAIN-LAB.md` records both labs.

### Standalone server, before promotion

All twenty scripts through the full contract. **Thirteen applied real changes
and restored them**, three had nothing to do, two are read-only, and the two
domain-controller scripts declined as they should on a host that is not one.

Two results came out of it, and only one is a defect.

**`Enable-VssPreservation` exposed a harness defect, not a script one.** On a
fresh server there is no shadow storage association, so the script **creates**
one — and removing an association discards the snapshots in it while
`vssadmin delete shadowstorage` is not a documented command, so its rollback
declines **permanently** and exits 1. That is `docs/DESIGN.md` §4.1's fourth
outcome and `docs/DEPLOYMENT.md` §7 documents it. `lab/Invoke-LabCycle.sh`
scored it as two failures. It never surfaced on Server 2019 because the
association already existed there, so nothing was created and nothing was
irreversible: **the defect needed a host nobody had run this on.** The harness
now reads the run's status out of the manifest rather than grepping stdout for a
sentence, and reports a permanent decline as its own outcome.

**`Enable-WefCollector` exits 2 here, and that is the known limit.** `wecutil cs`
returns 15080 and the apply exits 2 after starting Wecsvc. The client-SKU gate
added in v1.1.0 does not apply — this is `ProductType 3` — and v1.1.0's own note
says so: the gate catches only the client case, and on a *server* that is not
your collector the script still does what you ask.

### Domain controller of a new forest

`ProductType 2`, `DomainRole 5`, functional level 7. **All twenty scripts pass
the full contract: fourteen applied real changes and restored them, four had
nothing to do, two are read-only, nothing failed.**

Three things are proven here for the first time.

**The two domain-controller scripts finally apply rather than decline.**
`Enable-AdObjectAuditing` and `Enable-LegacyAuthAudit` exist for this host class
and every previous measurement of them on a non-controller could only record a
correct refusal.

**`Enable-WefCollector` completes a full cycle — anywhere.** On Server 2019 it
carried W-1, the `svchost` split that stopped Wecsvc registering the
SubscriptionManager URL; on client SKUs it declines or cannot activate the
subscription. On a fresh Server 2022 forest it passes 6 of 6, and
`Enable-WefClient` passes against it.

**There is no "Windows Server 2022" functional level, and the lab is at the
ceiling.** Asked rather than assumed: `Install-ADDSForest -ForestMode` on this
OS accepts nothing above `WinThreshold`, and `Set-ADForestMode` stops at
`Windows2016Forest`. Level 7 is the maximum Server 2022 offers.

### Member server of that forest

`ProductType 3`, `DomainRole 3`, secure channel True. **All twenty scripts pass:
zero failures.** The two controller scripts decline, as they must on a member
that is not one, and the rest complete the contract.

This is the class most of an MSP fleet actually is — a domain-joined application
or file server — and it had never been measured on any OS newer than 2019.

**`Enable-WefCollector` passes here and exited 2 on the standalone**, on the same
OS build, the same day, with the same code. The only difference between the two
hosts is domain membership, and the standalone's failure was `wecutil cs`
returning 15080, "the subscription is saved successfully, but it can't be
activated at this time". A source-initiated subscription authenticates its
sources by machine account, which a workgroup host has no way to do — so the
correlation is exact and the mechanism is plausible, but this pass did not
isolate it. Recorded as an observation, not a proven cause.

**The permanent-decline fix was proven on a live host here.** Earlier the same
day, `Enable-VssPreservation`'s permanent decline could only be re-checked
against archived run directories, because the first cycle had already created
the shadow storage association on that host and creation is irreversible — the
case cannot be replayed on a machine that has seen it. This member was fresh, so
the harness met the real thing and reported it correctly:

```
PERMANENT DECLINE: the rollback refused to undo a change that can never
be undone, and said which one. ... but it does mean the host was NOT
returned to its baseline.
```

Five checks, zero failures, where the unfixed harness would have scored two
failures against a script behaving exactly as `docs/DESIGN.md` §4.1 specifies.

### The `major 2` branch finally executed — 2026-09-12

**`Remove-PowerShellV2`'s v1.0.1 fix shipped in a public release with one branch
that had never run.** That fix distinguishes *a v2 engine really ran* (the child
reports PSVersion major 2) from *it fell back to 5.1* (major 5), and only the
fall-back path had ever been measured — Windows 11 build 26200 has no v2 engine
at all, and the Server 2019 lab never had it enabled. Windows 10 was the obvious
host and is out of scope.

Server 2022 still offers it. The optional feature is present and the engine key
ships enabled; the missing ingredient is .NET 3.5, without which the v2 CLR
cannot load. Installing `NET-Framework-Core` and `PowerShell-V2` made
`powershell.exe -Version 2` genuinely run, and the whole chain was then measured
on one host in one sitting:

| Step | Result |
|---|---|
| before | `-Version 2` → **`MAJOR=2`** — a v2 engine really ran |
| `-Audit` | **`PowerShell 2.0 CAN RUN on this host - ScriptBlock logging can be bypassed. the child engine reported PSVersion major 2, so a v2 engine really ran`** |
| full contract cycle | **6 of 6** |
| `-Apply` | 1 change, exit 0 |
| after | `-Version 2` → *"The Windows PowerShell 2 engine is not installed on this computer"*, and the engine key is gone |
| control | the same command without `-Version 2` still answers `MAJOR=5` |

So the branch is correct, the removal works, **and the exposure closes without a
reboot on this path** — the feature dropped to `Available` and the engine key
disappeared in the same run. The control matters: without it, "no output from
the v2 engine" would be indistinguishable from a broken host.

**One reporting imprecision found while doing it, recorded not fixed.** On a host
left mid-transition (`EnablePending`), the script printed *"no restart is
pending"*. Its `$script:RestartNeeded` means *this run did not cause one*, which
is true, but the sentence reads as a claim about the host — and the script had
just read `EnablePending` from Windows. The advice around it is right (*"do not
treat this host as covered until that is understood"*); only the clause is
misleading. Not fixed here: a wording change to a shipped script deserves its own
test rather than a tail-end edit.

### The operational result worth knowing before a fleet push

**Do not run `Enable-AdObjectAuditing` in the minutes after promoting a domain
controller.** Run three minutes after `NTDS` started, it refused with

```
DACL CHANGED on CN=AdminSDHolder,... This script must never do that.
Refusing to continue; the previous descriptor is in the manifest for this run.
```

and exited 2. That is the guard working exactly as designed: the script sets
SACLs and must never touch permissions on the object whose ACL SDProp stamps
onto every protected group, so on detecting a DACL it did not write it stops
rather than risk it.

It was not the script. Sampling the DACL every 20 seconds for two minutes with
nothing running showed it perfectly stable — 22 ACEs, identical hash — and
re-running on the settled controller gave `apply exit 0`, idempotent, rollback
complete, **6 of 6**. Active Directory was still writing its own descriptors
minutes after the promotion reboot. An MSP arming a freshly promoted controller
would see exit 2 and read it as a bug; it is a timing window, and the remedy is
to wait.

The re-run's one remaining failure was the familiar manifest artefact — the
earlier aborted run left an unresolved record, so the second rollback legitimately
resolved it rather than declining. Drained, it scored 6 of 6.

## Scripts

### Do the existing stamps survive the P-1 parameter refactor? (2026-08-28)

Yes, and here is exactly what was re-proven rather than assumed. The P-1 fix
(`docs/DESIGN.md` §3) removed all 67 value-validation attributes from the param
blocks of 24 scripts and re-implemented them as body checks, so it touched every
script in this table. What it changed is how an **invalid** argument is rejected;
a valid invocation binds and runs the same code as before. Re-proven on the lab
(Server 2019 Datacenter 17763) after the refactor:

- **23 of the 24 transformed scripts still start, bind and reach their normal
  path** — OLD vs NEW on the same command line returned the same exit code *and*
  the same final line, script by script. `Invoke-TriageCollection` is the
  exception: its full collection was too heavy to run twice, so only its reject
  path is proven and its valid-run comparison is owed.
- **One full L3 cycle end to end** on a transformed script
  (`Enable-ServerPrefetch`): `-Audit` → `-Apply` → `-Apply` again (idempotent) →
  `-Rollback` restored the pre-apply state.
- **The new reject path** returns `2` with an operator-readable message on all 24.

What was **not** re-run: the full L3/L4 cycle of the other 23 scripts. Their
stamps stand on the argument above plus the same-exit-code/same-output evidence,
not on a fresh cycle each. A reviewer who wants that stronger claim should re-run
the cycles; this note exists so nobody mistakes the current stamps for
post-refactor full re-validation.

**All 20 implemented, all 20 proven.** The domain lab
(`lab/DOMAIN-LAB.md`) closed the last four gaps: `Enable-LegacyAuthAudit` and
the DNS-server half of `Enable-DnsVisibility` reach **L4** on a real domain
controller, and both WEF halves reach L3 on their own side.

`Enable-AdObjectAuditing` was the last holdout and reached **L4** too. Its
read/write mechanism had to be rebuilt from one that could not read a single
SACL, and then its rollback had to learn that `AddAuditRule` **merges** into an
existing ACE rather than appending — so removing "what we added" was removing
what was already there. Both are fixed and proven on AdminSDHolder itself, the
object whose ACL is stamped onto every protected group in the domain.

A script being written is not a script being safe. Twenty-one were written in
one batch on 2026-08-24 and then reviewed adversarially; the review found
defects in every one, including several that would lose evidence silently, and
running them found more that the review had not. What is left is recorded in
the review log kept in the development repository.

The collectors, their validation state and their open defects moved with
`ir-collection/` to [`Secur01/IronBlackBox-IR`](https://github.com/Secur01/IronBlackBox-IR)
on 2026-08-25.

| Script | Level | OS proven on | Date | Notes |
|---|---|---|---|---|
| `logging-hardening/Enable-IRVisibility.ps1` | **L4** | Windows Server 2019 Datacenter, build 17763, PS 5.1.17763.9121 — member **and** `lab.example` DC | 2026-09-01 | Full Audit → Apply → Apply → Rollback cycle on both hosts, 6/6 each. Effects verified by observing real events, not just registry values. L4 because the DC-scoped subcategories (Kerberos, Computer Account Management) were proven on a real domain controller. Client SKU remains unproven — no client SKU in the lab, so PNP Activity with a real removable device is untested. Transcript rotation re-validated 2026-09-01: `-Apply` registers `\IronBlackBox\IronBlackBox-TranscriptRotation` (daily 03:20, SYSTEM/Highest); the handler compressed day-folders past `-TranscriptCompressAfterDays` (48,024 -> 1,996 bytes) and deleted one past `-TranscriptKeepDays` (200 days old), while today and yesterday were left untouched. The size backstop was forced with 16 MB of incompressible data against a 10 MB cap: it evicted oldest-first, stopped as soon as it was under, and wrote one `FINDING` per eviction that was still inside the retention policy — `-Audit` surfaced those as exit 1. `-Rollback` removed the task and left every transcript and the handler in place, and a second `-Rollback` still exited 0. `-Apply -DisableTranscription` wrote `EnableTranscripting=0`, registered no task, and left existing transcripts on disk. A final `-Audit` on the restored host exited 0. **2026-09-02:** the lateral-movement channels, a gap `docs/ARTIFACT-MATRIX.md` exposed by being read as a grid — the two TerminalServices Operational channels and the three SMB channels had nothing arming them and nothing protecting them. `Set-PowerShellChannelSize` was generalised to `Set-TrackedChannelSize` and is now called twice; `-LateralMovementChannelSizeBytes` defaults to 64 MB. Proven on the lab: `-Audit` names all five with the exact `wevtutil` command and leaves 5 of 5 ceilings unchanged; `-Apply` takes all five from 1 MB and 8 MB to 67108864 bytes; a second `-Apply` reports 7 channels already at the floor and changes nothing; `-Rollback` restores all 5 original ceilings exactly. A bug was introduced and caught in this change: the loop variable was named `$channel` while the new parameter is `$Channel`, and PowerShell names are case-insensitive, so they were one variable — the same class as the reserved-`$mode` trap. It failed on the lab at exit 2 before the rename to `$channelName`. **A real event rate for these five channels is NOT measured**: this lab is driven over SSH and serves no files, so they held 1, 3, 0, 0 and 0 events. The default is justified by a circular log's ceiling being cheap, not by an observed rate. **2026-09-02, from an adversarial review of that same change** — four defects it introduced or widened: `Restore-EventChannelChange` reported `restored` on `wevtutil`'s exit code alone, which `verification/facts.json` already measured as unsound (a shrinking `sl /ms:` exited 0 without sticking while an EventLog policy specified a larger size), and now reads the channel back — proven on the lab, 5 of 5 restores reported "read back and confirmed"; case 3 of the rollback doctrine could be switched off BY the record, because an unparseable `newMaxSizeBytes` left the guard's `-gt 0` test false and fell through to a write, and now declines; the free-space gate judged each channel as if it were alone, so one call authorised up to five times the growth its floor was verified against, and now accumulates per volume; and a channel absent from the host was a finding — a permanent exit 1 with no lever — and is now a host limit. Two more from the same review: the transcript rotation task is now registered IMMEDIATELY after transcription is switched on, before anything else that can throw — every call after it has failure paths that raise, and sizing five more channels widened that window by five throw sites (proven: the rotation section prints at output line 12, the channel sections at 38); and a DISABLED channel is now reported instead of being sized in silence, because `IsEnabled` was read only to record it — proven by disabling `Microsoft-Windows-SMBServer/Audit`, which produced exactly one finding naming `wevtutil.exe sl <channel> /e:true`, and none once re-enabled. Four more from the review's tail: at rollback, a channel absent from the host declined as RETRYABLE, which is the A-2 convergence defect — absent and merely unreadable now get different verdicts, discriminated by enumerating `Get-WinEvent -ListLog *` rather than by matching an error message, because message text is locale-dependent (proven: a fabricated channel name resolves to the permanent branch, a real one to the readable branch; **the full permanent-decline path through a real manifest record is NOT exercised** — that needs a channel to vanish from Windows); the free-space gate defaulted to `C:\` when a channel's `LogFilePath` could not be resolved, measuring one disk to authorise growth on another, and now reports and skips; the README's measurement command listed four channels while a code comment pointed operators at it for five more, and now lists all of them; and `$runId` in the shared Manifest region shadowed the `-RunId` parameter — latent, but the same trap that broke `Set-TrackedChannelSize`, so it was renamed **in the template** and re-copied to all 18 scripts rather than edited in place. **2026-09-02, final review pass:** `Set-TrackedChannelSize` was rewritten to use the two functions `Set-EventLogSizing` already uses — `Get-EventChannelFileState` to resolve each channel's volume and `Test-EventLogDiskHeadroom` to judge it — in the same order: resolve all, sum per volume, one verdict per volume, then write. Writing a private version of that had produced three defects, the third of which no earlier pass had noticed: growth was computed from the configured ceiling rather than from the .evtx file's real size, which UNDER-counts, because raising MaxSize authorises a channel to reach the target and what is already consumed is the file. Measured: for `Microsoft-Windows-SMBServer/Audit` the old arithmetic claimed 58,720,256 bytes of growth and the correct one 67,039,232 — the file is 69,632 bytes, not the 8 MB its ceiling allowed. Across the five channels the guard now reports 319.67 MB where it would have reported about 280 MB. Proven: one volume verdict rather than five per-channel questions, `-Apply` 5 of 5, idempotent, `-Rollback` 0 of 5. |
| `anti-tampering/Remove-PowerShellV2.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-23 | Audit → Apply → Apply → Rollback → Rollback. Feature disabled and re-enabled via DISM, host returned to its exact baseline. |
| `anti-tampering/Protect-EventLogs.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-23 | Audit → Apply → Apply → Rollback, with `-RemoveAdminClear`. Hardening proven functionally: clearing a log went from permitted to `Access is denied` and back. **2026-09-02:** `-Rollback` took the channel AND the descriptor straight from the manifest and handed them to `wevtutil sl /ca:` as SYSTEM, with no guard — `Assert-SddlNotMorePermissive` covers the apply path only, and cannot cover this one because a rollback legitimately loosens. `Assert-ChannelRestorable` now applies a constraint the script owns: the channel must be one `-Channels` names and must exist, the descriptor must parse, and it must not grant write or CLEAR to a well-known unprivileged principal. The restore also reads the descriptor back instead of trusting `wevtutil`'s exit code. Proven on the lab: an owned channel with the host's real descriptor is allowed and a read-only grant to Everyone is allowed, while a non-owned channel, a channel absent from the host, a malformed descriptor, an empty one, `CLEAR` for Everyone and `write` for BUILTIN\Users are each declined by name; and a full `-Apply -RemoveAdminClear` → `-Rollback` cycle changed three descriptors and restored all three byte-identically, each reported "read back and confirmed". |
| `anti-tampering/Test-VisibilityDrift.ps1` | **L2** | Windows Server 2019 Datacenter, build 17763 | 2026-08-28 | Read-only by design, so L3 does not apply. Proven by a full sabotage-and-detect cycle across all four change types. **2026-08-28 (AT-2 fixed): now verifies the full intended audit set via `expectation` manifest records — proven by switching off `Logon` (already-enabled, no change record) and getting exit 1 naming `{0CCE9215}`, where it was previously blind.** **2026-09-02:** two silent blind spots closed. Measured across all 18 scripts: three wrote an `eventchannel` change with `newMaxSize` and two with `newMaxSizeBytes`, and this script read only the first spelling — so a shrunk AppLocker or ForwardedEvents channel was never checked. `Protect-ForensicArtifacts` wrote a `service` change with `serviceName` while `Set-TimelineIntegrity` wrote `service`, so a W32Time change keyed on an empty string and could never verify. The reader now tries every name a field has been written under (the manifest is append-only, so renaming the writers does not rename what is on disk), the writers are aligned on the unit-bearing name, and `tools/check.ps1` now fails the build when two scripts write the same change type with different field names. Proven on the lab: a post-fix record carries `newMaxSizeBytes` and no `newMaxSize`, so the old reader found an empty value on it; shrinking the AppLocker channel from 134217728 to 1052672 bytes is now reported as drift with exit 1; and the service key resolves `W32Time` from either spelling. |
| `logging-hardening/Enable-ServerPrefetch.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-24 | Audit → Apply → Apply → Rollback, baseline restored exactly. **The setting does not take effect on this host** — see below. |
| `logging-hardening/Enable-LolbinAudit.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-28 | Audit → Apply → Apply → Rollback → Rollback, read-only proven by diff, baseline restored exactly. Effect proven by observing real 8003 events, not by reading the policy store. **2026-08-28 (AT-4): now sizes the AppLocker channel via `wevtutil sl` — proven 1052672 → 134217728 on Apply, idempotent, and restored to 1052672 on Rollback.** |
| `anti-tampering/Protect-ForensicArtifacts.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-25 | Audit → Apply → Apply → Rollback → Rollback with `-EnableLastAccessUpdates`, baseline restored exactly. Service change type proven by sabotaging DPS to Stopped/Disabled, restoring it, and rolling back to the sabotaged state. One declared deviation from strictly-read-only — see below. |
| `anti-tampering/Deploy-TamperAlerts.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-28 | Audit → Apply → Apply → Rollback → Rollback, read-only proven by diff. Forward-looking detection proven by effect: clearing a log fired the task within five seconds and the handler wrote the alert. **2026-08-28 (AT-3): the handler now pages by per-channel EventRecordID, oldest-first — proven lossless across a forced cap (mark advanced 701274→703039→703084→703101, MISSING=0) where the old newest-200 + timestamp bookmark dropped events under a same-second burst.** **2026-09-08, the state-file silencing pass (C1/H1 plus two cross-model reviews).** The forward-looking handler keeps an UNSIGNED, unhashed JSON state file, and everything else about that handler is verified - the task must exist, its action must name this root's handler, and the handler's bytes are compared against the template - so the state file was the one input nothing checked. Four defects, all of them silencing rather than breaking, each proven with a differential control that reproduces the pre-fix behaviour: (1) the rate guard tested only `delta -lt 15s`, which a NEGATIVE delta always satisfies, so a `lastRunUtc` forged into the future made every wake `exit 0` before the scan AND before the state rewrite - permanent, self-sustaining, one file edit; measured pre-fix as 0 alert lines with the forged stamp intact, post-fix as a TAMPER alarm, a completed scan (14 lines) and the stamp healed to the real clock in the same run. (2) A per-channel bookmark above the channel's newest record filtered every later event out while looking exactly like a quiet channel - `Int64.MaxValue` planted, caught, discarded, rescanned. (3) The `notices` repeat-suppression map had the same future-stamp bug and was WORSE, because its else-branch re-persists the original stamp, so unlike `lastRunUtc` it never healed: an attacker who renders a watched channel unreadable, reads the exact localised message Windows returns for it and writes that message under a future stamp removes the only line that reports the channel has gone dark, permanently. Proven on a deliberately unreadable channel: the forged stamp now raises a TAMPER alarm, the SCAN-NOTE is still emitted, and the forgery is not carried forward. (4) **The bookmark did not have to be impossible to hide a destruction event.** On a quiet channel the next `EventRecordID` is simply the current newest plus one, so a mark planted at that value sits inside the legal range - no ceiling check can fire - and skips the `1102` that follows; a mark above an already-logged `1102` does the same to it. Measured: with the mark planted at the target record, the pre-fix handler produced 0 lines about that record and 0 alarms of any kind. Fixed by a DESTRUCTION SWEEP: ids 1102/104/524 are read from the 24h floor on every wake, independent of the bookmark, and ordered BEFORE the bookmarked query because `Get-WinEvent` raises a terminating error when a filter matches nothing and the catch ends in `continue` - placed after it, the sweep would never run on exactly the hosts that need it. Repeats are throttled for 1 hour by a per-record stamp that suppresses ONLY on proof and only briefly: a stamp that is absent, unparseable, in the future or expired all report, so a forged throttle entry is worth at most an hour and every gap reports. All four verified on the lab, 20 assertions, 0 failures, plus the parent-side cross-check naming all four impossible shapes in one finding at exit 1 while leaving the file untouched, and `-Apply` resetting it with no manifest record and no applied/recorded mismatch. **Two of these were defects in the first version of THIS pass**, caught by the code review, and both were false accusations rather than misses: a mark with a blank `lastRecordId` was reported as a shape 'this script cannot have written' when `Set-ScanBookmark` writes exactly that for a record with a null `RecordId` - a permanent exit 1 with no lever, re-created by every `-Apply` - and a future `LastTimeUtc` was called forged when `TimeCreated` is the host clock at write time, so a VM restored from a snapshot leaves genuinely future-dated records behind. The first accusation was removed; the second is now bounded at the writer (`Set-ScanBookmark` clamps its stamp to `now`) and worded to name the clock as a cause. The review also showed the tighter per-source ceiling was wrong FOR THE HANDLER - a mark below the channel ceiling hides only history already alerted on, so filtering by watched id rejected forgeries that suppress nothing at the cost of a backward scan of the channel on every wake; the tight ceiling is still correct in the retrospective scan, where a mark demotes a real hit out of the exit code. Also fixed: a CRLF payload in `lastRunUtc` parsed, tripped the alarm and injected blank lines into a line-oriented alert log (now sanitised like every neighbouring writer), and the log kept ONE rotation generation so 8 MB of induced noise destroyed every TAMPER line before it - now five. The rendered handler is 400+ lines of PowerShell that, at the time of this pass, **no gate parsed**, so it was parsed under the real 5.1 parser on the lab as part of each run above; `tools/check.ps1` gate 12 has covered it since later the same day (REVIEW-FINDINGS G-1). **2026-09-08, two false all-clears in the same script.** (1) The existing-task branch printed `[ ok ] ... already registered (state Disabled)` and stopped there: the state was in the output for a human to read, which is not the same as checking it. A disabled task never fires, so the entire forward-looking detector was off behind a green run - one `schtasks /change /disable` away. Now tested, not just printed: a `Disabled` task is a finding naming the exact re-enable command, and `Unknown` is reported as undetermined rather than as failure. Proven on the lab by disabling the real armed task: `[ ok ]` became a finding at exit 1, and the task was restored to `Ready` (5 of 5 assertions). The printed `schtasks.exe /Change /TN "IronBlackBox\IronBlackBox-TamperAlert" /ENABLE` was itself executed on the lab in both directions, exit 0 each way, because a command in operator-facing output does not ship on the strength of looking right. One bug was caught doing this: `[char] '\\'` is a TWO-character string in PowerShell and the cast throws `String must be exactly one character long`, which would have turned the finding into exit 2 - proven to throw before the fix, then corrected to `[char] '\'`. (2) `-MaxEventsPerSource` silently decided the real lookback. `Get-WinEvent` is asked for the NEWEST N events inside the `-LookbackDays` window, so whenever the cap binds the oldest part of the window is never read - and it was reported only as `there may be more`. Measured at the DEFAULTS on an idle lab host: the `command-line` source (4688) was examined back to `2026-09-08 14:49`, under three hours, against a heading claiming `2026-08-09 17:30`. A capped source now prints its real floor as a date and states plainly that anything older was not read (4 of 4 assertions). The default itself is left as an open decision - the review log kept in the development repository D-3. **2026-09-08, D-3 closed.** `-MaxEventsPerSource` was deciding the real lookback: `Get-WinEvent` returns the NEWEST N inside the window, so a bound cap left the oldest part unread behind the phrase "there may be more". Measured at the OLD defaults on an idle lab host, the 4688 source covered under three hours against a heading claiming thirty days. Split into two parameters, because one number was doing two incompatible jobs: `-MaxEventsPerSource` (500 -> 2000) for the watched-id sources, whose events are rare, and a new `-MaxCommandLineEvents` (2000) for the 4688 sweep, documented as the recent tail rather than a window because 4688 has no server-side filter on 5.1. Measured after: **zero** watched-id sources cap where two did before; the 4688 source reaches 1.3 days instead of 2h40 and says in its own line that it is the tail, not the window; the heading no longer states the window as fact; and a capped source prints the date it actually reached. Runtime cost measured rather than assumed: 9.1s -> 20.8s on a full `-Audit`. 4 of 4 assertions. |
| `logging-hardening/Enable-Sysmon.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-25 | Audit → Apply → Apply → Rollback → Rollback with a staged Sysmon 15.21 and Olaf Hartong's `sysmonconfig.xml`. Recording proven by observing Sysmon event ID 1. Three defects found by running it, one of them a false "Sysmon collects nothing" on a working host. **2026-09-08:** the recording probe ran `& "$env:ComSpec"` - an environment variable, in a script that runs as SYSTEM. Anything able to set `ComSpec` for that context chose the executable a SYSTEM process would launch, which is an arbitrary-execution primitive handed out by the hardening toolkit itself, and it was the one native target in this script that was not anchored. Now resolved through `Get-NativeToolPath -RequireAnchored`. The more interesting half is what that exposed: three of the five return paths of `Test-SysmonRecording` reported `Recording = $false` when no observation had been made at all, and the caller turned that into the finding *"a process started by this script produced no event ID 1 ... Sysmon is installed and is not collecting"* - a statement about a process that was never started, which would send an operator hunting a driver fault that does not exist. Every return now carries `Observed`, and the caller has three verdicts instead of two: recording, observed not recording, and not established. The absence of any Sysmon channel keeps `Observed = $true`, because that absence IS the observation. |
| `anti-tampering/Protect-DefenderConfig.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-25 | Audit → Apply → Apply → Rollback → Rollback, baseline restored exactly. All three change types exercised end to end against real Defender exclusions, including DF-1: the baseline now refuses to absorb an exclusion it just reported. |
| `anti-tampering/Test-DefenderPosture.ps1` | **L2** | Windows Server 2019 Datacenter, build 17763, PS 5.1.17763.9121 | 2026-09-08 | Read-only by design — no `-Apply`, no `-Rollback` and no Manifest region, so L3 does not apply. Read-only proven by a **609-item** before/after snapshot across one `-Audit`: both Defender registry trees enumerated recursively (`HKLM:\SOFTWARE\Microsoft\Windows Defender` and the Policies tree), six Defender services with status and start mode, and the entire toolkit root tree — **ZERO differences**, including inside its own root. What it reported on this host: `AMRunningMode = Normal`, `AMServiceEnabled = True`, `MsMpEng.exe` running, `RealTimeProtectionEnabled = True`, signatures 0 days old (last updated 2026-09-07T16:25:48Z), and the Defender Operational channel enabled with 1104 records. `IsTamperProtected = False` was reported as a `[limit]`, not a finding, and correctly so: turning tamper protection on needs Intune or Defender for Endpoint, so no `-Apply` of this script can ever clear it — `docs/DESIGN.md` §3.1. The run's exit 1 came from the isolated test root inheriting ACEs from `ProgramData` — that is the root-DACL finding, not a posture result. Created 2026-09-07 when `Protect-DefenderConfig` was split in two. **Deployment consequence, see `docs/DEPLOYMENT.md` §2:** a monitor still watching only `Protect-DefenderConfig` for posture does not start erroring — it returns 0 on a host whose real-time protection has been switched off. |
| `logging-hardening/Enable-LegacyAuthAudit.ps1` | **L4** | Windows Server 2019 DC, `lab.example` | 2026-08-25 | Full cycle on a real primary domain controller. Read the live NTLM and LDAP state, found a genuine event 2886 (this DC does not require LDAP signing), and restored the baseline. |
| `logging-hardening/Enable-DnsVisibility.ps1` | **L4** | Windows Server 2019 DC, `lab.example` | 2026-08-25 | Full cycle **including the DNS-server half** — the `dnscmd` path where D-1 lived. Also L3 on the domain-joined member. |
| `logging-hardening/Enable-WefCollector.ps1` | **L4** | Windows Server 2019 DC, `lab.example` | 2026-08-27 | Full cycle, and **forwarding demonstrated end to end**: 145 events arrived in `ForwardedEvents` from the member, with the source listed under `EventSources` and heartbeating. Required fixing W-1 (the svchost split) on the host first — the script detects and names that condition but deliberately does not change it. **2026-08-27: W-2 fixed and Security forwarding proven.** The 26 Security event IDs were in a single `<Select>`, over Microsoft's documented 20-expression ceiling; the source silently dropped that channel and kept delivering the other two. Now chunked 20 + 6: the subscription reached verdict **100** for the first time and 30 marked 4688 events arrived within 40 s with command lines intact. **AT-1 fixed the same day**: 9 Security IDs and 1 System ID added (26 → 35, chunked 20 + 15), including 4698 and 4719. Proven — a forwarded 4698 arrived carrying **1,660 bytes of task XML with its `<Command>` intact**. |
| `logging-hardening/Enable-WefClient.ps1` | **L4** | Windows Server 2019 member, `lab.example` | 2026-08-27 | Full cycle, and **forwarding demonstrated end to end** once W-1 was cleared on the collector: WinRM logged `Enumeration completed successfully` and `EventDelivery completed successfully`, and 145 events reached the collector. Security forwarding proven end to end once W-2 was fixed on the collector. **2026-08-27: the script now interprets forwarder events 101 and 102 per subscription, from structured fields, and names the unreadable channel and its error code** — proven on the lab against a live 101, a live 102 and a live 100 in the same enumeration round, with dropped and stale verdicts excluded and counted. |
| `logging-hardening/Enable-AdObjectAuditing.ps1` | **L4** | Windows Server 2019 DC, `lab.example` | 2026-08-25 | Full cycle on a real primary domain controller, all three targets returning to their exact pre-apply SACLs including AdminSDHolder's pre-existing `0xC0020` ACE. Effect proven: modifying the Domain Controllers OU produced 8 × event 5136 and 10 × event 4662. |
| `logging-hardening/Set-TimelineIntegrity.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-25 | Full cycle, baseline restored. Effect proven with a real peer: the clock was pushed 12s out and the record kept both the offset as found (-11.9857s) and after correction (-3.34e-05s). **2026-08-28 (T-3):** `Restore-ServiceChange` had no host resolution and wrote the recorded previous StartType back unconditionally, clobbering a deliberate post-apply change and calling it a rollback. It now resolves three ways. |
| `logging-hardening/Enable-UsnJournalTracking.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-25 | Full cycle with a real journal growth. Enlarging a journal is **irreversible on this OS** — measured, and now stated by the script instead of reported as a successful restore. |
| `anti-tampering/Enable-VssPreservation.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763 | 2026-08-25 | Apply, idempotent re-apply and rollback all proven, V-1 and V-2 fixed. **2026-08-28 (R-1):** a second `-Rollback` no longer declines a change the host already holds at its pre-apply value; under the three-way doctrine in `docs/DESIGN.md` §4.1 that case counts as `restored`, so the run converges and the drift detector stops reporting correctly-restored changes. **2026-09-02 (V-1, second half):** `vssadmin resize shadowstorage` put the protected volume in both `/for=` and `/on=`, so on a host whose diff area is relocated to another disk the command asked Windows to RELOCATE it — discarding the snapshots the script exists to preserve — while the headroom guard had measured the other disk. `/on=` now follows the resolved diff volume, and the manifest records the volume the bytes actually land on. **2026-09-02: proven end to end against a genuinely relocated diff area.** The earlier attempt used a VHD hosted on `C:`, which VSS refuses as "nested too deeply to participate in the VSS operation" — that error is about a backing file living on the protected volume, not about sharing a physical disk. A real second partition works: `C:` was shrunk online by 15 GB and `D:` created on the same disk, and `vssadmin add shadowstorage /for=C: /on=D:` was accepted. With the area on `D:`, `-Audit` printed "the shadow storage area for C: lives on D:, so free space and the floor are measured there"; `-Apply` sized it without relocating it; the manifest recorded `volume=C: diffVolume=D:`; and `-Rollback` restored the previous maximum with the area still on `D:`. The decisive evidence is not a reading of the code but Windows' own process-creation audit — event 4688 captured `vssadmin.exe resize shadowstorage /for=C: /on=D: /maxsize=4187467038`. No second EBS volume was needed. **2026-09-02:** a manifest-supplied volume now passes the same resolution `-Volume` passes before it reaches `vssadmin` — proven on the lab: `C:`, `D:` and a bare `C` are accepted and normalised, while `Z:` (absent), a UNC path, a `\\?\Volume{guid}\` path, an empty value and `C:\Windows` are each declined with a finding. |
| `anti-tampering/Enable-VssSnapshotSchedule.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763, PS 5.1.17763.9121 | 2026-09-08 | Audit → Apply → Apply → Rollback, on a toolkit root the script created and stamped itself, so this was a real first arming rather than an adoption. `-Apply` registered `\IronBlackBox\IronBlackBox-VssSnapshot` (daily 06:30 and 18:30 plus up to 15 minutes of random delay) and reported 1 change against exactly 1 manifest `change` record. The second `-Apply` reported "already registered (state Ready)" and `0 change(s) applied`, with **zero host differences** — measured over every task under `\IronBlackBox\` and the whole toolkit root tree. The manifest gained a `run`/`run-end` pair and **no** new `change` record, which is `docs/DESIGN.md` §4's no-change run and the reason the manifest is excluded from a host-state diff. `-Rollback` removed the task and returned the scheduled-task set to the pre-run baseline exactly, leaving the `.ironblackbox` stamp, the manifest and the inert handler script — each of which the script's help says it leaves. **Measured, and it settles the `# UNVERIFIED:` marker on `-UserId`:** `S-1-5-18` is accepted by `New-ScheduledTaskPrincipal` and reads back as `UserId=SYSTEM LogonType=ServiceAccount RunLevel=Highest`. Microsoft still documents no accepted format for `-UserId`, so the marker stays and the script goes on reading the principal back instead of asserting it. **Two false output strings were fixed before this run:** the no-findings verdict claimed "shadow storage and the snapshot task are configured" in a script that never reads shadow storage, two sections below its own line saying it does not; and the generated handler's header named `Enable-VssPreservation` as its author, which would send a responder who found the file to the wrong script. **NOT proven here:** that a snapshot SUCCEEDS. That needs a shadow storage association on the target volume, which `Enable-VssPreservation` owns; this script does not read one and its verdict now says so. **2026-09-08, the AT-12 port.** The existing-task branch used to `return 0` as soon as it saw the task, so a toolkit update that changed the handler template NEVER reached an armed host: the task existed, the run printed "already registered", and the OLD handler kept running until somebody did a full `-Rollback` then `-Apply`. `Deploy-TamperAlerts` had learned this (AT-12) and this script had not - a fix that landed in one copy of a pattern and not the other. Found while correcting this script's own handler header, a correction that would have reached no armed host. Now the branch compares the deployed handler against `Get-SnapshotHandlerScriptText` (one source, so the writer and the checker cannot disagree) and rewrites it on drift under `-Apply`, returning 0 recorded changes because no manifest record is written for a toolkit-owned derived file. **A change of VOLUME is deliberately NOT treated as version drift.** The volume is stamped into the handler and the registered task's description names it, so rewriting the handler for a different volume would re-point what gets snapshotted while leaving a task that says otherwise - a silent change of target on a client's host, the same class of act as `Register-ScheduledTask -Force`, which this script refuses everywhere. It is reported and left alone in BOTH modes. Proven on the lab, 16 assertions, 0 failures: `-Apply` registers and writes the handler (and the corrected header reached the host); a second `-Apply` reports "matches this toolkit version", 0 changes, zero host differences; a hand-staled handler on an already-registered task is reported by `-Audit` at exit 1 and rewritten byte-identically by `-Apply` with the count still 0 and no applied/recorded mismatch; a handler pointing at `Z:\` is reported as a change of target and left untouched by both `-Audit` and `-Apply`; `-Rollback` removes the task and returns the scheduled-task set to baseline. One bug was introduced and caught during this change: the volume-reading regex was written in a DOUBLE-quoted PowerShell string, where a backslash escapes nothing, so `"\$volume"` interpolated the empty `$volume` and the pattern degraded to `^\s*\s*=\s*'...'` - matching the FIRST quoted assignment in the handler instead of the volume one. Rewritten single-quoted and unit-tested against the shipped literal. The rendered handler is now covered by `tools/check.ps1` gate 12 (REVIEW-FINDINGS G-1). |

### `exit 1` as the permanent state of a healthy fleet (2026-09-02)

Measured before the fix, on a fully armed host: **ten of the eighteen scripts
exited `1`**, and several could never reach `0` there. An RMM monitor built on
this toolkit's documented exit codes would be red on those hosts every night,
and a monitor that is always red gets muted — taking the findings that did matter
with it.

The exit code now means **an action exists**, not that a condition exists.
`Write-HostLimit` prints `[limit]`, is counted separately in the result, and
never touches the exit code. The test between the two is the lever, not the
severity — `docs/DESIGN.md` §3.1 is the contract.

Five conditions were reclassified, each because no `-Apply` of its script will
ever clear it on the host in question:

| Script | Condition | Why no lever |
|---|---|---|
| `Protect-DefenderConfig` | `IsTamperProtected = False` | needs Intune or Defender for Endpoint |
| `Enable-ServerPrefetch` | no `.pf` files, fast media only | measured: the setting is written, survives a reboot, and Windows removes it again |
| `Protect-ForensicArtifacts` | no `.pf` files, fast media only | same, and its own docstring already said absence there is not tampering |
| `Enable-LolbinAudit` | a LOLBin this Windows build does not ship | the rule is written anyway; presence is not ours to change |
| `Enable-LolbinAudit` | no complete publisher identity | `pcalua.exe` reports an empty `BinaryName`; the path rule is written and works |

Both Prefetch cases are conditional on the media, so on ordinary disks they stay
findings — the reclassification is measured, not blanket.

Result on the armed lab host: **eleven of eighteen scripts exit `0`**, with four
host limits reported, and **every remaining `1` names something an operator can
act on** — a Sysmon config to stage, a WEF collector to bring up, the Atomic
exclusion still sitting on the host, `-EnableLastAccessUpdates` not passed, a
time source the lab DC cannot serve while it is switched off, and 119 real
log-clear events this host accumulated during testing.

*(That last item was wrong, and the negative-path pass below found it: 118 of
those 119 were already past the bookmark and returned on every run, which is the
permanently-red monitor this whole section exists to remove. Fixed there.)*

### The negative-path pass, and the finding it found in the fix above (2026-09-03)

A clean cycle exercises the happy path. But 112 of the fixes made in the
medium/low sweep landed on error paths — corrupt input, wrong types, exhausted
retries — and **no happy-path cycle reaches any of them**. So they were driven
directly.

**Manifest sabotage.** All eighteen scripts against four damaged manifests each
— last record truncated mid-token, complete but with no final newline, a corrupt
record in the middle, and raw binary — plus an empty file on the six that accept
one. All clean: the repairable cases exit `0` after quarantining or terminating,
and the unrepairable ones exit `2` with `[FAIL] Manifest is corrupt at line N of
M and cannot be repaired automatically`, never treating corruption as an empty
manifest.

Verified at the artefact level rather than by exit code alone: the `.torn-*`
quarantine file holds the damaged bytes **verbatim** (`{"recordType":"chan`), the
manifest is re-readable afterwards, and there is **zero `.repair`/`.prerepair`
residue** — the `File::Replace` rewrite leaves nothing behind. On the
unterminated file the last byte went `0x7D` → `0x0A` and the next append produced
**zero unreadable lines**.

**Wrong-typed registry values.** A `REG_SZ`, `REG_MULTI_SZ` and `REG_BINARY`
planted where each script expects a `DWORD`. Two different correct behaviours,
which is the point: `Protect-ForensicArtifacts` **refuses to interpret** and says
so by name, because it *reads* the value to answer a question and an
uninterpretable value means it cannot answer. `Enable-ServerPrefetch` **names the
type** (`EnablePrefetcher = 1 (String)`) and proposes the documented value,
because it *sets* that value and `previousKind` in the manifest is what restores
the `REG_SZ` on rollback. Neither produced a raw .NET exception trace. The
original value **and kind** were restored after each case.

*(The test's own expectation was wrong here, not the code — it wanted a refusal
from both. Recorded because a negative pass that only reports the code's failures
and not the harness's is not being read carefully.)*

**The taxonomy, re-measured.** Twenty-six of those 112 fixes touched exit codes,
so the armed-host measurement in the section above was run again: **twelve of
eighteen exit `0`** (eleven of the fourteen actually armed), and every remaining
`1` names an action.

That re-measurement found a real defect, and it is in the section above. That
section closed by accepting `119 real log-clear events this host accumulated
during testing` as a legitimate remaining `1`. It is not. `Deploy-TamperAlerts`
bounds its retrospective scan by `-LookbackDays`, **not** by the bookmark,
so 118 of those 119 were events already past the bookmark that come back on every
single run — one cleared Security log would have held that host at `1` for thirty
days after an operator had already read it. Exactly the permanently-red monitor
the reclassification was for, reintroduced by the reasoning that classified by
seriousness rather than by the lever. `docs/DESIGN.md` §3.1 now carries the case.

Measured after the fix, on the same host:

| | exit | findings |
|---|---|---|
| armed, nothing new since the bookmark | `1` | 1 — the Security log's reach, which `Enable-IRVisibility` can extend |
| after `wevtutil cl "Windows PowerShell"` | `1` | 3 — the same one, plus **two** `[NEW]` hits |

The two are the same act caught through independent paths: event `104` from the
channel and the `4688` command line of `wevtutil.exe cl`. The detector was not
muted to buy the lower number — 118 lines of history moved out of the exit code
and the new event stands clear of them.

**The review of that fix found three defects in it, and one of them was worse
than the noise.** Recorded because the measurement above was already green when
they were found, which is exactly when a fix stops being examined:

- The output told the operator to adjust `-RetrospectiveDays`. **No such
  parameter exists** — it is `-LookbackDays`. An operator following the message
  would have hit a parameter-binding failure, which this project's own exit
  taxonomy maps to host exit `1`: the spurious `1` the change existed to remove.
  Fifth invented identifier this project has caught by review or by execution,
  after `Format-Mib`, `Get-ChannelAccess`, `-MaxSizePercent` and
  `$script:ToolkitRootPath`.
- Moving the hits to `Write-Info` took them out of the exit code **and out of the
  result section's arithmetic**, which made `No findings: nothing in the window`
  reachable on a host with a list of tamper indicators printed immediately above
  it. A false all-clear in a tamper detector, introduced by a fix for noise. The
  result section now names both classes it is not counting, and the all-clear
  line is reachable only when both are zero. Reproduced on the lab in the exact
  state that triggers it — bookmark advanced past every hit by an `-Apply`, then
  `-Audit -LookbackDays 3` to drop the Security-log-reach finding that had been
  masking it — which is `0` findings with five indicators still listed. Result:
  `Nothing NEW: 5 indicator(s) reported before, listed above. None of that is
  part of the exit code.`, exit `0`, and the `nothing in the window` line absent.
  Two runs were needed to reach that state, which is why the first measurement
  did not find it.
- The doctrine text claimed no `-Apply` "with any parameters" removes one of
  these, two lines above a message telling the operator to change a parameter
  that does hide them. Reworded to what is actually true: nothing the script
  *does* removes a past event, and only time takes them out of view.

**The security review found that the fix had turned a cosmetic file into
authority over the exit code.** This is the most serious thing in this section,
and it was created by the fix above, not found in old code.

Before the split, forging `alerts\tamper-scan-state.json` changed a prefix —
`NEW` versus `seen before` — and nothing else. After it, a hit at or below the
mark is out of the exit code, so setting `lastRecordId` to `Int64.MaxValue`
silences that source permanently, and because `Set-ScanBookmark` only ever
advances, **no `-Apply` repairs it**. Clearing the Security log already requires
the privilege needed to write that file. Every other administrator route to
blinding this detector is loud or is itself a finding: delete the bookmark and
everything reports as new, delete the scheduled task and
`Register-TrackedAlertTask` reports it, edit the handler and its hash check
reports it. The split had made bookmark forgery the only quiet one.

The safety comment on `Test-EventIsNew` claimed the opposite of what the code
does. It said `-gt` makes a reset or reused record number *re-report* an event
rather than hide one. `-gt` classifies a RecordId at or **below** the mark as
already-seen, which hides it. True and harmless while the prefix was the only
consequence; not harmless afterwards.

Fixed by rejecting a mark that cannot be justified, in two independent ways:

| Check | Rule |
|---|---|
| the mark stands above its own source | a mark is only ever advanced to a record this script retrieved, so a value above the newest record that source's own filter can return is one no run can have written — discard it, report the source from the start of the window, and raise a finding naming both numbers |
| the mark cannot vouch for the event | a mark now records the window it examined (`sinceUtc`) and whether that examination was complete (`capped`); a hit older than that window, or from a source that was capped, is reported as new |

The ceiling deliberately uses each source's own filter and not its channel: a
channel-wide ceiling sits above what a per-source mark can legitimately reach,
which is exactly the gap a forged value needs.

Measured on the lab, after the fix:

| Test | Result |
|---|---|
| bookmark from the previous version, no `sinceUtc` | 5 new, 0 demoted — fails closed on upgrade, self-corrects at the next `-Apply` |
| `-Apply`, then `-Audit` | 1 new, 4 demoted — normal demotion intact |
| `lastRecordId` forged to `Int64.MaxValue` on `audit-log-cleared` and `wevtutil-clear` | both named as impossible (`848185` and `936743` are the real ceilings), marks discarded, **1 new / 4 demoted — identical to the un-forged run**, so nothing was silenced |
| `-Apply -LookbackDays 1`, then `-Audit -LookbackDays 30` | **118 new**, 2 demoted — the 29 unexamined days are reported, not demoted |

The second finding is the ordinary-operator one and needed no attacker: `-Apply`
advances a mark to the newest record it *retrieved*, which is not the newest that
exists. A narrow `-LookbackDays`, or any source busy enough to reach
`-MaxEventsPerSource`, leaves events below the mark that no run ever printed.
Before the split those were mislabelled; after it they would have left the exit
code unseen.

**The flagship indicator, finally measured instead of inferred.** The earlier
"the detector was not muted" run used `wevtutil cl "Windows PowerShell"`, which
clears neither Security nor System — so no mark could have been above its
channel, and the case that matters was never exercised. Clearing Security
directly:

| | value |
|---|---|
| newest Security `RecordId` before the clear | 937094 |
| oldest after the clear | 937101 — the 1102 itself |
| newest after the clear | 937107 |
| reported | `[find] [NEW] the Security audit log was CLEARED (event 1102) ... record 937101`, exit `1` |

`verified-lab` on Windows Server 2019 build 17763, 2026-09-03: **`wevtutil cl`
does not reset `EventRecordID`** — the counter continued across the clear on
Security, and independently on System and `Windows PowerShell`. Microsoft
documents nothing about this; *Event Log Records* says the first record written
is number 1 and is silent on clearing, and `EvtClearLog`, `ClearEventLog`,
`EventRecord.RecordId` and the 1102 page say nothing either. So this is a lab
measurement on one build and not a general Windows fact — other builds, and
replacing the `.evtx` with the service stopped, are unmeasured. It matters
because if a counter ever did restart, post-clear events would fall below the
mark; that is now caught by the ceiling check rather than relying on this
behaviour.

**A trap in the instrument, worth recording.** `wevtutil gli Security` reports
`oldestRecordNumber: 1` on a log whose real oldest `EventRecordID` is 937101.
That field is not an `EventRecordID`. Anything reasoning about record numbers
must read them from the events.

**Environment limits, stated rather than worked around.** `Set-TimelineIntegrity`
cannot reach `0` on this lab: EC2 does not route to `time.windows.com`, so
`w32tm /query /source` still reports `Local CMOS Clock` after a successful
`-Apply` and the offset is unmeasurable. The findings are accurate about the
host, and they name the action (point it at a reachable peer). Not evidence the
script is wrong, and not evidence it is right on a host with real NTP.

### Native tool resolution, and the two sites my own greps could not see (2026-09-03)

`Get-NativeToolPath`, `Invoke-NativeCommand` and `Get-PowerShellHostPath` were
copied into scripts **outside** any template region, so the drift check never
compared them. Measured before moving them: the code bodies of all fourteen
`Invoke-NativeCommand` copies were byte-identical, but two had dropped the
docstring explaining why the wrapper exists and a third had gained a note telling
the next author not to improve it. Comment-only drift, so nothing was broken —
recorded because `docs/AUTHORING.md` had *predicted* this failure and told
authors to diff by hand, and hand-diffing did not catch it.

All three now live in a `Native commands` region. The guard was proven rather
than assumed: removing `Sysnative` from one script's copy produces
`[FAIL] region 'Native commands' diverges from docs/SCRIPT-TEMPLATE.ps1`, naming
the file and both line numbers.

**Then the security review found two sites still resolving through PATH, and
neither looked like the thing I was grepping for.**

| | what it was | why the grep missed it |
|---|---|---|
| `Enable-DnsVisibility` | `Get-Command -Name 'dnscmd.exe' -CommandType Application`, whose `.Source` was then executed as SYSTEM — including in `-Audit`, which is where role detection runs | a cmdlet call, not `& tool.exe` |
| `Enable-IRVisibility` | `New-ScheduledTaskAction -Execute 'powershell.exe'`, SYSTEM at Highest, daily, for the life of the host | the Task Scheduler service does the resolving, not PowerShell |

The DNS one is worst on a host *without* the role: there is no System32 copy to
shadow, so any user-writable PATH directory wins outright, and a planted
`dnscmd.exe` exiting 0 from `. /info` made the script conclude a DNS server was
present — after which `-Apply` fed it `/config` writes. Fixed with a
`-RequireAnchored` mode that returns `$null` instead of a bare name, so absence
means "the role is not installed" rather than "ask PATH".

The task one had two shipped siblings already doing it right via
`Get-PowerShellHostPath`. Fixed, and the already-deployed case is now reported
rather than silently rewritten — rewriting it would have needed a manifest record
whose rollback (`Remove-TrackedScheduledTask`) **unregisters** the task, which
would have deleted a task predating the run.

Proven on the lab host the *previous* version armed:

```
[find] the transcript rotation task runs "powershell.exe", an unqualified name the
Task Scheduler service resolves itself, as SYSTEM at Highest every night. ... clear
it by hand and re-run: Unregister-ScheduledTask -TaskPath '\IronBlackBox\'
-TaskName 'IronBlackBox-TranscriptRotation' -Confirm:$false
```

**Three claims the review made from memory, measured instead of repeated**
(Windows Server 2019 build 17763, 2026-09-03):

| Claim | Measured |
|---|---|
| `winrm.cmd` calls `cscript` unqualified | **true** — its whole body is `@cscript //nologo "%~dpn0.vbs" %*`. Anchoring the wrapper bought nothing for that tool and added the SYSTEM process's current directory as a vector, since `cmd.exe` searches it before PATH. Replaced with an anchored `cscript.exe` plus the explicit `winrm.vbs` path: **byte-identical output and exit code**, so the parser is untouched |
| `powershell.exe` sits fourth in the machine PATH | **true** — rank 4, `C:\Windows\System32\WindowsPowerShell\v1.0\`. Three entries precede it, so the task finding's severity is measured, not assumed |
| `System32` first means a 32-bit host never reaches `Sysnative` | **true** — from a 64-bit process `Sysnative` does not exist and this falls through to `System32` unchanged; from a 32-bit process all three exist, so `System32` first served the redirected copy and `Sysnative` was dead code. The docstring already claimed Sysnative existed to escape redirection; the order made that impossible. Reordered |

**The gate that should have caught all of this.** `tools/check.ps1` skipped every
command name ending in `.exe` — deliberately, because those are not PowerShell
commands — which left the whole class unguarded. Two gates added, each proven by
reintroducing the exact regression:

| Reintroduced | Result |
|---|---|
| `-Execute 'powershell.exe'` | `[FAIL] Enable-IRVisibility.ps1 names 1 native target(s) without a path ... -Execute 'powershell.exe'` |
| `-FilePath 'wevtutil.exe'` | `[FAIL] Protect-EventLogs.ps1 names 1 native target(s) without a path ... -FilePath 'wevtutil.exe'` |
| a second region named `Native Commands` | `[FAIL] duplicate #region name "Native Commands" at line 709` |

That third one closes a hole the review found in the gate itself: region bodies
went into a case-insensitive dictionary keyed by name, so a duplicate silently
kept only the **last** body and an edited earlier copy passed everything. It was
already live — my own rename pass had missed two regions named `Native command`,
one letter from the template-owned name.

Two more fixes from the same pass. `Get-NativeToolPath`'s fallback was
fail-open **and silent**; it now raises a finding naming the tool, because for an
in-box binary a System32 that does not hold it is a broken or hostile host, and an
empty `%SystemRoot%` means the RMM stripped the environment — both name an action.

> **The fallback itself was not exercised until 2026-09-08**, and until then this
> paragraph asserted a behaviour nothing had run. Now measured, on Server 2019
> build 17763 under real PS 5.1, against `Get-NativeToolPath` lifted verbatim out
> of `docs/SCRIPT-TEMPLATE.ps1`: `cmd.exe` resolves to
> `C:\Windows\System32\cmd.exe`; a name absent from all three directories
> returns `$null` under `-RequireAnchored`; without that switch it returns the
> bare name **and raises exactly one finding naming the tool**; and two further
> calls for the same tool add no more findings, so the once-per-tool guard holds.
> 5 of 5 assertions.

And `Enable-LolbinAudit`'s two `& ... 2>&1` plus `$LASTEXITCODE` calls now go
through `Invoke-NativeCommand`: under this script's `$ErrorActionPreference =
'Stop'`, a native tool's first stderr line is a terminating `NativeCommandError`,
so for the common failure mode the crafted message naming the exit code and the
channel was **unreachable**. The file was carrying the wrapper unused.

Regression on the lab after all of it — 17 files touched, the shared region
re-copied five times:

| | result |
|---|---|
| `-Audit`, all 18 | 12 exit `0`, 6 exit `1`, and **zero** exceptions or "is not recognized" across all 18 |
| `-Apply` then `-Rollback` on the four changed write paths | clean, zero exceptions |

`Enable-IRVisibility` moved from `0` to `1` — correctly: it is detecting the
unanchored task its own previous version registered on this host.

### Every `-Apply` capable script cycled after the native refactor (2026-09-03)

The security review's one process finding was that the `-Apply`/`-Rollback` sites
now going through `$script:<Tool>Path` had not executed since the change, and CI's
smoke test is `-Audit` only. So all of them were run — the set determined by
introspection (`[switch] $Apply` in the source) rather than by picking the ones
that looked affected: **17 scripts, 34 runs, `Remove-PowerShellV2` last because
it is the only one that asks for a reboot.**

**Zero exceptions across all 34 runs.** Manifest afterwards: 830 lines, **0
unreadable**, and zero `.repair`/`.prerepair` residue.

Three results needed explaining rather than accepting, and none was a defect:

| Result | Explanation |
|---|---|
| `Enable-WefClient -Apply` → exit `2` | `[FAIL] -Apply needs -CollectorUri (the subscription manager address). Nothing changed.` The harness omitted a required parameter; the script refused cleanly. Re-cycled **with** it: `-Apply` exit `1`, `-Rollback` exit `0` removing `...\SubscriptionManager\1 (did not exist before)` |
| `Enable-VssPreservation -Rollback` → exit `1` | `DECLINED restoring shadow storage on C: from 7.80 GB down to 7.62 GB: Microsoft documents that resizing may make shadow copies disappear, and 3 exist right now.` The three-way rollback doctrine, case 3, working as designed |
| `Enable-WefCollector -Apply` → exit `1` with 4 findings | The apply landed: Wecsvc `Running/Automatic`, ForwardedEvents enabled at 2 GB, subscription created. The fourth finding is the toolkit reporting on itself — `1 change(s) were RECORDED in the manifest but did NOT land on the host` — the SubscriptionManager URL reservation blocked by the svchost separation recorded as W-1 |

The re-cycled `Enable-WefClient` also settles the `winrm.cmd` replacement inside
the real script rather than in a side-by-side probe: the anchored `cscript.exe`
plus explicit `winrm.vbs` produced `listener: Address=* Transport=HTTP Port=5985
Enabled=true`, parsed by the untouched parser.

**Two harness defects, recorded because both are recurrences.** The first run
named its helper function `R`, which is the built-in alias for `Invoke-History`,
so every call bound to that instead — the same trap as `SV` for `Set-Variable`
earlier in this project. The second used `Write-Output` inside a function whose
return value was consumed by `+=`, so all 34 result lines went into the
accumulator and none reached the console; the runs had happened, the measurement
had not. Nothing about the toolkit was learned from either attempt, which is the
point: a green harness that measured nothing looks exactly like a green harness
that measured everything.

### REVIEW-FINDINGS item 3 closed: three names for one function (2026-09-03)

The finding named two duplicated numeric parsers. There were **three**, and the
third was invisible to a grep for the other two because its docstring said so on
purpose: `ConvertFrom-DriftNumericToken` in `Test-VisibilityDrift` opens with
*"Deliberately NOT named ConvertFrom-NumericToken"*, explains that two scripts
already carry that name and a third carries `ConvertFrom-FsutilNumber`, and says
it is named for where it lives *until the template owns one*. It was cited as
decision 3 in the finding it was an instance of.

Divergence measured before unifying, because unifying toward the weakest copy
would have shipped a defect:

| Copy | Group separators | Hex | Decimal | Overflow |
|---|---|---|---|---|
| `ConvertFrom-FsutilNumber` (USN) | strips space, comma **and dot** | `UInt64::TryParse` HexNumber | `^[0-9]+$` | rejects above `Int64::MaxValue` |
| `ConvertFrom-NumericToken` (DNS) | space and comma only | same | same | same |
| `ConvertFrom-DriftNumericToken` (drift) | **strips none** | `[Convert]::ToInt64` in try/catch | `NumberStyles::Integer`, so a leading sign parses | throws, caught, `$null` |

So on a dot-grouping locale the DNS copy returned `$null` — "unknown" — for a
value the USN copy read correctly, and the drift copy returned `$null` for any
grouped value at all. Unified to the USN behaviour, which is the only one whose
reasoning was written down: every value read through here is an integer, so a
`.` between digits is a thousands separator.

One behaviour deliberately changed: a signed token now returns `$null` instead of
a negative. All four drift call sites already test for `$null` and return
`NOT-VERIFIED` with a named reason, so a bogus negative becomes "could not be
read" rather than a size comparison against a negative number.

The unified function, exercised on the lab against the inputs all three old
callers see:

| Input | Result |
|---|---|
| `65536`, `0x10000` | `65536` |
| `65.536`, `65,536`, `65 536` | `65536` — the case the DNS and drift copies could not read |
| `1.5` | **`15`** |
| `-5`, `abc`, `''` | `$null` |
| `9223372036854775807` / `...808` | parsed / `$null` |

`1.5 → 15` is the documented hazard, and measuring it is why the docstring says
in capitals that this function must never be pointed at a fractional value. The
strip is only safe because nothing in this toolkit reads fractional native
output; a caller that ever does needs its own parser, not a flag on this one.

Guard proven: reverting one copy's strip to `[\s,]` produces
`[FAIL] Test-VisibilityDrift.ps1 — region 'Native commands' diverges from
docs/SCRIPT-TEMPLATE.ps1 (1 lines differ)`. All 16 definitions — 15 scripts plus
the template — sit inside that region, so there is no copy left that nothing
compares.

Cycled after the change: `Enable-UsnJournalTracking` and `Enable-DnsVisibility`
`-Apply` then `-Rollback` all exit `0` with zero exceptions, `Test-VisibilityDrift`
exits `1` on real drift with **zero** `NOT-VERIFIED` — no parse failures anywhere.
`Enable-UsnJournalTracking` reports `max 1,024.0 MiB (1073741824 bytes)`, read
through the unified parser.

**Still open, and named rather than swept in:** about ten ad-hoc `TryParse` sites
remain in `Enable-IRVisibility`, `Protect-ForensicArtifacts` and
`Enable-WefClient`. They were not touched. Each has its own contract to judge —
some may want `0` rather than `$null` — and folding them in blind would be the
same mistake as unifying toward the weakest copy. `ConvertTo-DecimalOrZero` in
`Deploy-TamperAlerts` is deliberately separate: it returns `[decimal]` and `0`,
which its name and its use for event record numbers both require.

### The ad-hoc numeric parses, and the one that would have broken fr-FR (2026-09-03)

Closing REVIEW-FINDINGS item 3 left about ten ad-hoc `TryParse` sites, named
rather than swept in because each has its own contract. Read one at a time,
**nine were already right** — invariant culture and the correct type. Two deserve
recording as correct: `Set-TimelineIntegrity`'s clock offset uses `[double]` with
`NumberStyles::Float` because a skew is *genuinely* fractional, so it rightly does
not go through the integer parser; and `Enable-WefClient`'s forwarder diagnostic
carries a comment naming the exact trap the others fell into — *"the no-provider
TryParse overload uses the ambient culture"*.

The sweep found more sites than the finding listed, because the search that found
the first ten looked for the wrong thing. Every no-provider overload:

| Site | Parses |
|---|---|
| `Assert-ParameterRange` — **the template's `Parameter validation` region, so 16 scripts** | an operator-supplied number |
| `Get-AuditPolicyState` in `Enable-AdObjectAuditing` **and** `Enable-IRVisibility` (byte-identical, md5 `67c671cdf6`, outside any region) | the auditpol CSV setting value |
| `Get-ProcessCreationAuditState` in `Deploy-TamperAlerts` | the same column |
| `Test-AuditPolExpectation` in `Test-VisibilityDrift` | the same column |
| `Write-Alert` inside `Deploy-TamperAlerts`' **generated handler** | an event property value |

**The template one is a real defect, and it lands on this shop's own estate.**
`[double]::TryParse($text, [ref] $n)` uses the ambient culture. Measured against
the toolkit's actual fractional values:

| Value | en-US | fr-FR | de-DE |
|---|---|---|---|
| `0.05` | `0.05` | **refused** | **5** |
| `0.10` | `0.1` | **refused** | **10** |
| `0.90` | `0.9` | **refused** | **90** |
| `0.1` | `0.1` | **refused** | **1** |

So an operator on French Windows passing `-MaxFreeSpaceFraction 0.05` was told
`0.05 ... is not a number` and got exit `2`. On German Windows the same value
silently became `5`, then failed the range check with a message naming a number
the operator never typed. Defaults escaped it — `Assert-ParameterRange` returns
early for a parameter that was not supplied — so it needed an explicit value to
bite.

The naive fix would have been a second defect. Measured across all four
combinations:

| Input | ambient fr | ambient de | invariant + thousands | **invariant, Float only** |
|---|---|---|---|---|
| `2,5` | 2.5 | 2.5 | **25** | refused |
| `2.5` | refused | **25** | 2.5 | 2.5 |
| `1 000` | 1000 | refused | refused | refused |

`NumberStyles::Float` with `InvariantCulture` is the only column that transforms
nothing: it refuses ambiguous locale input and names it in the throw. Not
digits-only, which would have been simpler, because `MaxFreeSpaceFraction`
(0.01–0.90) and `SkewWarningSeconds` (min 0.1) are real fractions. A locale
number that survives as the wrong magnitude — de-DE `2.000` meaning two thousand,
read as 2 — then fails the range check on the next line, which is loud. That is
the acceptable failure mode; a silent factor of ten is not.

One thing checked before shipping, because getting it wrong would have broken
every non-English host in the other direction: **`[string]` of a `[double]` is
not culture-dependent in PowerShell.** Measured under en-US, fr-FR and de-DE, it
produces `0.05` in all three, so both `[double]` parameters round-trip through
the invariant parse correctly.

Also measured, and worth knowing about the layer above: for an `[int]`-typed
parameter, PowerShell's own binding rejects `abc` and `2,5` **before**
`Assert-ParameterRange` runs, which per the P-1 doctrine is an untrappable host
exit `1`. So this parse is reached only for the `[double]` parameters and for
arrays — which is exactly where the fractional values live, and exactly where the
defect was.

Validation. `-MaxFreeSpaceFraction 0.05` now exits `0` and
`-SkewWarningSeconds 2.5` is accepted; `-TranscriptKeepDays 99999` still exits `2`
naming the range. Full audit of all 18 on a re-armed host: **12 exit `0`, zero
exceptions** — identical to the baseline before any of this. `Enable-IRVisibility`
returned to `0`, because the rollback cycle removed the unanchored rotation task
and the re-arm registered it against the absolute path: the remediation this
toolkit prints is the one that clears its own finding.

**Still open, and deliberately:** `ConvertTo-DecimalOrZero` in
`Deploy-TamperAlerts` returns `[decimal]` and `0` rather than `$null`, which its
name and its use for event record numbers both require. It is not a duplicate of
`ConvertFrom-NativeInteger` and must not be folded into it.

### The VSS split, and the rollback it would have broken (2026-09-07)

`Enable-VssPreservation` did two jobs - arrange the shadow storage association a
snapshot needs, and register the task that takes them - which met docs/AUTHORING.md's own
test literally. The task half is now `Enable-VssSnapshotSchedule`, at **338 lines
of script-specific logic, under the 700 budget**; the parent kept the storage half.

**What the split would have broken if made naively.** A host armed before it holds
one run carrying BOTH a `shadowstorage` and a `scheduledtask` record under
`Enable-VssPreservation`. Moving the `scheduledtask` branch out would have left
those records hitting the dispatcher's `default`, which declines **retryably** -
so the run never leaves the eligible set, `-Rollback` selects it again on every
run and never converges, and the task itself stays on the host unremovable by the
toolkit. That is the R-1 defect section 4.1 was written to remove, reintroduced on
every already-deployed host.

So the parent keeps the branch and the shared restorer. A script has to be able to
undo what it applied, including under its old shape.

Proven rather than asserted, on the lab: the task was unregistered, the
**pre-split** version of the script (`git show HEAD:...`) re-registered it and
wrote a `scheduledtask` record under its name, and the **post-split** version
rolled it back — `[ ok ] Removed scheduled task
\IronBlackBox\IronBlackBox-VssSnapshot; the handler script was left in place.`
with the task gone afterwards. The dispatcher handles records one at a time, so
this is the whole of the claim; a mixed run adds nothing to it.

The lab held **no** mixed run to test against, incidentally, which is worth
knowing: an idempotent `-Apply` on an already-armed host writes no records at all
(`0 change(s) applied`), so the manifest carries far fewer runs than the number of
times these scripts have been run.

**Two shared regions, both gate-protected.** `Scheduled task helpers [shared]`
carries `Get-ToolkitScheduledTask`, `New-TaskMarker` and
`Remove-TrackedScheduledTask` across the four scripts that register a task -
which fixed a live defect the split exposed: that rollback function existed in
**three distinct versions**, comment-only differences verified before unifying,
with nothing comparing them. `VSS volume [shared]` carries `Resolve-VolumeRoot`
across the two halves, because both must agree on what "the volume" means or a
snapshot of one volume is armed against storage for another.

`Enable-IRVisibility`'s copy of the restorer said "the handler script **and every
transcript** were left in place" - true of its task and of no other. That note
moved to its call site rather than being dropped to make the copies identical.

**Four defects in this change, all found by running it.** Three were mine and one
belonged to the gate:

- The new script's `Main`, copied from the parent, still validated
  `-ShadowStoragePercent` and `-MinimumFreeDiskPercent`, which it does not
  declare. Clean refusal - `[FAIL] The variable '$ShadowStoragePercent' cannot be
  retrieved`, exit 2, no raw exception - but it made the script unrunnable in
  every mode. Replaced with this script's own parameter checks.
- Its manifest run header recorded the parent's parameters for the same reason.
- The two copies of `VSS volume [shared]` disagreed on the first try, because the
  comment said "this one" and "that one" and therefore read as mirror images. The
  gate caught it; the comment now names both scripts, which is better prose
  anyway.
- The gate's own marker handling: `-match` REPLACES `$Matches`, so reading
  `$Matches['name']` after testing the header for `[shared]` returned the inner
  match's groups and every marked region would have been named `$null`. It passed
  the build only because no region carried a marker yet.

Cycled on the lab after the fixes: `-Audit` 0, `-Apply` 0, `-Audit` 0
(idempotent), `-Rollback` 0, zero exceptions, and the parent still exits 0 on
audit. `tools/check.ps1` passes on 20 files.

### The Defender split, and two gates that had to exist first (2026-09-07)

`Protect-DefenderConfig` did two jobs: report what Defender is configured to do,
and track its exclusion list against a recorded baseline. The posture half is now
`Test-DefenderPosture` — 306 lines of script-specific logic, **read-only by
construction**: no `-Apply`, no `-Rollback`, and no Manifest region, because a
script that records no change needs no record writer.

**The analysis was wrong twice before it was right, and both corrections came
from checking rather than reasoning.**

First read: the split looked entangled, because the posture region's functions
were referenced 2 to 9 times across the whole file. Checking *which regions*
referenced them said otherwise — `Get-DefenderExclusion` and
`Test-ExclusionContain` are called only from `Exclusion baseline` and `Exclusion
severity`, never from posture. They were simply **filed in the wrong region**.
Reference counts measure coupling; they do not locate it.

Second read: the dependency closure of the posture half came out at 290 lines and
did not include `Get-DefenderStatus`. It should have. The closure followed the
**call graph**, and `Test-DefenderPosture` and `Test-DefenderPresence` receive
that data as a `-Status` **parameter** — so the new script called them without it
and was unrunnable. A call-graph closure misses every dependency that arrives as
an argument.

Five script-scope variables were missing for the same reason: the moved functions
read state declared in a preamble that stayed behind. The lab reported it as
`[FAIL] The variable '$script:RunningModeEnabled' cannot be retrieved because it
has not been set` — a clean exit 2, and the whole script dead. Every gate had
passed.

**So two gates now exist, and both are proven on the exact bugs that produced
them:**

| Gate | Catches |
|---|---|
| Script-scope variables are assigned | `Test-DefenderPosture.ps1 reads 1 script-scope variable(s) it never assigns: $script:RunningModeEnabled` |
| Mandatory parameters are supplied | `Test-DefenderPosture.ps1 line 1188: Test-DefenderPresence called without -Status and with 0 positional argument(s)` |

Each needed a correction of its own, and both are worth recording:

- The first was written as a regex over raw text and failed
  `Set-TimelineIntegrity` on the line `# NOT $script:Snapshot or anything that
  could collide with a parameter name` — a **comment** warning the next author off
  that very name. Rewritten on the AST, which sees neither comments nor strings.
- Then a cosmetic fix to its message silently disabled it. `UserPath` for
  `$script:Foo` is `script:Foo`, so printing it after a `$script:` prefix doubled
  the scope; switching to `UnqualifiedPath` fixed the message and returned the
  **empty string** for every name, which was then always present in the assigned
  set. The gate passed on everything while measuring nothing — and it took a
  mutation test to notice, because *a gate that measures nothing looks exactly
  like a gate that measures everything*. That sentence is already in this file
  about a test harness; it now applies to a gate written after it.
- The second assumed every call in the project passes parameters by name. True of
  the dev scripts and **false** of the collectors: `IronBlackBox-IR`'s
  `Export-Autoruns` calls `Add-Coverage` positionally twelve times, which is valid
  PowerShell, and the gate went red on all twelve. Positional arguments are
  counted now.

Validation on the lab. `Test-DefenderPosture` exits `0` with one host limit —
`IsTamperProtected = False`, correctly a limit and not a finding — and reports
running mode, service state, `MsMpEng.exe`, real-time protection, signature age
against its own `-SignatureAgeThresholdDays` threshold, and the Defender channel.
`Protect-DefenderConfig` cycles `-Audit` / `-Apply` / `-Audit` / `-Rollback` at
`0` with zero exceptions. `tools/check.ps1` passes on 21 files here and 11 in the
IR repository.

### The rollback constraint pattern, applied to every restorer (2026-09-02)

`docs/DESIGN.md` §4 says the manifest is operator-writable input, not trusted
state. Three restorers acted on that and the rest did not, so `-Rollback` could
be steered by a record into writing something no `-Apply` of that script would
ever write. The constraint now always comes from the **script**, never from the
record:

| Constraint | Where | Refuses |
|---|---|---|
| owned registry keys | template `Restore-TrackedChange`, declared per script as `$script:OwnedRegistryKey` | a key outside what the script writes; **everything**, in the 5 scripts that write no registry values at all |
| path under the toolkit root | `Enable-IRVisibility` (auditpol backup), `Protect-DefenderConfig` (baseline file) | a path outside the root, including a `..\..` traversal, normalised first |
| volume | `Enable-VssPreservation` | anything `-Volume` would not accept |
| channel and descriptor | `Protect-EventLogs` | a channel it does not own; a descriptor granting write or CLEAR to an unprivileged principal |
| Windows feature | `Remove-PowerShellV2` | any feature other than `MicrosoftWindowsPowerShellV2*` |

Measured, not assumed: **11 of the 18 scripts never call
`Set-TrackedRegistryValue`**, yet every one carried the registry restorer — attack
surface with no legitimate use. Those now refuse a registry record outright.

`tools/check.ps1` enforces the invariant: a script carrying the restorer must
declare `$script:OwnedRegistryKey`, non-empty exactly when it calls the setter.
Emptying `Enable-LolbinAudit`'s declaration fails the build.

Proven on the lab. Constraints: a root-relative path and a nested one are
accepted while `C:\Windows\System32\config\SAM`, a `..\..` traversal, a UNC
path, an empty value and `C:\Users\Public\audit.csv` are declined by name;
`MicrosoftWindowsPowerShellV2` and `...V2Root` are accepted while `TelnetClient`,
`SMB1Protocol`, `IIS-WebServer` and an empty name are declined;
`Enable-IRVisibility` accepts its own Transcription key and declines both
`W32Time\Parameters` and `Image File Execution Options`, while
`Enable-WefClient` refuses every key. Happy path: five full
`-Apply` → `-Rollback` cycles (`Enable-IRVisibility`, `Enable-ServerPrefetch`,
`Set-TimelineIntegrity`, `Protect-ForensicArtifacts`, `Enable-LolbinAudit`) each
completed with rollback exit 0 and **zero** constraint refusals.

### `Enable-ServerPrefetch`: the script works, the setting does not

This is the one script so far whose honest conclusion is that it cannot deliver
what its name promises on the hardware it was tested on. The mechanics are
proven — `-Audit` read-only by diff, `-Apply` idempotent, `-Rollback` restoring
the baseline exactly — but the *outcome* is not:

On the lab (Server 2019, system volume reporting **MediaType SSD, BusType NVMe,
SpindleSpeed 0**), `EnablePrefetcher = 3` was written and read back, survived the
reboot itself, and was then **removed again a few minutes into normal
operation** — observed twice. `gpresult` reported no Group Policy applied
(`N/A`), no AWS agent config referenced prefetch, and **SysMain was Running and
Automatic the whole time**, so a stopped service was not the cause. No `.pf`
file was ever produced.

Windows is understood to disable prefetching on fast media. That is *consistent*
with the measurements but **not proven here**, because proving it needs a host
with rotational media and there was none. So the script reports the media type
before changing anything, warns in those terms, applies the setting anyway
(reversible, and where a host honours it the payoff is real), and tells the
operator to re-check afterwards — `Test-VisibilityDrift` reports the value as
drifted when the OS drops it, which is exactly the signal wanted.

`-Apply` exits **1**, not 0, because the finding "this host records no execution
history" is still true after applying. The script refuses to claim success it
cannot demonstrate.

Practical consequence for the toolkit's promises: on modern SSD-backed servers,
do not tell an MSP that Prefetch will be there. The absence of `.pf` is itself
the DFIR-relevant finding, and `Invoke-TriageCollection` (now in
`IronBlackBox-IR`) already reports it.

### The rollback doctrine, and 29 false drifts down to 1

The flagship reported **29 changes drifted** on a host where every one had been
correctly restored. Fixing it meant settling the rollback contract, and the
measured result is:

| | before | after |
|---|---|---|
| Changes reported as drifted on a restored host | **29** | **1** — genuinely unresolved |
| Scripts draining their rollback backlog in one `-Rollback` | 0 of 14 | **13 of 14** |
| Change types the detector could not verify | 2 (`usnjournal`, `shadowstorage`) | 0 |
| Runs that could never be closed | 1, forever | 0 — `-AbandonRun` closes it on the record |
| Drift on a fully restored host | 29 | **0** |

The last one needed `-Rollback -AbandonRun <runId>`, because one case can never
resolve itself: a decline is *retryable* on the assumption somebody might put the
value back, and when the thing that changed it is a later run of the same script,
nobody will. Proven on the run that produced the problem — **18 restored, 1
abandoned**, the run out of the eligible set, and every later drift check naming
the decision in its coverage section so it stays visible.

The doctrine and the evidence are in the review log kept in the development repository, and the contract
in `docs/DESIGN.md` §4.1–4.2. The short
version: a restorer resolves the host **three** ways rather than two — what the
run set, what it recorded before, or neither — plus a fourth outcome for a change
that can never be undone. And a rollback records **which** changes it restored,
because a run with one legitimate decline and eighteen restores was still making
the detector expect all nineteen.

**Two regressions came out of applying this across seventeen scripts, and both
passed the entire static gate.** The mechanical loop propagation replaced every
script's own dispatch with the template's registry-only restorer, so sixteen
scripts silently lost the ability to roll back `auditpol`, `channelaccess`,
`windowsfeature` and `scheduledtask` changes. Restoring those dispatches by
matching the first occurrence per file then broke `Protect-EventLogs`' if/else
into a single call, and six registry changes failed with "Cannot bind argument
to parameter 'Channel'". Both were caught by running rollbacks on the lab. Every
dispatch block is now diffed in full against its previous version.

### The domain-member sweep: what changing `DomainRole` cost

All fourteen scripts previously proven on a standalone host were re-run after
the member joined `lab.example`, because `DomainRole` went 2 → 3 and
several branch on it. **Nine passed the full contract 6/6 unchanged**, and the
five below did not. Those five are **three** defects, not five: R-1 accounts for
three of the rows on its own.

| Script | Result | Which defect |
|---|---|---|
| `Enable-IRVisibility` | 5/6 | R-1 |
| `Protect-EventLogs` | 5/6 | R-1 |
| `Enable-VssPreservation` | 5/6 | R-1 |
| `Set-TimelineIntegrity` | 5/6 | a declined service restore — the T-3 shape |
| `Enable-UsnJournalTracking` | 2/6 | U-3, the host silently refusing the resize |

Every R-1 occurrence reads identically — *"second rollback did not decline"* —
and it is now the single most common failure in the suite.

**And it is worse than a non-converging rollback.** Running the flagship
`Test-VisibilityDrift` on the member after the sweep, with every script applied
and then rolled back, produced **29 changes reported as drifted** — 19 from
`Enable-IRVisibility`, 9 from `Protect-EventLogs`, 2 from
`Enable-VssPreservation`, 1 from `Enable-UsnJournalTracking`. Every one of them
had been correctly restored. The detector excludes only runs whose rollback
completed, and R-1 makes those rollbacks record as `failed` — so **one
un-undoable change in a run poisons every other change in that run**, and the
flagship cries wolf on a clean host. R-1 is Tier 1 for that reason, not for the
convergence problem it was filed under.

**T-4 and T-6 did not reproduce.** Both predicted a permanent exit 1 on a
domain-joined host, and `Set-TimelineIntegrity` ran audit exit 1 → apply exit 1
→ idempotent → rollback exit 0 on the member. The member's time source is the
DC, which is the condition T-6 describes, and no permanent finding appeared.
Both need re-examining against this evidence rather than being carried forward
on the review's word.

### Security context: the thing that would have looked like four broken scripts

`[adsisearcher]` succeeds or fails purely on the caller's identity, and its
failure text — *"The specified domain either does not exist or could not be
contacted"* — reads like DNS and is not. Measured three ways:

| Where, as whom | Result |
|---|---|
| DC, SSH as `Administrator` → `LAB\Administrator` | works |
| Member, SSH as `Administrator` → the **local** account | **fails** |
| Member, as SYSTEM via a scheduled task | works |

SYSTEM authenticates to the network as the computer account, which is a domain
principal. So an AD-facing script must never be validated by SSH-ing to a member
as its local Administrator — and SYSTEM is how an RMM runs it anyway, so that is
the honest test either way. Full detail in `lab/DOMAIN-LAB.md`.

### A lab-harness defect that invalidated a whole round of results

`lab/Invoke-LabCycle.sh` found its own output with `ls lab/runs | tail -1` — the
newest directory. That is correct only while nothing else uses the lab. Running
two cycles concurrently against the member and the DC made them read each
other's output, and a rollback that had printed "Rollback complete" was reported
as "rollback did not report completion". Every result from that window was
discarded and re-run. It now parses the run directory out of the runner's own
output.

The first attempt at that fix was itself wrong in a way worth recording:
`code=$(run_it)` runs the function in a **subshell**, so the variable it set was
discarded and three more spurious failures appeared. Capturing a function's
output and its side effects at the same time does not work in bash.

### The four Tier 1 fixes, and the two measurements that corrected the review

**`fsutil usn createjournal` will not shrink a journal.** Measured twice on
Server 2019, from `maxsize 0x40000000`: `m=33554432 a=8388608` and then
`m=67108864 a=16777216` both exited **0** and left Maximum Size, Allocation
Delta *and First Usn* unchanged. Microsoft says createjournal "updates the
change journal's maxsize and allocationdelta" and does not say a smaller value
is honoured — here it is not.

Two consequences, in opposite directions. U-1's stated danger was too strong:
the blind `createjournal` does **not** trim history, so it is a false-state and
broken-rollback defect rather than a data-destruction one. And a defect nobody
had noticed is real: **enlarging a journal cannot be undone**, and the restorer
printed the read-back disagreement and then reported `[ok] Restored` and
`Rollback complete` with exit 0 in the next two lines. It now declines, exits 1,
and says so — and `-Apply` warns before acting rather than after.

**`time.windows.com` is unreachable from the lab; the Amazon Time Sync Service
is.** `w32tm /stripchart /computer:169.254.169.123` works from the instance
where `time.windows.com` returns `error: 0x800705B4` on every sample. That made
the clock work provable for the first time. It also settled the output format:
Server 2019 emits **one unlabelled value per line** — `01:20:38, +00.0004969s` —
not the two-column `d:… o:…` shape. The anchored parser handles both.

**T-1, proven.** The clock was pushed 12 seconds forward, then `-Apply` ran
against that peer:

```
asFound.measuredOffsetSeconds = -11.9856746     <- the clock as found
measuredOffsetSeconds         = -3.34E-05       <- after the resync
clockWasStepped               = True
```

Before the fix the record kept only `-3.34E-05`. A responder reading it would
have concluded the host's clock was fine and trusted every timestamp written
while it was twelve seconds out.

Running this also surfaced a latent break: `Measure-ClockOffset` called
`ConvertFrom-OffsetToken -Text` while the parameter had been renamed `-Line`, so
every call threw the moment `w32tm` produced output. It had been invisible
because the lab had no NTP route and the output was empty, and PSScriptAnalyzer
cannot see it — it validates parameters against known cmdlets and assumes an
unknown name is a local function.

**V-2, proven on the lab.** After applying the 12% default (9.60 GB),
`-Apply -ShadowStoragePercent 5` now declines instead of silently lowering the
maximum to 4.00 GB. The old guard armed only while snapshots existed, so a host
between backup jobs — which is what this lab looks like — was exactly the case
it did not cover. `-ForceShrink` still goes through, and says what it is doing.

**V-1 and D-1, proven in isolation**, because both need hardware this lab does
not have (a second disk, a domain controller). Both comparisons are in
the review log kept in the development repository; the sharpest is D-1's second row, where the old
parser returned a **build number** rather than the setting even when the correct
value was on the following line.

**What `-Rollback` left on the lab, all declared by the scripts themselves:** a
shadow storage association on `C:` at 9.60 GB (removing one is not a documented
operation), a USN journal at 4 GiB (fsutil will not shrink it), and the VSS
handler script. Each is reported as a finding at the moment it is declined,
which is how R-1 was found.

### `Protect-DefenderConfig`: DF-1, the detector that switched itself off

`-Apply` reported a newly appeared exclusion as a `[high]` finding and, **in the
same run**, wrote it into the baseline. The next run compared the host against a
baseline that now contained the attacker's exclusion and reported it clean. The
one mechanism the script exists to provide disabled itself, permanently, without
a single line that was untrue.

An existing baseline is now never updated over an unexplained addition. Proven
on the lab, in order, against real Defender exclusions:

| Step | Result |
|---|---|
| `-Apply` on a clean host | baseline created, exit 1 (tamper protection off) |
| Attacker adds `C:\Users\Public\Downloads` and extension `ps1` | — |
| `-Audit` | both named `[high]`, exit 1 |
| `-Apply` | **REFUSES**: "absorbing them would make the next run report this host clean", both named, 0 changes, exit 1 |
| `-Apply -RemoveExclusion 'C:\Users\Public\Downloads' -RemoveExclusionType Path` | removed and confirmed gone; the refusal **recounts to 1** and still blocks on `ps1` |
| `-Apply -AcceptNewExclusions` | absorbs it, and the manifest records `"acceptedNew":["Extension: ps1"]` |
| `-Audit` | no new exclusion since the baseline |
| `-Rollback` ×3 | previous baseline restored → removed exclusion re-added → baseline file deleted, "there was no baseline before this run" |

The recount after a removal matters: a removal may take away exactly the
exclusion that was flagged, and then the baseline has nothing to absorb and no
reason to refuse.

**The first baseline is deliberately still written without the switch.** There
is nothing to absorb then, only a reference to establish — and that first
snapshot does take whatever is on the host as normal, including anything an
attacker put there before the toolkit arrived. That is inherent to any baseline,
which is why the run that creates one prints the full exclusion inventory for a
human to read.

**Measured aside.** `Get-MpPreference` returns a one-element array containing an
empty string for an exclusion list that is empty. The script already treats that
as "none" — the same `Mandatory [string[]]` trap that made `Set-TimelineIntegrity`
exit 2, handled correctly here.

DF-2 is out of scope by the maintainer's decision.

### `Enable-Sysmon`: it called a working recorder dead

**The worst of the three.** With Sysmon installed and demonstrably collecting,
the script reported:

```
[find] service present but no matching kernel driver - Sysmon collects nothing
```

Measured on that same host, at that same moment:

| Source | Answer about `SysmonDrv` |
|---|---|
| `Win32_SystemDriver` | 345 drivers, **zero** matching `*sysmon*` |
| `Get-Service SysmonDrv` | Running / Boot |
| `sc.exe query SysmonDrv` | exit 0, `KERNEL_DRIVER`, `RUNNING` |
| `fltmc filters` | `SysmonDrv`, 2 instances, altitude 385201 |
| `HKLM\…\Services\SysmonDrv` | `Type=1`, `Start=0` |
| The channel itself | 428 records, **33 process-creation events in two minutes** |

`SysmonDrv` is a file system **minifilter**, and `Win32_SystemDriver` does not
enumerate it — boot-start drivers in general *are* in that set (`ACPI`, `CLFS`,
`acpiex`), so the omission is specific. The CIM class had been chosen for a good
reason (it is immune to WOW64 registry redirection) and that reason was still
right; it just cannot see this driver. Declaring a working forensic recorder
dead is worse than saying nothing — it sends a technician hunting an install
that is not broken, and teaches them to distrust the tool. Now falls back to
`HKLM\SYSTEM\CurrentControlSet\Services` (not redirected — redirection applies to
`HKLM\SOFTWARE`) and names which source found the driver. The audit went from
exit 1 to **exit 0** on a correctly armed host.

**`Sysmon64.exe -c` exits 0 when Sysmon is not installed.** It prints its banner
and "Sysmon is not installed on this computer", and the script read exit 0, took
the nine banner lines for content, and reported `[ok] 9 line(s) of active
configuration dumped` — two sections after correctly reporting that Sysmon was
not installed at all. Same class as the `fsutil` and `dnscmd` parsers in
the review log kept in the development repository: a tool's exit code is not a claim about its output.
There is no active configuration on a host with no Sysmon, so the question is no
longer asked.

**"Applied, but not demonstrated" became a demonstration.** The script used to
raise a finding telling the operator that a process started now should produce
event ID 1. It now starts one itself and looks. The honest half of that
limitation stays stated: `-c` dumps a text rendering rather than the file, so
the loaded rules can never be proven to match the XML on any host — but whether
Sysmon is *recording* is directly measurable, and is now measured.

**Declared residue.** After `Sysmon64.exe -u` the service, the driver and the
channel are all gone, but Sysmon's own copy of itself remains at
`%SystemRoot%\Sysmon64.exe` — its uninstall does not remove it. The script now
names the file instead of claiming the host is "back to having no Sysmon", and
does not delete it: on a host where somebody else installed Sysmon first, that
file is not the toolkit's to remove.

**A lab-harness defect found in passing, and it would have contaminated every
later test.** `lab/Invoke-LabRun.sh` quoted arguments with bash's `printf '%q'`,
but the remote shell is `cmd.exe`, where backslash is not an escape character.
`C:\lab-staging\Sysmon64.exe` arrived as `C:\\lab-staging\\Sysmon64.exe`. `Test-Path`
still returned `True`, because Windows tolerates doubled separators — which is
exactly why it went unseen. What it breaks is anything that reports, hashes or
string-compares the path: any manifest record built from an argument. Quoting is
now done for `cmd`.

### `Deploy-TamperAlerts`: the alert feed was more than half Defender's own housekeeping

**Proven by effect, not by inspection.** With the task deployed, clearing an
event log fired it **within five seconds**, `LastTaskResult=0`, and the handler
appended the alert to `tamper-alerts.log`. That is the forward-looking half of
the script doing its job on a real host.

**And then the feed showed what was wrong with it.** Event 5007 is "Microsoft
Defender Antivirus Configuration has changed" — the only event that can reveal
an exclusion being added, so it cannot be dropped. But Defender raises it for
its own bookkeeping constantly. Every distinct value across 67 events on an
**idle** lab host:

| count | value under `HKLM\SOFTWARE\Microsoft\Windows Defender\` |
|---|---|
| 40 | `Diagnostics\InitializingComponentProgress` |
| 28 | `CoreService\WdConfigHash` |
| 12 | `ServiceStartStates` |
| 4 | `Features\EcsConfigs\ETag\Tag` |
| 4 | `Diagnostics\CleanupComponentProgress` |
| 3 | `IsServiceRunning` |
| 2 each | `Features\Controls\{260,248,203,_32,80,79}`, `ReportingGUID`, `OldMachineGUID` |
| 1 | `Features\EcsConfigs\NIS_EnableUsoSupport` |

Not one is a security setting, and every one was being written into the
RMM-facing alert log labelled `TAMPER`. **Findings on this host: 116 → 55**, and
Defender alerts 67 → 0.

The handling is **demotion, not deletion**: those events move to the
retrospective scan's "Context, not alerts" section, stay in the Defender
channel, and stop reaching the RMM. An event is only noise when **every**
Defender value it names is housekeeping — one that names a housekeeping value
alongside anything else stays an alert, because suppressing a real change for
arriving next to a routine one is the failure this filter exists to prevent. The
token list is measured on one host, which is exactly why nothing is deleted.

The list has one home: it is substituted into the generated handler from the
deploying script's `$script:DefenderSelfMaintenanceValues`, so the live watcher
and the retrospective scan cannot drift apart.

**The gate earned its keep here.** The first version of the predicate used
`$matches`, and PSScriptAnalyzer refused it — that is a PowerShell automatic
variable, the same class of trap as `$mode`. The second used `'Diagnostics\\'`,
which in a single-quoted PowerShell string is a literal *double* backslash, so
no token ever matched; the filter passed every check and reduced the noise by
nothing. Only re-running it on the lab and counting the findings showed it.

**Declared residue after `-Rollback`.** The scheduled task is removed. The alert
log, the handler and both bookmarks are deliberately left: "the alert log is
evidence; a rollback does not delete evidence." An empty `\IronBlackBox` Task
Scheduler folder also remains.

### `Protect-ForensicArtifacts`: the one declared deviation from strictly-read-only

This script's row has said "one declared deviation from strictly-read-only - see
below" since 2026-08-25, and there was no below. The sentence pointed at a section
that had never been written, which is the kind of promise that costs a reader
their trust in every other row.

Here it is, measured rather than recalled. 2026-09-02, Server 2019: a full
before/after snapshot of 459 items across a single `-Audit` - the Prefetch and
FileSystem registry keys, the SysMain, DPS, EventLog and VSS service states, and
the toolkit root's whole tree plus its DACL. Exactly one item differed:

```
=> SVC VSS = Running/Manual
<= SVC VSS = Stopped/Manual
```

`-Audit` started the Volume Shadow Copy service. Not by calling `Start-Service` -
the script contains no such call on that path - but by running
`vssadmin list shadows` to report whether a recovery point exists, which starts
VSS on demand to answer.

**Why it is declared rather than fixed.** Reporting that a host has no shadow copy
to recover deleted evidence from is one of the more useful things this script
says, and there is no way to ask that question without asking VSS. The start type
is untouched, so nothing outlives the query, and the service was already
configured to start on demand.

**What changed as a result.** `docs/DESIGN.md` section 2 used to promise that
`-Audit` "never writes to the registry, the filesystem outside its own output, or
any service". That was contradicted by the toolkit's own behaviour. It now
promises no change to service *configuration*, and section 2.1 states the rule for
a new script: read through a tool that starts an on-demand service if you must,
never start one yourself, and say so in the output rather than leaving an operator
to find it in a diff.

### `Protect-ForensicArtifacts`: last-access was reported backwards by Windows itself

**The stock Server 2019 default hides a real visibility gap, and `fsutil`'s
wording points the wrong way.** Measured on the lab, on a value nothing had
touched:

```
NtfsDisableLastAccessUpdate = 0x80000003
fsutil behavior query disablelastaccess -> "DisableLastAccess = 3  (System Managed, Enabled)"
```

Backdating a file's `LastAccessTime` by ten days, reading the file, and
re-reading the timestamp: **unchanged**. Last-access updates are not happening.
So "Enabled" in that line qualifies *DisableLastAccess*, not the timestamps —
read the natural way it would have a responder trusting access times Windows
never wrote.

`fsutil behavior` documents `disablelastaccess {1|0}` and nothing else, so the
script had been treating `0x80000003` as an unrecognised value: it raised an
"undocumented value" finding on **every untouched Server 2019** and said nothing
about the gap that was actually there. Now `0` means recorded and anything else
means not recorded, the raw value is printed in hex as well as decimal (the high
bit makes it read back as a negative `Int32`), and `-EnableLastAccessUpdates`
writes `0` with the previous value recorded for rollback.

**The one place `-Audit` is not a pure read, now declared.** Asking what shadow
copies exist demand-starts the Volume Shadow Copy service — measured from a
`Stopped/Manual` baseline, three ways, all of which left it `Running`:
`Get-CimInstance Win32_ShadowCopy`, `vssadmin list shadows`, and
`vssadmin list shadowstorage`. There is no read path that avoids it, because
that service is what answers the question. The start type is untouched. The
script now says so in its output rather than leaving an operator to discover a
service transition they did not ask for.

**F-1 fixed.** `Restore-TrackedService` set the start type first and then tried
the stop; when the stop failed it returned `declined` with the start type
**already changed**. The guard at the top of that function compares the host
against what the run *set*, so every retry would then find the start type
different, conclude somebody else had been here, and decline forever — accusing
a third party of a change the function itself had made. The start type is now
put back on stop failure, so a retryable rollback is left where the retry
expects it; if that revert also fails, the script says exactly which value to
set by hand.

### `Enable-LolbinAudit`: four defects that only execution could find

The static gate passed this script. So did a full contract cycle. Running it and
then **looking for the events it exists to produce** found four defects, two of
them serious.

**1. `wmic.exe` is not in System32.** Measured: `C:\Windows\System32\wbem\wmic.exe`
and `C:\Windows\SysWOW64\wbem\wmic.exe`, both Authenticode `Valid`, BinaryName
`WMIC.EXE`. The script searched System32 only, concluded "not present on this
host", and wrote a path rule at `%SYSTEM32%\wmic.exe` — a path wmic will never
occupy. So the most-used LOLBin in the list had **no effective rule**, while the
console reported it as covered. Fixed with a `wbem` group used by both the
on-disk search and the path fallback, so the two cannot disagree; wmic now gets
a **publisher** rule, which also follows the binary if it is copied or renamed.

**2. The policy was inert and the script reported success.** On a host where
AppLocker had never been active, `-Apply` merged the policy, re-read it,
confirmed `Exe` enforcement `AuditOnly`, started AppIDSvc, and reported
`2 change(s) applied`. Then `certutil.exe` ran and produced **zero events**. The
policy was in the store and not being evaluated. After
`gpupdate /target:computer /force` plus an AppIDSvc restart it fired, and every
later `-Apply` fired immediately.

`Test-AppLockerPolicy` cannot detect this — it evaluates a policy *object*
in-process and answered `Denied / rule=IronBlackBox LOLBin audit: certutil.exe`
for a policy the kernel was not enforcing. Only an execution proves an
evaluation. `-Apply` now runs `certutil.exe -?` as a canary (proven to raise 8003
exactly like a real invocation, because AppLocker evaluates at process creation
and ignores arguments), polls the channel, and either reports the policy **live**
or raises a finding telling the operator to refresh policy and re-run. It is
guarded to `-Apply`: `Invoke-HostCheck` runs in every mode, and executing a
binary is not something `-Audit` may do.

**3. The allow-all baseline rule floods the channel with 8002.** The baseline
rule exists so the deny rules produce targeted 8003s instead of turning every
process into one. It does that — and replaces the problem with 8002, "was
allowed to run", once per process start. Measured on an **idle** lab host with
two SSH sessions:

| Measurement | Value |
|---|---|
| Events in the channel | 75, spanning **2.0 minutes** |
| Of which 8002 "allowed to run" | 71 |
| Of which 8003 (the actual signal) | 3 |
| `FileSize` vs `MaximumSizeInBytes` | 1,052,672 of 1,052,672 — **already rolling** |

At the channel's default size the whole log turns over about every two minutes
on an idle server, so an 8003 hit survives roughly that long. On a busy host it
is seconds. Both `-Audit` and `-Apply` now report this with the numbers.

**This one is not fully fixed, and it needs a decision.** The script's header
defers channel sizing to `Enable-IRVisibility` — which does not touch the
AppLocker channel at all (zero references). Each script assumes the other covers
it. Either `Enable-IRVisibility` gains the AppLocker channel in its sizing list,
or this script sizes it and the division of labour changes.

**4. "No publisher information" was false.** `pcalua.exe` is Authenticode
`Valid` and Microsoft-signed; what it lacks is a `BinaryName`. Falling back to a
path rule is **correct** — a publisher rule with an empty BinaryName would match
every Microsoft Windows binary on the host — but the message accused a signed
binary of being unsigned. Reworded to say what is actually missing.

**Residue after `-Rollback`, both deliberate and declared.** The local policy
returns to `<AppLockerPolicy Version="1" />` — the allow-everything baseline rule
is gone, which is the consequential part. Two things do not return: AppIDSvc is
left **running** with its start type restored (documented in the script header:
stopping it would deactivate any other AppLocker policy on the host), and an
empty `SrpV2` registry key remains — the known toolkit-wide residue where
created keys are not recorded.

### A trap that will bite the next script

`$mode` is effectively a reserved variable name. PowerShell names are
case-insensitive and its scoping is dynamic, so the shared `Invoke-Main`'s local
`$mode` masks a script *parameter* called `$Mode` inside every function it calls.
A `-Mode` parameter silently received the string `'Audit'`, and the hashtable
lookup on it returned `$null`. Renamed to `-PrefetchMode`, and recorded in
`docs/AUTHORING.md` so the next script does not repeat it.

### The end-to-end scenario, proven

This is the milestone the whole design was aimed at, run on the lab in order:

1. All three state-changing scripts `-Apply` → 29 changes recorded.
2. `Test-VisibilityDrift` → **exit 0**, 29 checked, 0 drifted.
3. A sabotage script undoes one change of each type: sets
   `EnableScriptBlockLogging` to 0, deletes
   `ProcessCreationIncludeCmdLine_Enabled`, switches Process Creation auditing
   off, gives administrators the CLEAR right back on Security, and re-enables
   the PowerShell v2 feature.
4. `Test-VisibilityDrift` → **exit 1**, and it named all five, each attributed
   to the script that owns it:

```
[Enable-IRVisibility] ...\EnableScriptBlockLogging - the value no longer matches what was applied
[Enable-IRVisibility] ...\ProcessCreationIncludeCmdLine_Enabled - the value is gone
[Enable-IRVisibility] audit policy - 1 of 14 subcategor(y/ies) switched off: {0CCE922B-...}
[Protect-EventLogs]   channel Security - the descriptor was loosened: S-1-5-32-544 gained 0x4
[Remove-PowerShellV2] feature MicrosoftWindowsPowerShellV2 - was set to Disabled, now Enabled
```

5. Re-running the three owning scripts with `-Apply` repaired everything.
6. `Test-VisibilityDrift` → **exit 0** again, 30 checked, 0 drifted.

That is the manifest design earning its keep: three scripts, four change types,
one detector, and no shared module between them.

### What the drift detector cannot see, and declares

Every run prints a coverage section, including its blind spots. An `-Apply` that
found the host already compliant recorded a run with `changeCount: 0` and **no
change records** — so those settings have no reference state and their loss is
undetectable here. Rather than let exit 0 imply "the host is fine", the script
names each such run. Closing that gap means having the applying scripts record
verified-but-unchanged settings too, which is a change to the manifest contract
and to all three scripts.

Also excluded: runs with a completed rollback. A rolled-back change is supposed
to be gone, and reporting it as drift would train an operator to ignore the
output.

### What `Protect-EventLogs` proved, and the trap it reproduced

The hardening is **proven functionally**, not by inspecting a descriptor:
`wevtutil cl Application` returned exit 5 `Access is denied.` after `-Apply`,
and exit 0 again after `-Rollback`. Administrators' mask went `0x5` → `0x1` on
Security and `0x7` → `0x3` on Application and System, while SYSTEM kept
`0xF0005` untouched.

**It reproduced the exact defect that this project's predecessor published.**
`DiscretionaryAcl.RemoveAccess('Allow', admins, 0x4, 'None')` returned without
error and left the mask at `0x7` — removing nothing, while regenerating a
valid-looking descriptor. Had the script trusted that return, it would have
reported success while changing nothing, or in a near variant, granted the very
right its name promises to remove. Two guards now exist:

1. `Assert-SddlNotMorePermissive` refuses to write any descriptor where a
   principal would GAIN a right, a deny ACE would be dropped, or a new principal
   would appear. Rights may only be removed.
2. After writing, the descriptor is re-read and the bit's absence asserted.

A second trap: **descriptor text is not comparable.** .NET regenerates using
abbreviations (`CCDCLC`) where Windows prints hex (`0x7`) — same meaning,
different text. A string comparison would rewrite the channel on every run, so
all comparison decodes to per-SID masks. That is what the idempotent second
`-Apply` (0 changes) actually tests.

**Retention is a loaded gun, and the ADML says so.** Microsoft's own help text:
Retention enabled and the log full means "new events are not written to the log
and are lost" — the log *stops recording*. `AutoBackupLogFiles` only applies
when Retention is enabled. Both are **REG_SZ**, not DWord. The script writes
AutoBackup first so the pair never passes through the dangerous state.

**Not implemented, deliberately:** automatic purging of archived `.evtx`. Doing
it safely needs the exact archive filename pattern, and that could not be
observed — the MaxSize policy overrides the local channel config, so a rollover
cannot be forced by shrinking the channel. Writing deletion code against a
guessed pattern is how evidence gets destroyed. The script reports disk headroom
as a finding instead.

### What `Remove-PowerShellV2` proved, and the trap it found

The script exists to close a bypass: PowerShell 2.0 predates ScriptBlock
logging, so `powershell -Version 2` runs code that `Enable-IRVisibility` cannot
see. What the lab showed is that "is the feature installed" and "is there a
bypass" are **different questions**:

| Source | Verdict on the same host, same moment |
|---|---|
| DISM `Get-WindowsOptionalFeature` | `MicrosoftWindowsPowerShellV2` = **Enabled** |
| ServerManager `Get-WindowsFeature` | `PowerShell-V2` = **Removed** |
| Launching it | **exit -65536** — the engine cannot run |

The two Windows APIs contradict each other. The launch attempt settles it: with
.NET 3.5 absent there is no v2 CLR, so no bypass exists today regardless of what
either API says. The script therefore reports the exposure by *trying to launch
the engine*, prints the API disagreement instead of silently preferring one, and
still removes the feature — because installing .NET 3.5 later, for a legacy app
or by an attacker, would make the engine usable again.

It deliberately does not touch .NET 3.5 itself: that would neutralise PSv2 more
thoroughly and break every legacy application on the host.

Cycle: `-Audit` read-only proven by diff; `-Apply` disabled the feature; a second
`-Apply` reported 0 changes; `-Rollback` re-enabled it and the host matched its
pre-Apply baseline exactly; a second `-Rollback` declined to replay. No restart
was required on this SKU.

### What `Enable-IRVisibility` actually proved

Not "the values were written" — the events were observed:

| Setting | Evidence |
|---|---|
| ScriptBlock logging | 4104 events appear for a canary script block in a new session |
| Module logging | 4103 events appear — this settles the `ModuleNames` `*`=`*` convention, which the ADMX does not document |
| Command line on 4688 | `Process Command Line: "C:\Windows\system32\cmd.exe" /c ...` present, no reboot needed |
| Transcription | files written to `Transcripts\20260823\PowerShell_transcript.<host>.<id>.<stamp>.txt` |
| Audit policy | 14 of the 18 targeted subcategories enabled (4 were already compliant), effective immediately, survives a reboot |
| Event log sizing | 1048576 KB policy → channel reports 1073741824 bytes. **This is the proof that the unit is kilobytes** |
| Firewall logging | `DomainProfile.log` created — but only after a `NT SERVICE\mpssvc` grant and a reboot |

Idempotence: a second `-Apply` reported 18 registry values already set and all 18
targeted audit subcategories already covering what IR needs — 0 changes. Note the
audit logic only ever ADDS auditing (`-bor`), so a host already logging more than
the script asks for keeps its settings. Rollback removed
every registry value and restored the full audit policy via `auditpol /restore`,
returning all 60 subcategories to their exact pre-Apply values.

### Things running it taught us that no amount of reading would have

1. **Firewall logging needs a REBOOT.** It was unchanged after
   `gpupdate /target:computer /force` and correct after a restart. The
   script now says so rather than implying the setting is live.

   > **Corrected 2026-08-26 — event log sizing does NOT need a reboot.** This
   > entry originally claimed sizing and firewall logging both required a
   > restart. Re-measured with a distinctive value nothing else uses: writing
   > `MaxSize = 1572864` left the channel at its old size, and after
   > `gpupdate /target:computer /force` `wevtutil gl Security` reported
   > `maxSize: 1610612736` — exactly `1572864 * 1024`. A computer policy
   > refresh is sufficient. The firewall half of the original claim was not
   > re-tested and still stands.
2. **The firewall service cannot write to the toolkit's own directory.** It runs
   as `NT Authority\LocalService`, so the root's SYSTEM+Administrators DACL
   leaves it no access and the log silently never appears. `NT SERVICE\mpssvc`
   needs an explicit Modify grant.
3. **`Get-NetFirewallProfile` does not reflect GPO policy.** With logging active
   and files being written, it still reported `LogBlocked: False` and the
   default log path, because it reads the local store. Any script auditing
   firewall logging must read the policy registry key instead.
4. **An audit that reported the wrong path.** `-Audit` used a temp directory as
   the toolkit root, so it announced it would set `OutputDirectory` to a temp
   path while `-Apply` would set the real one. Fixed: the work directory and the
   reported root are now separate parameters.

### The Logmira comparison: 13 subcategories added, 7 refused

Blumira's Logmira GPO was used as an external reference baseline — not an
integration, and no GPO deployment. Its `audit.csv` enables 42 subcategories
against IronBlackBox's 20, leaving 23 gaps. Thirteen were added, three left
optional, seven refused. Four of those decisions would have gone the other way
on the documentation alone.

**What the lab overturned:**

| Claim | Source | What was measured |
|---|---|---|
| Event 4703 comes from Authorization Policy Change | learn.microsoft.com | **False on Server 2019.** A/B with each subcategory alone: Token Right Adjusted → 104 × 4703 in ~30s; Authorization Policy Change → **0**. This is why one is excluded and the other added. |
| Other Policy Change Events is safe at Success and Failure | Logmira baseline | **630 × 5447 from a single `gpupdate /force`** on a host with 484 WFP filters. At Failure only: **0**. Set to 2, not Logmira's 3. |
| Removable Storage produces event 6416 | IronBlackBox's own comment | **False.** Microsoft lists only 4656/4658/4663 there; 6416 is PNP Activity, which the toolkit did not enable. It claimed an event it never produced. Comment corrected and PNP Activity added. |
| Seven of the 23 gaps are "new logging" | assumption | **False.** Server 2019 already enables 17 subcategories out of the box, including System Integrity, both Kerberos subcategories and Computer Account Management. Adding them PINS a default so drift can be detected — it does not increase volume. |

**Proven by effect, not by read-back** — after `-Apply`, activity was generated
and the resulting events counted:

| Subcategory | Trigger | Observed |
|---|---|---|
| Other Object Access Events | `schtasks /Create` then `/Delete` | 4698 ×1, 4699 ×1 |
| Group Membership | a logon by a freshly created local account | 4624 ×2 → **4627 ×2**, exactly 1:1 |
| Security State Change | `Set-Date` ±2 seconds | 4616 ×4 |
| Authorization Policy Change | granting `SeDebugPrivilege` via `secedit` | **4704 ×1** |
| Computer Account Management | creating and deleting a computer object on the DC | 4741 ×1, 4743 ×1 |
| Kerberos Authentication Service | `klist purge` + `gpupdate` from the member | **4768 ×2**, naming `LAB-MEMBER$` |
| Kerberos Service Ticket Operations | same | **4769 ×5** |
| Other System Events | reboot | 5033 ×1 (firewall driver started) |

A first attempt at Authorization Policy Change reported **zero** 4704 and looked
like a dead subcategory. The test was wrong, not the setting: it granted
`SeBatchLogonRight`, a **logon right**, which surfaces as 4717 under
Authentication Policy Change. Privileges produce 4704; logon rights produce
4717. Recorded as fact `4704-is-privileges-4717-is-logon-rights`.

Not proven by effect, and stated as such: **PNP Activity** (6416 needs a real
removable device; EC2 has none), **Certification Services** (no AD CS role in
the lab), and **System Integrity**'s code-integrity events (5038/6410 need a
tampered binary). System Integrity was, however, measured as **silent** — the
event 5061 flood that was the reason to hesitate never appeared, across a
reboot and a full workload on both hosts.

**Rollback:** both hosts returned to exactly the 17-subcategory Windows default
with `MaxSize` back to absent, on the member and the DC. Contract cycle 6/6 on
each.

**One thing rollback does not undo.** Removing the `MaxSize` policy value and
refreshing policy does **not** shrink the channel back — it keeps the last size
it was given. `Test-VisibilityDrift` cannot see this because it compares the
policy value, not the channel. The log simply stays large, which is harmless,
but "rollback returned the host to baseline" is not literally true for channel
size. Recorded as fact `eventlog-channel-keeps-size-after-policy-removal`.

### The event log disk guard, proven on the path that never runs

Raising the Security log to 2 GB made the sizing step capable of causing the
outage it exists to prevent, so it is now gated on free disk space using the
same arithmetic as `Test-ShadowStorageHeadroom`: the floor is applied to
**projected** free space, not today's, and the volume measured is the one that
will actually **hold** the bytes — read from `wevtutil gl`, never assumed to be
`C:`.

The allow path is exercised by every run. The refusal path is the one that
matters and it never runs by accident, so it was forced with an absurd size:

```
-Audit                          [ ok ] C:\ - 54.38 GB free, logs may grow by 2.47 GB;
                                       worst case leaves 51.91 GB free, at or above
                                       the 10% floor of 8.00 GB

-Audit -SecurityLogSizeKb 60000000
                                [find] REFUSED C:\ - 54.38 GB free, logs may grow by
                                       57.69 GB; worst case would leave -3.31 GB free,
                                       under the 10% floor of 8.00 GB

-Apply -SecurityLogSizeKb 60000000
    Security    MaxSize ABSENT - the guard correctly blocked the write
    Application MaxSize ABSENT
    System      MaxSize ABSENT
```

**Two defects in the guard, both visible only by exercising the refusal.**
`Format-ByteCount` had no negative branch, so the single most important number
in a refusal printed as `-3550867456 bytes` beside neatly formatted ones. And
the per-channel message said `C:\ cannot take it` for a 256 MB Application log,
implying that log did not fit when the verdict is per **volume** and the
shortfall was the sum — the message now names the combined figure and says no
log on the volume is resized.

Contract cycle **6/6 on the member and 6/6 on the DC** after the fixes.

### U-3, and what a sweep across 18 files actually costs

`-Apply` reported the number of manifest records written, not the number of
changes that landed. `docs/DESIGN.md` §3 already forbade exactly that, so this
was 18 files violating a contract the project had already written down.

Reproduced, then fixed, then proven — on the one script where a change can be
recorded and silently not land:

```
before   [find] C: journal is UNCHANGED at 4,096.0 MiB ...
         [ ok ] 1 change(s) applied and recorded.

after    [ ok ] 0 change(s) applied.
         [find] 1 change(s) were RECORDED in the manifest but did NOT land
```

`-Rollback` then closes that record through case 2 of the three-way resolution:
*"the size recorded before this run — either the resize never landed or it has
already been undone. Nothing to restore."*

**The sweep found three things worth more than the fix.**

**1. 10 of 18 files silently refused the mechanical edit.** They call
`Invoke-HostCheck` with parameters, so a literal replacement hit only their
reporting line and left `$verified` undefined. The patch asserted per file and
printed the 10 rather than skipping them; they were reverted to HEAD and redone
with paren-matching for the multi-line and single-line `try` shapes.
`Set-TimelineIntegrity` needed a third variant — its `Invoke-HostCheck` returns
an object, so the count comes off `.ChangeCount`.

**2. The gate passes a script that prints an undefined variable.** Measured on a
deliberately broken copy: BOM, AST parse, banned-syntax, PSScriptAnalyzer — all
four PASS. On the host it throws at that line, so a broken file would have
crashed at the end of a successful `-Apply` and reported an execution error.
`Main` is excluded from the helper drift check by design
(`tools/check.ps1:372`), so **no gate check covers that region of any script**.

**3. Three scripts fail a rollback check that has nothing to do with this.**
`Set-TimelineIntegrity`, `Enable-Sysmon` and `Protect-ForensicArtifacts` exit 0
from `-Rollback`, print their own completion line, and leave the manifest
without a `completed` rollback record. Each was re-run from HEAD with the U-3
change stashed and failed identically, so it is **not** a regression from this
work. Filed as R-2.

Regression sweep, both hosts:

| Result | Scripts |
|---|---|
| 6/6 | 15 — including all four the domain lab unblocked |
| 5/6 | 3 — R-2 only, pre-existing |
| drift | member exit 0 · DC exit 1 (the known WefCollector unverifiable) |

### R-2: the harness was the defect, and my write-up invented a cause

R-2 was filed against three scripts. There was no script defect.

`Invoke-LabCycle.sh` judged the rollback step by grepping stdout for the literal
string `Rollback complete`. For all three scripts the first `-Apply` reported
`0 change(s) applied` — a legitimate no-op on a host already in the wanted
state — so `-Rollback` correctly printed *"Nothing to roll back: no eligible run
for this script in the manifest"*, and the harness called correct behaviour a
failure. **Second false failure from this file**, after the concurrency defect
its own header records.

It was also filed claiming *"the manifest gains no completed rollback record"*.
The harness never reads the manifest — a mechanism described without being read,
the same mistake as AD-2, in a session where the evidence was already on disk.

**The trap in fixing it** was that simply accepting the decline would have made
all three report 6/6 while never exercising rollback — a green that cannot
support the L3 claim it resembles. The harness now separates the two:

```
[ ok ] rollback correctly declined - the apply was a no-op, so there is nothing to undo

         NOT PROVEN: the first -Apply changed nothing, so the rollback half of
         the contract was never exercised. This run does NOT support an L3 claim.
```

Each script was then given real work, and each proved its rollback:

| Script | What gave it work | Result |
|---|---|---|
| `Protect-ForensicArtifacts` | `-EnableLastAccessUpdates` | 6/6 complete |
| `Set-TimelineIntegrity` | `-Force -NtpServer 169.254.169.123` | 6/6 complete |
| `Enable-Sysmon` | staged `Sysmon64.exe` + minimal config | 6/6 complete |

Verified by effect, not by the string: Sysmon service **absent** after rollback,
`NtfsDisableLastAccessUpdate` back to **2147483651** (`0x80000003`, System
Managed, high bit intact), time source unchanged, and `Test-VisibilityDrift`
reporting **0 recorded changes, no drift** — the manifest backlog fully drained.

Sysmon is now staged at `C:\lab-staging\Sysmon64.exe` with a lab config beside it,
so this script's rollback is exercisable from here on rather than silently
skipped.

### W-1: both sides were correct. Windows was hosting the services apart

Two scripts, both verified against their own host, and forwarding that never
established. The cause was neither script.

Above roughly 3.5 GB of RAM Windows hosts each service in its own svchost
process. WinRM then owns the one URL reservation `HTTP://+:5985/WSMAN/` and
everything under it, so Wecsvc — in a different process — cannot register
`.../WSMAN/SUBSCRIPTIONMANAGER/WEC/`. The source's enumeration reaches WinRM,
which has no handler for that path, and comes back *"the requested HTTP URL was
not available"*: WS-Man 2150859027, event 105.

Measured both ways on a 7.9 GB collector:

```
SPLIT    Wecsvc 3200 / WinRM 3088   one reservation      WinRM [142] failed 2150859027
MERGED   Wecsvc  776 / WinRM  776   three reservations   WinRM [132] completed successfully
                                    incl. SUBSCRIPTIONMANAGER/WEC     [132] EventDelivery ok
```

`SvcHostSplitDisable = 1` is needed under **both** service keys plus a **reboot**
— Wecsvc alone does not do it, and a service restart does not either, because
svchost grouping is decided at boot.

End to end: `wecutil gr` gained an `EventSources` section naming the member with
`LastHeartbeatTime`, and **145 events** landed in `ForwardedEvents`.

**The health check that was green throughout the failure.**
`Write-SubscriptionRuntimeStatus` already looked for "no event source" and
**could not fire**: its threshold was `$shown -le 1` against a three-line output
of `Subscription:` / `RunTimeStatus: Active` / `LastError: 0`. Those last two
describe the subscription, not whether anything uses it. Now it requires an
`EventSources` section.

**Detection, not repair.** Merging the hosts changes how WinRM is hosted, so the
script names the condition and changes nothing — the AppLocker/NTLM/LDAP stance.
Three branches, each exercised: reservation present, Wecsvc stopped (reported as
its own simpler cause rather than blamed on svchost), and split with the service
running.

**Two claims in the first pass were wrong**, both from inference instead of reading:
that `Enable-WefClient` probes the wrong channel — it probes both and takes the
first present, which is right — and that no plugin serving the SubscriptionManager
URI was the defect, when that endpoint is a URL path served by Wecsvc and not a
plugin resource at all. Worth recording because both were asserted before being
checked.

### W-2: what a day of isolation bought, and the probe that lied

W-2 is not closed, but it went from "undiagnosed" to reproducible from
configuration with the search space cut to one list.

**The probe that lied.** The earlier write-up said NETWORK SERVICE cannot read
the Security log. Measured properly — as a scheduled task genuinely running as
`NT AUTHORITY\NETWORK SERVICE`, with only the channel ACE and no Event Log
Readers membership:

| Probe | Result |
|---|---|
| `Get-WinEvent -ListLog Security` | **FAIL** — unauthorized |
| `Get-WinEvent -FilterHashtable @{LogName='Security'}` | **FAIL** — same message |
| `wevtutil qe Security /c:1` | **exit 0**, real event returned |
| raw `EventLogReader` API | **OK**, event 4648 |

So that identity **can** read Security *records* and **cannot** read Security
*metadata* — and `Get-WinEvent` queries metadata first. `Get-WinEvent` is the
wrong instrument for "can this account read that log", and using it produced a
confident, wrong conclusion. Adding NETWORK SERVICE to `Event Log Readers` is
also unnecessary: the token gains `S-1-5-32-573` immediately and the read
behaviour is identical either way.

**Security does forward.** 4688 ×20 and 4624 ×9 arrived — all timestamped after
a test subscription was created, **none before**. So it was not a sampling
artifact: the toolkit's own subscription genuinely never forwarded Security.

**The cause is the query content**, from a two-way split with one variable each:

```
baseline query verbatim  +  fast delivery settings   -> [101] channel unreadable
short query              +  baseline delivery settings -> [100] created successfully
```

**Eliminated inside the query**, each as its own subscription: Security alone,
System alone, PowerShell/Operational alone, all three together with short ID
lists, `ReadExistingEvents=false`, System's full 6-ID list, PowerShell's full
4-ID list — every one of them **100**. And a clone of the baseline under a
different `SubscriptionId` reproduces the **101**, so it is configuration and
not per-instance state.

What is left is the Security select with all 26 event IDs, in combination. One
variant of it produced no source-side event at all with an empty `EventSources`
— recorded as **weak** evidence, because it was measured with 14 subscriptions
live and they may confound each other.

**Next step, named:** bisect the 26-ID Security select in halves, one
subscription at a time, in a clean state.

**One more self-inflicted lesson.** A cleanup loop reported 13 successful
subscription deletions that had not happened: `wecutil ds <id> /q:true` fails
because `/q` is not valid for `ds`, and the output was piped to `Out-Null`. The
project already records that a native tool's exit code is not a claim about its
output; this discarded both.

### The 26-ID bisect: a retraction, and why the instrument mattered more than the result

The 26 Security event IDs were bisected to find the ceiling. The bisect ran,
produced a clean-looking answer — **24 IDs OK, 25 FAIL** — and **that answer was
wrong**.

The harness judged each round by *"did event 100 or 101 appear on the source
within 80 seconds"*. An absence within a window is not a verdict. Proven by
re-running an earlier round: the **same 24-ID query returned OK once and
NO EVENT later**, with the 2-ID control passing in between. The instrument, not
the host, produced the difference.

Rebuilt to judge on **collector state** — poll `wecutil gr` for an
`EventSources` section naming the source — and the picture inverted:

| Query | Verdict |
|---|---|
| control, 2 IDs | REGISTERED in 15 s |
| **all 26 baseline Security IDs** | **REGISTERED in 15 s** |

So there is no count threshold and no toxic ID. **The bisect result is
retracted.** The ID list was never the problem.

**What the effort did establish.** The baseline subscription sits permanently in
the event-**101** state, and in that state it forwards
`Microsoft-Windows-PowerShell/Operational` but not Security. Every subscription
that received event **100** forwarded Security correctly. Counted three ways and
agreeing: 602 × 4688 in `ForwardedEvents`, oldest 11:18:31Z — which is *after*
the first test subscription was created, and none before it. An undisturbed
420-second window with only the baseline present delivered **nothing**
(602 → 602).

**A second retraction.** The earlier claim that NETWORK SERVICE cannot read the
Security log was also wrong: it reads *records* fine with the channel ACE alone.
`Get-WinEvent` queries log *metadata* first, and that is the call that fails —
so `Get-WinEvent` is the wrong instrument for "can this identity read that log",
and it produced a confident wrong answer.

**Next step, with the right instrument:** three channels with full ID lists to
reproduce the 101, then shorten one channel's list at a time — collector-state
verdict only.

Two instruments lied in this one investigation, and both lies were confident.
The control run is what caught each of them.

## Shared foundation

Not one of the 18, but tracked here because every script inherits from it.

| File | Level | OS proven on | Date | Notes |
|---|---|---|---|---|
| `docs/SCRIPT-TEMPLATE.ps1` | **L3** | Windows Server 2019 Datacenter, build 17763, PS 5.1.17763.9121 | 2026-08-23 | Full Audit → Apply → Apply → Rollback → Rollback → Audit cycle on the EC2 lab. Torn-manifest quarantine proven. Two defects found by execution that no static gate or review caught. |

### What the L3 run actually proved

The lab is `t3.large`, Windows Server 2019 (not 2022 — the instance was built
from a 2019 AMI, and 2019 is arguably the more representative SMB target).
Every claim below is a recorded run, not an inference.

| Step | Result |
|---|---|
| `-Audit` | exit 1, 6 findings; a before/after snapshot diff was **identical** — read-only proven |
| `-Apply` | exit 0, 6 changes, manifest records match the section 4 contract exactly |
| `-Apply` again | exit 0, **0 changes** — idempotent, and this is what exercises the typed value comparison across all six kinds |
| `-Rollback` | exit 0, all 6 values restored |
| `-Rollback` again | exit 0, "nothing to roll back" — no replay |
| `-Audit` after | exit 1, 6 findings — back to the starting state |

Encoding round-trip, read out of the real manifest: `REG_EXPAND_SZ` stored
unexpanded as `%SystemRoot%\System32`; `REG_QWORD` as the string
`"4294967296"`; `REG_BINARY` as `"AQID+g=="`; `REG_MULTI_SZ` as a real JSON
array. An `-Apply` that changed nothing still wrote its `run` and `run-end`
with `changeCount: 0`, so `Test-VisibilityDrift` has a reference state.

**Torn-line quarantine, proven end to end.** A truncated record with no
trailing newline was appended to a 19-line manifest, then `-Apply` ran: the
torn bytes were moved to `manifest.jsonl.torn-<stamp>.jsonl` (preserved, not
discarded — verified by reading the file back) and the run completed. The
following `-Rollback` exited 0 and restored all six values. Without the
quarantine that `-Rollback` would have exited 2 permanently.

### Binary questions — settled, all favourable

| Question | Answer |
|---|---|
| Is SYSTEM in the Administrator role? | **Yes.** `NT AUTHORITY\SYSTEM \| IsInRole=True`, via a scheduled task running as `S-1-5-18`. `Assert-Elevated` works under RMM. |
| Does `Set-Acl` take a from-scratch `DirectorySecurity` with `SetOwner`? | **Yes.** Resulting SDDL `O:BAG:…D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` — owner Administrators, inheritance protected, SYSTEM and Administrators full control. Exactly the intended DACL. |
| Is `Dispose()` reachable from PS 5.1? | **Yes**, on both `Mutex` (with `ReleaseMutex`) and `RegistryKey`. `OpenBaseKey(LocalMachine, Registry64)` also works. |

### `GetFullPath` normalisation — one hole found and closed

| Input | Result |
|---|---|
| `C:\Windows\System32.` | → `C:\Windows\System32` — normalised, deny-list catches it |
| `C:\Windows\System32 ` | → `C:\Windows\System32` — normalised |
| `C:` | → `C:\Users\Administrator` (the process CWD) — confirms the bare-`C:` reject was necessary |
| `C:\PROGRA~1\x` | → **unchanged**. 8.3 short names are NOT normalised, so `C:\PROGRA~1\ibb` would have slipped past a deny-list comparing against `C:\Program Files`. Now rejected outright. |

### Defects the lab found that nothing else did

1. `Assert-SupportedKind` was validating `previousKind` unconditionally, but a
   change that *created* a value records `previousKind` as null — correctly, since
   rolling it back means deleting the value. Every rollback of a newly created
   value failed with `kind "" is not supported`.
2. `Restore-TrackedChange` re-encoded `newValue`, which was already in manifest
   form, so comparing a `REG_BINARY` threw trying to cast `"AQID+g=="` to
   `byte[]`.

Both failed **closed** — status `failed`, run left retryable, host unchanged —
which is the one thing that went right about them.

### The Atomic Red Team exercise: telemetry measured against real attacker behaviour

**2026-08-27.** 11 approved atomics plus one approval-gated extra, run against the
armed lab. Full detail is in the Atomic exercise records kept in the development repository, with the
reconstruction side in the Atomic exercise records kept in the development repository.
Atomic Red Team at `6132b92`; every command read from its YAML and written
verbatim to its own file before execution.

This is the first measurement of what the configuration *produces*, as opposed to
what it *sets*. **33 PASS, 4 PARTIAL, 6 FAIL** across the expected evidence items,
and **7 of 11 attacker activities reconstructed COMPLETE** from the evidence alone.

| What the exercise proved works | Evidence |
|---|---|
| ScriptBlock logging, module logging and transcription each independently defeat base64 + string-concatenation obfuscation | 4104 wrote the deobfuscated `Write-Host` as its own event; 4103 wrote the bound parameter values; the transcript wrote the decoded line and its output |
| 4698 reproduces a scheduled task completely | 1,603 bytes of task XML: action, trigger, principal, run level, `ClientProcessId`, `SubjectLogonId` — the persistence is reconstructable after the task is deleted |
| Command-line auditing is the single highest-value setting | Removing it collapses **six of eleven** activities: the /24 sweep, every `net` query, two cleartext passwords, the `wmic` target, the `auditpol` commands |
| `auditpol` tampering cannot hide the commands that did it | 3 × 4688 with exact command lines + 13 × 4719 naming the actor and subcategory; Detailed Tracking is disabled last, so every command was recorded before the switch |
| PowerShell logging survives an `auditpol` tamper | 11 × 4104 written while 8 subcategories sat at 0 and a control probe produced zero 4688 |
| A rejected account creation is distinguishable from a successful one | 4720 → 4724 → 4729 → 4726 within one millisecond |
| `Test-VisibilityDrift` detects an audit-policy tamper | Exit 1 under live tamper, naming the drifted subcategory GUIDs |

Six things it proved do **not** work, now filed as W-2 (sharpened) and AT-1
through AT-9 in the review log kept in the development repository:

1. **Security-channel forwarding is stalled and says it is healthy.** It delivered
   1,036 events and stopped at `12:59:24Z`; the PowerShell query on the same
   subscription ran two hours longer. `wecutil gr` reported Active / LastError 0
   throughout. A WinRM restart did not clear it. **If the source host's Security
   log were destroyed, the collector would hold 4103/4104 and 7045 — and nothing
   else.**
2. **The subscription does not ask for 4698 or 4719**, the two richest events the
   exercise found.
3. **`Test-VisibilityDrift` missed `Logon`, `Logoff` and `Special Logon`** — 9 of
   13 tampered subcategories caught. It verifies recorded *changes*, and those
   three were already enabled at Apply time, so nothing was recorded about them.
4. **`Enable-DnsVisibility` does not see `nslookup`.** 255 lookups produced 255 ×
   4688 and one relevant DNS-channel record.
5. **`Enable-AdObjectAuditing`'s SACLs are not on the SAMR path.** Domain
   enumeration produced 4662: 0, 5145: 0 on the DC.
6. **`Sensitive Privilege Use` cost 5,562 events against 669 × 4688** in the same
   window, contributing to no reconstruction.

Two Atomic Red Team defects were found in passing: `T1136.001` ships a password
containing its own account name (rejected by default complexity), and `T1047`
"WMI Execute Remote Process" ships an unquoted `DOMAIN\user` that `wmic` refuses
with `Invalid Global Switch.` — both are silent no-ops as written.

Lab left clean: audit policy restored **byte-identical** (SHA256 matched twice),
the created user, task and service confirmed gone, and the `lab-attacker` scaffolding
account deleted with its password removed from both hosts.

### W-2 closed: the Security query, and the ceiling Microsoft documents

**2026-08-27.** `New-SubscriptionXml` emitted all 26 Security event IDs as one
XPath expression. Microsoft: *"If the XPath expression is a compound expression
that contains more than 20 expressions ... you must use a structured XML query"*
([Consuming Events](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events)).
The script already used a structured query — that does not lift the limit, it is
how you stay under it, by spreading terms across several `<Select>` elements.

Measured on Server 2019 build 17763.9121, one WinRM restart per round, verdict
read from the source's `Microsoft-Windows-Forwarding/Operational`:

| Terms in one `<Select>` | Security-only | With System + PowerShell |
|---|---|---|
| up to **23** | 100 created successfully | 100 |
| **24** and above | 102, error 5004 | 101, one or more channels unreadable |

Isolated: a 22-term query padded to a *longer* XPath than the 24-term one still
returned 100, so it is the **term count**, not the string length. Each half of
the ID list returned 100 on its own, so it is **not a toxic ID**. All 26 across
two `<Select>` elements returned 100, so the limit is **per-selector**.

Proven on the shipped code: `-Rollback` → `-Apply` → WinRM restart gave
**`id=100 IronBlackBox-Baseline is created successfully`**, the first 100 this
project has ever produced; 30 marked 4688 events then arrived in
`ForwardedEvents` within 40 seconds with the command line intact; re-`-Apply`
reported 0 changes. A regression guard was added and **proven to fire** — a
deliberately broken chunk loop exits 2 and creates nothing.

**And the diagnostic that should have caught it now exists.** The 101 event
carries a structured `QueryStatus` document naming the failing channel:

```xml
<t:Channel Name="Microsoft-Windows-PowerShell/Operational" ErrorCode="0"/>
<t:Channel Name="Security" ErrorCode="15001"/>
<t:Channel Name="System" ErrorCode="0"/>
```

That event sat in `Microsoft-Windows-Forwarding/Operational` on the source for two
days. `Enable-WefClient` read the channel and printed the last ten events without
interpreting any of it. It now reports a verdict **per subscription** from the
structured `Id`, `Status` and `ErrorCode` fields — never from the localised
message — and names the unreadable channel. Two bugs in that addition were found
and fixed by running it: it first reported 30 long-deleted subscriptions as live,
then a time-window bound leaked a deleted one back 46 seconds later. The rule
that works uses the forwarder's own behaviour: every round unsubscribes
everything first, so a subscription whose newest event is **103** is gone, and a
verdict older than the newest **103** belongs to a previous round. Both exclusions
are counted out loud rather than silently applied.

**Why it took two days**, and the correction that matters: over the ceiling the
source drops the offending channel and keeps delivering the others, while
`wecutil gr` reports `Active` / `LastError 0` / fresh heartbeat. Nothing on the
collector reports a missing channel. Two earlier conclusions were retracted in
the process — "the ID list has never been the problem" (it was the whole problem)
and "forwarding worked then stalled at 12:59:24Z" (it never started; the events
in that window came from hand-made test subscriptions). Both retractions are
written up in the review log kept in the development repository.

### AT-1 closed: what the subscription was never asking for

**2026-08-27.** The Security query selected 26 IDs and omitted the two richest
artifacts the Atomic exercise produced. Nine Security IDs and one System ID added,
every one named from [Microsoft's Appendix L table](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
rather than from memory: **4698, 4699, 4702, 4719, 4724, 4738, 4729, 4757, 4771**
and **7009**. Security goes 26 → 35, which the W-2 chunker emits as 20 + 15.

`4719` is one of the few events Microsoft rates **High** criticality — *"one
occurrence of the event should be investigated"* — and `Deploy-TamperAlerts`
treats it as a primary signal. It was not being forwarded.

Rejected on measured or cited grounds rather than added: 4768/4769 (workload
dependent, very high on a DC; 4771 gives the signal at failure-only volume),
5145, 4673/4674 (**5,562 events in nine minutes against 669 process creations,
zero contribution to any reconstruction**), 4657/4663 (need SACLs the toolkit does
not place), and the rest of Microsoft's baseline surface, which is real value but
would be the bulk-add this project's own rule forbids.

**Proven end to end**: `-Rollback` → `-Apply`, WinRM restart on the source →
verdict **100**; a task created and deleted, one audit subcategory toggled and
restored byte-identical; first poll of the collector returned
`4698=1 4699=1 4719=2 4688=27`, with the forwarded 4698 carrying **1,660 bytes of
`TaskContent` and `<Command> = True`**.

Two new findings came out of reading Microsoft's own WEF baseline while doing this,
both filed: **AT-10** — IronBlackBox uses no `<Suppress>` and no per-field
filtering anywhere, where Microsoft's baseline strips exactly the noise this
exercise measured (on the DC: 25 of 28 `4672` were SYSTEM, 6 of 7 `5140` were
machine accounts on SYSVOL or IPC$, 53 of 54 `4624` were type 3) — and **AT-11**
— the toolkit enables `Certification Services` auditing for 4886/4887/4888 and
then forwards none of them, because the audit target set and the forwarding ID
list were written independently with nothing reconciling them.

### AT-10 closed: filtering the measured noise, without touching the signal

**2026-08-28.** The subscription forwarded everything unfiltered. Two inline
predicates added, each on its own `<Select>` for its own event ID — never a
query-scoped `<Suppress>`, because Microsoft documents that a `<Suppress>` applies
to the whole `<Query>`, and the Security query holds 4688: a SYSTEM suppression
there would have deleted 40-50% of process-create events (the services and
SYSTEM-run tasks). Filters: **4672** excluding `S-1-5-18` (SYSTEM always holds
special privileges — 83% of 4672 on the DC, never an escalation signal) and
**5140** excluding `IPC$`/`NetLogon` (GP-refresh noise; SYSVOL kept). Both verified
with the subscription's own XPath via `Get-WinEvent -FilterXPath`: 0 SYSTEM survive
the 4672 keep-filter, 0 IPC$/NetLogon survive the 5140 keep-filter, and 27 of 27
4688 (25 user + 2 SYSTEM) forwarded afterwards. 4624 by LogonType was deliberately
**not** filtered: type-3 network logons are load-bearing for cross-host
reconstruction (proven in the Atomic exercise) and IronBlackBox is
single-subscription, so Microsoft's baseline/Suspect split does not apply. Rollback
→ reapply reproduces the query byte-for-byte.

### Still unproven

- **Client SKUs.** Windows 10/11 licensing is not available on EC2. Anything
  branching on `ProductType` is unproven there.
- **WOW64 registry redirection.** The code now uses an explicit `Registry64`
  view, which is proven to work from a 64-bit host. It has not been run from
  `SysWOW64\powershell.exe` to confirm it defeats the redirect.
- **Junction TOCTOU** between the reparse-point walk and `Set-Acl`.
- **Concurrency**: two simultaneous runs, and `AbandonedMutexException`.
- **Non-English Windows.** The well-known SIDs exist precisely for this, but no
  fr-FR host has run any of it.
- **Empty and single-element `REG_MULTI_SZ`** round-trips.
- Registry keys the toolkit creates are not recorded, so a rollback removes the
  values and leaves the empty key behind. Residue, not data loss.
