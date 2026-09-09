# Design

The conventions every script in this repository follows, and why. Short by
intent — a previous incarnation of this project had a 28,000-word specification
and one script to show for it.

Read this before writing a script. Read `docs/AUTHORING.md` for the hard constraints.

---

## 1. The three layers

An aircraft black box survives the crash and tells you what happened. A Windows
host, by default, does not: no ScriptBlock logging, no command line on 4688, no
Prefetch on servers, PowerShell v2 still installed, no forwarding, no baseline.
Every layer of this toolkit exists to close part of that gap.

| Folder | Job | Nature |
|---|---|---|
| `logging-hardening/` | Arm the recorder — turn on the logging Windows leaves off | changes state |
| `anti-tampering/` | Protect the recorder from the crash — stop the logging being disabled or cleared | changes state |
| `ir-collection/` | Read the recorder after the crash — fast triage for the responder | read-only, and **in a separate private repository**, [`Secur01/IronBlackBox-IR`](https://github.com/Secur01/IronBlackBox-IR) |

The scenario this is built for: a responder lands on an incident, the MSP says
"we ran the toolkit eight months ago", and the artifacts are already there —
ScriptBlock logs, Shimcache, Amcache, Prefetch, WMI subscriptions, USN journal.

---

## 2. Modes

Every script in this repository that changes anything has exactly three modes.
Three kinds of script have `-Audit` only, because they are read-only by nature
and have nothing to apply: `Test-VisibilityDrift`, which compares the host
against the manifest; `Test-DefenderPosture`, which reports whether Defender is
present, running and protecting; and the collectors in `IronBlackBox-IR`. This
document remains the contract for all of them, and is owned here.

`Test-DefenderPosture` is `-Audit`-only for a reason worth stating: every lever
that would fix a bad posture belongs to Defender or to a third-party AV, not to
this toolkit. Starting a stopped antimalware service or re-enabling real-time
protection is an EDR-suspect action, and a hardening script that does it can
break the very product it was meant to report on. It reports; the MSP decides.

| Mode | Behaviour |
|---|---|
| `-Audit` | **The default.** Reports current state and what `-Apply` would change. Writes nothing to the registry, nothing to the filesystem outside its own output, and changes no service configuration. See 2.1 for the one thing it can still move. |
| `-Apply` | Makes the changes, recording the previous value of each one first. |
| `-Rollback` | Restores the previous values recorded by a prior `-Apply`, resolving each change against the host three ways - see 4.1. |

### 2.1 What `-Audit` can still move, and why the wording above is careful

A read-only script can still invoke a query tool that has a side effect, and one
does.

MEASURED, 2026-09-02, Server 2019: a full before/after snapshot of 459 items -
the Prefetch and FileSystem registry keys, four service states, and the toolkit
root's tree and DACL - across a single `Protect-ForensicArtifacts -Audit`. Exactly
one item differed:

```
=> SVC VSS = Running/Manual
<= SVC VSS = Stopped/Manual
```

The script calls no `Start-Service`. It runs `vssadmin list shadows` to report
whether a recovery point exists, and `vssadmin` starts the Volume Shadow Copy
service on demand to answer. The start type is untouched, so nothing outlives the
query, and the service was already configured to start this way.

That is why the row above says "changes no service **configuration**" rather than
"never writes to any service". The earlier absolute wording was contradicted by
the toolkit's own behaviour, which is worse than a narrower promise kept: an
operator who diffs a host after an audit and finds a started service has been
told something false by this document.

**The rule this sets for a new script.** `-Audit` may read through a tool that
starts an on-demand service to answer. It may not start a service itself, change
a start type, or leave anything running that was not configured to. If a query
has a side effect an operator could notice, the audit output says so at the time
rather than leaving them to find it in a diff.

`-Audit` being the default matters: an MSP technician who runs a script with no
arguments, on a production host, at 4pm, must not change anything.

## 3. Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing needs doing, or the requested change succeeded |
| `1` | Something needs doing, or drift detected — the RMM-alertable state |
| `2` | Execution error — the script could not do its job |

MSPs alert on these, so they are a contract, not a convention. Be disciplined.

### 3.1 Findings versus host limits

`1` means **an action exists**, not that a condition exists. This is the
difference between a signal and a permanently red light.

Measured on the lab before this rule existed: ten of eighteen scripts exited `1`
on a fully armed host, and several could never reach `0` there. Tamper protection
cannot be turned on without Intune. A LOLBin that this Windows build does not
ship will not appear. `pcalua.exe` reports an empty `BinaryName`, so its
AppLocker rule falls back to a path condition — correctly, and forever. An MSP
whose monitor is red on a host every night mutes it, and then it hides the
`NEW Path exclusion` that the same script exists to catch.

So there are two output kinds, and the test between them is not severity:

| | Test | Exit code |
|---|---|---|
| `Write-Finding` | is there a lever? a switch to pass, a file to stage, an exclusion to remove, a second run to make | counts toward `1` |
| `Write-HostLimit` | no lever exists — no `-Apply` of this script, with any parameters, on any number of runs, will clear it on this host | never affects the exit code |

Both print. Both are counted and reported in the result. A host limit is not
hidden; it is just not an alarm, because there is no action for the alarm to
prompt.

**The test is deliberately about the lever and not about seriousness.**
`IsTamperProtected = False` is serious and is a limit. `Sysmon is not installed`
is mundane and is a finding, because staging a binary clears it. Getting this
backwards — classifying by how bad it sounds — reintroduces exactly the
permanently-red monitor this rule exists to prevent.

One residual class is deliberately left as a finding: a lever the operator has
chosen not to pull, such as `-EnableLastAccessUpdates` on a fleet that does not
want the I/O. Acknowledging those needs a mechanism this toolkit does not have,
and treating "I decided against it" as "impossible" would be a lie in the
output.

A third case surfaced later, in the negative-path pass, and resolves by the same
test rather than by a new rule. `Deploy-TamperAlerts` scans backwards over
`-LookbackDays` and marks each hit against a bookmark that only `-Apply`
advances. The window is that lookback period, **not** the bookmark, so a hit
already past the bookmark comes back on every run for as long as the event is in
the channel. Measured on the lab: 118 of them, and one cleared Security log
would have held the exit code at `1` for thirty days after an operator had read
it. Nothing the script *does* removes one — each is a past event, and no `-Apply`
rewrites the past; only time takes them out of view, when they age out of
`-LookbackDays` or roll out of their channel. So they print under their own
heading, are counted, and stay out of the exit code. Only `[NEW]` counts.

The counted part is load-bearing, not decoration. The first version of this
change printed them with `Write-Info` and nothing else, which made the script's
`No findings: nothing in the window` line reachable on a host that had a list of
tamper indicators printed directly above it. A detector that goes quiet is worse
than the noise the split removed, so the result section names both classes it is
not counting.

**The transferable rule: whatever decides that a true statement stays out of the
exit code becomes security-relevant the moment it does.** Here the decider is a
JSON file of high-water marks, which had been cosmetic — forging it swapped a
prefix. Once it gated the exit code, forging it silenced a source permanently,
and it was the only administrator route to blinding this detector that produced
neither noise nor a finding. So a mark is now refused unless it can be justified:
one that stands above the newest record its own source can return is impossible
to have written and is discarded with a finding, and one that cannot say which
window it examined, or that examined it incompletely, does not get to demote
anything. Both fail toward noise, which is the only acceptable direction.

**Elevation is checked in code, by an `Assert-Elevated` helper that exits `2`.**
Deliberately *not* `#Requires -RunAsAdministrator`: that directive aborts the
script before its own code runs and yields a host exit code of `1`, which
collides with "findings". An unprivileged run would silently look like drift.

A failed write in `-Apply` is `2`. The intent record for that change stays in
the manifest — it was flushed before the attempt, which is the whole point of
section 4 — and `-Rollback` resolves it against the host. What the toolkit never
does is report a change as *applied* when it was not.

*(An earlier revision of this section said "and no manifest entry", which
contradicted section 4 and described a design that would lose the previous
value on exactly the failure it was meant to survive.)*

### Parameter validation is done in the body, not by `[Validate*]` attributes

Same collision, one layer earlier. A binding-time validation failure never
reaches the script: PowerShell rejects the argument, writes its own error, and
the **host** exits `1`. An RMM then records "drift" on a host where nothing ran
and nothing was read.

Measured on PS 5.1 (Windows Server 2019 Datacenter 17763, 2026-08-28), each via
`powershell.exe -File`:

| Bad invocation | Exit |
|---|---|
| `[ValidateRange]` violated | `1` |
| `[ValidateSet]` violated | `1` |
| wrong type (`-Days abc` on an `[int]`) | `1` |
| unknown parameter (`-Bogus`) | `1` |
| ambiguous parameter set (`-Audit -Apply`) | `1` |
| valid invocation | `0` |

Neither a script-scope `trap` nor a `begin { trap { } }` intercepts any of them —
binding finishes before either exists. So the only way a script can answer a bad
value with `2` is to accept the argument and check it in the body. That is what
the template's **Parameter validation** region does: `Assert-ParameterRange`,
`-Set`, `-Pattern`, `-Count` and `-NotEmpty` throw, and the bottom
`catch { exit 2 }` reports it with a message naming the parameter, the value and
the bounds.

Two rules make the translation faithful:

- **Only supplied arguments are checked.** A `[Validate*]` attribute runs only
  when its parameter is *bound*, and several parameters are legitimately empty
  when omitted (`-Volume`, `-RemoveExclusionType`). `Test-ParameterSupplied`
  reads `$script:SuppliedParameter`, which is `$PSBoundParameters` captured at
  **script** scope — inside a function that automatic variable holds the
  *function's* own bound parameters, which for `Invoke-Main` is always empty.
- **Every element of an array parameter is checked**, and set matching stays
  case-insensitive, because that is what the attributes did.

**What this does not cover.** Three binding failures still exit `1` and no
in-script code can change that: a wrong **type**, an **unknown** parameter, and
an **ambiguous parameter set**. Declared types are kept deliberately — dropping
`[int64]` to catch the first would hand every downstream comparison an
unconverted string, a worse defect than the one being fixed.

For a deployment that needs *every* bad invocation to read as `2`, invoke through
the wrapper rather than `-File`. Measured: it maps all five classes above to `2`
and leaves a valid run's own exit code untouched.

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { & 'C:\ProgramData\IronBlackBox\Enable-IRVisibility.ps1' -Apply; exit $LASTEXITCODE } catch { exit 2 }"
```

---

## 4. The manifest

`<ToolkitRoot>\manifest.jsonl` — the record of everything this toolkit changed
on the host. It is what makes `-Rollback` and `Test-VisibilityDrift` possible.
It is the single most important design surface in the project, because a lost
previous value is an unrecoverable change on a client's production server.

### Format: JSONL, append-only

One self-contained JSON object per line. **Never a single JSON array.** A
truncated array — power loss, full disk, an antivirus lock mid-write — is
unparseable in its entirety, which means one interrupted write destroys every
previous value on the endpoint. A torn final line in JSONL is discardable and
the records before it are still readable.

Append-only also means an earlier record is never rewritten, so no new write can
corrupt an old one.

### Records

| `recordType` | Written | Carries |
|---|---|---|
| `run` | once, at the start of an `-Apply` or `-Rollback` | `runId`, `script`, `version`, `mode`, `startedUtc`, `hostname`, `parameters` |
| `change` | **before** each individual change is made | `runId`, `changeId`, `recordedUtc`, and the change body below |
| `run-end` | when the run finishes, including the failure path | `runId`, `completedUtc`, `changeCount`, `status` (`completed` / `completed-with-failures`) |
| `rollback` | around a `-Rollback` | the **target** `runId`, `timestampUtc`, `status`, `detail`, and the `restoredChangeIds` / `permanentChangeIds` / `abandonedChangeIds` lists — see 4.1 |

**A `change` record is written and flushed to disk before the change it
describes is made.** Not after. A process killed between a registry write and
its record leaves a modified host whose previous value existed only in memory —
roughly thirty such windows per `-Apply`. The record goes down first, carrying
both the previous and the intended value; `-Rollback` resolves an unconfirmed
one against the host: equal to the intended value means the write landed and is
restorable, equal to the previous value means it never happened.

Flush with `FileStream.Flush($true)` — the `$true` overload commits to the
device, not just to the OS cache.

### Change bodies

Registry:
```
{ type: "registry", path, name, valueExisted, previousValue, previousKind,
  newValue, newKind }
```
Directory / file ACL:
```
{ type: "directory", path, pathExisted, previousSddl, previousOwner,
  previousInheritanceProtected, removeOnRollback }
```

Four details that are each a defect if got wrong:

- **`path` and `name` are separate fields.** Joined into one string and re-split
  later, any value name containing a backslash mis-splits — and the rollback
  writes into a *different* registry key. An empty (default) value name also
  degenerates to a single element.
- **`previousKind` / `newKind` are mandatory.** The value kind is the one piece
  of state that cannot be reconstructed from the value. Restore a
  `REG_EXPAND_SZ` as `REG_SZ` and `%SystemRoot%` stops expanding; restore a
  `REG_QWORD` as `REG_DWORD` and it truncates. Read values with
  [`RegistryValueOptions.DoNotExpandEnvironmentNames`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registryvalueoptions)
  so what is stored is the unexpanded original.
- **`REG_BINARY` is base64, `REG_QWORD` is a string.** A byte array round-trips
  through JSON as `Object[]` of numbers, and PS 5.1 deserializes JSON integers
  as `Int32` where PS 7 uses `Int64` — so an `-Apply` and a later `-Rollback`
  can disagree on the type of the value they are handling.
- **Names by well-known SID, never by string.** `BUILTIN\Administrators` is
  `Administrateurs` on fr-FR Windows — a real deployment target for this
  toolkit. Use `S-1-5-32-544` and `S-1-5-18`.

### Reading it

- **A corrupt manifest is an error, never an empty one.** `-Apply` on an
  unreadable manifest exits `2` and refuses to proceed. Returning "no records"
  on a parse failure is how a previous implementation overwrote and destroyed
  recoverable rollback data.
- A torn **final** line is tolerated on read (it is an interrupted write).
- **An `-Apply` that changes nothing still writes its `run` and `run-end`
  records**, with `changeCount: 0`. On a host already compliant by GPO there is
  otherwise no evidence the toolkit ever ran, and `Test-VisibilityDrift` has no
  reference state to compare against.
- **A run that already has a finished `rollback` is not replayed.** "Finished"
  is any `status` starting with `completed`, never equality with `completed` —
  see the doctrine below. Without that, a second `-Rollback` restores values
  that were already restored, on top of whatever legitimately changed since.

### 4.1 The rollback doctrine

Every restorer resolves the change **three** ways against the host, and there is
a fourth outcome for one it can never undo:

| Case | Host holds | Outcome |
|---|---|---|
| 1 | what the run set | undo it → `restored` |
| 2 | the recorded previous state | already undone, **or the write never landed** — nothing to do → `restored` |
| 3 | neither | a third party has been here → `declined` (retryable) |
| 4 | — | un-undoable by design or by the OS → `declined-permanent` |

Case 2 is not a nicety. Without it the second `-Rollback` of a run declines
everything the first restored, the run never leaves the eligible set, and
`Test-VisibilityDrift` goes on expecting changes that are correctly gone. It also
covers the case this document has always specified and no implementation had: a
recorded write that never landed looks exactly like a change already restored,
and both mean "leave it alone and count it done".

The `rollback` record's `status` is one of:

| Status | Meaning | Run still eligible? |
|---|---|---|
| `completed` | everything restored | no |
| `failed` | a failure, or a retryable decline | **yes** |
| `completed-with-permanent-declines` | everything that could be undone was; the rest never can be | no |
| `completed-abandoned-by-operator` | an operator ran `-Rollback -AbandonRun <runId>` | no |

The record also carries **which** changes, by `changeId`:
`restoredChangeIds`, `permanentChangeIds`, `abandonedChangeIds`. A per-run status
is not enough — a run with one legitimate decline and eighteen restores is
`failed`, and a detector reading only the status would expect all nineteen back.
Host state cannot substitute for these lists: a value returned to its
pre-hardening state by a rollback and a value an attacker switched off are
indistinguishable from outside.

### 4.2 `-AbandonRun`, and why it has to exist

Case 3 declines as *retryable* on the assumption that whatever changed the value
might change it back. When the thing that changed it is a **later run of the same
script**, it never will — so the run stays eligible forever and blocks
`-Rollback` from reaching anything older.

`-Rollback -AbandonRun <runId>` is the operator's escape. It rolls back
everything it still can, then records that a person chose to stop trying on the
rest, naming every change abandoned. It does **not** touch the host and does not
claim anything was undone.

Four properties make it safe enough to exist:

1. **It names a run.** Not a switch, never "the most recent" — abandoning cannot
   be the accidental result of a habitual command line.
2. **It rolls back first.** Only what still declines is abandoned. Abandoning a
   change that would have restored cleanly would be the worst version of this.
3. **It refuses** a run that does not exist, belongs to another script, is not an
   `-Apply` run, or is already finished. It never abandons a run with a thrown
   failure either: that is a bug or a broken host, not a decision.
4. **It stays visible.** `Test-VisibilityDrift` reports every abandoned run in
   its coverage section, by run id and date, on every later run. The changes stop
   being *expected*; the decision does not stop being *visible*.

What it costs is real and is stated in the output: the abandoned changes are no
longer reported, so if one of them is a setting an attacker switched off, this is
the operator choosing not to be told about it again.

**A torn final line is quarantined before the next write.** `-Apply` and
`-Rollback` both validate the manifest before their first append. This is the
one exception to append-only, and it is not optional: `FileMode.Append` writes
straight onto an unterminated final line, producing `{truncated}{"recordType":
"run",…}` as a single physical line. That line is then no longer the last one,
so the tolerance above stops applying, and **every** later `-Rollback` fails
with "manifest is corrupt" — permanently, with every previous value sitting
readable on disk and unreachable. The torn bytes are moved to a sibling
`.torn-<stamp>.jsonl` file rather than discarded, and the surviving records are
rewritten verbatim.

Deliberately absent: a five-state transaction protocol, size rotation and
compaction. The manifest grows linearly with the number of changes made, which
for a toolkit run monthly by an RMM is small. **If the lab proves one of these
is needed, it gets added on evidence** — not in advance.

---

## 5. The toolkit root

`C:\ProgramData\IronBlackBox` by default, `-ToolkitRoot` to override.

`-ToolkitRoot` is operator input that decides which directory gets its ACEs
stripped, its inheritance disabled, and its ownership reassigned. `C:\` or
`C:\Windows` — from a typo, or an RMM variable that expanded to nothing — is an
unrecoverable outage delivered by the hardening script itself.

Every script therefore runs the value through `Assert-SafeToolkitPath` before
deriving anything from it. The path must be canonical, rooted, local, not a
volume root, at least two levels below it, neither a system directory nor an
ancestor of one, and free of reparse points along its whole length.

A directory that already exists, holds files, and carries no `.ironblackbox`
stamp is **refused**, not adopted — the stamp is what separates a legitimate
idempotent re-run from an operator pointing the toolkit at somebody else's data.

The root itself gets a DACL with inheritance disabled and access for SYSTEM and
Administrators only. `C:\ProgramData`'s default DACL otherwise lets an
unprivileged user edit or delete the record of everything the toolkit hardened.
Subdirectories that need wider access get explicit narrow grants from the script
that creates them.

---

## 6. Standalone scripts, no shared module

Helpers are **copied** from `docs/SCRIPT-TEMPLATE.ps1` into each script. There
is no `.psm1`, no classes, no dot-sourcing.

This is deliberate duplication. The audience deploys via RMM, often as a single
command against a single file; a module dependency means a second artifact to
stage, a `PSModulePath` that differs under SYSTEM, and an install step that
kills adoption. Deployment friction beats DRY here.

The cost is real, and it has already been measured. An adversarial review of the
template found 15 provable defects in these helpers. Had all 28 scripts that
inherit this template existed at that point — the 18 here plus the ten collectors
in `IronBlackBox-IR`, which copy the same regions — it would have been 15 fixes
propagated by hand across 28 files, and a copy that quietly missed one would look
fine.

So the duplication is kept, and `tools/check.ps1` enforces it: the **helper
drift check** parses the `#region` blocks of every script in the three family
directories and compares each one that shares a name with the template's.
Divergence fails the gate:

```
[FAIL] Enable-IRVisibility.ps1 — region 'Manifest' diverges from docs/SCRIPT-TEMPLATE.ps1 (3 lines differ)
```

Propagating a fix stays manual. Drifting silently becomes impossible. Two rules
follow from this, and they are not optional:

- **Copy a helper unchanged, or not at all.** A locally "improved" copy is how
  scripts stop agreeing on what the manifest means. If a helper needs to
  change, it changes here first and every copy follows.
- **Omitting a region is fine; editing one is not.** The template is a buffet.
  A read-only collector carries `Output` and the elevation check and nothing
  else — it has no business shipping a manifest writer it never calls. The
  drift check compares by region name, so what is absent is never flagged.

The comments inside the helpers are part of the copied text. Each one records
why a specific defect was fixed; a copy that strips them has kept the code and
thrown away the reason, and the check treats that as drift.

---

## 7. Safety

- **Nothing that can break production by default.** AppLocker, NTLM and LDAP
  scripts are audit-only by design. Enforcement is the MSP's decision, made
  after reading the audit data. Do not add enforcement switches.
- **Never touch RMM connectivity.** A script that locks out the RMM has locked
  out its own remediation.
- **Downloaded binaries** (Sysmon, autorunsc): verify the Authenticode signature
  chains to Microsoft before executing. No signature, no execution.
- **VSS**: check free disk space before resizing shadow storage.
- **Client vs server SKU**: check `ProductType` wherever behaviour differs.
- **Watcher scripts** (tamper alerts): bookmark and dedupe, and exclude their own
  process tree — a watcher that triggers on its own events is a loop.

---

## 8. Distribution

Two supported methods:

1. **Standalone** — the MSP downloads only the `.ps1` files it wants and builds
   its own RMM components. Maximum transparency; every script is self-contained.
2. **Release ZIP** — each GitHub release ships the whole toolkit plus
   `SHA256SUMS.txt`. One RMM package instead of 18 components, extracted under
   the toolkit root.

**Non-goal: a bootstrap script that downloads other scripts at runtime.**
`SYSTEM` + PowerShell + download + execute is a pattern EDRs flag, correctly.
This project does not work around an EDR to solve a packaging problem. The
Release ZIP exists so that nobody needs to.

Authenticode signing of the scripts themselves is deferred past v1.0; the
release checksums are the integrity story until then.

---

## 9. Validation

`docs/VALIDATION.md` is the only file allowed to claim something was tested, and
it records what actually ran, on what, when. A script with no row there has never
run anywhere.

The rule behind it: **never state a Windows fact from memory.** Every registry
path, event ID, auditpol subcategory, capability name, service name, SDDL mask
and WMI class in this repository is a claim about an operating system. Cite it to
Microsoft's documentation, derive it from a recorded run on the lab, or mark it
unverified. Those are the only three options, and plausibility is not one of them.

No static gate on Linux can validate any of those literals. `tools/check.ps1`
proves syntax and API surface. Behaviour is proven on the lab or not at all.
