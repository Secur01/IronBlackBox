# Authoring a script

Operational companion to `docs/DESIGN.md` (the contract). This is the *how*,
written down because the same mistakes were made more than once.

Read `verification/facts.json` before writing any Windows literal. It records
what has been measured on a real host and what has not.

## The hard constraints

The rules the scripts themselves cite, gathered here so a citation in a comment
can actually be read. `docs/DESIGN.md` is the contract for modes, exit codes and
the manifest; these are the constraints on top of it.

**The cardinal rule: never state a Windows fact from memory, and never claim
validation that did not happen.** Every registry path, capability name, service
name, event ID or cmdlet parameter is either cited to `learn.microsoft.com` or
marked `# UNVERIFIED:` with what needs checking. Only `docs/VALIDATION.md` may
say a script ran somewhere, and only with a dated row. The words *tested on*,
*works on*, *verified on* and *compatible with* never appear as an OS claim
anywhere else. An earlier incarnation of this project shipped a README claiming
"tested on Windows Server 2016/2019/2022" when nothing had ever executed on
Windows.

**Never claim an effect you have not observed.** Reading a setting back out of
the registry proves the registry holds it, and nothing else. An AppLocker policy
here passed every read-back and was not being evaluated; a Sysmon install was
reported as collecting nothing while it collected 33 events in two minutes.
Where the effect is observable — an event ID, a file appearing, a command
failing — observe it, and where it is not, say so in the output.

**Never touch anything that can break RMM connectivity.** The toolkit is
deployed *through* the RMM agent, so a script that disrupts WinRM hosting, the
agent's transport or its service is a script that removes the only way to reach
the host and undo it. Where a fix would require that, the script reports and
refuses.

**Nothing breaks production by default.** The AppLocker, NTLM and LDAP scripts
are audit-only and carry no enforcement switch, not even an optional one.
Enforcement is the MSP's decision, made with its own change control.

**A downloaded binary is verified before it is executed.** Authenticode
signature checked and confirmed as Microsoft, matched on relative-distinguished-name
boundaries rather than as a substring — `O=Microsoft Corporation` must not be
satisfied by `O=Microsoft Corporation Ltd`, and both spellings have been
measured in the wild.

**Free space is checked on the volume that will hold the data**, which is not
always the volume being protected. Shadow storage for `D:` can live on `C:`. A
hardening script that fills a client's system volume has caused an outage rather
than prevented one, so the worst case — the area growing to its whole new
maximum — is computed, printed, and refused if it would breach the floor.

**Zero module dependencies.** In-box cmdlets and .NET only: no
`Install-Module`, and `[adsisearcher]` rather than the AD module. A hardening
script must not need the internet to run.

**300–700 lines of script-specific logic**, not counting the regions copied from
`docs/SCRIPT-TEMPLATE.ps1`. An MSP has to be able to read a script before
deploying it as SYSTEM. A predecessor reached 3,161 lines and was unreviewable;
past 700 the script is doing two jobs and the script list should say so before
the code does.

## Composition

A script is the template's helper regions, copied verbatim, plus its own logic.
Never hand-write the helpers. Extract them:

```python
import io, re
tpl = io.open('docs/SCRIPT-TEMPLATE.ps1', encoding='utf-8-sig').read()
def region(name):
    pat = re.compile(r'^[ \t]*#region[ \t]+' + re.escape(name) + r'[ \t]*-*[ \t]*$', re.M)
    m = pat.search(tpl)
    end = tpl.index('#endregion', m.end())
    return tpl[m.start():end + len('#endregion')]
```

Then assemble, in this order, and **write the UTF-8 BOM first**:

1. Comment-based help block and `param()`
2. `$ErrorActionPreference`, `Set-StrictMode -Version 1.0`, the `$script:*` vars
3. The copied regions
4. Your own regions — names must NOT collide with a template region name
5. `#region Main` with `Invoke-Main` and the outer `try { exit (Invoke-Main) }`

```bash
printf '\xEF\xBB\xBF' > family/Verb-Noun.ps1
cat head.ps1 regions.txt body.ps1 main.ps1 >> family/Verb-Noun.ps1
```

## The buffet, and its one rule

Copy the regions the script actually uses and delete the rest. A read-only
collector has no business carrying the manifest writer.

- `Output` — always. Everything calls `Write-Ok` / `Write-Finding`.
- `Elevation and path safety` — always. `Assert-Elevated`, `Assert-SafeToolkitPath`.
- `Native commands` — if it launches any in-box tool, registers a scheduled
  task, or parses a number out of native output. `Get-NativeToolPath`,
  `Invoke-NativeCommand`, `Get-PowerShellHostPath`, `ConvertFrom-NativeInteger`.
- `Toolkit root` — if it writes anything under the toolkit root, or takes a lock.
- `Manifest` — only if it records changes (so: only if it has `-Apply`).
- `Registry` — only if it *changes* registry values. Reading a value needs
  nothing from this region.

**Copy a region unchanged or not at all.** `tools/check.ps1` fails the build on
any edited copy, comments included: each comment records why a defect was fixed,
and a copy that drops it has kept the code and thrown away the reason.

A region must tolerate the absence of regions it was not copied with. That is
not theoretical — `Initialize-ToolkitRoot` referenced `$script:ManifestPath` and
broke the first collector that did not take the Manifest region.

## Traps that have already cost us

Each of these was found by running code on a real host. None were caught by the
parser or PSScriptAnalyzer.

**`$mode` is a reserved name.** PowerShell names are case-insensitive and its
scoping is dynamic, so `Invoke-Main`'s local `$mode` masks a script *parameter*
named `$Mode` inside every function it calls. Name yours `-PrefetchMode`,
`-CollectionMode`, anything else.

**`Int32 + String` throws.** `Write-Info ($items.Count + ' found')` fails —
PowerShell coerces the string to Int32. Cast: `[string] $items.Count + ' found'`.

**`-or` short-circuits.** `$changed = $changed -or (Set-Something ...)` stops
calling `Set-Something` after the first success. Count instead:
`if (Set-Something ...) { $changeCount++ }`.

**Never compare a security descriptor as text.** .NET regenerates SDDL with
rights abbreviations (`CCDCLC`) where Windows prints hex (`0x7`) — same meaning,
different string. Decode to per-SID masks.

**Never trust an ACL helper's return value.** `DiscretionaryAcl.RemoveAccess`
returned success and removed nothing. Compute the mask explicitly, write it, then
re-read and assert the result.

**Custom date formats need `InvariantCulture`.** In a custom format string `:` is
the culture's time separator, so `HH:mm:ss` renders as `20.08.21` on fi-FI. Use
`Get-UtcStamp` from the Output region.

**A `Mandatory [string]` parameter rejects an empty string.** That is why the
`Write-*` helpers are `[AllowEmptyString()]` and not mandatory: they are called
from the outer catch with `$_.Exception.Message`, which can be empty, and a
binding exception thrown inside a catch skips the `exit 2` below it.

**Locked files differ.** `.evtx` and `Amcache.hve` can be read with
`FileShare::ReadWrite`. The `SYSTEM` hive and `SRUDB.dat` cannot — they need
`reg save` or a shadow copy. Do not assume; `Invoke-TriageCollection` has the
proven methods.

## Native commands

Wrap them, and never name one without a path.

That rule is enforced by `tools/check.ps1`, which fails any `CommandAst` naming a
`.exe`/`.cmd`/`.bat`/`.vbs`/`.ps1` that is not rooted, and any `-Execute` or
`-FilePath` bound to a literal with no directory separator. It did not exist
until a security review found two shipped violations by hand: a `Get-Command
-Name 'dnscmd.exe'` whose `.Source` was executed as SYSTEM, and a scheduled task
registered `-Execute 'powershell.exe'` that ran nightly as SYSTEM for the life of
the host. Neither looks like `& tool.exe`, which is all the greps of the day were
looking for.

Both halves now live in the template's **`Native commands`** region, so the
drift check compares your copy like any other shared region: copy the region
whole, and change it only in `docs/SCRIPT-TEMPLATE.ps1`.

- `Get-NativeToolPath` returns an absolute path, testing `Sysnative` then
  `System32` then `SysWOW64` — that order deliberately, so a 32-bit host gets the
  native binary rather than the redirected one. It falls back to the bare name
  when none holds the file, and raises a finding saying so. Pass
  `-RequireAnchored` to get `$null` instead, wherever a tool's *absence* is itself
  the answer: DNS role detection turns on whether `dnscmd.exe` exists, and
  falling back to a name there would let a planted binary answer a question about
  which roles a host has.

  Resolve each tool **once**, into a `$script:<Tool>Path` in a script-local
  `Native tool paths` region, and pass that. Some older scripts resolve per call
  (`Test-VisibilityDrift`, `Protect-ForensicArtifacts`) or keep the assignment in
  a topic region (`Enable-AdObjectAuditing`); both are correct, neither is the
  pattern to copy.

- Do not spawn a `.cmd` wrapper. Measured on the lab: `winrm.cmd` is
  `@cscript //nologo "%~dpn0.vbs" %*` — `cscript` unqualified, resolved by
  `cmd.exe`, which searches the **current directory** before PATH. Anchoring the
  wrapper buys nothing and adds the working directory of a SYSTEM process as a
  vector. Call an anchored `cscript.exe` with the `.vbs` path spelled out.
- `Invoke-NativeCommand` keeps a non-zero exit from throwing under
  `$ErrorActionPreference = 'Stop'` and merges stderr so a failure message is not
  lost.

A script with no native calls omits the region entirely, which the drift check
allows. Two do: `Protect-DefenderConfig` and `Enable-ServerPrefetch`.

`Remove-PowerShellV2` omits it while still launching one, deliberately.
It needs the v1.0 engine at an exact path and it must FAIL when that path is
absent — an unavailable engine means "whether v2 can run here is unknown", which
is exit 2, not an all-clear. `Get-NativeToolPath`'s fallback to the bare name
would turn that into a silent PATH lookup, so it builds and tests the path
itself. Do not "unify" it into the shared helper: that would make it weaker.

*(This section previously said the pair was not template-owned and told you to
diff it by hand. That had already failed in the way it predicted — the code was
byte-identical across all fourteen copies, but two had dropped the docstring
explaining why the wrapper exists and a third had gained a note telling the next
author not to improve it. Comment-only drift, so nothing was broken; it is
recorded because "kept the code, threw away the reason" is what the gate exists
to catch, and hand-diffing did not catch it.)*

Prefer parsing a **numeric column by index** over matching display text:
`auditpol /backup` carries a numeric setting value precisely so nothing has to
match the localised string "Success and Failure".

## Address principals by SID

`BUILTIN\Administrators` is `Administrateurs` on fr-FR Windows. Use
`S-1-5-32-544`, `S-1-5-18`. Service SIDs (`NT SERVICE\mpssvc`) resolve through
`NTAccount.Translate` and are not localised.

## Exit codes are a contract

`0` clean, `1` findings or drift, `2` execution error. An RMM alerts on these.

- A collector that finds a gap in visibility returns **1**. That is the finding,
  not a failure.
- "The toolkit was never run here" is **0**, not 1 — do not cry wolf on
  unmanaged hosts.
- A script that applied its setting but cannot demonstrate the effect returns
  **1**, not 0. `Enable-ServerPrefetch` does exactly this.

## Say what you did not prove

Every script's header states what it deliberately does not do and why. If a
Windows fact could not be verified, mark it `# UNVERIFIED:` in the code and add
it to `verification/facts.json` under `openQuestions`.

Then run the gate, and fix until clean:

```bash
pwsh -NoProfile -File ./tools/check.ps1
```

L1 is what the gate gives you. It proves syntax and API surface and **nothing
about behaviour on Windows**. Only a recorded run on the lab moves a script past
it, and `docs/VALIDATION.md` is the only place allowed to say so.
