# Atomic Validation

What this toolkit does to a Windows host, measured against real ATT&CK techniques
rather than asserted.

**This is not a badge.** Every number below came from executing
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) atomics on a
live domain-joined Windows Server and reading the result. Where the answer was
"nothing", it says nothing. Where an atomic failed to run, it is excluded from the
verdict instead of being counted as a detection failure.

**This is the second exercise, run on 2026-08-31.** The first ran on 2026-08-27
against 11 atomics and produced the AT-1…AT-12 findings that shaped the toolkit;
its plan and per-technique telemetry verdicts are kept in
the Atomic exercise records kept in the development repository. This one
re-ran after every one of those findings was fixed, on a wider technique set, and
adds the comparison the first could not make: the same host, unarmed.

## How it was measured

**22 activities across 8 ATT&CK tactics**, run twice on the *same* host from the
*same* AMI baseline: once **unarmed** (stock Windows Server 2019, domain-joined),
once **armed** with this toolkit. The armed pass and the reconstruction were then
run a second time on 2026-09-01, against the code as shipped, after **AT-13** was
found and fixed; the unarmed numbers are unaffected by that fix and stand from the
first pass. The AMI restore between passes is what makes the
two columns comparable — the second host is not "the first host after cleanup", it
is the same starting state.

Atomic Red Team pinned at commit
`6132b92779873cb0d05bef07ba0a480d47eb1cc8` (342 techniques), SHA-256 of the
downloaded archive `B5657EC1904A9F83916AF08F08871956A1B28333FA3F9759E3C0AABA7CD64341`.

Three disciplines make the numbers mean something:

1. **Ground truth, always.** After every pass, a separate inventory checks whether
   each attack *actually happened* — was the account created, the task registered,
   the subscription written. **21 of 22 executed**, identically in both passes.
   The rest are excluded, not scored. An early version of this harness wrote the
   atomic commands to a `.tmp` file, which `powershell -File` and `cmd /c` both
   refuse to execute; without the ground-truth check it would have published 22
   confident "detection failed" rows for attacks that never ran. The reverse also
   happened: three probes looked for the wrong artifact — the task Atomic creates
   is named `spawn`, not `T1053*` — and were corrected against the captured
   command line, which proves a command ran where an effect check cannot.
2. **Attribution by content, not by event ID.** "A 4688 appeared" proves nothing —
   4688s appear constantly. Every count below is of events whose **command line
   matches the atomic's own command**.
3. **Reconstruction from the collection alone.** The last column asks the only
   question that matters in an incident: an analyst receives the collected
   evidence package and nothing else — can they see the attack?

## The matrix

| Technique | Tactic | Unarmed host | Armed: attributed evidence | In the collection alone |
|---|---|---|---|---|
| `T1074.001` | Collection | PSop:4103x2 | 1× `4688`+cmdline, 1× `4104` | yes |
| `T1003.001` | Credential Access | — | *did not execute — excluded* | — |
| `T1552.006` | Credential Access | **nothing** | 1× `4688`+cmdline | yes |
| `T1070` | Defense Evasion | **nothing** | 1× `4688`+cmdline *(Windows recreates the USN journal at once)* | yes |
| `T1070.001` *(manual)* | Defense Evasion | Sys:104x1 | 1× `4688`+cmdline | yes |
| `T1140` | Defense Evasion | AppL:8003x2 | 2× `4688`+cmdline | yes |
| `T1218.010` | Defense Evasion | AppL:8003x1 | 2× `4688`+cmdline | yes |
| `T1218.011` | Defense Evasion | Sec:4648x3, Sec:4624x3 | 1× `4688`+cmdline | yes |
| `T1562.001` *(manual)* | Defense Evasion | **nothing** | 1× `4688`+cmdline, 3× `4104` | yes |
| `T1018` | Discovery | **nothing** | 1× `4688`+cmdline | yes |
| `T1087.002` | Discovery | **nothing** | 4× `4688`+cmdline | yes |
| `T1047` | Execution | AppL:8003x1 | 2× `4688`+cmdline | yes |
| `T1059.001` | Execution | **nothing** | 1× `4688`+cmdline *(the remote download failed, so no App Paths key)* | yes |
| `T1059.003` | Execution | **nothing** | 2× `4688` (not attributable — see note) | no |
| `T1490` | Impact | Sec:4799x8, Sec:4624x1 | 2× `4104` | yes |
| `T1021.002` | Lateral Movement | **nothing** | 3× `4688`+cmdline | yes |
| `T1021.006` | Lateral Movement | WinRM:145x767, WinRM:132x767 | 9× `4104` | yes |
| `T1053.005` | Persistence | **nothing** | 2× `4688`+cmdline | yes |
| `T1136.001` | Persistence | Sec:4722x1, Sec:4720x1 | 2× `4688`+cmdline | yes |
| `T1543.003` | Persistence | **nothing** | 1× `4688`+cmdline *(no effect — this host has no Fax service)* | yes |
| `T1546.003` | Persistence | WMI:5861x1 | **named by a collector** | yes |
| `T1547.001` | Persistence | **nothing** | 2× `4688`+cmdline, **named by a collector** | yes |

*(manual)*: the technique is absent from the pinned Atomic Red Team commit, so an
equivalent action was run by hand instead. **19 of the 21 rows are Atomic Red Team
tests; these 2 are not.** They are counted in the measurement totals below because
the host telemetry was captured the same way, but anyone replaying the pinned
commit will find 19 tests, not 21.

`T1059.003` is the one row, of twenty-one, where attribution fails rather than the
toolkit: two `4688` events fall inside its window, but the atomic writes text to a
file through a shell whose command line carries none of the keywords this harness
extracts, so they cannot be tied to it by content. Counting them would be exactly
the unattributed-event-ID mistake this method exists to avoid, so they are not
counted.

**Two corrections to an earlier version of this table**, both in the direction of
having under-reported the toolkit:

- The collection column first read **13 of 21**. Seven of the eight "no" answers
  were never probed at all — the first reconstruction pass tested only fourteen
  techniques and the rest defaulted to "no". An absence of measurement presented
  as a negative result is precisely the mistake this document exists to avoid, and
  it was in this document. The re-run probes twenty.
- The re-run also happened after **AT-13** was fixed, which is the substantive half
  of the change: the PowerShell evidence that had rolled away now survives to the
  collection. See below.

**Where `4104` attribution is weaker than `4688`.** A `4688` count is the
attacker's own command line, so it cannot come from anywhere else. A `4104` count
is script *text*, and this harness writes each atomic's command to a `.ps1` before
running it — so ScriptBlock logging records that text whether the command
succeeded or not, and the harness's own diagnostic scripts land in the same
channel. Verified: `T1003.001`, which did not execute, still produced five `4104`
hits containing its keyword, one of which proved to be an unrelated diagnostic
script of this harness. `4104` is therefore counted only for atomics whose payload
*is* a PowerShell command, and never as proof that an attack ran.

## What the numbers say

| | |
|---|---|
| activities executed and scored | **21 of 22** |
| **completely invisible on the unarmed host** | **11 of 21** |
| carrying attributed evidence once armed | **17 of 21** |
| reconstructable from the collection alone | **20 of 21** |
| `4688` events on the unarmed host | **0** — `Process Creation` is `No Auditing` by default |

The single highest-value setting is command-line auditing in `4688`. On the
unarmed host it does not exist, and 11 techniques leave no trace whatsoever.
Armed, **ten of those eleven** are recoverable with the attacker's own command
line attached. The eleventh is `T1059.003`: two `4688` events fall in its window
and neither can be tied to it by content, so this document does not count them —
the note above the summary explains why.

Six of the command lines that `4688` captured, verbatim. The first three are
techniques the unarmed host recorded **nothing at all** for; the last three it
did record, but with nothing that names what ran — an AppLocker `8003`, a pair of
logon events, and a `104` saying a log had been cleared:

```
findstr /S cpassword \sysvol\*.xml
fsutil usn deletejournal /D C:
SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe
certutil -decode ...\T1140_calc.txt
rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)
wevtutil cl "Windows PowerShell"
```

Two artifacts were **named outright** by a collector, with no prompting and no
knowledge of what had been run:

- `Export-Autoruns` → `run-key / Atomic Red Team: target file does not exist`
- `Get-WmiPersistence` → `SUBSCRIPTION filter "AtomicRedTeam-WMIPersistence-CommandLineEventConsumer-Example" -> CommandLineEventConsumer`

## Command-line auditing puts secrets in the Security log

This is the cost of the toolkit's most valuable setting, and it belongs here
rather than in a footnote. With `4688` command-line auditing on, the Security log
captures passwords typed on a command line:

```
net1 user /add "T1136.001_CMD" "Atmc!L2#7391x"
net use \\Target\C$ P@ssw0rd1 /u:DOMAIN\Administrator
```

Enabling this changes who may read that log. `Protect-EventLogs` hardens the
channel ACLs for exactly this reason — but an MSP should make that decision
knowingly, not discover it later.

## What this exercise found in the toolkit itself

**AT-13 — the toolkit destroyed its own PowerShell evidence.**
`Enable-IRVisibility` switched ScriptBlock logging *on* and left
`Microsoft-Windows-PowerShell/Operational` at its 15 MB default. Measured: the
copy inside the triage collection spanned **eleven seconds**
(`00:04:21.4Z → 00:04:32.0Z`) while the activities it was meant to evidence ran
half an hour earlier and had rolled away entirely. Running the collectors — which
are themselves PowerShell — is what destroyed it.

No earlier check caught this, because every earlier check measured
*configuration* — is ScriptBlock logging on? — and none measured *retention*.

**Fixed, and the fix re-measured on the same host** rather than assumed:

| `Microsoft-Windows-PowerShell/Operational` in the collection | Size | History it holds |
|---|---|---|
| before the fix | 15 MB | **11 seconds** |
| after the fix | 101 MB | **1,427 minutes — nearly a full day** |

That is the substantive reason the collection column moved: the ScriptBlock
evidence for the Defender exclusion, the VSS deletion, the WinRM execution and the
data staging had all rolled away before the collector reached them, and now
survives. The whole exercise was re-run against the fixed code so that this
document describes the toolkit as shipped, not an earlier one.

## What was NOT tested

Stated plainly, because a matrix without this section is marketing:

- **Sysmon was deliberately not installed.** Every number here is a **floor**: what
  well-configured *native* Windows gives you. Sysmon would raise it.
- **1 of 22 activities is excluded**: `T1003.001` (LSASS dump via comsvcs.dll)
  **did not execute**, so there is nothing to score either way — an attack that
  never ran cannot be counted as a detection failure. Its keyword does turn up in
  five `4104` events, which is the reason `4104` is never treated here as proof
  that something ran; see the note above the summary table. Three other
  activities ran but had no lasting effect — no Fax service to reconfigure, a
  remote download that failed, a USN journal Windows recreates at once — and are
  scored on the command that ran.
- **One host, one OS.** Windows Server 2019 Datacenter build 17763, domain-joined,
  single-domain forest at Server 2016 functional level. No client SKU, no
  multi-domain forest, no workgroup host.
- **Detection, not prevention.** This toolkit records; it does not block. Nothing
  here says an attack was stopped.
- **No EDR was present.** Results on a host with an EDR will differ.
- **Two Atomic Red Team defects were worked around** and are documented in the
  harness: `T1136.001`'s default password contains the account name (Windows
  rejects it), and any password over 14 characters makes `net user` ask an
  interactive pre-Windows-2000 compatibility question that fails unattended.

## Reproducing this

Everything needed to repeat the measurement is stated above rather than shipped:
the Atomic Red Team commit is pinned by hash, the technique and test numbers are
in the matrix, and the host is described in *What was NOT tested*. The two
deviations are the ones marked *(manual)*.

One detail is worth passing on because it costs an afternoon to rediscover: on a
domain member, anything that binds LDAP must run **as SYSTEM**, not as an
interactive administrator. An SSH or RDP session lands on a local account with no
domain credentials, and the bind fails while the network is provably fine — DNS
resolves, the DC answers, port 389 is open. SYSTEM authenticates as the computer
account, which is a domain principal, and is also how an RMM invokes these
scripts. A one-shot scheduled task with `/RU SYSTEM /RL HIGHEST` is enough.
