# Scripts

The scope of this repository: 20 scripts in two layers, plus a third layer that
lives in a separate private repository. This list is the source of truth for
*what gets built*. `docs/DESIGN.md` is the source of truth for
*how*, and `docs/VALIDATION.md` for *what has actually been proven*.

Adding a script to this list, removing one, or changing what one is for is a
scope decision, not a judgement call made while writing code.

The Status column is copied from `docs/VALIDATION.md`, which is the only file
allowed to say where a script has run. All 20 are written and all 20 carry a
dated row: six reached L4 against a real domain controller, twelve L3, and two
L2 because they are read-only and have no `-Apply` to prove. Every script with
an `-Apply` is L3 or better. Read a script's row before deploying it — the row,
not this table, carries the caveats.

Two placements in the list below differ from the original plan, and both are
placements rather than deferrals — the behaviour ships, in a different script.

**Alerting on event 1102 is in `Deploy-TamperAlerts`, not `Protect-EventLogs`.**
`wevtutil cl`, the command that produces 1102, is one of `Deploy-TamperAlerts`'
own stated examples, so the detection sits with the script built for it.
`Protect-EventLogs` still owns the ACLs and retention that make clearing a log
hard in the first place.

**Defender preferences are not in `Enable-IRVisibility`.** They are not registry
state, so tracking and rolling them back needs a change type that script does not
introduce, and folding them in would have tripled its risk for the least central
setting. `Protect-DefenderConfig` covers the exclusion-auditing half; the
forensics preferences are their own increment and are not in v1.0.

## `logging-hardening/` — arm the recorder

Turn on the forensic logging Windows leaves off by default.

| Script | Purpose | Status |
|---|---|---|
| `Enable-IRVisibility.ps1` | Anchor script: ScriptBlock and module logging, PowerShell transcription, command line on 4688, IR audit policy (31 subcategories), event log sizing, firewall logging | **L4** on Server 2019 member + DC |
| `Enable-Sysmon.ps1` | Install and configure Sysmon with a modular config (Olaf Hartong's by default) | **L3** on Server 2019 |
| `Enable-LolbinAudit.ps1` | AppLocker in audit mode, targeted at LOLBins (certutil, mshta, rundll32, …) | **L3** on Server 2019 |
| `Enable-LegacyAuthAudit.ps1` | NTLM auditing plus unsigned-LDAP diagnostics on domain controllers | **L4** on Server 2019 DC |
| `Enable-DnsVisibility.ps1` | DNS client logging, plus DNS debug logging on domain controllers | **L4** on Server 2019 DC |
| `Enable-ServerPrefetch.ps1` | Enable Prefetch on Windows Server, where it is off by default | **L3** on Server 2019 — but the setting does not hold on SSD/NVMe hosts, see VALIDATION.md |
| `Enable-WefClient.ps1` | Windows Event Forwarding, client side — the poor man's SIEM | **L4** on Server 2019 member |
| `Enable-WefCollector.ps1` | Windows Event Forwarding, collector side | **L4** on Server 2019 DC |
| `Set-TimelineIntegrity.ps1` | Enforce NTP, and record timezone and clock skew | **L3** on Server 2019 |
| `Enable-AdObjectAuditing.ps1` | SACLs on AdminSDHolder, GPOs, and the domain controllers OU | **L4** on Server 2019 DC |
| `Enable-UsnJournalTracking.ps1` | Enable and size the USN journal — traces mass renames and deletions | **L3** on Server 2019 |

## `anti-tampering/` — protect the recorder from the crash

Stop an attacker, or a careless technician, from switching the recorder off.

| Script | Purpose | Status |
|---|---|---|
| `Remove-PowerShellV2.ps1` | Remove PowerShell v2 — the classic ScriptBlock logging bypass | **L3** on Server 2019 |
| `Protect-EventLogs.ps1` | Event log ACLs and retention. Alerting on 1102 moved to `Deploy-TamperAlerts` (see note) | **L3** on Server 2019 |
| `Protect-ForensicArtifacts.ps1` | Prevent the silent disabling of Prefetch, SRUM and UserAssist | **L3** on Server 2019 |
| `Enable-VssPreservation.ps1` | VSS shadow storage: the dedicated area a snapshot needs | **L3** on Server 2019 |
| `Enable-VssSnapshotSchedule.ps1` | The scheduled task that takes the snapshots. Split out of `Enable-VssPreservation` on 2026-09-07; arm it AFTER that script | **L3** on Server 2019 |
| `Protect-DefenderConfig.ps1` | The Defender exclusion baseline: diff it, record it, alert on a newly added one | **L3** on Server 2019 |
| `Test-DefenderPosture.ps1` | What Defender is configured to do — running mode, real-time and tamper protection, signature age. Read-only, no `-Apply` at all. Split out of `Protect-DefenderConfig` on 2026-09-07 | **L2** on Server 2019 |
| `Deploy-TamperAlerts.ps1` | Detect destruction commands (`vssadmin delete shadows`, `wevtutil cl`, …) — the ransomware signal thirty seconds ahead | **L3** on Server 2019 |
| `Test-VisibilityDrift.ps1` | **Flagship.** Compare current host state against the manifest and flag what has been turned off | **L2** on Server 2019 (read-only, so L3 n/a) |

## `ir-collection/` — read the recorder after the crash

**Not in this repository.** The ten read-only collectors live in
[`Secur01/IronBlackBox-IR`](https://github.com/Secur01/IronBlackBox-IR), which
stays private. Publishing a collector set publishes the hunt plan, which is
worth more to an attacker than to a defender.

## Order of deployment

Nothing here depends on another script having run first — each one reads the
host, decides, and records its own changes. Four orderings still matter, and
`docs/DEPLOYMENT.md` section 3 is the fuller account of them.

1. **`Enable-IRVisibility` first.** It is what the rest is protecting. A host
   that has not been armed has nothing for `anti-tampering/` to defend and
   nothing for `Test-VisibilityDrift` to compare against.
2. **`Enable-WefCollector` before `Enable-WefClient`.** The collector runs on the
   collector host and the client on every source, and the collector has to be
   initialised before a source can reach it.
3. **`Enable-VssPreservation` before `Enable-VssSnapshotSchedule`.** The second
   registers the task that writes into the storage area the first arranges. A
   task armed with no storage area fails every snapshot while looking correctly
   configured.
4. **`Test-VisibilityDrift` last, and then on a schedule.** It reads the
   manifest every other script writes, so it is only as complete as the runs
   that came before it.

## What the lab could not prove

- **Client SKU behaviour, now measured twice.** Windows 11 Pro build 26200 was
  measured on 2026-09-09 as a workgroup client and on 2026-09-10 as a domain
  member — the per-script outcome for each is in `docs/VALIDATION.md` and is
  deliberately not restated here, because a copied count is how this file came
  to disagree with it. Between them the two passes found four defects, including
  `Remove-PowerShellV2` reporting a PSv2 bypass that does not exist on that
  build and `Enable-VssPreservation` exiting 2 for a capability a client SKU does
  not have. Four *effects* were observed rather than only the writes — 4104, a
  transcript, a 4688 carrying the command line, and an 8003 per LOLBin — and
  Windows Event Forwarding from a client is proven end to end, 221 events on the
  collector. Older Windows 11 builds remain unmeasured, and an MSP fleet holds
  several. **Windows 10 is out of scope** — end of support was October 2025 and
  this project does not measure it, which is a decision rather than a gap.
- **Prefetch on fast media.** `Enable-ServerPrefetch` writes the setting
  correctly and the host removes it again minutes later on an NVMe system
  volume. The mechanics are proven; the outcome is not. Its row explains what
  was measured.
