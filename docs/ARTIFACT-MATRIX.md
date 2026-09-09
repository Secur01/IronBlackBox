# Artifact matrix

One row per forensic artifact, and what this toolkit does about it: turns it on,
keeps it on, or reads it back after the incident.

The point of reading it as a grid is the gaps. An artifact that is armed but not
protected is one `reg delete` away from gone. One that is protected but not
collected is evidence nobody retrieves.

Rows come from the scripts themselves — each script's own sections and change
records — not from a wish list. Where a row says a script cannot do something,
that limitation is stated in the script too.

## A note on the event IDs in this table

An ID appears here only where this project has grounds for it: a row in
`verification/facts.json`, an event observed during validation and recorded in
`docs/VALIDATION.md`, or a channel and ID pair that a script reads in its own
code. Where the grounds were only recollection, the row names the **channel or
the audit subcategory** instead — those come from the scripts themselves.

Seven IDs were removed from an earlier draft of this table for exactly that
reason — 1149 and 21/24/25 from the RDP rows, and 4722, 4732 and 4769 from the
logon and Kerberos rows. They may well be right; they were not checked, and a
matrix that mixes measured IDs with remembered ones is worth less than one that
mixes none.

## How to read the columns

| Column | Means |
|---|---|
| **Armed by** | the script that turns the artifact on, or sizes it so it holds useful history |
| **Protected by** | the script that notices, and where it can reverses, the artifact being switched back off |
| **Collected** | whether the private `IronBlackBox-IR` half retrieves it during an incident |

**The Collected column is deliberately a yes or a no and not a script name.**
Which collector reads which artifact, in what order, is the hunt plan — that is
the reason the collection half stays private, and naming the mapping here would
publish it a column at a time.

## Execution and process history

| Artifact | Armed by | Protected by | Collected |
|---|---|---|---|
| Process creation with full command line (4688) | `Enable-IRVisibility` | `Test-VisibilityDrift` | yes |
| PowerShell script block logging (4104) | `Enable-IRVisibility` | `Remove-PowerShellV2`, `Test-VisibilityDrift` | yes |
| PowerShell module logging (4103) | `Enable-IRVisibility` | `Test-VisibilityDrift` | yes |
| PowerShell transcripts | `Enable-IRVisibility` | `Test-VisibilityDrift` | yes |
| Sysmon process, network and image-load events | `Enable-Sysmon` | `Test-VisibilityDrift` | yes |
| Prefetch (`.pf`) | `Enable-ServerPrefetch` | `Protect-ForensicArtifacts` | yes |
| SRUM — per-process resource and network usage | — *(on by default)* | `Protect-ForensicArtifacts` | yes |
| UserAssist — per-user GUI execution | — *(on by default)* | `Protect-ForensicArtifacts` | yes |
| AppLocker audit-mode events (8003) over LOLBins | `Enable-LolbinAudit` | `Test-VisibilityDrift` | yes |

**PowerShell v2 is the hole in the first four rows.** `powershell -Version 2`
runs code that script block logging never sees, which is why removing the engine
is an anti-tampering job and not a nice-to-have.

**Prefetch does not hold on fast media.** Measured: `EnablePrefetcher` is
written, survives a reboot, and Windows removes it again minutes into normal
operation on an NVMe host. Both scripts report that as a host limit rather than
an alert, and it means execution history on a modern server usually comes from
4688 and Sysmon instead.

## Authentication and lateral movement

| Artifact | Armed by | Protected by | Collected |
|---|---|---|---|
| Logon and account events (4624, 4625, 4720) | `Enable-IRVisibility` *(audit policy: Logon, Special Logon, Account Lockout, User/Computer/Other Account Management)* | `Test-VisibilityDrift` | yes |
| NTLM authentication auditing | `Enable-LegacyAuthAudit` *(DC)* | `Test-VisibilityDrift` | yes |
| Unsigned-LDAP diagnostics (2886, 2889) | `Enable-LegacyAuthAudit` *(DC)* | `Test-VisibilityDrift` | yes |
| RDP session history *(`TerminalServices-LocalSessionManager`)* | `Enable-IRVisibility` *(sizing)* | `Test-VisibilityDrift` | yes |
| RDP connection history *(`TerminalServices-RemoteConnectionManager`)* | `Enable-IRVisibility` *(sizing)* | `Test-VisibilityDrift` | yes |
| SMB client security events | `Enable-IRVisibility` *(sizing)* | `Test-VisibilityDrift` | yes |
| SMB server security and audit events | `Enable-IRVisibility` *(sizing)* | `Test-VisibilityDrift` | yes |
| Kerberos authentication and service tickets | `Enable-IRVisibility` *(audit policy, DC-scoped: Kerberos Authentication Service, Kerberos Service Ticket Operations)* | `Test-VisibilityDrift` | yes |

`Enable-LegacyAuthAudit` is **audit-only with no enforcement switch, not even an
optional one**. Restricting NTLM or requiring LDAP signing on a live domain
breaks authentication for file shares, line-of-business apps, appliances and
backup agents. That decision is not one a hardening script gets to make.

## Directory and privilege

| Artifact | Armed by | Protected by | Collected |
|---|---|---|---|
| AdminSDHolder SACL (4662, 5136) | `Enable-AdObjectAuditing` *(DC)* | `Test-VisibilityDrift` | yes |
| Group Policy object SACLs | `Enable-AdObjectAuditing` *(DC)* | `Test-VisibilityDrift` | yes |
| Domain Controllers OU SACL | `Enable-AdObjectAuditing` *(DC)* | `Test-VisibilityDrift` | yes |
| Audit policy itself (4719 on change) | `Enable-IRVisibility` | `Deploy-TamperAlerts`, `Test-VisibilityDrift` | yes |

`Enable-AdObjectAuditing` **never touches a DACL** — only the audit ACE — and it
proves it did not. Widening a DACL on AdminSDHolder would be a domain compromise
delivered by a hardening tool.

## Filesystem and destruction

| Artifact | Armed by | Protected by | Collected |
|---|---|---|---|
| NTFS USN change journal | `Enable-UsnJournalTracking` | `Test-VisibilityDrift` | yes |
| NTFS last-access timestamps | `Protect-ForensicArtifacts` *(`-EnableLastAccessUpdates`)* | `Protect-ForensicArtifacts` | yes |
| Volume shadow copies | `Enable-VssPreservation` *(storage area)* + `Enable-VssSnapshotSchedule` *(the scheduled snapshot, and it must run second — see `docs/DEPLOYMENT.md` §3)* | `Enable-VssPreservation`, `Deploy-TamperAlerts` | yes |
| Recycle Bin contents | — | `Protect-ForensicArtifacts` *(reports only)* | yes |
| Shadow-copy deletion attempts (`vssadmin delete shadows`, WMI equivalents) | `Enable-IRVisibility` *(4688 command line)* | `Deploy-TamperAlerts` | yes |

**Enlarging a USN journal is irreversible on this OS.** Measured, and the script
says so rather than reporting a successful restore it did not perform.

## The log store itself

| Artifact | Armed by | Protected by | Collected |
|---|---|---|---|
| Event log capacity (Security, Application, System) | `Enable-IRVisibility` | `Protect-EventLogs`, `Test-VisibilityDrift` | yes |
| PowerShell channel capacity | `Enable-IRVisibility` | `Test-VisibilityDrift` | yes |
| Who can clear each log | — | `Protect-EventLogs` *(reports; removes the Administrators CLEAR right only with `-RemoveAdminClear`)* | yes |
| Log retention and archiving | `Protect-EventLogs` | `Test-VisibilityDrift` | yes |
| Log clearing (1102, 104) | `Enable-IRVisibility` *(audit policy)* | `Deploy-TamperAlerts` | yes |
| Forwarded copies on a second host | `Enable-WefClient`, `Enable-WefCollector` | `Test-VisibilityDrift` | yes |

**Forwarding is the only row that survives the host.** Everything else in this
table lives on the machine an attacker is standing on. If one thing here is worth
the deployment effort on a fleet you would have to investigate, it is WEF.

## Network and name resolution

| Artifact | Armed by | Protected by | Collected |
|---|---|---|---|
| DNS client query log | `Enable-DnsVisibility` | `Test-VisibilityDrift` | yes |
| DNS server debug log | `Enable-DnsVisibility` *(DC, `-IncludeDnsServerDebugLog`)* | `Test-VisibilityDrift` | yes |
| Firewall connection logging | `Enable-IRVisibility` | `Test-VisibilityDrift` | yes |

The DNS server debug log is opt-in because it is high volume and is a per-host
decision, not a fleet default.

## Endpoint protection posture

| Artifact | Armed by | Protected by | Collected |
|---|---|---|---|
| Defender exclusion list | — | `Protect-DefenderConfig` *(baseline and diff)* | yes |
| Defender configuration change events (5007) | — *(on by default)* | `Deploy-TamperAlerts` | yes |
| Defender tamper protection state | — *(needs Intune or Defender for Endpoint)* | `Test-DefenderPosture` *(reports as a host limit)* | yes |
| Defender running/protecting state (`AMRunningMode`, `RealTimeProtectionEnabled`, signature age) | — *(Defender's own, not this toolkit's to set)* | `Test-DefenderPosture` | yes |

`Protect-DefenderConfig` **refuses to absorb an exclusion that appeared since its
baseline**. Quietly updating the baseline would make the next run report the host
clean, which is how a tamper detector becomes decoration.

The exclusion baseline and the running state have been two scripts, on purpose,
since 2026-09-07: `Protect-DefenderConfig` owns the recorded exclusion baseline and the alert on a
new exclusion, and `Test-DefenderPosture` owns whether Defender is present,
running and protecting. **Schedule both.** A monitor watching only the first does
not start erroring on a host whose real-time protection was switched off — it
returns `0`, because the script it is watching no longer looks. `docs/DEPLOYMENT.md`
§2 carries the migration note.

## Timeline

| Artifact | Armed by | Protected by | Collected |
|---|---|---|---|
| Time synchronisation source | `Set-TimelineIntegrity` | `Test-VisibilityDrift` | yes |
| Recorded timezone and clock offset | `Set-TimelineIntegrity` | — *(a record, not a setting)* | yes |

Every artifact above is timestamped by this host's clock. A free-running clock
does not stop the collection working — it stops the timeline correlating with
anything else, which is most of what an investigation is.

## Where the gaps are

Read as a grid, three rows have no **Armed by** and are on only because Windows
ships them that way: SRUM, UserAssist, and Defender's own event channel. Nothing
in this toolkit turns them on, so nothing in this toolkit will notice if a future
Windows default turns them off. They are audited, not armed.

**The lateral-movement gap this grid exposed is half closed, and the half that
is left is worth knowing.** Reading the table as a grid is what found it: the RDP
and SMB channels had nothing in *either* column. Both carry lateral movement,
both are on by default, and both ship tiny — measured on Server 2019, 1 MB for
each RDP channel and 8 MB for each SMB channel, against the 2 GB this toolkit
gives the Security log.

**Armed, now.** `Enable-IRVisibility` sizes all five through
`-LateralMovementChannelSizeBytes`, default 64 MB, and `Test-VisibilityDrift`
sees them, because a sized channel is recorded like any other change.

**Not protected the way the three classic logs are.** `Protect-EventLogs` writes
retention through the EventLog *policy*, and that policy does not reach a modern
channel. Measured: passing one to its `-Channels` used to report "2 change(s)
applied" while the channel's retention did not move — that is now refused with
the reason, rather than reported as a success. So these five get capacity and
drift detection, and they do not get archive-on-full. No mechanism this project
knows of gives a modern channel that.

**And the event rate is not measured.** This lab is driven over SSH and serves no
files, so the five channels held 1, 3, 0, 0 and 0 events. How long 1 MB of RDP
history lasts on a host people actually connect to is unknown here. The 64 MB
default is justified by a circular log's ceiling being cheap, not by an observed
rate. On a busy file server, measure first.

One row has no **Protected by**: the timezone and skew record, because it is a
record this toolkit wrote rather than a host setting that can drift.

And `Test-VisibilityDrift` appears in the Protected column more than anything
else, which is the honest shape of the toolkit: most protection here is
*detection* of tampering, reported to an RMM, rather than prevention. Preventing
an administrator from turning off their own logging is not something a script can
do — noticing within a scheduled run is.
