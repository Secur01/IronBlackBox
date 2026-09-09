<#
.SYNOPSIS
    Turns on NTLM authentication auditing and unsigned-LDAP diagnostics on a
    domain controller, and reports who is still using them. AUDIT ONLY.

.DESCRIPTION
    docs/VALIDATION.md is the only file allowed to say where this script has
    run; read its row before deploying. Facts that could not be cited to
    learn.microsoft.com are still marked "# UNVERIFIED:" in the code with what
    needs checking - those markers are per-fact and do not clear just because
    the script as a whole has been exercised.

    AUDIT ONLY, BY DESIGN, WITH NO ENFORCEMENT SWITCHES - NOT EVEN OPTIONAL
    ONES. Restricting NTLM or requiring LDAP signing on a live domain breaks
    authentication for everything still using them: file shares, old
    line-of-business apps, appliances, scanners, backup agents. That decision
    belongs to the MSP after reading a month of audit data, and a script must
    not offer to make it. There is no -Enforce, no -RestrictNtlm and no
    -RequireLdapSigning; adding one is a change to docs/DESIGN.md section 7
    first. The distinction is enforced in code and not only in this comment:
    Assert-AuditOnlyTarget refuses any write outside an allow-list of three
    audit values, and refuses every enforcement value by name.

    On a domain controller, and nowhere else, it sets the two NTLM AUDIT values
    so the DC records which accounts and clients still use NTLM; enables and
    sizes the Microsoft-Windows-NTLM/Operational channel those events land in;
    raises "16 LDAP Interface Events" to level 2, which makes the DC log event
    2889 naming each client that binds without signing; and reports, read-only,
    the NTLM restriction values, LDAPServerIntegrity, LdapEnforceChannelBinding,
    LmCompatibilityLevel, the channel state and a summary of events 2889 (by
    client IP and account) and 8001-8004. That 2889 summary is the deliverable:
    it is the list an MSP works through before it can require LDAP signing.

    What this script deliberately does NOT do:
      - restrict NTLM in any direction, for any account scope (see above);
      - set LDAPServerIntegrity or LdapEnforceChannelBinding - both are read and
        reported, and changing either is the action that breaks clients;
      - change LmCompatibilityLevel: forcing NTLMv2-only has the same blast
        radius as restricting NTLM;
      - touch member servers or clients. Auditing incoming NTLM is useful there
        too, but this is scoped to DCs and exits 0 elsewhere rather than
        half-covering a fleet;
      - configure the NTLM exception lists, which matter only under enforcement;
      - collect the audited events. That is Invoke-TriageCollection's job.

.PARAMETER Audit
    Default. Strictly read-only. Reports current state and what -Apply would do.

.PARAMETER Apply
    Writes the audit values, recording each previous value to the manifest first.

.PARAMETER Rollback
    Restores the previous values recorded by a prior -Apply, event channel
    included.

.PARAMETER ToolkitRoot
    Base directory for the manifest. Default C:\ProgramData\IronBlackBox.
    Validated before use - see Assert-SafeToolkitPath.

.PARAMETER DomainAuditValue
    Value written to AuditNTLMInDomain; default 7, intended as the policy's
    "Enable all". # UNVERIFIED: the option-to-number mapping is not published on
    learn.microsoft.com. A wrong value audits less than intended; it cannot
    block authentication, because this value enforces nothing.

.PARAMETER IncomingAuditValue
    Value written to AuditReceivingNTLMTraffic; default 2, intended as "Enable
    auditing for all accounts". # UNVERIFIED, same caveat.

.PARAMETER NtlmChannelSizeKb
    Target size of the NTLM operational channel in kilobytes, default 65536
    (64 MB). NTLM audit events are one per authentication, so the shipped
    channel size does not hold a month of them on a busy DC.

.PARAMETER MinimumFreeDiskPercent
    Floor, as a percentage of the volume, that the worst-case growth authorised
    by -NtlmChannelSizeKb must leave free. Default 10. Measured on the volume
    the channel's .evtx actually lives on, which is not necessarily C: - see
    Set-TrackedEventChannel. A channel that would breach the floor is reported
    and left alone rather than sized.

.PARAMETER LookbackDays
    How far back to summarise events 2889 and 8001-8004. Default 30.

.PARAMETER MaxEventScanned
    Hard cap on records read per query, so this never walks a multi-gigabyte
    channel. Default 20000.

.PARAMETER RunId
    -Rollback only. The run to roll back. Defaults to the most recent
    rollback-eligible run for this script.
.PARAMETER AbandonRun
    -Rollback only, and it names a run id rather than being a switch. Stops
    trying to roll back that run, on the record.

    It rolls back everything it still can, then writes a manifest record saying
    an operator chose to give up on the rest, naming every change abandoned. It
    does NOT touch the host and does NOT pretend anything was undone - whatever
    those changes left behind stays exactly where it is.

    What it costs: Test-VisibilityDrift stops reporting the abandoned changes,
    because the run leaves the eligible set. If one of them is a setting an
    attacker switched off, this is you choosing not to be told about it again.

    Use it when a rollback declines forever because the host holds neither what
    the run set nor what it recorded - which happens when a LATER run of the same
    script changed that value. Without this, such a run stays eligible
    indefinitely and blocks -Rollback from reaching anything older.

.EXAMPLE
    .\Enable-LegacyAuthAudit.ps1
    Reports what is missing and summarises the legacy authentication already in
    the logs. Changes nothing.

.EXAMPLE
    .\Enable-LegacyAuthAudit.ps1 -Apply
    Turns the auditing on and records every previous value.

.EXAMPLE
    .\Enable-LegacyAuthAudit.ps1 -Rollback
    Puts the audit values and the event channel back as they were.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.0.1
    License : MIT

    Windows PowerShell 5.1. No module dependencies. Requires local
    administrator; enforced in code by Assert-Elevated, deliberately not by
    #Requires -RunAsAdministrator (see docs/DESIGN.md section 3).

    Exit codes: 0 clean or not applicable here, 1 findings, 2 execution error.
    A host that is not a domain controller is 0 with a clear message - not a
    finding, not an error. Legacy authentication FOUND in the logs is a finding
    (exit 1) even after a successful -Apply: it is what the MSP has to act on.
#>

[CmdletBinding(DefaultParameterSetName = 'Audit')]
param(
    [Parameter(ParameterSetName = 'Audit')]
    [switch] $Audit,

    [Parameter(ParameterSetName = 'Apply', Mandatory = $true)]
    [switch] $Apply,

    [Parameter(ParameterSetName = 'Rollback', Mandatory = $true)]
    [switch] $Rollback,

    [Parameter()]
    [string] $ToolkitRoot = 'C:\ProgramData\IronBlackBox',

    [Parameter()]
    [int] $DomainAuditValue = 7,

    [Parameter()]
    [int] $IncomingAuditValue = 2,

    [Parameter()]
    [int] $NtlmChannelSizeKb = 65536,

    [Parameter()]
    [int] $MinimumFreeDiskPercent = 10,

    [Parameter()]
    [int] $LookbackDays = 30,

    [Parameter()]
    [int] $MaxEventScanned = 20000,

    [Parameter(ParameterSetName = 'Rollback')]
    [string] $RunId,

    # See Invoke-AbandonRun for what this does and what it costs. Deliberately
    # not a switch: abandoning requires naming the run, so it can never be the
    # accidental consequence of a habitual command line.
    [Parameter(ParameterSetName = 'Rollback')]
    [string] $AbandonRun
)

$ErrorActionPreference = 'Stop'
# Version 1.0, not 2.0: 2.0 also throws on a non-existent property, and the
# manifest records read back from JSON legitimately carry different property
# sets per recordType. Catching typo'd variables is the win worth having here.
Set-StrictMode -Version 1.0

# P-1: the arguments the operator actually supplied, captured at SCRIPT scope.
# Read by Test-ParameterSupplied so the body-level parameter checks validate
# exactly what [Validate*] attributes used to - supplied values only. Inside a
# function $PSBoundParameters is that function's own, so it cannot be read there.
$script:SuppliedParameter = $PSBoundParameters

$script:ScriptName    = 'Enable-LegacyAuthAudit'
$script:ScriptVersion = '1.0.1'

# Populated by Initialize-ToolkitRoot / Start-ManifestRun.
$script:ManifestPath = $null
$script:CurrentRunId        = $null
$script:ChangeIndex  = 0
$script:Findings     = New-Object System.Collections.ArrayList
# Conditions that are true, worth printing, and that no -Apply of this script will
# clear on THIS host. Counted separately from findings and deliberately kept out
# of the exit code - see Write-HostLimit.
$script:HostLimits   = New-Object System.Collections.ArrayList
$script:LockHandle   = $null

#region Output ---------------------------------------------------------------

# [AllowEmptyString()] on all of these, and not Mandatory. These are called
# from the outermost catch with $_.Exception.Message, which can be empty: a
# Mandatory [string] refuses an empty value with a binding exception thrown
# INSIDE the catch, so the 'exit 2' below it never runs and powershell.exe
# returns host code 1 instead — read by an RMM as "findings", the exact
# collision docs/DESIGN.md section 3 exists to prevent.

function Write-Section {
    param([Parameter()][AllowEmptyString()][string] $Text = '')
    Write-Host ''
    Write-Host ('== ' + $Text + ' ') -ForegroundColor Cyan
}

function Write-Ok {
    param([Parameter()][AllowEmptyString()][string] $Text = '')
    Write-Host ('  [ ok ] ' + $Text) -ForegroundColor Green
}

function Write-Finding {
    param([Parameter()][AllowEmptyString()][string] $Text = '')
    [void] $script:Findings.Add($Text)
    Write-Host ('  [find] ' + $Text) -ForegroundColor Yellow
}

function Write-HostLimit {
    <#
        A condition that is TRUE, worth printing, and that NO -Apply of this
        script - with any parameters, on any number of runs - will clear on this
        host.

        THE TEST IS NOT SEVERITY, IT IS WHETHER A LEVER EXISTS. Is there a switch
        to pass, a file to stage, a second run to make? Then it is a finding and
        it belongs in the exit code: "Sysmon is not installed" clears once an
        operator stages the binary, and "not changed without -Force" clears once
        they pass -Force. Those SHOULD be exit 1 until someone acts.

        A host limit is different in kind. Tamper protection cannot be turned on
        without Intune, and no run of this toolkit will ever report otherwise on a
        host that does not have it. If that raised exit 1, an RMM monitor built
        on this toolkit's documented exit codes would be red on that host
        forever - and a monitor that is always red gets muted, which costs the
        operator every OTHER finding this toolkit would have raised. The steady
        state of a healthy armed fleet has to be 0, or the signal is worthless.

        So a host limit prints as [limit], is counted separately in the result,
        and does not touch the exit code. The information is not hidden; it is
        just not an alarm.
    #>
    param([Parameter()][AllowEmptyString()][string] $Text = '')
    [void] $script:HostLimits.Add($Text)
    Write-Host ('  [limit] ' + $Text) -ForegroundColor DarkYellow
}

function Write-Failure {
    param([Parameter()][AllowEmptyString()][string] $Text = '')
    Write-Host ('  [FAIL] ' + $Text) -ForegroundColor Red
}

function Write-Info {
    param([Parameter()][AllowEmptyString()][string] $Text = '')
    Write-Host ('  ' + $Text) -ForegroundColor Gray
}

function Get-UtcStamp {
    # InvariantCulture is required, not cosmetic. In a CUSTOM format string ':'
    # is the culture's time separator placeholder, so on fi-FI this renders
    # 20.08.21 instead of 20:08:21 — every timestamp in a forensic manifest
    # would be non-ISO and unsortable. Verified on this dev box.
    # https://learn.microsoft.com/en-us/dotnet/standard/base-types/custom-date-and-time-format-strings
    return (Get-Date).ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ss.fffZ',
        [System.Globalization.CultureInfo]::InvariantCulture)
}

#endregion

#region Parameter validation -------------------------------------------------

# Value ranges are enforced HERE, not by [ValidateRange]/[ValidateSet]/
# [ValidatePattern]/[ValidateCount] attributes, because a binding-time failure
# never reaches this script: PowerShell rejects the argument and the HOST exits
# 1 - the code docs/DESIGN.md section 3 reserves for "findings", so an RMM
# records drift on a host where nothing ran. Same collision that rules out
# `#Requires -RunAsAdministrator` (see Assert-Elevated). These helpers throw and
# the bottom `catch { exit 2 }` reports it. Three binding failures still exit 1
# and no in-script code can change that - wrong type, unknown parameter,
# ambiguous parameter set; docs/DESIGN.md section 3 carries the measurements and
# the invocation wrapper that closes them.
#
# Call these FIRST in Invoke-Main - before Assert-Elevated, any lock, any host
# access - so a bad argument costs nothing and changes nothing.

function Test-ParameterSupplied {
    <#
        Was this parameter actually given on the command line?

        ONLY SUPPLIED ARGUMENTS ARE CHECKED, because that is what the attributes
        did: [Validate*] runs only when a parameter is BOUND. Several parameters
        are legitimately empty when omitted (-Volume, -RemoveExclusionType), so
        checking unconditionally would reject command lines that work today.

        $script:SuppliedParameter is assigned $PSBoundParameters at SCRIPT scope,
        right after Set-StrictMode. It cannot be read from $PSBoundParameters
        here: inside a function that automatic variable holds the FUNCTION's own
        bound parameters, which for Invoke-Main is always empty.
    #>
    param([Parameter(Mandatory = $true)][string] $Name)
    if ($null -eq $script:SuppliedParameter) { return $true }
    return ([bool] $script:SuppliedParameter.ContainsKey($Name))
}

function Assert-ParameterRange {
    <#
        A numeric parameter inside its documented bounds, or a throw naming the
        parameter, the value and the bounds. Every element is checked, which is
        what the attribute does on an array parameter.

        Comparison is in [double]. Every bound this toolkit uses is well below
        2^53, where double is still exact; a larger bound would need decimal.

        PARSED AS INVARIANT TEXT, WITHOUT GROUP SEPARATORS, and measured because
        every other option silently changes the operator's number. With the
        no-provider overload this used before - ambient culture - '2.5' parses as
        TWENTY-FIVE on de-DE. With InvariantCulture and the default styles, '2,5'
        parses as twenty-five instead. NumberStyles::Float with InvariantCulture
        is the only combination that transforms nothing: it REFUSES '2,5' and
        '1 000' and names them in the throw below, and reads '2.5' as two and a
        half everywhere.

        Not digits-only, which would be simpler: -ShadowStoragePercent and the
        disk-headroom fractions take real bounds like 0.01 and 0.90. A locale
        number that survives this parse as the wrong magnitude - de-DE '2.000'
        meaning two thousand, read as 2 - then fails the range check on the next
        line, which is loud. That is the acceptable failure; a silent factor of
        ten is not.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][AllowNull()] $Value,
        [Parameter(Mandatory = $true)][double] $Minimum,
        [Parameter(Mandatory = $true)][double] $Maximum
    )
    if (-not (Test-ParameterSupplied -Name $Name)) { return }
    foreach ($item in @($Value)) {
        $numeric = 0.0
        if (-not [double]::TryParse([string] $item, [System.Globalization.NumberStyles]::Float,
                [System.Globalization.CultureInfo]::InvariantCulture, [ref] $numeric)) {
            throw ('-' + $Name + ' is "' + [string] $item + '", which is not a number. Expected a ' +
                   'number between ' + [string] $Minimum + ' and ' + [string] $Maximum + '.')
        }
        if ($numeric -lt $Minimum -or $numeric -gt $Maximum) {
            throw ('-' + $Name + ' is ' + [string] $item + ', outside the supported range ' +
                   [string] $Minimum + ' to ' + [string] $Maximum + '. Nothing was read or changed.')
        }
    }
}

function Assert-ParameterSet {
    <#
        A parameter whose value must be one of a fixed list. The throw names the
        list, because the operator cannot see it in the param block any more.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][AllowNull()] $Value,
        [Parameter(Mandatory = $true)][string[]] $Allowed
    )
    if (-not (Test-ParameterSupplied -Name $Name)) { return }
    # Case-INSENSITIVE, matching [ValidateSet]'s own default, so this change
    # cannot reject a command line that used to work.
    foreach ($item in @($Value)) {
        $matched = $false
        foreach ($candidate in $Allowed) {
            if ([string]::Equals([string] $item, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
                $matched = $true
                break
            }
        }
        if (-not $matched) {
            throw ('-' + $Name + ' is "' + [string] $item + '", which is not one of: ' +
                   ($Allowed -join ', ') + '. Nothing was read or changed.')
        }
    }
}

function Assert-ParameterPattern {
    <#
        A parameter that must match a shape. -Describe carries that shape in
        words: an MSP reading an RMM log should not have to read a regex.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][AllowNull()] $Value,
        [Parameter(Mandatory = $true)][string] $Pattern,
        [Parameter(Mandatory = $true)][string] $Describe
    )
    if (-not (Test-ParameterSupplied -Name $Name)) { return }
    foreach ($item in @($Value)) {
        if ([string] $item -notmatch $Pattern) {
            throw ('-' + $Name + ' is "' + [string] $item + '", which is not ' + $Describe +
                   '. Nothing was read or changed.')
        }
    }
}

function Assert-ParameterCount {
    <#
        An array parameter with a bounded element count.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()] $Value,
        [Parameter(Mandatory = $true)][int] $Minimum,
        [Parameter(Mandatory = $true)][int] $Maximum
    )
    if (-not (Test-ParameterSupplied -Name $Name)) { return }
    $count = 0
    if ($null -ne $Value) { $count = @($Value).Count }
    if ($count -lt $Minimum -or $count -gt $Maximum) {
        throw ('-' + $Name + ' was given ' + [string] $count + ' value(s); this script accepts ' +
               [string] $Minimum + ' to ' + [string] $Maximum + '. Nothing was read or changed.')
    }
}

function Assert-ParameterNotEmpty {
    <#
        A parameter that must carry something when it is supplied. Replaces
        [ValidateNotNullOrEmpty()].
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][AllowEmptyCollection()] $Value
    )
    if (-not (Test-ParameterSupplied -Name $Name)) { return }
    $empty = $false
    if ($null -eq $Value) { $empty = $true }
    elseif ($Value -is [string]) { $empty = [string]::IsNullOrWhiteSpace($Value) }
    elseif ($Value -is [System.Array]) { $empty = (@($Value).Count -eq 0) }
    if ($empty) {
        throw ('-' + $Name + ' was supplied with no value. Nothing was read or changed.')
    }
}

#endregion

#region Elevation and path safety --------------------------------------------

function Assert-Elevated {
    # Not #Requires -RunAsAdministrator: that aborts before this script's own
    # code and returns host exit code 1, which collides with "findings".
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $principal.IsInRole($adminRole)) {
        Write-Failure 'Administrator rights are required. Nothing was read or changed.'
        exit 2
    }
}

function Assert-SafeToolkitPath {
    <#
        -ToolkitRoot decides which directory gets its ACEs stripped, its
        inheritance disabled and its ownership reassigned. C:\ or C:\Windows —
        a typo, or an RMM variable that expanded to nothing — is an
        unrecoverable outage delivered by the hardening script itself.

        Returns the canonical path, or throws.
    #>
    param([Parameter(Mandatory = $true)][string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'ToolkitRoot is empty.'
    }

    # Reject before canonicalising: GetFullPath resolves a drive-relative path
    # ('C:foo', and bare 'C:') against the process working directory, silently
    # producing something the operator never typed.
    #
    # The '^[A-Za-z]:$' arm is not redundant: '[^\\/]' requires a character
    # after the colon, so a bare 'C:' slipped through. An RMM variable that
    # collapses to 'C:' would then resolve to the agent's own working
    # directory — and the toolkit would strip the ACEs off it and reassign
    # its owner, locking the RMM out of its own working directory. Verified
    # on this dev box: 'C:' does not match the original pattern.
    if ($Path -match '^[A-Za-z]:$' -or $Path -match '^[A-Za-z]:[^\\/]') {
        throw ('ToolkitRoot is drive-relative and ambiguous: ' + $Path)
    }
    if ($Path -match '^\\\\') {
        throw ('ToolkitRoot must be a local path, not a UNC path: ' + $Path)
    }

    # 8.3 short names are NOT normalised by GetFullPath — proven on the lab
    # (Windows Server 2019): 'C:\PROGRA~1\x' comes back unchanged. So
    # 'C:\PROGRA~1\ibb' would sail past the protected-directory list below,
    # which compares against 'C:\Program Files' as a string. Rejected outright
    # rather than expanded: there is no legitimate reason to hand this toolkit
    # a short-name path, and rejecting is safer than resolving.
    if ($Path -match '~\d') {
        throw ('ToolkitRoot must not use an 8.3 short name; give the full path: ' + $Path)
    }

    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')

    if (-not [System.IO.Path]::IsPathRooted($full)) {
        throw ('ToolkitRoot is not rooted: ' + $Path)
    }

    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.Length -le $root.TrimEnd('\').Length) {
        throw ('ToolkitRoot must not be a volume root: ' + $full)
    }

    # At least two levels below the volume root: C:\Foo is one bad rmdir away
    # from being indistinguishable from a system-managed directory.
    $relative = $full.Substring($root.Length).Trim('\')
    if ($relative.Split('\').Count -lt 2) {
        throw ('ToolkitRoot must be at least two levels below the volume root: ' + $full)
    }

    # The volume must be a local fixed disk. docs/DESIGN.md section 5 claims
    # the path is "local" but only UNC was rejected, so a mapped network drive
    # (Z:\ after 'net use') or a subst'ed drive passed. Both are real problems:
    # rollback data for a domain controller living on a file server is
    # unreachable exactly when the file server is the thing that broke, and
    # FileStream.Flush($true) over SMB does not give the commit-to-device
    # guarantee section 4 depends on. A subst drive additionally defeats the
    # protected-directory list below, since its root reports as its own volume.
    $driveInfo = New-Object System.IO.DriveInfo($root)
    if ($driveInfo.DriveType -ne [System.IO.DriveType]::Fixed) {
        throw ('ToolkitRoot must be on a local fixed disk; ' + $root +
               ' is ' + $driveInfo.DriveType + ': ' + $full)
    }

    # Never a system directory, never an ancestor of one, and never INSIDE one.
    #
    # Derived from environment variables rather than Environment.GetFolderPath:
    # GetFolderPath is redirected under WOW64, so a 32-bit host (RMMs do launch
    # SysWOW64\powershell.exe) resolves 'System' to SysWOW64 and 'ProgramFiles'
    # to Program Files (x86) — which would drop the real System32 out of a
    # security deny-list. Building a deny-list from an API whose result depends
    # on the calling process's bitness is a structural defect regardless of
    # what the lab says about the exact values.
    $systemRoot = $env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($systemRoot)) { $systemRoot = 'C:\Windows' }
    $systemRoot = $systemRoot.TrimEnd('\')
    $systemDrive = $env:SystemDrive
    if ([string]::IsNullOrWhiteSpace($systemDrive)) { $systemDrive = 'C:' }
    $systemDrive = $systemDrive.TrimEnd('\')

    $protected = @(
        $systemRoot,
        ($systemRoot + '\System32'),
        ($systemRoot + '\SysWOW64'),
        ($systemRoot + '\WinSxS'),
        ($systemDrive + '\Program Files'),
        ($systemDrive + '\Program Files (x86)'),
        ($systemDrive + '\Users'),
        ($systemDrive + '\ProgramData')
    )

    foreach ($dir in $protected) {
        $candidate = $dir.TrimEnd('\')
        if ($full -eq $candidate) {
            throw ('ToolkitRoot must not be a system directory: ' + $full)
        }
        if ($candidate.StartsWith($full + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ('ToolkitRoot must not be an ancestor of the system directory ' + $candidate + ': ' + $full)
        }
    }

    # Being INSIDE a system directory was never checked, so C:\Windows\Temp\ibb
    # and C:\Windows\System32\ibb were both accepted. The ACL damage is bounded
    # to the created leaf, but the manifest — the rollback data — would live
    # somewhere EDRs and cleanup tooling treat specially.
    #
    # ProgramData is the deliberate exception: it is the documented home for
    # per-machine application state and the toolkit's own default root lives
    # there. It stays in the list above so it cannot be targeted directly or
    # as an ancestor, but a subdirectory of it is exactly right.
    $programData = ($systemDrive + '\ProgramData')
    foreach ($dir in $protected) {
        $candidate = $dir.TrimEnd('\')
        if ($candidate -eq $programData) { continue }
        if ($full.StartsWith($candidate + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ('ToolkitRoot must not be inside the system directory ' + $candidate + ': ' + $full)
        }
    }

    # Reparse points anywhere along the path defeat every check above: the ACL
    # would land on the target, not on what the operator named.
    $walk = $full
    while (-not [string]::IsNullOrEmpty($walk) -and $walk.Length -gt $root.TrimEnd('\').Length) {
        if (Test-Path -LiteralPath $walk) {
            $item = Get-Item -LiteralPath $walk -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('ToolkitRoot path crosses a reparse point at ' + $walk)
            }
        }
        $walk = [System.IO.Path]::GetDirectoryName($walk)
        if ($null -eq $walk) { break }
        $walk = $walk.TrimEnd('\')
    }

    return $full
}

#endregion

#region Native commands ------------------------------------------------------

function Get-NativeToolPath {
    <#
        An absolute path to an in-box tool, or the bare file name when no
        expected location holds it.

        WHY NOT THE BARE NAME. `& 'fsutil.exe'` resolves through PATH, and this
        script runs as SYSTEM. A machine PATH entry an unprivileged user can
        write to - a third-party installer misconfiguration, not a hypothetical -
        would then decide which binary runs with SYSTEM's token.

        The candidate directories are TESTED rather than asserted: this project
        has no learn.microsoft.com citation for where Windows keeps these
        binaries, so a wrong guess must cost nothing. Sysnative and SysWOW64 are
        candidates as well because System32 is redirected for a 32-bit host
        process, and an RMM launching SysWOW64\powershell.exe is how that
        happens here.

        SYSNATIVE IS TESTED FIRST, and the order is load-bearing. Measured on the
        lab, 2026-09-03: from a 64-bit process %SystemRoot%\Sysnative does not
        exist, so this falls through to System32 unchanged; from a 32-bit process
        all three exist. With System32 first, a 32-bit host was therefore served
        the REDIRECTED SysWOW64 copy of every tool and Sysnative was never
        reached - which made the paragraph above describe something the code could
        not do.

        Falling back to the bare name keeps behaviour identical to PATH
        resolution wherever anchoring cannot be done, so this hardens the normal
        host without turning an unusual layout into a missing tool. Pass
        -RequireAnchored to refuse that fallback.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $FileName,
        # Returns $null instead of the bare name. For callers where the tool's
        # ABSENCE is itself the answer - DNS role detection turns on whether
        # dnscmd.exe exists - the fallback is not a graceful degradation: it hands
        # back a name that resolves through PATH, so a planted binary would get to
        # answer a question about which roles this host has installed.
        [switch] $RequireAnchored
    )

    # Empty %SystemRoot% skips the loop and falls through to the finding below,
    # rather than returning the bare name silently as it used to - the docstring's
    # "launched without %SystemRoot%" case is now actually reported.
    $root = $env:SystemRoot
    if (-not [string]::IsNullOrWhiteSpace($root)) {
        foreach ($directory in @('Sysnative', 'System32', 'SysWOW64')) {
            $candidate = [System.IO.Path]::Combine([System.IO.Path]::Combine($root, $directory), $FileName)
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }
    if ($RequireAnchored) { return $null }
    # SAID OUT LOUD, once per tool. Returning the bare name brings back the exact
    # PATH lookup this function exists to remove, and a degradation nobody is told
    # about is one an operator learns of from an incident. For an in-box tool, a
    # System32 that does not hold it is a broken or hostile host rather than an
    # unusual layout - and an empty %SystemRoot% means the RMM launched this with
    # a stripped environment. Both name an action, so both are findings.
    # Test-Path 'variable:...' rather than a bare read: under Set-StrictMode 1.0 a
    # read of $script:UnanchoredTool BEFORE its first assignment throws "cannot be
    # retrieved because it has not been set", which turned this loud finding into a
    # script-terminating crash on exactly the fallback path it exists to report -
    # measured on PS 5.1. This is the idiom $script:ManifestPath already uses.
    if (-not (Test-Path 'variable:script:UnanchoredTool')) { $script:UnanchoredTool = @{} }
    if (-not $script:UnanchoredTool.ContainsKey($FileName)) {
        $script:UnanchoredTool[$FileName] = $true
        Write-Finding ($FileName + ' was not found under %SystemRoot% in Sysnative, System32 or ' +
                       'SysWOW64, so it will be invoked by name and resolved through PATH - the ' +
                       'lookup this toolkit anchors everywhere else. Either this host is missing an ' +
                       'in-box tool or it was launched without %SystemRoot% in its environment.')
    }
    return $FileName
}

function Invoke-NativeCommand {
    <#
        Runs a native executable and returns its output and exit code without
        letting a non-zero exit throw under $ErrorActionPreference = 'Stop'.
        Native stderr is merged so a failure message is not lost.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $FilePath,
        [Parameter(Mandatory = $true)][string[]] $Arguments
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    # AC-1: both of the next two lines could kill the whole script, and did.
    # Seeded so neither leaves $code or $output undefined under StrictMode.
    $code = $null
    $output = @()
    try {
        $output = & $FilePath @Arguments 2>&1
        # NOT `$code = $LASTEXITCODE`. Measured on the lab (PS 5.1): with
        # Set-StrictMode -Version 1.0, reading $LASTEXITCODE before ANY native
        # command has set it throws "The variable '$LASTEXITCODE' cannot be
        # retrieved because it has not been set." Get-Variable returns $null
        # instead of throwing.
        $code = Get-Variable -Name LASTEXITCODE -ValueOnly -ErrorAction SilentlyContinue
    }
    catch {
        # Measured on the lab: a path that is not a valid executable makes `&`
        # raise a TERMINATING error even under $ErrorActionPreference =
        # 'Continue' - "failed to run: The specified executable is not a valid
        # application for this OS platform" - so setting EAP does not contain it
        # and this function had no catch at all. The error escaped to the bottom
        # `catch { exit 2 }`, so a staged-binary check DIED instead of reporting
        # a finding. The launch failure is the useful output here.
        $output = @($_.Exception.Message)
    }
    finally {
        $ErrorActionPreference = $previous
    }
    # No exit code means it never ran. -1, not 0, so every caller that tests
    # `-ne 0` treats "did not launch" as the failure it is.
    if ($null -eq $code) { $code = -1 }
    return [PSCustomObject] @{
        ExitCode = $code
        Output   = @($output | ForEach-Object { [string] $_ })
    }
}

function Get-PowerShellHostPath {
    <#
        Built from %SystemRoot% rather than from $PSHOME so the registered task
        does not inherit the bitness of whatever process created it: an RMM
        launching the SysWOW64 host would otherwise bake the 32-bit engine into a
        task the 64-bit scheduler service runs.

        # UNVERIFIED: the literal path
        # %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe. The caller
        # Test-Path's it before registering anything, so a wrong path is a refusal
        # rather than a task that silently never works.
    #>
    $root = $env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($root)) { $root = 'C:\Windows' }
    return [System.IO.Path]::Combine($root, 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

function ConvertFrom-NativeInteger {
    <#
        An INTEGER out of a native tool's text output: decimal, or hex with an 0x
        prefix, which is how fsutil prints. Returns [long], or $null when the text
        is not a number to trust - and $null means "unknown" at every call site,
        never zero. A zero would read as a real value: "log nothing" for a DNS log
        level, "no journal" for a USN size.

        GROUP SEPARATORS ARE STRIPPED, INCLUDING '.', and that is only safe
        because every value read through here is an integer. On a locale that
        groups with dots, 65.536 is sixty-five thousand and not sixty-five point
        five - so the dot has to go. The same strip applied to a genuinely
        fractional value would silently multiply it, so DO NOT reach for this
        function to read one. There is no fractional native output in this toolkit
        today; if that changes, that caller needs its own parser, not a flag here.

        This replaces ConvertFrom-FsutilNumber and ConvertFrom-NumericToken, which
        were the same function under two names and had already diverged by exactly
        one character: the DNS copy stripped '[\s,]' and not '[\s,\.]', so on a
        dot-grouping locale it returned $null - "unknown" - for a value the USN
        copy read correctly. Nothing compared them, because tools/check.ps1
        compares regions by name and both lived in script-local ones.
    #>
    param([Parameter()][AllowEmptyString()][string] $Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $token = $Text.Trim() -replace '[\s,\.]', ''

    $value = [System.UInt64] 0
    $parsed = $false
    if ($token -match '^0[xX][0-9a-fA-F]+$') {
        $parsed = [System.UInt64]::TryParse($token.Substring(2),
            [System.Globalization.NumberStyles]::HexNumber,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref] $value)
    }
    elseif ($token -match '^[0-9]+$') {
        $parsed = [System.UInt64]::TryParse($token,
            [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref] $value)
    }
    if (-not $parsed) { return $null }
    if ($value -gt ([System.UInt64] [System.Int64]::MaxValue)) { return $null }
    return [System.Int64] $value
}

#endregion

#region Toolkit root ---------------------------------------------------------

function Set-ToolkitRootAcl {
    <#
        The toolkit root's DACL is OWNED by the toolkit, not borrowed from the
        host: inheritance off, SYSTEM and Administrators only, owner reassigned.
        There is deliberately no manifest record and no rollback for it - a
        -Rollback that handed this directory back to an unprivileged creator
        would undo the one control protecting every other recorded change.
    #>
    param([Parameter(Mandatory = $true)][string] $Path)

    # Well-known SIDs, not names: BUILTIN\Administrators is "Administrateurs"
    # on fr-FR Windows, a real deployment target.
    # https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited ACEs
    $acl.SetOwner($adminsSid)

    foreach ($sid in @($systemSid, $adminsSid)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
             [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }

    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-ToolkitRootAclProblem {
    <#
        The invariant the toolkit root must hold, expressed as PROPERTIES rather
        than as equality against one expected SDDL: inheritance disabled, owned
        by SYSTEM or Administrators, and no other principal able to write, delete
        or re-permission anything inside it.

        Property-based on purpose. An administrator who grants a backup agent
        READ access has not created a privilege-escalation path, and a check that
        re-wrote the DACL on every run to undo their deliberate change is exactly
        the churn the previous design was right to avoid. Write access is a
        different thing: it puts the manifest that -Rollback trusts, and the
        handler scripts a SYSTEM scheduled task executes, under someone else's
        control. So this reports what is merely non-standard and repairs only
        what is dangerous.

        Returns $null when the root is safe, otherwise the reason, phrased to be
        printed after "the toolkit root ...".
    #>
    param([Parameter(Mandatory = $true)][string] $Path)

    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop }
    catch { return ('has a DACL that cannot be read: ' + $_.Exception.Message) }

    if (-not $acl.AreAccessRulesProtected) {
        return 'still inherits ACEs from its parent, so anything granted on ProgramData applies inside it'
    }

    $trusted = @('S-1-5-18', 'S-1-5-32-544')

    $ownerSid = $null
    try { $ownerSid = [string] $acl.GetOwner([System.Security.Principal.SecurityIdentifier]) }
    catch { $ownerSid = $null }   # an orphaned owner SID is itself a reason to fail the check below
    if ([string]::IsNullOrEmpty($ownerSid) -or $trusted -notcontains $ownerSid) {
        $shown = 'an unreadable principal'
        if (-not [string]::IsNullOrEmpty($ownerSid)) { $shown = $ownerSid }
        return ('is owned by ' + $shown + ', not SYSTEM or Administrators - an owner can rewrite the DACL at will')
    }

    # Write covers creating and replacing content; the rest are the other ways to
    # remove what is there or to re-permission it back open.
    $dangerous = ([int] [System.Security.AccessControl.FileSystemRights]::Write -bor
                  [int] [System.Security.AccessControl.FileSystemRights]::Delete -bor
                  [int] [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                  [int] [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                  [int] [System.Security.AccessControl.FileSystemRights]::TakeOwnership)

    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = ''
        try { $sid = [string] $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) }
        catch { $sid = [string] $ace.IdentityReference }
        if ($trusted -contains $sid) { continue }
        if (([int] $ace.FileSystemRights -band $dangerous) -ne 0) {
            return ('grants write access to ' + $sid + ' (' + [string] $ace.FileSystemRights +
                    '), which puts the manifest and every handler script this toolkit writes under their control')
        }
    }

    return $null
}

function Initialize-ToolkitRoot {
    <#
        Creates the toolkit root if absent, with inheritance disabled and access
        for SYSTEM and Administrators only. ProgramData's default DACL otherwise
        lets an unprivileged user delete the record of everything this toolkit
        hardened.

        Refuses to adopt a populated directory that carries no stamp — that is
        an operator pointing the toolkit at somebody else's data, not a re-run.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [switch] $ReadOnly,
        # -Rollback must not be blocked by a missing stamp: someone deleting a
        # 60-byte marker file must not make recorded previous values
        # permanently unrestorable while the manifest itself is right there.
        [switch] $AllowMissingStamp
    )

    $stampPath = [System.IO.Path]::Combine($Path, '.ironblackbox')
    $existedBefore = Test-Path -LiteralPath $Path

    if ($existedBefore) {
        $hasStamp = Test-Path -LiteralPath $stampPath
        # Guarded, not assumed: this region is copied on its own into scripts
        # that do NOT take the Manifest region (a read-only collector has no
        # manifest), and under Set-StrictMode referencing an undeclared variable
        # throws. The buffet in docs/DESIGN.md section 6 only works if a region
        # tolerates the absence of the ones it was not copied with.
        $hasManifest = $false
        if (Test-Path 'variable:script:ManifestPath') {
            if (-not [string]::IsNullOrWhiteSpace($script:ManifestPath)) {
                $hasManifest = Test-Path -LiteralPath $script:ManifestPath
            }
        }
        if (-not $hasStamp -and -not ($AllowMissingStamp -and $hasManifest)) {
            # Enumerate WITHOUT -ErrorAction SilentlyContinue. Swallowing the
            # error made this guard fail OPEN: a directory that exists but is
            # not enumerable (a Deny ACE, someone else's data) looked empty, and
            # the toolkit went on to strip its DACL and reassign its owner. The
            # reparse-point walk below already fails closed on access denied;
            # two neighbouring guards must not have opposite failure policies,
            # and the one protecting client data does not get to be the lenient
            # one.
            $existing = @(Get-ChildItem -LiteralPath $Path -Force)
            if ($existing.Count -gt 0) {
                throw ('ToolkitRoot exists, is not empty, and carries no .ironblackbox stamp. Refusing to take ownership of ' + $Path)
            }
        }
    }

    if ($ReadOnly) {
        # Read-only mode never changes the DACL, but it must not stay silent
        # about an unsafe one either: this is the directory that holds the
        # manifest -Rollback trusts and the handler scripts a SYSTEM scheduled
        # task executes.
        if ($existedBefore) {
            $roProblem = Get-ToolkitRootAclProblem -Path $Path
            if ($null -ne $roProblem) {
                Write-Finding ('the toolkit root ' + $Path + ' ' + $roProblem +
                               '. -Apply re-applies SYSTEM + Administrators only.')
            }
        }
        return $existedBefore
    }

    if (-not $existedBefore) {
        [void] (New-Item -Path $Path -ItemType Directory -Force)
        Set-ToolkitRootAcl -Path $Path
    }
    else {
        # A root this run did NOT create is hardened too, every time it is unsafe.
        #
        # This block used to run only on creation, justified by a comment saying
        # that a drifted root ACL was "a finding for Test-VisibilityDrift to
        # report". It was not: nothing in this toolkit ever records or re-reads a
        # filesystem ACL, so the compensating control that sentence named had
        # never been written. What the gap actually produced is a local privilege
        # escalation, because this directory is where every SYSTEM-executed
        # handler script is written and where the manifest that -Rollback trusts
        # lives. An unprivileged user who pre-creates the root keeps its DACL,
        # and ProgramData grants CREATOR OWNER full control of what it creates
        # (measured, Server 2019).
        #
        # Re-hardening an adopted root destroys nothing, because the guard above
        # has already refused any populated directory that carries no stamp. What
        # reaches this line is either empty or a root a previous run created. The
        # "lost previous value" concern that motivated the old restriction lives
        # in that refusal, not here.
        $problem = Get-ToolkitRootAclProblem -Path $Path
        if ($null -ne $problem) {
            $previousSddl = ''
            try { $previousSddl = (Get-Acl -LiteralPath $Path).Sddl } catch { $previousSddl = '<unreadable>' }
            Write-Info ('toolkit root was adopted with an unsafe DACL - ' + $problem +
                        '. Re-applying SYSTEM + Administrators only. Previous SDDL, for the record: ' +
                        $previousSddl)
            Set-ToolkitRootAcl -Path $Path
        }
    }

    if (-not (Test-Path -LiteralPath $stampPath)) {
        Set-Content -LiteralPath $stampPath -Value ('IronBlackBox toolkit root, created ' + (Get-UtcStamp)) -Encoding ASCII
    }

    return $true
}

function Enter-ToolkitLock {
    <#
        An RMM that fires twice produces two runs appending to one manifest.
        A named mutex turns that into a clear message instead of interleaved
        JSON.

        The name is per script AND per toolkit root, not one global name for the
        whole toolkit. A single 'Global\IronBlackBox' meant an RMM policy that
        launched the logging-hardening scripts in parallel — the deployment
        model docs/DESIGN.md section 8 describes — would see the first succeed
        and every other one exit 2 without doing anything: an alert storm plus
        an unhardened fleet.

        The wait is bounded rather than zero, so two runs that merely overlap
        queue instead of failing.
    #>
    param([Parameter(Mandatory = $true)][string] $ToolkitRootPath)

    # Mutex names cannot contain a backslash except after the Global\ prefix.
    $rootToken = $ToolkitRootPath.ToLowerInvariant() -replace '[^a-z0-9]', '_'
    $name = 'Global\IronBlackBox_' + $script:ScriptName + '_' + $rootToken

    $created = $false
    $script:LockHandle = New-Object System.Threading.Mutex($false, $name, [ref] $created)

    $acquired = $false
    try {
        $acquired = $script:LockHandle.WaitOne(120000)
    }
    catch [System.Threading.AbandonedMutexException] {
        # The previous holder died without releasing — an RMM that killed a run
        # mid-flight. The mutex IS acquired despite the exception.
        # https://learn.microsoft.com/en-us/dotnet/api/system.threading.mutex
        $acquired = $true
        Write-Info 'A previous run of this script ended without releasing its lock; continuing.'
    }

    if (-not $acquired) {
        Write-Failure ('Another run of ' + $script:ScriptName +
                       ' is already working on ' + $ToolkitRootPath + '.')
        exit 2
    }
}

function Exit-ToolkitLock {
    if ($null -ne $script:LockHandle) {
        try {
            $script:LockHandle.ReleaseMutex()
        }
        catch [System.ApplicationException] {
            # Thrown when this thread does not own the mutex — it was acquired
            # by WaitOne rather than at construction. Not an error worth failing
            # a completed run over, but say so rather than swallowing it.
            Write-Verbose ('Toolkit lock was not owned by this thread on release: ' + $_.Exception.Message)
        }
        try { $script:LockHandle.Dispose() }
        catch { Write-Verbose ('Disposing the toolkit lock failed: ' + $_.Exception.Message) }
        $script:LockHandle = $null
    }
}

#endregion

#region Manifest -------------------------------------------------------------

function Write-ManifestRecord {
    param([Parameter(Mandatory = $true)][hashtable] $Record)

    $line   = ($Record | ConvertTo-Json -Depth 8 -Compress)
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes($line + "`r`n")

    # RETRY THE OPEN, because 18 scripts share one manifest and the lock does not.
    #
    # MEASURED, not anticipated. Enter-ToolkitLock's name is deliberately PER
    # SCRIPT so that an RMM launching the logging-hardening scripts in parallel -
    # the model in docs/DESIGN.md section 8 - does not have the first succeed and
    # the rest exit 2. But FileShare::Read admits readers and refuses writers, so
    # the second concurrent APPEND was failing at the file instead, one layer
    # below the lock that was shaped to prevent it. Two different scripts run with
    # -Apply simultaneously, five rounds on Server 2019: FOUR of the ten launches
    # exited 2 with "The process cannot access the file ... because it is being
    # used by another process." The manifest itself stayed intact - 361 lines,
    # none unreadable - so the share mode was doing its job. The failure was
    # entirely in giving up on the first try.
    #
    # exit 2 means the script did not do its job, so ~40% of a parallel fleet
    # deployment would silently not harden while reporting an execution error an
    # operator would blame on their deployment.
    #
    # Keyed on HResult, never on the message: message text is localised and this
    # toolkit runs on fr-FR hosts. Measured on PS 5.1: a sharing violation
    # surfaces as System.IO.IOException with HResult 0x80070020, and HResult is
    # publicly readable there.
    # 0x80070020 ERROR_SHARING_VIOLATION, 0x80070021 ERROR_LOCK_VIOLATION.
    # https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
    #
    # Jittered, because two processes retrying on the same fixed interval collide
    # on the same interval. Bounded, because a holder that never releases is a
    # different failure and must still reach the operator as one.
    $attempts    = 12
    $sharingCode = 0x80070020
    $lockCode    = 0x80070021
    $lastError   = $null
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        $stream = $null
        try {
            $stream = New-Object System.IO.FileStream(
                $script:ManifestPath,
                [System.IO.FileMode]::Append,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::Read)
            $stream.Write($bytes, 0, $bytes.Length)
            # $true commits to the device, not just to the OS cache. Without it a
            # host that loses power keeps the change and loses its previous value.
            $stream.Flush($true)
            return
        }
        catch {
            # PowerShell wraps a constructor throw in MethodInvocationException,
            # so the IOException is reached through InnerException.
            $ex = $_.Exception
            $guard = 0
            while ($null -ne $ex -and -not ($ex -is [System.IO.IOException]) -and $guard -lt 8) {
                $ex = $ex.InnerException
                $guard++
            }
            $code = $null
            if ($null -ne $ex) {
                try { $code = [int] $ex.HResult } catch { $code = $null }
            }
            if ($code -ne $sharingCode -and $code -ne $lockCode) {
                # Access denied, a missing directory, a full disk: retrying cannot
                # help and hides the real cause behind a delay.
                throw
            }
            $lastError = $_
            if ($attempt -lt $attempts) {
                Start-Sleep -Milliseconds (25 + (Get-Random -Minimum 0 -Maximum 60))
            }
        }
        finally {
            if ($null -ne $stream) { $stream.Dispose() }
        }
    }
    throw ('Could not append to the manifest after ' + [string] $attempts + ' attempts because another ' +
           'process is holding ' + $script:ManifestPath + '. All IronBlackBox scripts share this file, ' +
           'and the lock is per script by design; a holder that never releases is the thing to look for. ' +
           'Last error: ' + $lastError.Exception.Message)
}

function Read-Manifest {
    <#
        A corrupt manifest is an error, never an empty one: returning "no
        records" on a parse failure is how a previous implementation overwrote
        recoverable rollback data. A torn FINAL line is tolerated — that is an
        interrupted write, and every record before it is still good.
    #>
    if (-not (Test-Path -LiteralPath $script:ManifestPath)) {
        return @()
    }

    $lines   = @(Get-Content -LiteralPath $script:ManifestPath -Encoding UTF8)
    $records = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            [void] $records.Add(($line | ConvertFrom-Json))
        }
        catch {
            if ($i -eq ($lines.Count - 1)) {
                Write-Info 'Manifest ends in a torn line (interrupted write); ignoring it.'
            }
            else {
                throw ('Manifest is corrupt at line ' + ($i + 1) + ' of ' + $lines.Count + ': ' + $script:ManifestPath)
            }
        }
    }
    return $records.ToArray()
}

function Assert-ManifestUsable {
    <#
        Called before the first write of any -Apply or -Rollback. Two jobs.

        1. Honour the contract in docs/DESIGN.md section 4: "-Apply on an
           unreadable manifest exits 2 and refuses to proceed." That was
           documented but never implemented — -Apply only ever appended and
           never read the file, so it could not detect corruption at all.

        2. Quarantine an unterminated final line BEFORE appending after it.
           This is the defect that mattered most: FileMode::Append writes
           straight onto a torn line that has no trailing newline, producing
           {truncated}{"recordType":"run",...} as one physical line. That line
           is then no longer the last, so Read-Manifest's tolerance no longer
           applies and EVERY later -Rollback dies with "manifest is corrupt" —
           permanently, with every previous value sitting readable on disk and
           unreachable. On a client domain controller that means rollback by
           hand.

        Quarantine rewrites the file, which is the one exception to
        append-only. It is a deliberate repair: the torn bytes are preserved in
        a sibling .torn file, never discarded, and the surviving records are
        rewritten verbatim.
    #>
    if (-not (Test-Path -LiteralPath $script:ManifestPath)) { return }

    $bytes = [System.IO.File]::ReadAllBytes($script:ManifestPath)
    if ($bytes.Length -eq 0) { return }

    # 0x0A = LF. Records are written with CRLF, so a complete file ends in LF.
    $terminated = ($bytes[$bytes.Length - 1] -eq 0x0A)

    $text  = [System.Text.Encoding]::UTF8.GetString($bytes)
    $lines = @($text -split "`r?`n")
    # A terminated file yields a trailing empty element from the final newline.
    if ($lines.Count -gt 0 -and [string]::IsNullOrEmpty($lines[$lines.Count - 1])) {
        $lines = @($lines[0..($lines.Count - 2)])
    }
    if ($lines.Count -eq 0) { return }

    $lastIndex = $lines.Count - 1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ([string]::IsNullOrWhiteSpace($lines[$i])) { continue }
        $parsed = $true
        try { [void] ($lines[$i] | ConvertFrom-Json) }
        catch { $parsed = $false }

        if ($parsed) { continue }

        # An unparseable line that is NOT the unterminated last line means the
        # file is corrupt in a way this code did not cause and cannot reason
        # about. Fail closed rather than overwrite recoverable rollback data.
        if ($i -ne $lastIndex -or $terminated) {
            throw ('Manifest is corrupt at line ' + ($i + 1) + ' of ' + $lines.Count +
                   ' and cannot be repaired automatically: ' + $script:ManifestPath)
        }

        $tornPath = ($script:ManifestPath + '.torn-' +
                     (Get-UtcStamp).Replace(':', '').Replace('.', '') + '.jsonl')
        [System.IO.File]::WriteAllText($tornPath, $lines[$i], (New-Object System.Text.UTF8Encoding($false)))

        $kept = ''
        if ($i -gt 0) {
            $kept = (($lines[0..($i - 1)]) -join "`r`n") + "`r`n"
        }
        # Write to a temporary sibling and REPLACE, so an interruption during the
        # repair cannot leave a half-written manifest.
        #
        # This used to Copy then Delete, under a comment that claimed exactly the
        # protection Copy does not give: File::Copy writes the destination byte by
        # byte, so an interruption mid-copy leaves the manifest half-written -
        # the failure the comment promised to prevent, in the code meant to
        # prevent it.
        #
        # File::Replace, not File::Move: PS 5.1 runs on .NET Framework, where
        # File.Move has no overwrite parameter and throws when the destination
        # exists. Replace exchanges the two directory entries and keeps the old
        # content in the backup path until it is deleted, so the manifest is
        # either wholly old or wholly new at every instant.
        # https://learn.microsoft.com/en-us/dotnet/api/system.io.file.replace
        $tempPath   = ($script:ManifestPath + '.repair')
        $backupPath = ($script:ManifestPath + '.prerepair')
        [System.IO.File]::WriteAllText($tempPath, $kept, (New-Object System.Text.UTF8Encoding($false)))
        [System.IO.File]::Replace($tempPath, $script:ManifestPath, $backupPath)
        [System.IO.File]::Delete($backupPath)

        Write-Info ('Quarantined an interrupted final manifest record to ' +
                    [System.IO.Path]::GetFileName($tornPath) + '.')
        return
    }

    # THE OTHER HALF OF THE TORN-LINE DEFECT, and the loop above cannot see it.
    #
    # The loop only quarantines a final line that FAILS to parse. A record that
    # is COMPLETE but whose trailing newline never landed parses perfectly, hits
    # 'continue', and this function returns with the file still unterminated.
    # FileMode::Append then writes straight onto it and produces
    # {"complete record"}{"next record"} as one physical line - the exact
    # corruption the docstring above says this function exists to prevent, from
    # the one input it was not testing for.
    #
    # Nothing is quarantined here: the record is intact and belongs in the file.
    # Only the terminator is missing, so only the terminator is written.
    if (-not $terminated) {
        [System.IO.File]::AppendAllText($script:ManifestPath, "`r`n",
                                        (New-Object System.Text.UTF8Encoding($false)))
        Write-Info 'The manifest was missing its final newline; added it before appending.'
    }
}

function Start-ManifestRun {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Apply', 'Rollback')][string] $Mode,
        [hashtable] $Parameters = @{}
    )
    $script:CurrentRunId       = [System.Guid]::NewGuid().ToString()
    $script:ChangeIndex = 0
    Write-ManifestRecord -Record @{
        recordType = 'run'
        runId      = $script:CurrentRunId
        script     = $script:ScriptName
        version    = $script:ScriptVersion
        mode       = $Mode
        startedUtc = (Get-UtcStamp)
        hostname   = [System.Net.Dns]::GetHostName()
        parameters = $Parameters
    }
    return $script:CurrentRunId
}

function Write-ManifestChange {
    <#
        Written and flushed BEFORE the change it describes. A process killed
        between a registry write and its record leaves a modified host whose
        previous value existed only in memory.
    #>
    param([Parameter(Mandatory = $true)][hashtable] $Change)

    # Numbered from the next index but only committed AFTER the record is on
    # disk: incrementing first meant a failed write still advanced the counter,
    # so changeCount over-reported and the changeIds had a hole in them.
    $changeId = ($script:CurrentRunId + '-' + ($script:ChangeIndex + 1))
    Write-ManifestRecord -Record @{
        recordType   = 'change'
        runId        = $script:CurrentRunId
        changeId     = $changeId
        recordedUtc  = (Get-UtcStamp)
        change       = $Change
    }
    $script:ChangeIndex++
    return $changeId
}

<#
    THE ROLLBACK DOCTRINE. Every restorer in this toolkit implements this, and a
    restorer that does not is a defect.

    A restorer resolves the change THREE ways against the host, not two:

      1. the host holds what this run SET       -> undo it            'restored'
      2. the host holds the recorded PREVIOUS   -> already undone,
         value (or is absent, if the run           or the write never
         created it)                               landed: nothing to do
                                                                     'restored'
      3. the host holds something else          -> a third party has
                                                   been here          'declined'

    Plus a fourth outcome for a change that CANNOT be undone by this toolkit,
    ever - a journal it created and will not delete, an enlargement fsutil
    refuses to shrink, a shadow storage association with no documented removal:

      4. un-undoable by design or by the OS                'declined-permanent'

    WHY CASE 2 EXISTS, measured on the lab. Every restorer used to resolve two
    ways: host equals what the run set, or decline. So the SECOND rollback of a
    run declined everything the FIRST had already restored - "the descriptor no
    longer matches what this run set" about a descriptor the toolkit itself had
    just put back. The run therefore never left the eligible set, and
    Test-VisibilityDrift, which excludes only runs whose rollback COMPLETED,
    reported 29 changes as drifted on a host where every one of them had been
    correctly restored. One un-undoable change poisoned every other change in
    its run, forever. That was defect R-1, and case 2 is what closes it.

    Case 2 also settles the case docs/DESIGN.md section 4 always specified and
    no implementation had: a write that was recorded and never landed - an
    EventLog policy overriding a channel config, say - looks exactly like a
    change already restored, and both mean "leave it alone and count it done".

    RUN STATUS follows from the counts, and Get-RollbackRunStatus is the only
    place that decides it:

      all restored                          -> 'completed'
      any retryable decline, or a failure   -> 'failed'   (stays eligible)
      only permanent declines               -> 'completed-with-permanent-declines'

    Anything starting with 'completed' means the rollback did everything it can
    and the run is finished. Eligibility and drift both test for that prefix,
    never for equality with 'completed'.
#>
$script:RollbackRestored          = 'restored'
$script:RollbackDeclined          = 'declined'
$script:RollbackDeclinedPermanent = 'declined-permanent'

function Get-RollbackRunStatus {
    <#
        The single place a rollback's run status is decided. See the doctrine
        above. Returns a string whose 'completed' prefix is what
        Get-RollbackTargetRun and Test-VisibilityDrift both test.
    #>
    param(
        [Parameter(Mandatory = $true)][int] $Failures,
        [Parameter(Mandatory = $true)][int] $DeclinedRetryable,
        [Parameter(Mandatory = $true)][int] $DeclinedPermanent
    )

    if ($Failures -gt 0 -or $DeclinedRetryable -gt 0) { return 'failed' }
    if ($DeclinedPermanent -gt 0) { return 'completed-with-permanent-declines' }
    return 'completed'
}

function Invoke-AbandonRun {
    <#
        Gives up on rolling back one named run, on the record.

        WHY THIS EXISTS (the review log kept in the development repository, RB-1). Case 3 of the doctrine -
        the host holds neither what the run set nor what it recorded - declines
        as RETRYABLE, on the assumption that whatever changed the value might
        change it back. When the thing that changed it is a LATER run of the same
        script, it never will. Measured on the lab: one run held an
        EnableScriptBlockLogging value matching neither state, declined on every
        single -Rollback, and blocked -Rollback from ever reaching an older run.
        Thirteen of fourteen scripts drained their whole backlog in one rollback;
        that one could not drain at all.

        WHAT IT DOES NOT DO, and this is the part that matters. It does not touch
        the host. It does not pretend the change was undone. It writes a record
        saying an operator decided to stop trying, names every change it is
        giving up on, and says so on the console. The host keeps whatever it
        holds.

        WHAT IT COSTS. Test-VisibilityDrift stops expecting the abandoned
        changes, because the run leaves the eligible set. If one of those changes
        is a setting an attacker switched off, this is the operator choosing not
        to be told about it again. That is a real cost and it is why the run has
        to be named explicitly: -Rollback -AbandonRun <runId>, never a bare
        switch, and never "the most recent one".

        IT ROLLS BACK FIRST. Everything that can still be undone is undone, and
        only what still declines is abandoned. Abandoning a change that would
        have restored cleanly would be the worst version of this feature.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $RunIdToAbandon,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array] $DeclinedChangeIds,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array] $RestoredChangeIds
    )

    Write-ManifestRecord -Record @{
        recordType         = 'rollback'
        runId              = $RunIdToAbandon
        timestampUtc       = (Get-UtcStamp)
        # A status in the 'completed' family, so eligibility and drift both stop
        # offering this run - which is the entire point - but named so nobody
        # reading the manifest later mistakes it for a clean rollback.
        status             = 'completed-abandoned-by-operator'
        detail             = ([string] @($RestoredChangeIds).Count + ' restored, ' +
                              [string] @($DeclinedChangeIds).Count + ' abandoned on operator instruction')
        restoredChangeIds  = @($RestoredChangeIds)
        abandonedChangeIds = @($DeclinedChangeIds)
    }
}

function Test-AbandonRunTarget {
    <#
        Whether -AbandonRun names a run this script may abandon. Refuses rather
        than guessing, for the same reason -Rollback -RunId does: the manifest is
        operator-writable input.
    #>
    param([Parameter(Mandatory = $true)][string] $RunIdToAbandon)

    $records = Read-Manifest
    $run = $records | Where-Object {
        $_.recordType -eq 'run' -and [string] $_.runId -eq $RunIdToAbandon
    } | Select-Object -First 1

    if ($null -eq $run) {
        Write-Failure ('No run ' + $RunIdToAbandon + ' exists in the manifest.')
        return $false
    }
    if ([string] $run.script -ne $script:ScriptName) {
        Write-Failure ('Run ' + $RunIdToAbandon + ' belongs to ' + [string] $run.script +
                       ', not this script. Abandon it from there.')
        return $false
    }
    if ([string] $run.mode -ne 'Apply') {
        Write-Failure ('Run ' + $RunIdToAbandon + ' is a ' + [string] $run.mode +
                       ' run; only an -Apply run holds changes to abandon.')
        return $false
    }
    foreach ($record in $records) {
        if ($record.recordType -ne 'rollback') { continue }
        if ([string] $record.runId -ne $RunIdToAbandon) { continue }
        if (([string] $record.status).StartsWith('completed', [System.StringComparison]::Ordinal)) {
            Write-Failure ('Run ' + $RunIdToAbandon + ' is already finished (' +
                           [string] $record.status + '). There is nothing to abandon.')
            return $false
        }
    }
    return $true
}

function Stop-ManifestRun {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('completed', 'completed-with-failures', 'completed-abandoned-by-operator')]
        [string] $Status
    )
    Write-ManifestRecord -Record @{
        recordType   = 'run-end'
        runId        = $script:CurrentRunId
        completedUtc = (Get-UtcStamp)
        changeCount  = $script:ChangeIndex
        status       = $Status
    }
}

function Get-RollbackTargetRun {
    <#
        The most recent run for this script that has changes and has not already
        been rolled back successfully. Replaying a completed rollback restores
        values on top of whatever legitimately changed since.
    #>
    param([string] $ExplicitRunId)

    $records = Read-Manifest
    if ($records.Count -eq 0) { return $null }

    $rolledBack = @{}
    foreach ($record in $records) {
        # The PREFIX, not equality. 'completed-with-permanent-declines' means the
        # rollback did everything it can, so the run is finished and must not be
        # offered again - that is what stops -Rollback selecting the same run
        # forever. See the doctrine in the Registry region.
        if ($record.recordType -eq 'rollback' -and
            ([string] $record.status).StartsWith('completed', [System.StringComparison]::Ordinal)) {
            $rolledBack[[string] $record.runId] = $true
        }
    }

    $candidates = @($records | Where-Object {
        $_.recordType -eq 'run' -and
        $_.mode -eq 'Apply' -and
        $_.script -eq $script:ScriptName
    })

    if ($ExplicitRunId) {
        $candidates = @($candidates | Where-Object { $_.runId -eq $ExplicitRunId })
        if ($candidates.Count -eq 0) {
            throw ('No -Apply run with runId ' + $ExplicitRunId + ' for ' + $script:ScriptName + ' in the manifest.')
        }
    }

    # $candidateRunId, not $runId: PowerShell variable names are case-INSENSITIVE,
    # so a local named $runId and a script parameter named -RunId are one variable.
    # It is latent here - the parameter reaches this function as -ExplicitRunId
    # rather than being read directly - but it is the same trap that broke
    # Set-TrackedChannelSize in Enable-IRVisibility, and docs/AUTHORING.md records it for
    # $mode. Renamed rather than left for the next reader to rediscover.
    for ($i = $candidates.Count - 1; $i -ge 0; $i--) {
        $candidateRunId = [string] $candidates[$i].runId
        if ($rolledBack.ContainsKey($candidateRunId)) {
            if ($ExplicitRunId) {
                throw ('Run ' + $candidateRunId + ' has already been rolled back.')
            }
            continue
        }
        $changes = @($records | Where-Object { $_.recordType -eq 'change' -and $_.runId -eq $candidateRunId })
        if ($changes.Count -gt 0) {
            return [PSCustomObject] @{ RunId = $candidateRunId; Changes = $changes }
        }
    }
    return $null
}

#endregion

# The registry keys THIS script writes, and the only ones its -Rollback will
# write back. Read by Restore-TrackedChange in the Registry region; an empty
# array means "this script writes no registry values", which makes a registry
# record in its manifest a refusal rather than a write.
#   NTLM auditing under LSA (MSV1_0 is under it) plus the LDAP diagnostics.
$script:OwnedRegistryKey = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
    'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics',
    'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
)

#region Registry -------------------------------------------------------------

function Split-RegistryPath {
    <#
        Opens the hive through an EXPLICIT 64-bit registry view.

        [Microsoft.Win32.Registry]::LocalMachine follows the calling process's
        bitness, and RMMs do launch SysWOW64\WindowsPowerShell\v1.0\
        powershell.exe. Under WOW64, HKLM\SOFTWARE\... is redirected to
        HKLM\SOFTWARE\WOW6432Node\..., so a hardening write would land in the
        redirected key, have no effect on the machine, and then be CONFIRMED by
        a read-back through the same redirected view — a fleet reported
        compliant while none of it is hardened. Worse, the manifest records the
        unredirected path, so a later -Rollback from a 64-bit host writes the
        previous value into a real key the run never touched.
        https://learn.microsoft.com/en-us/windows/win32/winprog64/registry-redirector

        Registry64 on a 32-bit-only OS is documented to behave as the default
        view rather than failing, so this is safe on both.
        https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registrykey.openbasekey

        Caller must Dispose the returned Hive — OpenBaseKey hands back a new
        RegistryKey, unlike the static Registry::LocalMachine property.
    #>
    param([Parameter(Mandatory = $true)][string] $Path)

    $normalised = $Path -replace '^Registry::', ''
    $parts = $normalised -split '[:\\]', 2
    $hiveToken = $parts[0].ToUpperInvariant()
    $subKey = ''
    if ($parts.Count -gt 1) { $subKey = $parts[1].TrimStart('\') }

    # A bare hive with no subkey would make OpenSubKey('') hand back the hive
    # itself, which the caller would then Dispose — closing the process's
    # handle to that hive and breaking every later registry access.
    if ([string]::IsNullOrWhiteSpace($subKey)) {
        throw ('Registry path has no subkey, only a hive: ' + $Path)
    }

    switch ($hiveToken) {
        'HKLM'                { $hiveEnum = [Microsoft.Win32.RegistryHive]::LocalMachine; break }
        'HKEY_LOCAL_MACHINE'  { $hiveEnum = [Microsoft.Win32.RegistryHive]::LocalMachine; break }
        'HKCU'                { $hiveEnum = [Microsoft.Win32.RegistryHive]::CurrentUser;  break }
        'HKEY_CURRENT_USER'   { $hiveEnum = [Microsoft.Win32.RegistryHive]::CurrentUser;  break }
        'HKU'                 { $hiveEnum = [Microsoft.Win32.RegistryHive]::Users;        break }
        'HKEY_USERS'          { $hiveEnum = [Microsoft.Win32.RegistryHive]::Users;        break }
        'HKCR'                { $hiveEnum = [Microsoft.Win32.RegistryHive]::ClassesRoot;  break }
        'HKEY_CLASSES_ROOT'   { $hiveEnum = [Microsoft.Win32.RegistryHive]::ClassesRoot;  break }
        default { throw ('Unsupported registry hive in path: ' + $Path) }
    }

    $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        $hiveEnum, [Microsoft.Win32.RegistryView]::Registry64)

    return [PSCustomObject] @{ Hive = $hive; SubKey = $subKey }
}

# The six kinds this toolkit can round-trip through the manifest and restore.
# GetValueKind can also return 'None' (REG_NONE) and 'Unknown' (REG_LINK,
# REG_RESOURCE_LIST, …), which neither converter can handle: a REG_NONE
# byte[] falls to the default arm, JSON-encodes as [1,2,3], and comes back as
# the STRING "1 2 3" — the previous value destroyed and replaced by its text
# rendering, while the rollback reports success. Anything outside this set is
# refused rather than mangled.
$script:SupportedKinds = @('String', 'ExpandString', 'DWord', 'QWord', 'Binary', 'MultiString')

function Assert-SupportedKind {
    param([Parameter()][AllowEmptyString()][string] $Kind, [string] $Context)

    if ($script:SupportedKinds -notcontains $Kind) {
        throw ('Registry value kind "' + $Kind + '" is not supported by this toolkit (' +
               $Context + '). Supported: ' + ($script:SupportedKinds -join ', ') + '.')
    }
}

function ConvertTo-ManifestValue {
    <#
        REG_BINARY as base64 and REG_QWORD as a string: a byte array round-trips
        through JSON as Object[] of numbers, and PS 5.1 deserializes JSON
        integers as Int32 where PS 7 uses Int64 — so an -Apply and a later
        -Rollback can disagree on the type of the value they are handling.

        Returns a single-element array for MultiString rather than the array
        itself, because PowerShell unrolls a returned array: an empty
        REG_MULTI_SZ would come back as $null with valueExisted:$true, and the
        rollback would call SetValue($null, MultiString) and throw.
    #>
    param($Value, [string] $Kind)

    if ($null -eq $Value) { return $null }
    switch ($Kind) {
        'Binary'      { return [System.Convert]::ToBase64String([byte[]] $Value) }
        'QWord'       { return ([System.Int64] $Value).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        # Normalised to a real Int32. A derived script passing -Value $true
        # would otherwise serialise as JSON 'true' while the host reads back
        # Int32 1, and the rollback's guard would compare "True" to "1", decide
        # the host no longer holds its value, and decline to restore it.
        'DWord'       { return [System.Int32] $Value }
        'MultiString' { return ,([string[]] $Value) }
        default       { return [string] $Value }
    }
}

function ConvertFrom-ManifestValue {
    param($Value, [string] $Kind)

    if ($null -eq $Value) {
        # An empty REG_MULTI_SZ is a legitimate previous value and must restore
        # as an empty array, not as $null.
        if ($Kind -eq 'MultiString') { return ,([string[]] @()) }
        return $null
    }
    switch ($Kind) {
        'Binary'      { return [System.Convert]::FromBase64String([string] $Value) }
        'QWord'       { return [System.Int64]::Parse([string] $Value, [System.Globalization.CultureInfo]::InvariantCulture) }
        'DWord'       { return [System.Int32] $Value }
        'MultiString' { return ,([string[]] $Value) }
        default       { return [string] $Value }
    }
}

function Test-ManifestValueEqual {
    <#
        Type-aware equality. The previous implementation compared string
        interpolations of both sides, which is wrong in two ways that both
        cause the toolkit to report a host as already compliant when it is not
        — the worst possible failure for a tool whose job is arming logging:

        - '-eq' on strings is case-insensitive by default, so a REG_SZ holding
          "DISABLED" satisfied an intended "Disabled". No write, no finding,
          exit 0. Verified on this dev box.
          https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators
        - interpolating a string[] joins it with $OFS (a space), so
          @('C:\Program','Files\a') and @('C:\Program Files\a') interpolate
          identically. The mis-split REG_MULTI_SZ is exactly the defect to be
          repaired, and the comparison declared it already correct. Also
          verified here.
    #>
    param($Left, $Right, [Parameter()][AllowEmptyString()][string] $Kind)

    if ($null -eq $Left -and $null -eq $Right) { return $true }
    if ($null -eq $Left -or $null -eq $Right)  { return $false }

    switch ($Kind) {
        'MultiString' {
            $l = [string[]] $Left
            $r = [string[]] $Right
            if ($l.Count -ne $r.Count) { return $false }
            for ($i = 0; $i -lt $l.Count; $i++) {
                if (-not [string]::Equals($l[$i], $r[$i], [System.StringComparison]::Ordinal)) {
                    return $false
                }
            }
            return $true
        }
        'DWord' { return ([System.Int32] $Left) -eq ([System.Int32] $Right) }
        'QWord' {
            # Both sides are invariant decimal strings by this point.
            return [string]::Equals([string] $Left, [string] $Right, [System.StringComparison]::Ordinal)
        }
        default {
            # Ordinal: registry data is not culture text, and a case-insensitive
            # match here silently skips a needed write.
            return [string]::Equals([string] $Left, [string] $Right, [System.StringComparison]::Ordinal)
        }
    }
}

function Get-RegistryValueState {
    <#
        Reads with DoNotExpandEnvironmentNames so a REG_EXPAND_SZ is captured
        unexpanded — otherwise a rollback writes the expanded literal back and
        %SystemRoot% stops following the OS.
        https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registryvalueoptions
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Name
    )

    $split = Split-RegistryPath -Path $Path
    $key   = $null
    try {
        $key = $split.Hive.OpenSubKey($split.SubKey, $false)
        if ($null -eq $key) {
            return [PSCustomObject] @{ Exists = $false; Value = $null; Kind = $null; KeyExists = $false }
        }
        $names = @($key.GetValueNames())
        $present = $false
        foreach ($existing in $names) {
            if ([string]::Equals($existing, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                $present = $true
                break
            }
        }
        if (-not $present) {
            return [PSCustomObject] @{ Exists = $false; Value = $null; Kind = $null; KeyExists = $true }
        }
        $kind  = $key.GetValueKind($Name).ToString()
        $value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return [PSCustomObject] @{
            Exists    = $true
            Value     = (ConvertTo-ManifestValue -Value $value -Kind $kind)
            Kind      = $kind
            KeyExists = $true
        }
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $split -and $null -ne $split.Hive) { $split.Hive.Dispose() }
    }
}

function Set-RegistryValueRaw {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Name,
        [Parameter(Mandatory = $true)][string] $Kind,
        $Value
    )
    $split = Split-RegistryPath -Path $Path
    $key   = $null
    try {
        $key = $split.Hive.CreateSubKey($split.SubKey)
        if ($null -eq $key) { throw ('Cannot open or create registry key: ' + $Path) }
        $key.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]::$Kind)
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $split -and $null -ne $split.Hive) { $split.Hive.Dispose() }
    }
}

function Remove-RegistryValueRaw {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Name
    )
    $split = Split-RegistryPath -Path $Path
    $key   = $null
    try {
        $key = $split.Hive.OpenSubKey($split.SubKey, $true)
        if ($null -eq $key) { return }
        $key.DeleteValue($Name, $false)
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $split -and $null -ne $split.Hive) { $split.Hive.Dispose() }
    }
}

function Set-TrackedRegistryValue {
    <#
        The one entry point for changing a registry value. Records the previous
        value first, then writes, then reads back to confirm.

        Returns $true if it changed something, $false if the host already
        matched (which keeps -Apply idempotent).
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Name,
        [Parameter(Mandatory = $true)][ValidateSet('String', 'ExpandString', 'DWord', 'QWord', 'Binary', 'MultiString')][string] $Kind,
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $current  = Get-RegistryValueState -Path $Path -Name $Name
    $intended = ConvertTo-ManifestValue -Value $Value -Kind $Kind

    # A previous value the toolkit cannot round-trip must stop the change, not
    # be silently mangled on the way into the manifest.
    if ($current.Exists) {
        Assert-SupportedKind -Kind $current.Kind -Context ($Path + '\' + $Name + ', existing value')
    }

    if ($current.Exists -and $current.Kind -eq $Kind -and
        (Test-ManifestValueEqual -Left $current.Value -Right $intended -Kind $Kind)) {
        Write-Ok ($Description + ' — already set')
        return $false
    }

    if (-not $Apply) {
        Write-Finding ($Description + ' — would set ' + $Path + '\' + $Name)
        return $false
    }

    # Record before changing. Not after.
    [void] (Write-ManifestChange -Change @{
        type                = 'registry'
        path                = $Path
        name                = $Name
        valueExisted        = $current.Exists
        previousValue       = $current.Value
        previousKind        = $current.Kind
        newValue            = $intended
        newKind             = $Kind
        description         = $Description
    })

    Set-RegistryValueRaw -Path $Path -Name $Name -Kind $Kind -Value $Value

    # Confirm the kind as well as the value: a type mismatch between what was
    # asked for and what landed would otherwise pass unnoticed, and the manifest
    # would record a newKind the host does not actually hold.
    $confirmed = Get-RegistryValueState -Path $Path -Name $Name
    if (-not $confirmed.Exists -or
        $confirmed.Kind -ne $Kind -or
        -not (Test-ManifestValueEqual -Left $confirmed.Value -Right $intended -Kind $Kind)) {
        Write-Failure ($Description + ' — write did not read back at ' + $Path + '\' + $Name)
        throw ('Registry write could not be confirmed: ' + $Path + '\' + $Name)
    }

    Write-Ok ($Description + ' — set')
    return $true
}

function Restore-TrackedChange {
    <#
        Returns 'restored', 'declined' or 'declined-permanent' per the doctrine
        above. Throws on a failed write.

        Counting only thrown exceptions as failures is how an earlier version
        let a rollback that restored 9 of 12 values report 'completed', marking
        the run permanently rolled back while three original values stayed
        unreachable. A retryable decline still makes the whole rollback
        'failed'.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    if ($change.type -ne 'registry') {
        Write-Finding ('Cannot roll back change type "' + $change.type + '" — not implemented in this script.')
        return 'declined'
    }

    # Only when there WAS a previous value. A change that created a value
    # records previousKind as null, which is correct and not an unsupported
    # kind — rolling it back means deleting the value, and no kind is involved.
    # Proven on the lab: validating unconditionally made every rollback of a
    # newly created value fail with 'kind "" is not supported'.
    if ($change.valueExisted) {
        Assert-SupportedKind -Kind $change.previousKind -Context ($change.path + '\' + $change.name + ', recorded previous value')
    }

    # The manifest is operator-writable input, not trusted state. This used to
    # constrain the change to HKLM and stop there, which named the right threat
    # and mitigated none of it: HKLM is precisely where every privileged key
    # lives. Image File Execution Options, Winlogon, a service ImagePath and LSA
    # are all inside it.
    #
    # The constraint now comes from the SCRIPT, through $script:OwnedRegistryKey,
    # never from the record. Two cases, and the empty one is the important half:
    #
    #   declared, non-empty   the recorded path must sit at or under one of the
    #                         keys this script actually writes.
    #   declared EMPTY        this script writes no registry values at all, so a
    #                         registry record in its manifest cannot have come
    #                         from it. Refused outright. Measured: 11 of the 18
    #                         scripts never call Set-TrackedRegistryValue, yet
    #                         every one of them carried this restorer - pure
    #                         attack surface with no legitimate use.
    if ($change.path -notmatch '^(HKLM|HKEY_LOCAL_MACHINE):?\\') {
        throw ('Refusing to roll back a change outside HKLM: ' + $change.path)
    }
    if (-not (Test-Path 'variable:script:OwnedRegistryKey')) {
        throw ('This script does not declare $script:OwnedRegistryKey, so it cannot judge whether ' +
               ($change.path) + ' is a key it owns. Refusing to write it.')
    }
    if (@($script:OwnedRegistryKey).Count -eq 0) {
        throw ('Refusing to roll back a registry change: this script writes no registry values, so ' +
               'the record naming ' + $change.path + ' did not come from it.')
    }
    $recordedKey = ([string] $change.path).TrimEnd('\')
    $ownsKey = $false
    foreach ($owned in $script:OwnedRegistryKey) {
        $prefix = ([string] $owned).TrimEnd('\')
        if ([string]::Equals($recordedKey, $prefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            $recordedKey.StartsWith($prefix + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            $ownsKey = $true
            break
        }
    }
    if (-not $ownsKey) {
        throw ('Refusing to roll back ' + $change.path + ': it is not at or under any key this script ' +
               'writes (' + (($script:OwnedRegistryKey | ForEach-Object { [string] $_ }) -join '; ') + ').')
    }

    $hostState = Get-RegistryValueState -Path $change.path -Name $change.name

    # Both sides are ALREADY in manifest form: Get-RegistryValueState encodes
    # what it reads, and newValue was encoded when the record was written. Do
    # not re-encode — proven on the lab, feeding the base64 string "AQID+g=="
    # back through ConvertTo-ManifestValue throws trying to cast it to byte[].
    $intendedValue = $change.newValue

    # THE THREE-WAY RESOLUTION. See the doctrine at the top of this region.
    $holdsIntended = ($hostState.Exists -and
        (Test-ManifestValueEqual -Left $hostState.Value -Right $intendedValue -Kind $change.newKind))

    if (-not $holdsIntended) {
        # Case 2: does the host hold what it held BEFORE this run? Either this
        # value has already been restored, or the write never landed. Both mean
        # there is nothing to do and nothing wrong - and treating them as a
        # decline is what made a second rollback contradict the first.
        $holdsPrevious = $false
        if ($change.valueExisted) {
            $holdsPrevious = ($hostState.Exists -and
                (Test-ManifestValueEqual -Left $hostState.Value -Right $change.previousValue `
                     -Kind $change.previousKind))
        }
        else {
            # The run CREATED the value, so "as it was before" means absent.
            $holdsPrevious = (-not $hostState.Exists)
        }

        if ($holdsPrevious) {
            Write-Ok ($change.path + '\' + $change.name +
                      ' already holds its recorded previous state; nothing to restore.')
            return 'restored'
        }

        # Case 3: neither. Somebody else has been here.
        Write-Finding ($change.path + '\' + $change.name +
                       ' holds neither the value this run set nor the value recorded before it;' +
                       ' leaving it alone.')
        return 'declined'
    }

    if (-not $change.valueExisted) {
        Remove-RegistryValueRaw -Path $change.path -Name $change.name
        Write-Ok ('Removed ' + $change.path + '\' + $change.name + ' (did not exist before)')
        return 'restored'
    }

    $previous = ConvertFrom-ManifestValue -Value $change.previousValue -Kind $change.previousKind
    Set-RegistryValueRaw -Path $change.path -Name $change.name -Kind $change.previousKind -Value $previous
    Write-Ok ('Restored ' + $change.path + '\' + $change.name)
    return 'restored'
}

#endregion

#region Host role -------------------------------------------------------------

function Get-HostRoleState {
    <#
        Win32_ComputerSystem.DomainRole: 0 Standalone Workstation, 1 Member
        Workstation, 2 Standalone Server, 3 Member Server, 4 Backup Domain
        Controller, 5 Primary Domain Controller.
        https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem

        The test is "4 or 5", never "= 5": "Backup" is the pre-Windows 2000 name
        and every writable DC that does not hold the PDC emulator role reports 4.
    #>
    $roleName = @{
        0 = 'Standalone Workstation'; 1 = 'Member Workstation'
        2 = 'Standalone Server';      3 = 'Member Server'
        4 = 'Backup Domain Controller'; 5 = 'Primary Domain Controller'
    }
    $system = Get-CimInstance -ClassName Win32_ComputerSystem
    $role = [int] $system.DomainRole
    $name = 'unrecognised role ' + [string] $role
    if ($roleName.ContainsKey($role)) { $name = $roleName[$role] }

    return [PSCustomObject] @{
        DomainRole         = $role
        RoleName           = $name
        Domain             = [string] $system.Domain
        IsDomainController = ($role -eq 4 -or $role -eq 5)
    }
}

#endregion

#region Native tool paths ----------------------------------------------------

# Resolved once, at script scope, so every wevtutil call in this file is anchored
# and none of them can be diverted by a writable directory ahead of System32 in
# the machine PATH.
$script:WevtutilPath = Get-NativeToolPath -FileName 'wevtutil.exe'

#endregion

#region Audit-only guard ------------------------------------------------------

<#
    Every registry literal in this script, with its provenance. Do not "correct"
    any of these from memory.

    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 holds
    AuditReceivingNTLMTraffic and the two Restrict*NTLMTraffic values.
    # UNVERIFIED: learn.microsoft.com documents these as SECURITY POLICY
    settings and publishes neither the registry value names nor the number
    behind each option. The policy, its options ("Disable" / "Enable auditing
    for domain accounts" / "Enable auditing for all accounts") and its log
    ("Applications and Services Log\Microsoft\Windows\NTLM") are documented:
    https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-incoming-ntlm-traffic
    https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-incoming-ntlm-traffic
    A wrong AUDIT value name means no auditing, which the event report below
    will show. A wrong RESTRICT name is not a risk here: none is ever written.

    AuditNTLMInDomain lives under
    HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters - NOT under
    Lsa\MSV1_0. That is not a guess: Microsoft's Defender for Identity module
    documents reading it there, in the sample output of Get-MDIConfiguration
    -Configuration NTLMAuditing - "{@{Path=HKLM:\System\CurrentControlSet\
    Services\Netlogon\Parameters\; Name=AuditNTLMInDomain...".
    https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/get-mdiconfiguration
    # UNVERIFIED: the number for the policy's "Enable all" option, which is the
    setting Defender for Identity asks for:
    https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-ntlm-authentication-in-this-domain
    https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection

    LmCompatibilityLevel is under ...\Control\Lsa, cited:
    https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/audit-domain-controller-ntlmv1
    Read and reported, never written: 5 is NTLMv2-only, an enforcement decision
    with the same blast radius as restricting NTLM.
#>

$script:KeyMsv10          = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$script:KeyLsa            = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$script:KeyNetlogonParam  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$script:KeyNtdsDiagnostic = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
$script:KeyNtdsParameter  = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

# The ONLY three values this script may write. Anything else throws.
$script:WritableValue = @(
    @{ Path = $script:KeyMsv10;          Name = 'AuditReceivingNTLMTraffic' },
    @{ Path = $script:KeyNetlogonParam;  Name = 'AuditNTLMInDomain' },
    @{ Path = $script:KeyNtdsDiagnostic; Name = '16 LDAP Interface Events' }
)

# Names that ENFORCE. Refused by name wherever they appear, so a copy-paste into
# the wrong table cannot turn this script into an enforcement tool.
$script:ForbiddenValue = @(
    'RestrictSendingNTLMTraffic', 'RestrictReceivingNTLMTraffic',
    'RestrictNTLMInDomain', 'ClientAllowedNTLMServers', 'DCAllowedNTLMServers',
    'LmCompatibilityLevel', 'LDAPServerIntegrity', 'LDAPClientIntegrity',
    'LdapEnforceChannelBinding'
)

function Assert-AuditOnlyTarget {
    <#
        Throws unless (Path, Name) is one of the three audit values above, and
        throws on any enforcement value name regardless of path. This is the
        NTLM/LDAP equivalent of Protect-EventLogs' Assert-SddlNotMorePermissive:
        a named guard in front of every write.

        Both checks, not one. Either alone would be sufficient; two independent
        refusals mean a mistake in either table still stops the write, and on a
        domain controller's authentication configuration that redundancy is
        worth the lines it costs.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Name
    )

    foreach ($forbidden in $script:ForbiddenValue) {
        if ([string]::Equals($Name, $forbidden, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ('Refusing to write ' + $Path + '\' + $Name + ': that value ENFORCES a ' +
                   'restriction, and this script is audit-only by design (docs/DESIGN.md ' +
                   'section 7). Enforcement is the MSP''s decision, made after reading the data.')
        }
    }
    foreach ($allowed in $script:WritableValue) {
        if ([string]::Equals($allowed.Path, $Path, [System.StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals($allowed.Name, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            return
        }
    }
    throw ('Refusing to write ' + $Path + '\' + $Name +
           ': it is not one of the audit values this script is allowed to set.')
}

function Set-AuditOnlyDword {
    <#
        The single write path. Guards the target, then refuses to LOWER a level
        somebody already set higher: an administrator auditing incoming NTLM for
        "all accounts" must not be reduced to "domain accounts" by a hardening
        script, and a DC already logging LDAP interface events at level 5 keeps
        level 5.

        Returns 1 if it changed something, 0 if not, so callers accumulate with
        '+='. Never '$changed = $changed -or (...)': -or short-circuits, so once
        it is $true every later call is never made (docs/AUTHORING.md).
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][int] $Value,
        [Parameter(Mandatory = $true)][string] $Description
    )

    Assert-AuditOnlyTarget -Path $Path -Name $Name

    $current = Get-RegistryValueState -Path $Path -Name $Name
    if ($current.Exists -and $current.Kind -eq 'DWord' -and ([int] $current.Value) -gt $Value) {
        Write-Ok ($Description + ' - already at a higher level (' + [string] $current.Value +
                  '); leaving it alone')
        return 0
    }
    if (Set-TrackedRegistryValue -Path $Path -Name $Name -Kind 'DWord' `
        -Value $Value -Description $Description) {
        return 1
    }
    return 0
}

#endregion

#region NTLM and LDAP settings ------------------------------------------------

# Event IDs and their meanings are Microsoft's, from "Viewing events for
# assessing NTLM usage": 8001 on the client (outgoing), 8002/8003 on the server
# (incoming), 8004 on the domain controller (domain NTLM authentication).
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/jj865682(v=ws.10)
$script:NtlmAuditValue = @(
    @{ Path = $script:KeyNetlogonParam; Name = 'AuditNTLMInDomain'
       Description = 'NTLM audit: authentication in this domain (event 8004 on this DC)' },
    @{ Path = $script:KeyMsv10;         Name = 'AuditReceivingNTLMTraffic'
       Description = 'NTLM audit: incoming NTLM to this DC (event 8003)' }
)

# Read and reported, NEVER written. 'Meaning' says what absence implies, so the
# operator does not have to know the defaults.
$script:EnforcementValue = @(
    @{ Path = $script:KeyMsv10;         Name = 'RestrictReceivingNTLMTraffic'
       Meaning = 'incoming NTLM is not restricted' },
    @{ Path = $script:KeyMsv10;         Name = 'RestrictSendingNTLMTraffic'
       Meaning = 'outgoing NTLM is not restricted' },
    @{ Path = $script:KeyNetlogonParam; Name = 'RestrictNTLMInDomain'
       Meaning = 'domain NTLM authentication is not restricted' },
    @{ Path = $script:KeyLsa;           Name = 'LmCompatibilityLevel'
       Meaning = 'the OS default applies; 5 would mean NTLMv2 only' },
    # LDAP signing and channel binding. Documented for AD LDS instances as
    # 0 = signing disabled, 2 = signing required:
    # https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy
    # # UNVERIFIED: for AD DS the value lives under Services\NTDS\Parameters and
    # the mapping usually quoted is 1 = None, 2 = Require signing.
    # learn.microsoft.com documents the POLICY ("Domain controller: LDAP server
    # signing requirements") but not that registry value for AD DS - so the raw
    # number is printed and deliberately NOT interpreted. Same for
    # LdapEnforceChannelBinding, whose 0/1/2 mapping is published in KB4520412
    # and not on learn.microsoft.com.
    @{ Path = $script:KeyNtdsParameter; Name = 'LDAPServerIntegrity'
       Meaning = 'LDAP signing is not required by a local setting' },
    @{ Path = $script:KeyNtdsParameter; Name = 'LdapEnforceChannelBinding'
       Meaning = 'LDAP channel binding is not enforced by a local setting' }
)

function Write-EnforcementReport {
    Write-Section 'NTLM and LDAP enforcement state (read-only, never changed here)'
    foreach ($item in $script:EnforcementValue) {
        $state = Get-RegistryValueState -Path $item.Path -Name $item.Name
        if (-not $state.Exists) {
            Write-Info ($item.Name + ' - not set (' + $item.Meaning + ')')
        }
        else {
            Write-Info ($item.Name + ' = ' + [string] $state.Value + ' (' + $state.Kind +
                        ', raw value, not interpreted)')
        }
    }
    Write-Info 'No value above is written by this script, in any mode.'
}

function Set-NtlmAuditing {
    param(
        [Parameter(Mandatory = $true)][int] $DomainValue,
        [Parameter(Mandatory = $true)][int] $IncomingValue
    )
    Write-Section 'NTLM auditing'
    $changes = 0
    foreach ($target in $script:NtlmAuditValue) {
        $wanted = $IncomingValue
        if ($target.Name -eq 'AuditNTLMInDomain') { $wanted = $DomainValue }
        $changes += Set-AuditOnlyDword -Path $target.Path -Name $target.Name -Value $wanted `
            -Description ($target.Description + ' = ' + [string] $wanted)
    }
    Write-Info 'These are AUDIT values. Neither blocks any authentication.'
    return $changes
}

function Set-LdapInterfaceDiagnostic {
    <#
        Unsigned LDAP binds are surfaced by a DIAGNOSTIC level, not a policy:
        "16 LDAP Interface Events" = 2 (REG_DWORD) under
        HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics makes the DC
        log event 2889 per unsigned bind, naming the client IP and the identity
        it authenticated as. Key, value name and level are all cited:
        https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server
        (KB 935834, which also gives the event text and the "Binding Type:
        0 SASL without signing / 1 simple bind" field). The Diagnostics key is
        confirmed independently by Defender for Identity's instruction to remove
        "15 Field Engineering" from it:
        https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection
        Summary events, same KB: 2886 signing not required (at startup), 2887
        unsigned binds ALLOWED, 2888 unsigned binds REJECTED (both 24h
        summaries), 2889 one per unsigned bind.

        Raising a diagnostic level only increases what is recorded. It changes
        no authentication behaviour and cannot reject a bind.
    #>
    Write-Section 'Unsigned LDAP diagnostics'
    $changes = Set-AuditOnlyDword -Path $script:KeyNtdsDiagnostic `
        -Name $script:LdapDiagnosticName -Value $script:LdapDiagnosticLevel `
        -Description ('LDAP interface diagnostics level ' + [string] $script:LdapDiagnosticLevel +
                      ' (logs event 2889 per unsigned bind)')
    Write-Info 'Logging only: this does not require LDAP signing and cannot reject a bind.'
    return $changes
}

#endregion

#region Event evidence --------------------------------------------------------

$script:LdapDiagnosticName  = '16 LDAP Interface Events'
$script:LdapDiagnosticLevel = 2
# 'Log Name: Directory Service' is quoted verbatim in KB 935834's event samples.
$script:DirectoryServiceLog = 'Directory Service'
$script:NtlmChannelPrefix   = 'Microsoft-Windows-NTLM/'

function Test-EventLogPresent {
    <#
        'wevtutil gl <log>' exits non-zero for a log that does not exist, which
        is how a missing channel is told apart from a channel with no events.
        Get-WinEvent raises the same kind of error for both, so it cannot answer
        this question on its own.
    #>
    param([Parameter(Mandatory = $true)][string] $LogName)
    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @('gl', $LogName)
    return ($result.ExitCode -eq 0)
}

function Get-EventIdTally {
    <#
        Counts matching records per event ID, bounded twice: by time
        (-LookbackDays) and by record count (-MaxEventScanned). A DC with NTLM
        auditing on writes one event per authentication, so an unbounded read is
        a memory incident of the script's own making. Records come back too,
        because event 2889 needs its fields read and not just counted.

        Get-WinEvent raises a terminating error when a filter matches nothing;
        under $ErrorActionPreference = 'Stop' that would abort the run over an
        empty log - the exact case this has to report as "nothing seen yet".

        Detail carries whatever Windows said when the read produced nothing, and
        every caller MUST pass it to Write-EventReadNotice before printing any
        variant of "nothing found". Total = 0 on its own is not evidence of a
        quiet log: the same terminating error covers an access denied, a corrupt
        channel and an empty window, so a caller that reads only Total reports a
        failed query as a clean host.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $LogName,
        [Parameter(Mandatory = $true)][int[]] $EventId,
        [Parameter(Mandatory = $true)][int] $Days,
        [Parameter(Mandatory = $true)][int] $MaxEvents
    )

    $records = @()
    $detail = ''
    try {
        $records = @(Get-WinEvent -FilterHashtable @{
            LogName = $LogName; Id = $EventId; StartTime = (Get-Date).AddDays(-$Days)
        } -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch {
        # No matching events, or a genuine read failure. The caller has already
        # established the log exists, so this is "none found" with the message
        # kept for the operator - and Write-EventReadNotice is what makes that
        # true rather than a comment: the message used to be recorded here and
        # read nowhere in the file.
        $detail = $_.Exception.Message
    }

    $tally = @{}
    foreach ($record in $records) {
        $id = [int] $record.Id
        if ($tally.ContainsKey($id)) { $tally[$id] = $tally[$id] + 1 } else { $tally[$id] = 1 }
    }
    return [PSCustomObject] @{
        Records = $records
        Tally   = $tally
        Total   = $records.Count
        Capped  = ($records.Count -ge $MaxEvents)
        Detail  = $detail
    }
}

function Write-EventReadNotice {
    <#
        Reports the message Get-WinEvent produced when a query came back with
        nothing, and returns $true when it printed one.

        NOTHING HERE PARSES THE MESSAGE, and that is the whole point. Get-WinEvent
        raises the same terminating error for at least three different answers -
        the query matched nothing, this SKU has no such channel, the channel
        could not be read - and its text is LOCALISED, so picking out the English
        "No events were found" turns every empty query on a fr-FR DC into a read
        error. Deploy-TamperAlerts records the same decision for the identical
        ambiguity: print what Windows said and do not interpret it.

        Why it matters here more than anywhere else in this script: the event
        2889 summary is the deliverable, the list an MSP works through before it
        can require LDAP signing. Printing '[ ok ] no event 2889 in the window'
        off a Total of 0 told that MSP, in green, that there was nothing to work
        through - on a host where the read had failed.

        Neither a finding nor a host limit: which of the three answers this is
        cannot be known from here without interpreting that localised string, and
        two of the three have no lever.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Label,
        [Parameter()][AllowEmptyString()][string] $Detail = ''
    )

    if ([string]::IsNullOrWhiteSpace($Detail)) { return $false }
    $message = ($Detail -replace '[\r\n\t]+', ' ').Trim()
    if ($message.Length -gt 300) { $message = $message.Substring(0, 300) + '...' }
    Write-Info ($Label + ' - the read returned no records and Windows said: ' + $message)
    Write-Info '  Unless that is "no events matched", this section is not evidence of a quiet host.'
    return $true
}

function Get-UnsignedBindDetail {
    <#
        Pulls the client address and the account out of one event 2889.

        # UNVERIFIED: which inserted properties 2889 carries and in what order.
        KB 935834 documents the rendered MESSAGE (client IP address and port,
        the identity, then the binding type) but not the property layout, and
        2889 is a Classic-keyword event whose properties may arrive as a single
        combined string. So properties are tried first and the message is the
        fallback - and the fallback patterns are shape-based (an IPv4 address, a
        DOMAIN\user token) rather than matching any English label, because the
        message text is localised.
    #>
    param([Parameter(Mandatory = $true)] $EventRecord)

    $address = ''
    $account = ''
    $properties = @()
    if ($null -ne $EventRecord.Properties) { $properties = @($EventRecord.Properties) }
    if ($properties.Count -ge 1) { $address = [string] $properties[0].Value }
    if ($properties.Count -ge 2) { $account = [string] $properties[1].Value }

    $message = ''
    if ($null -ne $EventRecord.Message) { $message = [string] $EventRecord.Message }

    # The property values are SHAPE-checked, not just tested for emptiness.
    # Verified on this dev box against a synthetic 2889: when the event arrives
    # as a single combined insertion string - the Classic-keyword case this
    # cannot rule out - a "does it contain a digit" test accepts the whole
    # message as the client address, and the summary then groups by a
    # multi-line blob. An address must look like an address, or the message
    # regex takes over.
    if ($address -notmatch '^[0-9A-Fa-f\.:%\[\]]{3,64}$') {
        $address = ''
        $found = [regex]::Match($message, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?\b')
        if ($found.Success) { $address = $found.Value }
    }
    if ($account -notmatch '^[^\s]{1,128}\\[^\s]{1,128}$') {
        $account = ''
        $found = [regex]::Match($message, '(?m)^\s*([^\s\\/:*?"<>|]+\\[^\s\\/:*?"<>|]+)\s*$')
        if ($found.Success) { $account = $found.Groups[1].Value }
    }

    # Strip the TCP port from an IPv4 address only: an IPv6 address is full of
    # colons and a blind trailing-colon strip would mangle it.
    if ($address -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$') {
        $address = $address.Substring(0, $address.LastIndexOf(':'))
    }
    if ([string]::IsNullOrWhiteSpace($address)) { $address = 'unknown-client' }
    if ([string]::IsNullOrWhiteSpace($account)) { $account = 'unknown-account' }

    return [PSCustomObject] @{ Address = $address; Account = $account }
}

function Write-UnsignedLdapReport {
    <#
        The deliverable. Everything else here exists so that this summary is not
        empty on the next run: it is the list of clients an MSP has to fix
        before it can require LDAP signing.
    #>
    param(
        [Parameter(Mandatory = $true)][int] $Days,
        [Parameter(Mandatory = $true)][int] $MaxEvents,
        [Parameter(Mandatory = $true)][int] $TopCount
    )

    Write-Section ('Unsigned LDAP binds in the last ' + [string] $Days + ' day(s)')

    if (-not (Test-EventLogPresent -LogName $script:DirectoryServiceLog)) {
        Write-Finding ('the "' + $script:DirectoryServiceLog +
                       '" log does not exist here - it should on a DC')
        return
    }

    $summary = Get-EventIdTally -LogName $script:DirectoryServiceLog -EventId @(2886, 2887, 2888) `
        -Days $Days -MaxEvents $MaxEvents
    $summaryText = @{
        2886 = 'this DC does not require LDAP signing'
        2887 = '24h summaries of unsigned binds that were ALLOWED'
        2888 = '24h summaries of unsigned binds that were REJECTED (signing is required)'
    }
    foreach ($id in @(2886, 2887, 2888)) {
        if (-not $summary.Tally.ContainsKey($id)) { continue }
        $text = 'event ' + [string] $id + ' x' + [string] $summary.Tally[$id] + ': ' + $summaryText[$id]
        # 2888 means the DC is already rejecting them, which is the good state.
        if ($id -eq 2888) { Write-Info $text } else { Write-Finding $text }
    }

    $detail = Get-EventIdTally -LogName $script:DirectoryServiceLog -EventId @(2889) `
        -Days $Days -MaxEvents $MaxEvents
    if ($detail.Total -eq 0) {
        # The green line only when the read itself said nothing went wrong. Both
        # queries above and this one read the same log, so one notice covers the
        # whole section - which is why the 2886-2888 loop can stay silent on a
        # failed read without hiding it.
        if (-not (Write-EventReadNotice -Label ('event 2889 in "' + $script:DirectoryServiceLog + '"') `
                      -Detail $detail.Detail)) {
            Write-Ok 'no event 2889 in the window'
            Write-Info 'That only means something once the diagnostic level has been at 2 for a while.'
        }
        return
    }

    $tally = @{}
    foreach ($record in $detail.Records) {
        $bind = Get-UnsignedBindDetail -EventRecord $record
        $key = ($bind.Address + '  as  ' + $bind.Account)
        if ($tally.ContainsKey($key)) { $tally[$key] = $tally[$key] + 1 } else { $tally[$key] = 1 }
    }

    Write-Finding ([string] $detail.Total + ' unsigned LDAP bind(s) from ' + [string] $tally.Count +
                   ' distinct client/account pair(s)')
    if ($detail.Capped) {
        Write-Info ('the read stopped at the -MaxEventScanned cap of ' + [string] $MaxEvents +
                    '; there are more')
    }

    $ranked = @($tally.GetEnumerator() | Sort-Object -Property Value -Descending)
    $shown = 0
    foreach ($entry in $ranked) {
        if ($shown -ge $TopCount) { break }
        Write-Info ('  ' + [string] $entry.Value + ' x  ' + $entry.Key)
        $shown++
    }
    if ($ranked.Count -gt $shown) {
        Write-Info ('  ... and ' + [string] ($ranked.Count - $shown) + ' more pair(s)')
    }
    Write-Info 'Fix these clients BEFORE requiring LDAP signing. This script will not require it.'
}

function Write-NtlmEventReport {
    <#
        Counts the NTLM audit events already in the channel. On a first run this
        is normally zero, and that is the point: it is the before picture, and
        the same read a month later is the after.
    #>
    param(
        # Not Mandatory, and AllowEmptyCollection: a Mandatory parameter refuses
        # an empty array, and "there is no NTLM channel on this host" is exactly
        # the case this report exists to state.
        [Parameter()][AllowEmptyCollection()][string[]] $Channel = @(),
        [Parameter(Mandatory = $true)][int] $Days,
        [Parameter(Mandatory = $true)][int] $MaxEvents
    )

    Write-Section ('NTLM authentication events in the last ' + [string] $Days + ' day(s)')
    if ($Channel.Count -eq 0) {
        Write-Finding 'no Microsoft-Windows-NTLM channel here, so nothing to read'
        return
    }

    $meaning = @{
        8001 = 'outgoing NTLM from this host'
        8002 = 'outgoing NTLM seen by a restriction rule'
        8003 = 'incoming NTLM to this host'
        8004 = 'NTLM authentication in this domain (the DC-side event)'
    }
    foreach ($channelName in $Channel) {
        $query = Get-EventIdTally -LogName $channelName -EventId @(8001, 8002, 8003, 8004) `
            -Days $Days -MaxEvents $MaxEvents
        if ($query.Total -eq 0) {
            # "No events in the window" is the expected first-run answer and the
            # before picture this report exists to give - but only when the read
            # worked. A failed read prints what Windows said instead.
            if (-not (Write-EventReadNotice -Label $channelName -Detail $query.Detail)) {
                Write-Info ($channelName + ' - no NTLM audit events in the window')
            }
            continue
        }
        foreach ($id in @(8001, 8002, 8003, 8004)) {
            if ($query.Tally.ContainsKey($id)) {
                Write-Finding ('event ' + [string] $id + ' x' + [string] $query.Tally[$id] +
                               ' - ' + $meaning[$id])
            }
        }
        if ($query.Capped) { Write-Info ('  stopped at the cap of ' + [string] $MaxEvents) }
    }
    Write-Info 'Each of these is an authentication that would break if NTLM were restricted.'
}

#endregion

#region Event channel ---------------------------------------------------------

<#
    The audit events are worthless if the channel they land in is disabled or
    too small to hold a month, so the channel is part of what this script arms.
    That needs a change type of its own - a channel is neither a registry value
    nor an audit policy - kept deliberately small:

      { type: "eventchannel", channel, previousEnabled, previousMaxSizeBytes,
        newEnabled, newMaxSizeBytes, description }

    The channel NAME is discovered, not hard-coded: Microsoft documents the log
    by its Event Viewer path, "Applications and Services Log\Microsoft\Windows\
    NTLM", not by its wevtutil channel name, so # UNVERIFIED: that the channel
    is called exactly 'Microsoft-Windows-NTLM/Operational'. 'wevtutil el' is
    enumerated for channels starting 'Microsoft-Windows-NTLM/' and whatever is
    there is configured - the lesson verification/facts.json records under
    psv2-feature-names-differ-by-sku, where a hard-coded name would have matched
    nothing silently.

    'wevtutil gl' is parsed for 'maxSize:', a lab-proven read: fact
    eventlog-maxsize was measured with 'wevtutil gl Security' and its value is
    in BYTES, while the Group Policy MaxSize value is in kilobytes - so
    -NtlmChannelSizeKb is multiplied by 1024 first. # UNVERIFIED: the 'enabled:'
    line of the same output, which comes from the same dump as 'maxSize:' and
    'channelAccess:' (both read on the lab) but was not itself observed.

    The same dump carries 'logFileName:', which is what makes the disk guard in
    Set-TrackedEventChannel possible - see fact wevtutil-gl-reports-logfilename.
#>

$script:AuthorisedGrowthByVolume = @{}

function Get-AuthorisedGrowth {
    # What earlier channels in THIS run already booked on this volume. Raising a
    # ceiling leaves AvailableFreeSpace untouched, so without this every channel
    # would ask about the same unspent bytes and every one would be told yes.
    param([Parameter(Mandatory = $true)][string] $VolumeRoot)
    $key = $VolumeRoot.ToUpperInvariant()
    if ($script:AuthorisedGrowthByVolume.ContainsKey($key)) {
        return [decimal] $script:AuthorisedGrowthByVolume[$key]
    }
    return [decimal] 0
}

function Add-AuthorisedGrowth {
    param(
        [Parameter(Mandatory = $true)][string] $VolumeRoot,
        [Parameter(Mandatory = $true)][decimal] $Bytes
    )
    $key = $VolumeRoot.ToUpperInvariant()
    if (-not $script:AuthorisedGrowthByVolume.ContainsKey($key)) {
        $script:AuthorisedGrowthByVolume[$key] = [decimal] 0
    }
    $script:AuthorisedGrowthByVolume[$key] = [decimal] $script:AuthorisedGrowthByVolume[$key] + $Bytes
}

function Get-EventChannelState {
    <#
        Enabled state, maximum size, and where the channel's .evtx actually
        lives, from one 'wevtutil gl' dump.

        THE FILE PATH IS READ, NEVER ASSUMED. A channel can be relocated to
        another disk, and sizing it then authorises growth on a volume nothing
        measured - Enable-VssPreservation carried exactly that defect as V-1.
        Lab-measured under fact wevtutil-gl-reports-logfilename: 'wevtutil gl
        Security' emits 'logFileName: %SystemRoot%\System32\Winevt\Logs\
        Security.evtx' with the environment variable left UNEXPANDED, so it goes
        through ExpandEnvironmentVariables before it touches the filesystem.

        # UNVERIFIED: whether the 'logFileName' key name is localised on a
        # non-English host. If it were, VolumeRoot stays $null and the caller
        # REFUSES to size the channel. It never falls back to a guessed C: -
        # guessing is how the wrong volume gets measured, which is the whole
        # point of reading the path.
    #>
    param([Parameter(Mandatory = $true)][string] $Channel)

    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @('gl', $Channel)
    if ($result.ExitCode -ne 0) {
        return [PSCustomObject] @{
            Exists = $false; Enabled = $null; MaxSizeBytes = $null
            VolumeRoot = $null; FileBytes = [decimal] 0
            Detail = ($result.Output -join ' ')
        }
    }
    $enabled = $null
    $maxSize = $null
    $rawPath = $null
    foreach ($line in $result.Output) {
        if ($line -match '^\s*enabled:\s*(\S+)\s*$') {
            $enabled = [string]::Equals($Matches[1], 'true', [System.StringComparison]::OrdinalIgnoreCase)
        }
        elseif ($line -match '^\s*maxSize:\s*(\d+)\s*$') {
            $maxSize = [long] $Matches[1]
        }
        elseif ($line -match '^\s*logFileName:\s*(\S.*?)\s*$') {
            $rawPath = $Matches[1]
        }
    }

    $volumeRoot = $null
    $fileBytes = [decimal] 0
    $detail = ''
    if ([string]::IsNullOrWhiteSpace($rawPath)) {
        $detail = 'wevtutil gl reported no logFileName'
    }
    else {
        try {
            $full = [System.IO.Path]::GetFullPath(
                        [System.Environment]::ExpandEnvironmentVariables($rawPath))
            $root = [System.IO.Path]::GetPathRoot($full)
            if ([string]::IsNullOrWhiteSpace($root)) {
                $detail = ('logFileName has no volume root: ' + $full)
            }
            else {
                $volumeRoot = $root
                $item = Get-Item -LiteralPath $full -ErrorAction SilentlyContinue
                if ($null -ne $item) { $fileBytes = [decimal] $item.Length }
            }
        }
        catch {
            $detail = ('logFileName does not resolve to a path: ' + $rawPath)
        }
    }

    return [PSCustomObject] @{
        Exists = $true; Enabled = $enabled; MaxSizeBytes = $maxSize
        VolumeRoot = $volumeRoot; FileBytes = $fileBytes; Detail = $detail
    }
}

function Test-EventChannelDiskHeadroom {
    <#
        The arithmetic, stated so an operator can argue with it. A refusal they
        cannot check is a refusal they will work around.

        Raising maxSize consumes nothing today. It AUTHORISES the channel to grow
        to that size later, so the worst case is the target minus what the .evtx
        already occupies, and the floor is applied to the PROJECTED free space,
        not to today's. Applying it to today's would wave through every resize
        whose entire point is to consume more disk later - which is how a
        hardening script causes the outage it was deployed to prevent. Same
        reasoning as Test-EventLogDiskHeadroom in Enable-IRVisibility and
        Test-ShadowStorageHeadroom in Enable-VssPreservation.

        The guard self-resolves: once the log has grown into its allowance,
        growth falls towards zero and the volume passes, so a host with a big
        NTLM channel does not carry a permanent finding.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $VolumeRoot,
        [Parameter(Mandatory = $true)][decimal] $GrowthBytes,
        [Parameter(Mandatory = $true)][int] $FloorPercent
    )

    $booked = Get-AuthorisedGrowth -VolumeRoot $VolumeRoot
    try {
        $drive = New-Object System.IO.DriveInfo($VolumeRoot)
        $free = [decimal] $drive.AvailableFreeSpace
        $capacity = [decimal] $drive.TotalSize
    }
    catch {
        return [PSCustomObject] @{
            Allowed = $false
            Reason  = ('free space on ' + $VolumeRoot + ' could not be read (' +
                       $_.Exception.Message + '), so the cost is unknown')
        }
    }

    $projected = $free - $GrowthBytes - $booked
    $floor = [decimal] [math]::Floor($capacity * $FloorPercent / 100)
    $bookedText = ''
    if ($booked -gt 0) {
        # Named rather than folded into the arithmetic: an operator told "the
        # volume cannot take 64 MB" on a volume with gigabytes free will work
        # around the guard unless what this run already authorised is on the line
        # with it.
        $bookedText = (' once the ' + [string] $booked +
                       ' bytes this run already authorised on this volume are counted with it')
    }
    $verb = 'leaves'
    if ($projected -lt $floor) { $verb = 'would leave' }
    return [PSCustomObject] @{
        Allowed = ($projected -ge $floor)
        Reason  = ($VolumeRoot + ' has ' + [string] $free + ' bytes free; authorising ' +
                   [string] $GrowthBytes + ' bytes of growth ' + $verb + ' ' + [string] $projected +
                   $bookedText + ', against the ' + [string] $FloorPercent + '% floor of ' +
                   [string] $floor + ' bytes')
    }
}

function Get-NtlmChannelName {
    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @('el')
    if ($result.ExitCode -ne 0) {
        throw ('wevtutil el failed with exit code ' + [string] $result.ExitCode + ': ' +
               ($result.Output -join ' '))
    }
    $found = New-Object System.Collections.ArrayList
    foreach ($line in $result.Output) {
        $name = $line.Trim()
        if ($name.StartsWith($script:NtlmChannelPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void] $found.Add($name)
        }
    }
    return $found.ToArray()
}

function Set-TrackedEventChannel {
    <#
        Enables a channel and raises its maximum size, recording the previous
        state first and confirming by re-reading.

        The size test is ">= wanted", not "= wanted", deliberately: the event log
        service is free to round a requested size up, and an equality test would
        rewrite the channel on every run and report a change that is not one. A
        channel already bigger than asked for is left alone.

        A size raise is authorised only after Test-EventChannelDiskHeadroom
        agrees, on the volume the channel's own .evtx sits on.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Channel,
        [Parameter(Mandatory = $true)][long] $MaxSizeBytes
    )

    $before = Get-EventChannelState -Channel $Channel
    if (-not $before.Exists) {
        Write-Finding ($Channel + ' - channel not present here: ' + $before.Detail)
        return 0
    }

    $needEnable = ($before.Enabled -ne $true)
    $needSize   = ($null -eq $before.MaxSizeBytes -or $before.MaxSizeBytes -lt $MaxSizeBytes)
    if (-not $needEnable -and -not $needSize) {
        Write-Ok ($Channel + ' - already enabled and at least ' + [string] $MaxSizeBytes + ' bytes')
        return 0
    }

    # THE DISK GUARD, and it runs in -Audit too so the refusal is visible before
    # anyone reaches for -Apply. -NtlmChannelSizeKb is accepted up to 2097152
    # (2 GB) per matching channel, and docs/AUTHORING.md requires free space to be
    # checked on the volume that will hold the data - which is why
    # Get-EventChannelState reads logFileName instead of assuming C:. Domain
    # controllers are the hosts in a fleet least able to survive a full system
    # volume, and they are the only hosts this script runs on.
    if ($needSize) {
        if ([string]::IsNullOrWhiteSpace($before.VolumeRoot)) {
            Write-Finding ($Channel + ' - cannot locate its log file (' + $before.Detail +
                           '), so the disk cost of sizing it is unknown; leaving it alone.')
            return 0
        }
        # Worst case: the file fills to the new ceiling. What it already occupies
        # is not new growth.
        $growth = [decimal] $MaxSizeBytes - $before.FileBytes
        if ($growth -lt 0) { $growth = [decimal] 0 }
        $headroom = Test-EventChannelDiskHeadroom -VolumeRoot $before.VolumeRoot `
                        -GrowthBytes $growth -FloorPercent $MinimumFreeDiskPercent
        if (-not $headroom.Allowed) {
            Write-Finding ('REFUSED sizing ' + $Channel + ' to ' + [string] $MaxSizeBytes +
                           ' bytes: ' + $headroom.Reason + '. The channel is left exactly as it is. ' +
                           'Lower -NtlmChannelSizeKb or -MinimumFreeDiskPercent, or add disk.')
            return 0
        }
        # Booked in every mode, and only once the verdict is yes: a refused
        # volume gets no write, so nothing on it can grow and nothing is owed.
        Add-AuthorisedGrowth -VolumeRoot $before.VolumeRoot -Bytes $growth
    }

    if (-not $Apply) {
        Write-Finding ($Channel + ' - would enable and size to ' + [string] $MaxSizeBytes +
                       ' bytes (now enabled=' + [string] $before.Enabled + ', maxSize=' +
                       [string] $before.MaxSizeBytes + ')')
        return 0
    }

    [void] (Write-ManifestChange -Change @{
        type                 = 'eventchannel'
        channel              = $Channel
        previousEnabled      = $before.Enabled
        previousMaxSizeBytes = $before.MaxSizeBytes
        newEnabled           = $true
        newMaxSizeBytes      = $MaxSizeBytes
        description          = ($Channel + ': enabled, maxSize ' + [string] $MaxSizeBytes + ' bytes')
    })

    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath `
        -Arguments @('sl', $Channel, '/e:true', ('/ms:' + [string] $MaxSizeBytes))
    if ($result.ExitCode -ne 0) {
        throw ('wevtutil sl failed for ' + $Channel + ' with exit code ' +
               [string] $result.ExitCode + ': ' + ($result.Output -join ' '))
    }

    $after = Get-EventChannelState -Channel $Channel
    if ($after.Enabled -ne $true -or $null -eq $after.MaxSizeBytes -or
        $after.MaxSizeBytes -lt $MaxSizeBytes) {
        throw ('Channel ' + $Channel + ' did not read back as enabled and at least ' +
               [string] $MaxSizeBytes + ' bytes (enabled=' + [string] $after.Enabled +
               ', maxSize=' + [string] $after.MaxSizeBytes + ')')
    }
    Write-Ok ($Channel + ' - enabled, maxSize ' + [string] $after.MaxSizeBytes + ' bytes')
    return 1
}

function Restore-EventChannel {
    <#
        Returns 'restored', 'declined' or 'declined-permanent' per the doctrine
        in docs/DESIGN.md section 4.1; throws on a failed write. Declines
        unless the channel still holds what this run set - a channel somebody has
        since resized or disabled deliberately is not this script's to put back.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change

    # THE CONSTRAINT COMES FROM THE SCRIPT, NEVER FROM THE RECORD - the same rule
    # $script:OwnedRegistryKey enforces for the template's registry restorer. The
    # manifest is operator-writable input, and this restorer hands its channel
    # name straight to 'wevtutil sl /e: /ms:', so an unconstrained record could
    # disable or shrink the Security channel through the rollback path of a script
    # whose job is arming logging. Set-TrackedEventChannel is only ever called
    # with a channel Get-NtlmChannelName enumerated, so every legitimate
    # 'eventchannel' record from this script names one under the NTLM prefix; a
    # record naming anything else did not come from here.
    $channelName = [string] $change.channel
    if (-not $channelName.StartsWith($script:NtlmChannelPrefix,
                                     [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('Refusing to roll back a channel this script does not configure: "' + $channelName +
               '". It writes only channels starting ' + $script:NtlmChannelPrefix + '.')
    }

    $current = Get-EventChannelState -Channel $change.channel

    if (-not $current.Exists) {
        Write-Finding ($change.channel + ' - channel no longer present; leaving it alone.')
        return 'declined'
    }

    # WHAT WAS NEVER RECORDED CAN NEVER BE PUT BACK - doctrine case 4, and
    # neither of the two answers this used to give.
    #
    # Set-TrackedEventChannel treats an unread value as "needs changing":
    # $needEnable when 'enabled:' did not parse as true, $needSize when
    # 'maxSize:' did not parse at all. So a null here means the run DID write
    # that half of the channel and could not record what it overwrote, and
    # 'wevtutil sl' has no form meaning "put it back the way it was".
    #
    # Returning plain 'declined' for a null previousEnabled left the run
    # retryable, so every later -Rollback re-selected it and it blocked
    # everything older - the A-2 shape described below. A null
    # previousMaxSizeBytes was worse: it made the size half of the case-2 test
    # vacuously true, so a channel whose enabled state happened to match got an
    # [ ok ] line naming THIS RUN'S enlarged size as its "recorded previous
    # state", and the run was marked completed with the growth still in place.
    $enabledRecorded = ($null -ne $change.previousEnabled)
    $sizeRecorded    = ($null -ne $change.previousMaxSizeBytes)
    if (-not $enabledRecorded -or -not $sizeRecorded) {
        $unread = 'the previous maximum size'
        if (-not $enabledRecorded -and -not $sizeRecorded) {
            $unread = 'neither the previous enabled state nor the previous maximum size'
        }
        elseif (-not $enabledRecorded) {
            $unread = 'the previous enabled state'
        }
        Write-Finding ($change.channel + ' - ' + $unread + ' was never read, so this change can never ' +
                       'be undone by any run. The channel keeps what -Apply gave it (enabled=' +
                       [string] $current.Enabled + ', maxSize=' + [string] $current.MaxSizeBytes +
                       '); set it by hand with wevtutil sl if you need it smaller.')
        return $script:RollbackDeclinedPermanent
    }

    # Three-way host resolution (docs/DESIGN.md section 4, A-2). Case 2 FIRST: the
    # host already holds the PRE-APPLY state, so there is nothing to undo -
    # either the write never landed (an EventLog policy value can override
    # 'wevtutil sl /ms:' so the size never sticks - verification/facts.json) or it
    # has already been restored. The doctrine counts both as RESTORED - nothing
    # to do and nothing wrong - which is what makes the run leave the eligible
    # set. NOT 'declined-permanent': that is case 4, for a change no rollback
    # can ever undo. Returning plain 'declined' was the A-2 defect: it left the
    # run retryable, so every future -Rollback re-selected it and it never
    # converged. Proven on the lab.
    #
    # Both halves are known to be RECORDED by the guard above, so neither side of
    # this test can be vacuously satisfied by a value nobody ever read.
    $atPreviousSize = ($null -ne $current.MaxSizeBytes -and
                       [long] $current.MaxSizeBytes -eq [long] $change.previousMaxSizeBytes)
    if (($current.Enabled -eq [bool] $change.previousEnabled) -and $atPreviousSize) {
        Write-Ok ($change.channel + ' already holds its recorded previous state (enabled=' +
                    [string] $change.previousEnabled + ', maxSize=' + [string] $current.MaxSizeBytes +
                    '); nothing to undo.')
        return 'restored'
    }

    # Case 3: the host holds neither the applied value nor the previous one, so
    # somebody changed it after the -Apply; this rollback does not own it.
    if ($current.Enabled -ne [bool] $change.newEnabled -or $null -eq $current.MaxSizeBytes -or
        $current.MaxSizeBytes -lt [long] $change.newMaxSizeBytes) {
        Write-Finding ($change.channel + ' no longer holds what this run set; leaving it alone.')
        return 'declined'
    }
    # Case 1 falls through: the host holds what -Apply set - restore it.

    $enabledToken = 'false'
    if ([bool] $change.previousEnabled) { $enabledToken = 'true' }
    # /ms: unconditionally: reaching here means both halves were recorded, so
    # omitting it would leave the size this run raised in place while the [ ok ]
    # line below claimed the channel state was restored.
    $wevtArgs = @('sl', $change.channel, ('/e:' + $enabledToken),
                  ('/ms:' + [string] ([long] $change.previousMaxSizeBytes)))

    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments $wevtArgs
    if ($result.ExitCode -ne 0) {
        throw ('wevtutil sl failed restoring ' + $change.channel + ' with exit code ' +
               [string] $result.ExitCode + ': ' + ($result.Output -join ' '))
    }
    Write-Ok ('Restored the channel state on ' + $change.channel)
    return 'restored'
}

#endregion

#region Checks ----------------------------------------------------------------

function Invoke-HostCheck {
    <#
        The whole job, in the order an operator reads it: what the host is, what
        is enforced today, what gets turned on, and what the logs already say.
    #>
    param([Parameter(Mandatory = $true)] $Role)

    Write-Info ($Role.RoleName + ' in domain "' + $Role.Domain + '"')
    Write-EnforcementReport

    $changeCount = 0
    $changeCount += Set-NtlmAuditing -DomainValue $DomainAuditValue -IncomingValue $IncomingAuditValue
    $changeCount += Set-LdapInterfaceDiagnostic

    Write-Section 'NTLM operational channel'
    # @() around the call, not just around the return inside it: PowerShell
    # unrolls an empty array returned from a function into $null, and $null.Count
    # is $null - so the "no channel" finding below would never fire and the
    # script would go quiet on exactly the host that needs the warning.
    $channel = @(Get-NtlmChannelName)
    if ($channel.Count -eq 0) {
        Write-Finding ('no channel starting with ' + $script:NtlmChannelPrefix +
                       ' here - the NTLM audit events have nowhere to go')
    }
    foreach ($channelName in $channel) {
        $changeCount += Set-TrackedEventChannel -Channel $channelName `
            -MaxSizeBytes ([long] $NtlmChannelSizeKb * 1024)
    }

    Write-UnsignedLdapReport -Days $LookbackDays -MaxEvents $MaxEventScanned -TopCount 20
    Write-NtlmEventReport -Channel $channel -Days $LookbackDays -MaxEvents $MaxEventScanned
    return $changeCount
}

#endregion

#region Main -----------------------------------------------------------------

function Restore-LegacyAuthChange {
    <#
        Routes a change record to the right restorer. The template's
        Restore-TrackedChange only knows the registry and declines anything else
        - correctly, since silently "succeeding" on a change type it cannot undo
        is how a run gets marked rolled back while the host stays modified. This
        script introduces the 'eventchannel' type, so it handles that one here
        and delegates the rest.

        Returns 'restored', 'declined' or 'declined-permanent'; throws on
        failure.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    if ($change.type -eq 'eventchannel') {
        return (Restore-EventChannel -ChangeRecord $ChangeRecord)
    }
    return (Restore-TrackedChange -ChangeRecord $ChangeRecord)
}

function Invoke-Main {
    $mode = 'Audit'
    if ($Apply)    { $mode = 'Apply' }
    if ($Rollback) { $mode = 'Rollback' }

    Write-Host ''
    Write-Host ('IronBlackBox - ' + $script:ScriptName + ' v' + $script:ScriptVersion + ' [' + $mode + ']') -ForegroundColor White
    Write-Host '  AUDIT ONLY: this script never restricts NTLM and never requires LDAP signing.' -ForegroundColor Yellow

    # P-1: value checks BEFORE anything is read, locked or changed. These were
    # [Validate*] attributes; a binding-time failure exits 1, which collides with
    # "findings" (docs/DESIGN.md section 3). A throw here reaches exit 2.
    Assert-ParameterRange   -Name 'DomainAuditValue' -Value $DomainAuditValue -Minimum 0 -Maximum 7
    Assert-ParameterRange   -Name 'IncomingAuditValue' -Value $IncomingAuditValue -Minimum 0 -Maximum 2
    Assert-ParameterRange   -Name 'NtlmChannelSizeKb' -Value $NtlmChannelSizeKb -Minimum 1024 -Maximum 2097152
    Assert-ParameterRange   -Name 'MinimumFreeDiskPercent' -Value $MinimumFreeDiskPercent -Minimum 0 -Maximum 90
    Assert-ParameterRange   -Name 'LookbackDays' -Value $LookbackDays -Minimum 1 -Maximum 365
    Assert-ParameterRange   -Name 'MaxEventScanned' -Value $MaxEventScanned -Minimum 1 -Maximum 500000

    # -AbandonRun ALREADY names the run to act on, so a -RunId naming a different
    # one is a contradiction, not a preference - and the parameter sets accept the
    # pair. The resolution below used to compute the -RunId target and then throw
    # it away, so this combination acted silently on the abandoned run; worse, a
    # -RunId whose run was already rolled back made Get-RollbackTargetRun throw
    # and the run exit 2, defeating the escape hatch docs/DESIGN.md section 4.2
    # exists to provide, after the abandon target had already been approved.
    if (-not [string]::IsNullOrWhiteSpace($AbandonRun) -and
        -not [string]::IsNullOrWhiteSpace($RunId) -and
        -not [string]::Equals($RunId.Trim(), $AbandonRun.Trim(),
                              [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('-RunId ' + $RunId + ' and -AbandonRun ' + $AbandonRun + ' name different runs. ' +
               '-AbandonRun names the run to act on by itself; pass one or the other.')
    }

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')

    # Suitability gate. Not applicable is exit 0 with a clear message: never a
    # finding (an RMM must not alert on a member server for not being a DC) and
    # never an error. Deliberately BEFORE the lock and the manifest, so an
    # -Apply on the wrong host writes nothing at all - not even a run record.
    #
    # -Rollback is exempt: the manifest, not the host's current role, is the
    # authority on what this toolkit changed. A DC demoted after an -Apply must
    # still be able to undo it.
    if ($mode -ne 'Rollback') {
        $role = Get-HostRoleState
        Write-Section 'Host role'
        if (-not $role.IsDomainController) {
            Write-Info ($role.RoleName + ' (DomainRole ' + [string] $role.DomainRole + ')')
            Write-Section 'Result'
            Write-Ok 'Not a domain controller: nothing in this script applies here. Nothing was changed.'
            Write-Info 'NTLM domain auditing and LDAP interface diagnostics are domain controller settings.'
            Write-Info 'Auditing incoming NTLM on member servers is deliberately out of scope; see the header.'
            return 0
        }
    }

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        [void] (Invoke-HostCheck -Role $role)
        Write-Section 'Result'
        if ($script:Findings.Count -gt 0) {
            Write-Info ([string] $script:Findings.Count + ' finding(s). Re-run with -Apply to turn on what is missing.')
            Write-Info 'Findings here are of two kinds: auditing that is off, and legacy authentication that is'
            Write-Info 'already happening. The second kind is not fixed by -Apply - it is fixed by the clients.'
            return 1
        }
        if ($script:HostLimits.Count -gt 0) {
            Write-Ok ([string] $script:HostLimits.Count + ' host limit(s) reported above: true '  +
                      'on this host and not clearable by any -Apply, so they do not raise the '  +
                      'exit code.')
            return 0
        }
        Write-Ok 'No findings: the auditing is on and nothing legacy showed up in the window read.'
        return 0
    }

    Enter-ToolkitLock -ToolkitRootPath $resolvedRoot
    try {
        $allowMissingStamp = ($mode -eq 'Rollback')
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -AllowMissingStamp:$allowMissingStamp)
        Assert-ManifestUsable

        if ($mode -eq 'Apply') {
            [void] (Start-ManifestRun -Mode 'Apply' -Parameters @{
                toolkitRoot        = $resolvedRoot
                domainAuditValue   = $DomainAuditValue
                incomingAuditValue = $IncomingAuditValue
                ntlmChannelSizeKb  = $NtlmChannelSizeKb
                minimumFreeDiskPercent = $MinimumFreeDiskPercent
                lookbackDays       = $LookbackDays
            })

            $status = 'completed'
            # The VERIFIED change count, NOT the number of records written.
            # docs/DESIGN.md section 4 flushes a change record BEFORE its change,
            # so $script:ChangeIndex counts INTENTS. A setter that finds the host
            # silently refused returns without counting. Reporting ChangeIndex as
            # "applied" was defect U-3: 'fsutil usn createjournal' exits 0 for a
            # resize it declines, and -Apply printed "1 change(s) applied" two
            # lines under its own finding saying the journal was UNCHANGED.
            $verified = 0
            try {
                $verified = Invoke-HostCheck -Role $role
            }
            catch {
                Write-Failure $_.Exception.Message
                $status = 'completed-with-failures'
            }
            Stop-ManifestRun -Status $status
            Write-Section 'Result'
            if ($status -ne 'completed') { return 2 }
            Write-Ok ([string] $verified + ' change(s) applied.')
            if ($script:ChangeIndex -gt $verified) {
                Write-Finding ([string] ($script:ChangeIndex - $verified) + ' change(s) were RECORDED in ' +
                               'the manifest but did NOT land on the host - see above. The records stay by ' +
                               'design: -Rollback resolves each against the host, and one that never ' +
                               'landed needs nothing undone.')
            }
            elseif ($verified -gt $script:ChangeIndex) {
                Write-Finding ('more changes were applied (' + [string] $verified + ') than were recorded (' +
                               [string] $script:ChangeIndex + '). A change without a record cannot be rolled ' +
                               'back; treat this host as modified and investigate before re-running.')
            }
            Write-Info 'The NTLM audit values and the LDAP diagnostic level are documented to take effect'
            Write-Info 'without a restart. THIS WAS NOT VERIFIED HERE - no domain controller has run this.'
            Write-Info 'Confirm the effect the only way that proves it: come back in 24 hours and look for'
            Write-Info 'events 8004 in the NTLM channel and 2889 in the Directory Service log.'
            if ($script:Findings.Count -gt 0) {
                Write-Info ([string] $script:Findings.Count + ' finding(s) remain.')
                if ($script:HostLimits.Count -gt 0) {
                    Write-Info ([string] $script:HostLimits.Count + ' host limit(s) as well - see ' +
                                '[limit] above. Those are NOT part of the exit code.')
                }
                return 1
            }
            if ($script:HostLimits.Count -gt 0) {
                Write-Ok ([string] $script:HostLimits.Count + ' host limit(s) reported above: true on ' +
                          'this host and not clearable by any -Apply, so they do not raise the exit code.')
            }
            return 0
        }

        # Rollback
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun)) {
            Write-Section ('Abandoning run ' + $AbandonRun)
            Write-Info 'This does NOT undo anything and does NOT touch the host. It rolls back what it'
            Write-Info 'still can, then records that an operator chose to stop trying on the rest.'
            Write-Info 'Test-VisibilityDrift will stop reporting the abandoned changes for this run.'
            if (-not (Test-AbandonRunTarget -RunIdToAbandon $AbandonRun)) { return 2 }
        }

        # Resolved ONCE. Two calls meant the -RunId one ran first and could throw
        # ("Run <id> has already been rolled back.") before the -AbandonRun target
        # was ever reached - see the guard in the parameter checks above.
        $explicitRunId = $RunId
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun)) { $explicitRunId = $AbandonRun }
        $target = Get-RollbackTargetRun -ExplicitRunId $explicitRunId
        if ($null -eq $target) {
            Write-Section 'Result'
            Write-Info 'Nothing to roll back: no eligible run for this script in the manifest.'
            return 0
        }

        Write-Section ('Rolling back run ' + $target.RunId)
        [void] (Start-ManifestRun -Mode 'Rollback' -Parameters @{ targetRunId = $target.RunId })
        $failures = 0
        $declinedRetryable = 0
        $declinedPermanent = 0
        # PER-CHANGE OUTCOMES, and this is the other half of the R-1 fix.
        #
        # Excluding a whole run once its rollback completed is not enough. A run
        # can contain one change that legitimately declines - the host holds
        # neither value, because a LATER run of the same script touched it - and
        # eighteen that were restored perfectly. The run status is then 'failed',
        # and a detector that works per-RUN goes on expecting all nineteen, so
        # the eighteen restored ones are reported as drift forever. Measured
        # exactly that way on the domain member.
        #
        # Host state cannot substitute for this record: a value returned to its
        # pre-hardening state by a rollback and a value an attacker switched off
        # look identical. Only the rollback's own account of what it did can
        # tell them apart, so it writes that account down.
        $restoredIds = New-Object System.Collections.ArrayList
        $permanentIds = New-Object System.Collections.ArrayList
        $declinedIds = New-Object System.Collections.ArrayList
        # Reverse order: later changes may depend on earlier ones.
        for ($i = $target.Changes.Count - 1; $i -ge 0; $i--) {
            $changeId = [string] $target.Changes[$i].changeId
            try {
                $outcome = Restore-LegacyAuthChange -ChangeRecord $target.Changes[$i]
                if ($outcome -eq $script:RollbackDeclinedPermanent) {
                    $declinedPermanent++
                    [void] $permanentIds.Add($changeId)
                }
                elseif ($outcome -ne $script:RollbackRestored) {
                    $declinedRetryable++
                    [void] $declinedIds.Add($changeId)
                }
                else { [void] $restoredIds.Add($changeId) }
            }
            catch {
                $failures++
                Write-Failure $_.Exception.Message
            }
        }


        # -AbandonRun short-circuits the status: whatever still declines is given
        # up on, by name, on the record. Failures are NOT abandoned - a thrown
        # restorer is a bug or a broken host, not an operator decision.
        #
        # AND THERE HAS TO BE SOMETHING TO ABANDON. Without the count below, an
        # operator who reached for -AbandonRun on a run that then rolled back
        # perfectly got 'completed-abandoned-by-operator' on the forensic record
        # and exit 1 - a clean rollback permanently mislabelled as an operator
        # giveup, and reported as one by Test-VisibilityDrift on every later run
        # (docs/DESIGN.md section 4.2, property 4). Nothing was left undone, so
        # the honest answer is the ordinary completed path and exit 0.
        $abandonable = @($declinedIds).Count + @($permanentIds).Count
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun) -and $failures -eq 0 -and $abandonable -eq 0) {
            Write-Info ('Nothing needed abandoning: every change in run ' + $target.RunId +
                        ' restored cleanly, so this is recorded as an ordinary completed rollback.')
        }
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun) -and $failures -eq 0 -and $abandonable -gt 0) {
            Invoke-AbandonRun -RunIdToAbandon $target.RunId `
                -DeclinedChangeIds @($declinedIds.ToArray() + $permanentIds.ToArray()) `
                -RestoredChangeIds @($restoredIds.ToArray())
            Stop-ManifestRun -Status 'completed-abandoned-by-operator'
            Write-Section 'Result'
            Write-Info ([string] @($restoredIds).Count + ' change(s) restored, ' +
                        [string] (@($declinedIds).Count + @($permanentIds).Count) +
                        ' abandoned on your instruction. The host still holds whatever those changes' +
                        ' left behind, and this run will not be offered again.')
            return 1
        }

        $rollbackStatus = Get-RollbackRunStatus -Failures $failures `
            -DeclinedRetryable $declinedRetryable -DeclinedPermanent $declinedPermanent
        Write-ManifestRecord -Record @{
            recordType   = 'rollback'
            runId        = $target.RunId
            timestampUtc = (Get-UtcStamp)
            status       = $rollbackStatus
            detail       = ([string] $target.Changes.Count + ' change(s), ' +
                            [string] $failures + ' failure(s), ' +
                            [string] $declinedRetryable + ' declined (retryable), ' +
                            [string] $declinedPermanent + ' declined (permanent)')
            restoredChangeIds  = @($restoredIds.ToArray())
            permanentChangeIds = @($permanentIds.ToArray())
        }
        $runEndStatus = 'completed'
        if ($rollbackStatus -eq 'failed') { $runEndStatus = 'completed-with-failures' }
        Stop-ManifestRun -Status $runEndStatus

        Write-Section 'Result'
        if ($failures -gt 0) {
            Write-Info ([string] $failures + ' change(s) could not be restored. The run stays retryable.')
            return 2
        }
        if ($declinedRetryable -gt 0) {
            Write-Info ([string] $declinedRetryable + ' change(s) were left alone because the host holds' +
                        ' neither what this run set nor what was recorded before it. The run stays' +
                        ' retryable; read the finding(s) above before retrying.')
            return 1
        }
        if ($declinedPermanent -gt 0) {
            Write-Info ([string] $declinedPermanent + ' change(s) cannot be undone by this toolkit and' +
                        ' never will be - see the finding(s) above. Everything else was restored, so this' +
                        ' run is finished and will not be offered again.')
            return 1
        }
        Write-Ok 'Rollback complete.'
        return 0
    }
    finally {
        Exit-ToolkitLock
    }
}

try {
    exit (Invoke-Main)
}
catch {
    Write-Failure $_.Exception.Message
    if ($null -ne $_.ScriptStackTrace) { Write-Info $_.ScriptStackTrace }
    exit 2
}

#endregion

