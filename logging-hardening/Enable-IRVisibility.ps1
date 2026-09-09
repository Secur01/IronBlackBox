<#
.SYNOPSIS
    Turns on the Windows forensic logging that is off by default: PowerShell
    ScriptBlock and module logging, transcription, command line on process
    creation, an IR-oriented audit policy, event log sizing, and firewall
    connection logging.

.DESCRIPTION
    The anchor script of IronBlackBox. Most of the toolkit's value is here:
    without these settings a responder gets a host that cannot say what ran on
    it. Everything it changes is recorded to the manifest before the change is
    made, so -Rollback can put the host back.

    Every registry path, value name and value kind in this script is either
    extracted from the ADMX policy definitions Microsoft ships on the target OS
    (verification/facts.json records which) or measured on a lab host. None of
    it is written from memory. Audit subcategories are addressed by their
    well-known GUID rather than by display name, because the names are
    localised.

    What this script deliberately does NOT do:
      - Defender preferences. They are not registry state, so tracking and
        rolling them back needs a change type this script does not introduce.
        They belong in their own increment.
      - Object Access auditing for File System and Registry. Those produce
        nothing without SACLs on the objects themselves, and turning them on
        blind is how a Security log fills in an hour.
      - The Public firewall profile. Windows ships no logging policy for it;
        see verification/facts.json, fact firewall-logging.

.PARAMETER Audit
    Default. Strictly read-only. Reports what is currently off and what -Apply
    would turn on.

.PARAMETER Apply
    Turns the settings on, recording each previous value to the manifest first.

.PARAMETER Rollback
    Restores the previous values recorded by a prior -Apply.

.PARAMETER ToolkitRoot
    Base directory for the manifest, transcripts and the firewall log.
    Default C:\ProgramData\IronBlackBox. Validated before use.

.PARAMETER SecurityLogSizeKb
    Target size of the Security event log, in KILOBYTES (the unit the policy
    itself uses - see verification/facts.json, fact eventlog-maxsize).
    Default 2097152 (2 GB). The ADMX minimum is 20480.

    2 GB rather than 1 GB because the audit target list includes Group
    Membership, whose event 4627 was measured at exactly one event per logon
    session - it roughly doubles the per-logon record - and both Kerberos
    subcategories, which are high volume on domain controllers.

.PARAMETER OtherLogSizeKb
    Target size of the Application and System logs, in kilobytes.
    Default 262144 (256 MB).

.PARAMETER FirewallLogSizeKb
    Target size of each firewall profile log, in kilobytes. The ADMX allows
    128 to 32767; default 16384 (16 MB).

.PARAMETER PowerShellChannelSizeBytes
    Floor for both PowerShell channels, in BYTES because that is what
    'wevtutil sl /ms:' takes. The EventLog policy has its own MaxSize value which
    takes KILOBYTES instead, and confusing the two is this project's worst
    measured bug - but that value is not this parameter and does not reach a
    modern channel. Default 268435456 (256 MB). A channel already larger is left
    alone, so this never discards an event by shrinking.

.PARAMETER LateralMovementChannelSizeBytes
    Floor for the channels that carry lateral movement, also in BYTES. Default
    67108864 (64 MB). Covers RDP session and connection history and the three SMB
    channels - five channels Windows enables and then caps at 1 MB and 8 MB.

    These are a CEILING: an event log is circular, so raising this costs disk as
    the channel fills, not on the day it is set. This project could not measure a
    real event rate for them - the note above their list in the code says so - so
    on a busy file server measure before trusting the default.

.PARAMETER MinimumFreeDiskPercent
    Share of each volume that must still be free once EVERYTHING this run
    authorises on it has grown to its configured maximum. Default 10. A volume
    that would drop below the floor is SKIPPED rather than sized, and the run
    reports a finding - a smaller log is a degraded recorder, a full system disk
    is a dead server.

    Everything, not each thing separately: the event logs, both sets of sized
    channels and the transcript backstop are summed per volume across the whole
    run, because raising a ceiling consumes nothing on the day it is set, so
    free space has not moved when the next section asks. Judged one at a time
    they all fit and the volume still overflowed.

    Transcription is the exception to "skipped rather than applied". It is
    enabled either way and its allowance is still counted, so the resizes have
    to fit around it - an unrecorded PowerShell session is worse evidence loss
    than any log this guard would shrink.

    Enable-VssPreservation uses the same parameter name with a default of 20.
    The difference is deliberate: a shadow storage area is sized as a
    percentage of the volume and is large, while the event logs are a fixed and
    comparatively small allocation, so a 10% floor is proportionate here.

    Setting it to 0 does not disable the guard - it still refuses to authorise
    more growth than the volume has free space for. It only removes the
    reserve kept on top of that.

.PARAMETER IncludeInvocationLogging
    Also enable EnableScriptBlockInvocationLogging, which logs the start and
    stop of every script block. Off by default: it is extremely high volume and
    will bury 4104 on a busy host.

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
    .\Enable-IRVisibility.ps1
    Reports which visibility settings are missing. Changes nothing.

.EXAMPLE
    .\Enable-IRVisibility.ps1 -Apply
    Turns them on and records every previous value.

.EXAMPLE
    .\Enable-IRVisibility.ps1 -Rollback
    Restores the host to its pre-Apply state, audit policy included.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.0.1
    License : MIT

    Windows PowerShell 5.1. No module dependencies. Requires local
    administrator; enforced in code by Assert-Elevated, deliberately not by
    #Requires -RunAsAdministrator (see docs/DESIGN.md section 3).
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
    [int] $SecurityLogSizeKb = 2097152,

    [Parameter()]
    [int] $OtherLogSizeKb = 262144,

    [Parameter()]
    [int] $FirewallLogSizeKb = 16384,

    # AT-13. This script switches ScriptBlock logging ON - the highest-volume
    # PowerShell telemetry there is - and used to leave the channel that receives
    # it at its 15 MB default. Measured on the lab: under the load of this
    # toolkit's own collectors, 15 MB holds ELEVEN SECONDS. BYTES, not kilobytes:
    # wevtutil /ms: takes bytes, unlike the EventLog policy value of the same name.
    [Parameter()]
    [long] $PowerShellChannelSizeBytes = 268435456,

    [Parameter()]
    [long] $LateralMovementChannelSizeBytes = 67108864,

    # Transcription is the ONLY unbounded thing this toolkit turns on. The event
    # channels are circular - they hit their maximum and overwrite - so their disk
    # cost is a ceiling, not a growth rate. Transcripts are files, and PowerShell
    # never removes them. Measured on the lab: 233 files for 574 KB after two days,
    # so the pressure is file COUNT rather than bytes, and PowerShell already files
    # them into YYYYMMDD day folders - which is the unit this rotation works on.
    [Parameter()]
    [switch] $DisableTranscription,

    # Day folders older than this are compressed to <YYYYMMDD>.zip. Measured
    # compression on real transcripts: 2.7:1 - useful, but the real win is turning
    # thousands of tiny files into one.
    [Parameter()]
    [int] $TranscriptCompressAfterDays = 7,

    # The retention POLICY: day folders and archives older than this are deleted.
    [Parameter()]
    [int] $TranscriptKeepDays = 90,

    # A BACKSTOP, not the policy. If the total exceeds this, the oldest days are
    # evicted - and if that evicts anything younger than -TranscriptKeepDays, the
    # rotation records it and -Audit reports it as a finding. AT-13 is why: a size
    # cap without knowing the fill rate silently redefines the retention window,
    # and 15 MB of PowerShell/Operational turned out to hold eleven seconds.
    [Parameter()]
    [long] $TranscriptMaxBytes = 2147483648,

    [Parameter()]
    [int] $MinimumFreeDiskPercent = 10,

    [Parameter()]
    [switch] $IncludeInvocationLogging,

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

$script:ScriptName    = 'Enable-IRVisibility'
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

#region Scheduled task helpers [shared] --------------------------------------

# COPIED BETWEEN THE SCRIPTS THAT REGISTER A TASK, and marked [shared] so
# tools/check.ps1 compares the copies. Not in the template: the fifteen scripts
# that register no task have no use for it.
#
# It is a region because it was three. Remove-TrackedScheduledTask - the ROLLBACK
# for a scheduledtask change, so the code that undoes a change on a customer
# host - existed in three versions across Deploy-TamperAlerts,
# Enable-VssPreservation and Enable-IRVisibility. The three differed only in
# comments and one message, verified before unifying, but nothing was comparing
# them and nothing would have caught the first behavioural difference.
#
# The message says "the handler script was left in place" and nothing more.
# Enable-IRVisibility's copy also mentioned transcripts, which is true of its
# task and of no other; that note moved to its call site rather than being lost
# to make the copies identical.

function Get-ToolkitScheduledTask {
    <#
        Returns the task or $null. Microsoft does not document whether
        Get-ScheduledTask throws or returns nothing for a task that does not
        exist, so both are handled and neither is assumed. Matching is on the
        EXACT path and name - never a wildcard, because a wildcard here would be a
        wildcard in the rollback that calls it.
        https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask
    #>
    param(
        [Parameter(Mandatory = $true)][string] $TaskPath,
        [Parameter(Mandatory = $true)][string] $TaskName
    )
    try { $found = @(Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop) }
    catch { return $null }
    if ($found.Count -eq 0) { return $null }
    return $found[0]
}

function New-TaskMarker {
    <#
        The string embedded in the task's Description and recorded in the
        manifest. -Rollback refuses to unregister a task whose description no
        longer carries it.

        This is what turns "delete the task with this name" into "delete the task
        THIS RUN created". A name match alone is not enough: an operator, another
        tool, or a later toolkit version could legitimately own a task at the same
        path, and unregistering it because the name matched is exactly the "never
        delete a task you did not create" failure.
    #>
    return ('IronBlackBox|' + $script:ScriptName + '|' + [string] $script:CurrentRunId)
}

function Remove-TrackedScheduledTask {
    # The rollback for a 'scheduledtask' change. The same helper, body for body,
    # as the one in anti-tampering/Enable-VssPreservation.ps1 - a deliberate copy
    # per docs/AUTHORING.md, so it changes in both or in neither.
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change   = $ChangeRecord.change
    $taskPath = [string] $change.taskPath
    $taskName = [string] $change.taskName

    # The manifest is operator-writable input, not trusted state. Constrain the
    # folder the way the template constrains the registry hive on rollback, so a
    # tampered or planted manifest cannot turn -Rollback into "unregister any task
    # on this host, as SYSTEM".
    if ($taskPath -ne $script:TaskFolderPath) {
        throw ('Refusing to roll back a task outside ' + $script:TaskFolderPath + ': ' + $taskPath)
    }

    $task = Get-ToolkitScheduledTask -TaskPath $taskPath -TaskName $taskName
    if ($null -eq $task) {
        Write-Ok ('Scheduled task ' + $taskPath + $taskName + ' is already absent.')
        return 'restored'
    }

    $marker = [string] $change.marker
    $description = ''
    if ($null -ne $task.Description) { $description = [string] $task.Description }
    if ([string]::IsNullOrWhiteSpace($marker) -or
        $description.IndexOf($marker, [System.StringComparison]::Ordinal) -lt 0) {
        Write-Finding ('The task at ' + $taskPath + $taskName + ' does not carry this run''s marker, ' +
                       'so it is not the task this run registered. Leaving it alone.')
        return 'declined'
    }

    Unregister-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Confirm:$false
    if ($null -ne (Get-ToolkitScheduledTask -TaskPath $taskPath -TaskName $taskName)) {
        throw ('Unregister-ScheduledTask returned without error but ' + $taskPath + $taskName +
               ' is still registered.')
    }
    Write-Ok ('Removed scheduled task ' + $taskPath + $taskName + '; the handler script was left in place.')
    return 'restored'
}

#endregion

#region Native tool paths ----------------------------------------------------

# Resolved ONCE, here, and never called by bare name. This script runs as SYSTEM,
# so a bare name would let any machine PATH entry an unprivileged user can write
# to decide which binary runs with SYSTEM's token. Get-NativeToolPath falls back
# to the bare name when no expected directory holds the file - and says so as a
# finding - so an unusual layout degrades loudly instead of silently.
$script:AuditpolPath = Get-NativeToolPath -FileName 'auditpol.exe'
$script:WevtutilPath = Get-NativeToolPath -FileName 'wevtutil.exe'

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
#   ScriptBlock/Module/Transcription policy, the cmdline-on-4688 audit value,
#   event log sizing and firewall logging.
$script:OwnedRegistryKey = @(
    'HKLM:\Software\Policies\Microsoft\Windows\PowerShell',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit',
    'HKLM:\Software\Policies\Microsoft\Windows\EventLog',
    'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
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
#region Audit policy ----------------------------------------------------------

<#
    Audit policy is not registry state, so it needs its own change type and its
    own rollback path.

    Subcategories are addressed by well-known GUID, never by display name: the
    names are localised and a script matching on "Process Creation" reads
    nothing on a French or German host.

    Rollback works by restoring a full 'auditpol /backup' file captured before
    the first change, rather than by replaying individual settings. Two reasons,
    both proven on the lab:
      - The backup CSV carries a NUMERIC 'Setting Value' column (0 = none,
        1 = success, 3 = success and failure), so reading state does not depend
        on parsing localised text like "Success and Failure".
      - 'auditpol /restore' is the tool's own inverse operation and puts back
        the whole policy atomically, including anything this script never
        touched.
    Column values are read BY INDEX, not by header name, because the headers
    themselves may be localised (verification/facts.json, open question 4).
#>

# GUIDs verified on the lab via 'auditpol /list /subcategory:* /r'.
# SettingValue: 1 = Success, 2 = Failure, 3 = Success and Failure.
#
# The event IDs in the 'Why' column, and every "Microsoft recommends" or
# "Microsoft documents" below, come from that subcategory's own page under
# Microsoft's advanced audit policy reference, which lists per-role
# recommendations, an event-volume rating and an events list for each one:
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings
# The individual pages are linked from there as audit-<subcategory>. Volume
# figures attributed to "measured on the lab" are ours, not Microsoft's, and
# the two are kept apart on purpose.
#
# Choices err toward what a responder needs while avoiding the subcategories
# that flood a Security log. Several entries here are enabled by the Windows
# Server 2019 default policy already (Security State Change, System Integrity,
# Other System Events, Computer Account Management, and both Kerberos
# subcategories at Success): listing them is what makes them PINNED rather
# than merely inherited, so Test-VisibilityDrift can report it when something
# turns them off.
#
# Deliberately absent, and why - each measured on the lab unless noted:
#   File System / Registry object access - inert without SACLs, catastrophic
#     in volume once SACLs exist.
#   Filtering Platform Connection - one event per connection.
#   Token Right Adjusted - the sole source of 4703, measured at 104 events in
#     ~30 seconds of light WMI load. An RMM agent polling WMI is exactly the
#     workload Microsoft warns about, so this would dominate an MSP fleet's
#     Security log. Excluding it is what leaves Authorization Policy Change
#     (above) safe to enable: 4703 does NOT come from that subcategory on
#     Server 2019, despite what its learn.microsoft.com page lists.
#   Other Policy Change Events at SUCCESS - event 5447 fires once per Windows
#     Filtering Platform filter on every policy refresh; measured at 630 events
#     from a single 'gpupdate /force'. Enabled at Failure only (2) above, which
#     measured zero 5447 while keeping 6145. Note this only means the script
#     never CAUSES that flood: the apply logic is -bor, so a host where Success
#     is already on keeps it. Turning it back off is an operator decision, not
#     something this script will do.
#   Filtering Platform Policy Change - ~87 events per boot of WFP internals.
#     MPSSVC Rule-Level Policy Change (above) covers the firewall rule changes
#     that actually matter.
#   Other Account Logon Events - "This auditing subcategory does not contain any
#     events. It is intended for future use." (audit-other-account-logon-events)
#   Application Group Management / Application Generated - both audit
#     Authorization Manager, which Microsoft states "is very rarely in use and
#     it is deprecated starting from Windows Server 2012"
#     (audit-application-group-management, audit-application-generated).
#   RPC Events - No for every role, "Events in this subcategory occur rarely"
#     (audit-rpc-events); measured zero 5712 on the lab.
#   IPsec Driver - outside Microsoft's guidance scope; IPsec transport policy
#     is rare in the environments this toolkit targets.
#   SAM - 4661 handle requests. Microsoft gives no recommendation for this
#     subcategory and rates its event volume "High on domain controllers"
#     (audit-sam). Not reproduced on the lab (zero observed), so this exclusion
#     rests on Microsoft's volume rating plus low signal, not on a measurement
#     of ours.
#
# Special Logon and Authentication Policy Change are set to 1, not 3: both pages
# state "This subcategory doesn't have Failure events, so there is no
# recommendation to enable Failure auditing for this subcategory"
# (audit-special-logon, audit-authentication-policy-change), so a Failure bit is
# inert.
$script:AuditTargets = @(
    # Account Logon
    @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'Credential Validation';              Setting = 3; Why = '4776 - NTLM authentication attempts' },
    @{ Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Authentication Service';    Setting = 3; Why = '4768/4771 - domain logon, password spraying (DC only)' },
    @{ Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Service Ticket Operations'; Setting = 3; Why = '4769 - kerberoasting, lateral movement (DC only)' },
    # Account Management
    @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management';            Setting = 3; Why = '4720/4726 - accounts created and deleted' },
    @{ Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Name = 'Computer Account Management';        Setting = 1; Why = '4741/4742 - rogue machine account, RBCD (DC only)' },
    @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Security Group Management';          Setting = 3; Why = '4728/4732 - privilege granted' },
    @{ Guid = '{0CCE923A-69AE-11D9-BED3-505054503030}'; Name = 'Other Account Management Events';    Setting = 1; Why = '4782 - a password hash was accessed (DC only)' },
    # Detailed Tracking
    @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Process Creation';                   Setting = 1; Why = '4688 - what ran, with the command line' },
    @{ Guid = '{0CCE922C-69AE-11D9-BED3-505054503030}'; Name = 'Process Termination';                Setting = 1; Why = '4689 - closes the process lifetime for a timeline' },
    @{ Guid = '{0CCE9248-69AE-11D9-BED3-505054503030}'; Name = 'PNP Activity';                       Setting = 1; Why = '6416 - an external device was attached' },
    # Logon/Logoff
    @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon';                              Setting = 3; Why = '4624/4625 - who got in, and who failed' },
    @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Name = 'Logoff';                             Setting = 1; Why = '4634 - bounds a session' },
    @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'Special Logon';                      Setting = 1; Why = '4672 - administrative logon' },
    @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'Account Lockout';                    Setting = 3; Why = '4740 - password spraying' },
    @{ Guid = '{0CCE921C-69AE-11D9-BED3-505054503030}'; Name = 'Other Logon/Logoff Events';          Setting = 3; Why = 'RDP session connect/disconnect/reconnect' },
    @{ Guid = '{0CCE9249-69AE-11D9-BED3-505054503030}'; Name = 'Group Membership';                   Setting = 1; Why = '4627 - the groups in the token, at logon time' },
    # Object Access
    @{ Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}'; Name = 'File Share';                         Setting = 3; Why = '5140 - share accessed, lateral movement' },
    @{ Guid = '{0CCE9244-69AE-11D9-BED3-505054503030}'; Name = 'Detailed File Share';                Setting = 2; Why = '5145 - failures only; success is one event per file' },
    @{ Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Name = 'Removable Storage';                  Setting = 3; Why = '4656/4658/4663 - file access on removable media' },
    @{ Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Name = 'Other Object Access Events';         Setting = 3; Why = '4698-4702 - scheduled task created, deleted, updated' },
    @{ Guid = '{0CCE9221-69AE-11D9-BED3-505054503030}'; Name = 'Certification Services';             Setting = 3; Why = '4886/4887/4888 - AD CS certificate requested, issued, denied' },
    # Policy Change
    @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change';                Setting = 3; Why = '4719 - the attacker turning this off' },
    @{ Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Name = 'Authentication Policy Change';       Setting = 1; Why = 'trust and logon-right changes' },
    @{ Guid = '{0CCE9231-69AE-11D9-BED3-505054503030}'; Name = 'Authorization Policy Change';        Setting = 1; Why = '4704/4705 - a user right was granted or removed' },
    @{ Guid = '{0CCE9232-69AE-11D9-BED3-505054503030}'; Name = 'MPSSVC Rule-Level Policy Change';    Setting = 3; Why = 'firewall rules altered' },
    @{ Guid = '{0CCE9234-69AE-11D9-BED3-505054503030}'; Name = 'Other Policy Change Events';         Setting = 2; Why = '6145 - GPO security settings failed to apply' },
    # Privilege Use
    # AT-7: Failure (2), not Success+Failure (3). Measured in the Atomic exercise:
    # Success produced 5 562 events in nine minutes (3 107 x 4673 SeTcbPrivilege from
    # svchost/lsass, 2 455 x 4674 SeTakeOwnership) against 669 x 4688 - 8.3x the
    # volume of process creation, and not one contributed to any reconstruction. On
    # a fixed-size Security log that flood is what evicts 4688 and 4698. Failure
    # keeps the signal that matters (a privileged operation DENIED) at a fraction
    # of the volume. Additive model: a host where IronBlackBox arms this from 0
    # gets Failure-only; a host already at Success+Failure keeps it (-bor 2 = 3).
    @{ Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Name = 'Sensitive Privilege Use';            Setting = 2; Why = '4674 failures - a privileged operation was DENIED; Success is high-volume noise (AT-7)' },
    # System
    @{ Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Name = 'Security State Change';              Setting = 1; Why = '4616 - the system clock was moved' },
    @{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Name = 'Security System Extension';          Setting = 3; Why = '4697 - service and driver install' },
    @{ Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Name = 'System Integrity';                   Setting = 3; Why = '5038/6410 code integrity, 4612 audit events lost' },
    @{ Guid = '{0CCE9214-69AE-11D9-BED3-505054503030}'; Name = 'Other System Events';                Setting = 3; Why = '5025 - the Windows Firewall service was stopped' }
)

function Get-AuditPolicyState {
    <#
        Returns a hashtable of upper-case GUID -> integer setting value, read
        from 'auditpol /backup'. Empty hashtable if the policy cannot be read,
        which callers must treat as "unknown", never as "nothing is enabled".
    #>
    param([Parameter(Mandatory = $true)][string] $BackupPath)

    $state = @{}
    $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @('/backup', ('/file:' + $BackupPath))
    if ($result.ExitCode -ne 0) {
        throw ('auditpol /backup failed with exit code ' + $result.ExitCode + ': ' + ($result.Output -join ' '))
    }
    if (-not (Test-Path -LiteralPath $BackupPath)) {
        throw ('auditpol /backup reported success but wrote no file: ' + $BackupPath)
    }

    $lines = @(Get-Content -LiteralPath $BackupPath)
    if ($lines.Count -lt 2) { return $state }

    # By index, not by header name: the headers may be localised. The backup
    # format is
    #   Machine Name,Policy Target,Subcategory,Subcategory GUID,
    #   Inclusion Setting,Exclusion Setting,Setting Value
    # so the GUID is field 3 and the numeric value is the LAST field.
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $fields = $lines[$i] -split ','
        if ($fields.Count -lt 7) { continue }
        $guid = $fields[3].Trim()
        $raw  = $fields[$fields.Count - 1].Trim()
        $parsed = 0
        # WITH A PROVIDER. The no-provider overload uses the AMBIENT culture, the trap
        # Enable-WefClient's forwarder diagnostic already names. auditpol's setting value
        # is a small integer today so this parsed everywhere, but a value read from a
        # native tool is invariant text and never locale text.
        if ([int]::TryParse($raw, [System.Globalization.NumberStyles]::Integer,
                    [System.Globalization.CultureInfo]::InvariantCulture, [ref] $parsed)) {
            $state[$guid.ToUpperInvariant()] = $parsed
        }
    }
    return $state
}

function Set-AuditSubcategory {
    param(
        [Parameter(Mandatory = $true)][string] $Guid,
        [Parameter(Mandatory = $true)][int] $Setting
    )
    # 1 = Success, 2 = Failure, 3 = both. Anything else disables.
    $success = 'disable'
    $failure = 'disable'
    if (($Setting -band 1) -ne 0) { $success = 'enable' }
    if (($Setting -band 2) -ne 0) { $failure = 'enable' }

    $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @(
        '/set', ('/subcategory:' + $Guid), ('/success:' + $success), ('/failure:' + $failure))
    if ($result.ExitCode -ne 0) {
        throw ('auditpol /set failed for ' + $Guid + ' with exit code ' +
               $result.ExitCode + ': ' + ($result.Output -join ' '))
    }
}

function Test-AuditPolicyMatchesBackup {
    <#
        Does the EFFECTIVE audit policy already equal the policy in a recorded
        backup file? Used for case 2 of the rollback doctrine
        (docs/DESIGN.md section 4.1).

        Measured on the lab 2026-08-28, because this comparison is only sound if
        'auditpol /backup' reflects the live policy:
          - two backups of an unchanged policy are byte-identical;
          - after 'auditpol /set /subcategory:<guid> /success:disable
            /failure:disable' the backup DID change (Setting Value 3 -> 0).
        So a fresh backup compared against the recorded one is a real test of
        state, not of file age.

        Returns $true only on a confirmed match. Any failure to produce or read a
        fresh backup returns $false, so an unreadable comparison falls through to
        the normal restore rather than silently skipping it.
    #>
    param([Parameter(Mandatory = $true)][string] $BackupPath)

    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) { return $false }
    $probe = [System.IO.Path]::Combine($env:TEMP,
        ('ibb-auditpol-probe-' + [System.Guid]::NewGuid().ToString('N') + '.csv'))
    try {
        # NOT /file:(Join-Path ...) - PowerShell does not expand a subexpression
        # glued to a literal prefix in argument mode, and piped to Out-Null the
        # failure is invisible. Build the whole switch as one string.
        $fileArg = '/file:' + $probe
        $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @('/backup', $fileArg)
        if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $probe -PathType Leaf)) {
            return $false
        }
        $liveHash = (Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash
        $recordedHash = (Get-FileHash -LiteralPath $BackupPath -Algorithm SHA256).Hash
        return [string]::Equals($liveHash, $recordedHash, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
    finally { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
}

# AT-13: the PowerShell channels. See the note on -PowerShellChannelSizeBytes.
$script:PowerShellChannel = @('Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell')

# The channels that carry lateral movement, and the gap docs/ARTIFACT-MATRIX.md
# exposed by being read as a grid: every one of these was armed by NOTHING and
# protected by NOTHING. They are on by default, so this only raises a ceiling -
# and an event log is CIRCULAR, so a ceiling costs disk as it fills rather than
# all at once.
#
# Measured on Server 2019 with 'wevtutil gl': LocalSessionManager and
# RemoteConnectionManager ship at 1 MB each and the three SMB channels at 8 MB
# each, against the 2 GB this script gives the Security log. That is the whole
# case for sizing them - a channel two thousand times smaller than the Security
# log holds proportionally less history.
#
# # UNVERIFIED: which event IDs in these channels carry a remote source address,
# and how much history 1 MB actually represents on a host that is used over RDP.
# This lab is driven over SSH, so the only events present were listener startup
# (1136, 258, 20523, 32) - no connection was ever made to it. Do not write an
# event ID into a comment or a document here without reading one off a host that
# has real RDP and SMB traffic.
#
# WHAT THIS PROJECT COULD NOT MEASURE: a real event rate for any of them. This
# lab is driven over SSH and serves no files, so the channels held 1, 3, 0, 0 and
# 0 events. The default below is therefore justified by the ceiling being cheap
# and the channels being low-volume by nature, NOT by an observed rate. On a busy
# file server, read the volume before trusting it - the README's Disk footprint
# section carries the command.
$script:LateralMovementChannel = @(
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-SmbClient/Security',
    'Microsoft-Windows-SMBServer/Security',
    'Microsoft-Windows-SMBServer/Audit'
)

# Every channel this script's -Rollback is allowed to write, which is exactly the
# set it sizes. The constraint comes from the script, never from the record.
$script:OwnedChannel = @($script:PowerShellChannel + $script:LateralMovementChannel)

function Set-TrackedChannelSize {
    <#
        AT-13. Sizes a set of event channels through wevtutil sl /ms:.

        Called once for the PowerShell channels and once for the lateral-movement
        channels. One implementation, because the free-space gate, the floor
        semantics and the change record are the parts worth getting right once.

        WHY wevtutil AND NOT THE EventLog POLICY: the policy value that
        Security/Application/System use does not reach a modern channel - the same
        reason Set-AppLockerChannelSize in Enable-LolbinAudit uses wevtutil.
        'Windows PowerShell' is a classic log, but wevtutil sizes it too, so both
        go through here.

        MEASURED (lab, 2026-08-31): at its 15 MB default,
        Microsoft-Windows-PowerShell/Operational held ELEVEN SECONDS of history
        under the load of this toolkit's own collectors - so a single triage
        collection was enough to erase the PowerShell evidence of the 22 attack
        activities that preceded it.

        A FLOOR: a channel already at or above the target is left alone, so a
        second -Apply changes nothing and no event is ever discarded by shrinking.

        THE DISK GATE IS THE SIBLING'S, NOT A SECOND ONE. This resolves every
        channel through Get-EventChannelFileState and judges through
        Test-EventLogDiskHeadroom - the same two functions Set-EventLogSizing
        uses, in the same order: resolve all, sum growth per volume, one verdict
        per volume, then write. Three defects came from having written a private
        version of that instead:

          - it defaulted $volumeRoot to 'C:\' when a channel's path could not be
            read, which is V-1's mistake and the exact thing
            Get-EventChannelFileState refuses to do;
          - it judged each channel as if it were the only one being sized, so
            five channels growing 63 MB each were five independent questions;
          - it computed growth from the configured ceiling rather than from the
            file's real size, which UNDER-COUNTS. Raising MaxSize authorises the
            channel to reach the target; what is already consumed is the file, not
            the old ceiling. A channel capped at 8 MB whose .evtx is 68 KB
            authorises 64 MB of growth, not 56.

        docs/AUTHORING.md: copy a helper unchanged or not at all. A locally
        improved copy is how two functions stop agreeing about what a guard means.
    #>
    param(
        [Parameter(Mandatory = $true)][string[]] $Channel,
        [Parameter(Mandatory = $true)][long] $TargetBytes,
        [Parameter(Mandatory = $true)][string] $SectionTitle,
        # Named in a refusal so the operator is told which knob to turn, rather
        # than being told a number is too big and left to guess which one.
        [Parameter(Mandatory = $true)][string] $ParameterName
    )

    Write-Section $SectionTitle
    $changes = 0

    # PASS 1: resolve everything before judging anything.
    $growthByVolume = @{}
    $rootByVolume   = @{}
    $sizable        = New-Object System.Collections.ArrayList

    # $channelName, not $channel: PowerShell variable names are case-INSENSITIVE,
    # so a loop variable named $channel and the parameter $Channel are one
    # variable, and the first iteration overwrites the list with its own first
    # element. Same class as the reserved-$mode trap in docs/AUTHORING.md.
    foreach ($channelName in $Channel) {
        $log = Get-WinEvent -ListLog $channelName -ErrorAction SilentlyContinue
        if ($null -eq $log) {
            # A host limit, not a finding (docs/DESIGN.md 3.1). Whether this
            # Windows build and role ship a channel is not something any -Apply
            # changes, so as a finding it was a permanent exit 1 with no lever.
            Write-HostLimit ($channelName + ' does not exist on this host, so it cannot be sized. Not ' +
                             'every Windows build and role carries every channel.')
            continue
        }

        # A DISABLED channel is reported. Sizing a channel that is not recording
        # gives an empty reservoir a bigger ceiling, and docs/ARTIFACT-MATRIX.md
        # would then claim this script ARMS it. A finding rather than a host
        # limit: 'wevtutil sl <channel> /e:true' is the lever, and it is named.
        # This script deliberately does not pull it - enabling a channel an
        # administrator switched off is a different decision from sizing one they
        # left on.
        if ($null -ne $log.PSObject.Properties['IsEnabled'] -and $null -ne $log.IsEnabled -and
            -not [bool] $log.IsEnabled) {
            Write-Finding ($channelName + ' is DISABLED, so sizing it changes nothing that will be ' +
                           'recorded. Enable it first: wevtutil.exe sl "' + $channelName + '" /e:true')
        }

        $currentMax = 0
        if ($null -ne $log.PSObject.Properties['MaximumSizeInBytes'] -and $null -ne $log.MaximumSizeInBytes) {
            $currentMax = [long] $log.MaximumSizeInBytes
        }
        if ($currentMax -ge $TargetBytes) {
            Write-Ok ($channelName + ' already at ' + [string] $currentMax + ' bytes, at or above the ' +
                      [string] $TargetBytes + '-byte floor')
            continue
        }

        $file = Get-EventChannelFileState -Channel $channelName
        if (-not $file.Resolved) {
            Write-Finding ($channelName + ' - cannot locate its log file (' + $file.Detail +
                           '), so the disk cost of sizing it is unknown; leaving it alone.')
            continue
        }

        $growth = ([decimal] $TargetBytes) - $file.FileBytes
        if ($growth -lt 0) { $growth = [decimal] 0 }
        $key = $file.VolumeRoot.ToUpperInvariant()
        if (-not $growthByVolume.ContainsKey($key)) {
            $growthByVolume[$key] = [decimal] 0
            $rootByVolume[$key]   = $file.VolumeRoot
        }
        $growthByVolume[$key] = $growthByVolume[$key] + $growth
        [void] $sizable.Add([PSCustomObject] @{
            Name       = $channelName
            CurrentMax = $currentMax
            Enabled    = $(if ($null -ne $log.PSObject.Properties['IsEnabled'] -and
                                $null -ne $log.IsEnabled) { [bool] $log.IsEnabled } else { $true })
            VolumeKey  = $key
        })
    }

    # PASS 2: one verdict per volume, reported once rather than once per channel,
    # and against what the rest of this run has already booked on that volume -
    # this function is called twice and the event logs come through the same
    # figure a third time.
    $verdict = @{}
    foreach ($key in @($growthByVolume.Keys)) {
        $head = Test-EventLogDiskHeadroom -VolumeRoot $rootByVolume[$key] `
                    -GrowthBytes $growthByVolume[$key] -FloorPercent $MinimumFreeDiskPercent `
                    -AlreadyAuthorisedBytes (Get-AuthorisedGrowth -VolumeRoot $rootByVolume[$key])
        $verdict[$key] = $head
        # Booked only when ALLOWED: a refused volume gets no wevtutil call in
        # pass 3, so nothing on it can grow and nothing is owed.
        if ($head.Allowed) {
            Add-AuthorisedGrowth -VolumeRoot $rootByVolume[$key] -Bytes $growthByVolume[$key]
        }
        $summary = ($rootByVolume[$key] + ' - ' + (Format-ByteCount -Value $head.FreeBytes) +
                    ' free, these channels may grow by ' + (Format-ByteCount -Value $head.GrowthBytes) +
                    '; ' + $head.Reason)
        if ($head.Allowed) { Write-Ok $summary }
        else { Write-Finding ('REFUSED ' + $summary) }
    }

    # PASS 3: write only what a volume verdict allows.
    foreach ($entry in $sizable) {
        $head = $verdict[$entry.VolumeKey]
        if (-not $head.Allowed) {
            Write-Finding ($entry.Name + ' - not sized: the COMBINED request for ' + $head.VolumeRoot +
                           ' needs ' + (Format-ByteCount -Value $head.GrowthBytes) + ' and the volume ' +
                           'cannot take it, so no channel on it is resized. Lower -' + $ParameterName +
                           ', lower -MinimumFreeDiskPercent, or add disk.')
            continue
        }
        if (-not $Apply) {
            Write-Finding ($entry.Name + ' is ' + [string] $entry.CurrentMax +
                           ' bytes; would run: wevtutil.exe sl "' + $entry.Name + '" /ms:' +
                           [string] $TargetBytes)
            continue
        }

        $invariant = [System.Globalization.CultureInfo]::InvariantCulture
        # Recorded BEFORE the write. Sizes are invariant decimal strings, not JSON
        # numbers: PS 5.1 deserializes a JSON integer as Int32 and a channel size
        # can exceed Int32.
        [void] (Write-ManifestChange -Change @{
            type                 = 'eventchannel'
            channel              = $entry.Name
            previousEnabled      = $entry.Enabled
            previousMaxSizeBytes = ([long] $entry.CurrentMax).ToString($invariant)
            newEnabled           = $entry.Enabled
            newMaxSizeBytes      = ([long] $TargetBytes).ToString($invariant)
            description          = ($entry.Name + ' sized to ' +
                                    ([long] $TargetBytes).ToString($invariant) + ' bytes')
        })
        $result = Invoke-NativeCommand -FilePath $script:WevtutilPath `
            -Arguments @('sl', $entry.Name, ('/ms:' + [string] $TargetBytes))
        if ($result.ExitCode -ne 0) {
            throw ('wevtutil sl /ms: failed on ' + $entry.Name + ': ' + ($result.Output -join ' '))
        }
        # Read it back: a native tool exiting 0 proves nothing about its effect.
        $after = Get-WinEvent -ListLog $entry.Name -ErrorAction SilentlyContinue
        $afterMax = 0
        if ($null -ne $after -and $null -ne $after.PSObject.Properties['MaximumSizeInBytes']) {
            $afterMax = [long] $after.MaximumSizeInBytes
        }
        if ($afterMax -lt $TargetBytes) {
            Write-Finding ($entry.Name + ' did not read back at the requested size: asked ' +
                           [string] $TargetBytes + ', reads ' + [string] $afterMax +
                           '. An EventLog policy can override wevtutil (verification/facts.json).')
            continue
        }
        Write-Ok ($entry.Name + ' sized to ' + [string] $afterMax + ' bytes (was ' +
                  [string] $entry.CurrentMax + ')')
        $changes++
    }
    return $changes
}

function Restore-EventChannelChange {
    <#
        AT-13. Rolls back one 'eventchannel' record. This script produced none
        before, so it had no restorer for the type: adding the record without this
        would have failed every -Rollback with "change type not implemented".

        THREE-way resolution (docs/DESIGN.md section 4.1), as everywhere else
        since A-2.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $channel = [string] $change.channel
    # The manifest is operator-writable input: a planted record must not turn
    # -Rollback into "reconfigure any channel on this host".
    if ($script:OwnedChannel -notcontains $channel) {
        throw ('Refusing to roll back an eventchannel change for ' + $channel +
               '; this script only owns ' + ($script:OwnedChannel -join ', '))
    }
    $previousMax = 0
    # BILINGUAL BY NECESSITY. The manifest is append-only, so a record written
    # before the field names were aligned keeps its original spelling. Renaming
    # the writer above does not rename what is already on disk.
    $recordedPrevious = [string] $change.previousMaxSizeBytes
    if ([string]::IsNullOrWhiteSpace($recordedPrevious)) { $recordedPrevious = [string] $change.previousMaxSize }
    if (-not [long]::TryParse($recordedPrevious,
            [System.Globalization.NumberStyles]::Integer,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref] $previousMax)) {
        Write-Finding ($channel + ': the recorded previous maximum size is unreadable; declining rather than guessing')
        return 'declined'
    }
    $log = Get-WinEvent -ListLog $channel -ErrorAction SilentlyContinue
    if ($null -eq $log) {
        # ABSENT and MERELY UNREADABLE get different verdicts, and conflating them
        # costs convergence. -ErrorAction SilentlyContinue returns $null for both,
        # and this used to answer 'declined' for both - retryable. A channel that
        # is genuinely gone will never come back for this run, so the run never
        # left the eligible set: -Rollback re-selected it every time and
        # Test-VisibilityDrift went on expecting the change. That is A-2, exactly.
        #
        # The discriminator is an enumeration rather than the error text, because
        # matching a message is locale-dependent and this toolkit runs on fr-FR
        # hosts.
        $known = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                   Where-Object { [string]::Equals([string] $_.LogName, $channel,
                                                   [System.StringComparison]::OrdinalIgnoreCase) })
        if ($known.Count -eq 0) {
            Write-Finding ($channel + ' is not present on this host at all, so there is no channel to ' +
                           'restore a size to and no retry will change that. Recorded as permanently ' +
                           'declined so the rest of this run can finish.')
            return $script:RollbackDeclinedPermanent
        }
        Write-Finding ($channel + ' exists on this host but cannot be read, so a restore cannot be ' +
                       'verified; leaving it alone. This stays retryable - a permission or service ' +
                       'problem can clear.')
        return 'declined'
    }
    $currentMax = 0
    if ($null -ne $log.PSObject.Properties['MaximumSizeInBytes'] -and $null -ne $log.MaximumSizeInBytes) {
        $currentMax = [long] $log.MaximumSizeInBytes
    }

    # Case 2 first: the host already holds its recorded previous state - nothing
    # to undo, counted 'restored' so the run converges.
    if ($currentMax -eq $previousMax) {
        Write-Ok ($channel + ' already holds its recorded previous size (' + [string] $previousMax +
                  ' bytes); nothing to undo.')
        return 'restored'
    }
    # Case 3: neither the applied value nor the previous one.
    #
    # FAIL CLOSED on an unreadable intended size. $intendedMax used to be left at
    # 0 by a discarded TryParse, and the guard below read
    # 'if ($intendedMax -gt 0 -and ...)' - so a record carrying no
    # newMaxSizeBytes, a "0", or garbage SKIPPED case 3 entirely and fell straight
    # through to writing the record-supplied previous value. The manifest is
    # operator-writable input, so a guard a record can switch off is not a guard.
    $intendedMax = 0
    $recordedNew = [string] $change.newMaxSizeBytes
    if ([string]::IsNullOrWhiteSpace($recordedNew)) { $recordedNew = [string] $change.newMaxSize }
    $intendedParsed = [long]::TryParse($recordedNew,
        [System.Globalization.NumberStyles]::Integer,
        [System.Globalization.CultureInfo]::InvariantCulture, [ref] $intendedMax)
    if (-not $intendedParsed -or $intendedMax -le 0) {
        Write-Finding ($channel + ': the record does not say what size this run applied (' +
                       $(if ([string]::IsNullOrWhiteSpace($recordedNew)) { 'no value' } else { '"' + $recordedNew + '"' }) +
                       '), so there is no way to tell whether the host still holds it. Leaving it alone.')
        return 'declined'
    }
    if ($currentMax -ne $intendedMax) {
        Write-Finding ($channel + ' is ' + [string] $currentMax + ' bytes, not what this run set (' +
                       [string] $intendedMax + '); leaving it alone')
        return 'declined'
    }
    # Case 1: the host holds what -Apply set - restore it.
    if ($previousMax -lt $currentMax) {
        Write-Info ($channel + ': restoring the smaller previous size DISCARDS the events that no longer ' +
                    'fit. That is what the recorded previous value was.')
    }
    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath `
        -Arguments @('sl', $channel, ('/ms:' + [string] $previousMax))
    if ($result.ExitCode -ne 0) {
        throw ('wevtutil sl /ms: failed restoring ' + $channel + ': ' + ($result.Output -join ' '))
    }
    # READ IT BACK, the way the setter ninety lines up already does. A native
    # tool's exit code is not a claim about its output, and this is not a general
    # principle here - it is measured: verification/facts.json records that
    # 'wevtutil sl <channel> /ms:1052672' DID NOT STICK while the EventLog policy
    # specified a larger size, and wevtutil still exited 0. That call is exactly
    # this one, a shrink through sl /ms:. Reporting 'restored' on the exit code
    # alone would then mark the run completed - out of the eligible set AND out of
    # what Test-VisibilityDrift expects - while the channel kept the size this
    # toolkit set.
    $afterRestore = Get-WinEvent -ListLog $channel -ErrorAction SilentlyContinue
    $afterMax = -1
    if ($null -ne $afterRestore -and
        $null -ne $afterRestore.PSObject.Properties['MaximumSizeInBytes'] -and
        $null -ne $afterRestore.MaximumSizeInBytes) {
        $afterMax = [long] $afterRestore.MaximumSizeInBytes
    }
    if ($afterMax -lt 0) {
        Write-Finding ($channel + ': wevtutil exited 0 but the channel size cannot be read back, so the ' +
                       'restore is not confirmed.')
        return 'declined'
    }
    # A ONE-SIDED TOLERANCE, and it is defensive rather than required.
    #
    # This started as an exact '-ne', which a review flagged on the grounds that
    # wevtutil rounds /ms: up to a 64 KB multiple - a claim this repository makes
    # in the review log kept in the development repository and in the sibling setter's comment. Measured
    # 2026-09-02 on Server 2019 before believing it: 'wevtutil sl
    # Microsoft-Windows-SmbClient/Security /ms:9000000' produced a channel holding
    # exactly 9000000, so no rounding happened on that channel at that value. One
    # value on one channel is not a refutation of the general claim, and the claim
    # itself has no facts.json row, so the tolerance stays - it costs nothing and
    # an exact test would fail a correct restore wherever rounding DOES occur.
    #
    # The tolerance has to be one-sided. '-ge $previousMax' would have passed a
    # channel that never shrank at all, which is the exact fail-open this
    # read-back exists to close. So: at least the requested size, and less than one
    # 64 KB block above it.
    $roundingBlock = 65536
    if ($afterMax -lt $previousMax -or $afterMax -ge ($previousMax + $roundingBlock)) {
        Write-Finding ($channel + ': wevtutil exited 0 restoring ' + [string] $previousMax +
                       ' bytes but the channel now reads ' + [string] $afterMax +
                       ', which is outside the 64 KB rounding wevtutil applies. Something is overriding ' +
                       'the channel - an EventLog policy MaxSize does exactly this. Leaving the run ' +
                       'retryable rather than reporting a restore that did not land.')
        return 'declined'
    }
    Write-Ok ('Restored ' + $channel + ' to ' + [string] $previousMax + ' bytes (read back and confirmed)')
    return 'restored'
}

function Restore-AuditPolicyFromBackup {
    param([Parameter(Mandatory = $true)][string] $BackupPath)

    if (-not (Test-Path -LiteralPath $BackupPath)) {
        throw ('Audit policy backup is missing, cannot restore: ' + $BackupPath)
    }
    $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @('/restore', ('/file:' + $BackupPath))
    if ($result.ExitCode -ne 0) {
        throw ('auditpol /restore failed with exit code ' + $result.ExitCode + ': ' + ($result.Output -join ' '))
    }
}

#endregion

#region Visibility settings ---------------------------------------------------

# Registry locations, every one of them extracted from the ADMX policy
# definitions on the target OS. See verification/facts.json for the provenance
# of each. Do not "correct" these from memory.
$script:KeyScriptBlock   = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$script:KeyModuleLogging = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$script:KeyModuleNames   = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
$script:KeyTranscription = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
# Note: NOT under Software\Policies - this one really does live under
# Software\Microsoft. Confirmed in AuditSettings.admx.
$script:KeyAuditSettings = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$script:KeyEventLogBase  = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog'
$script:KeyFirewallBase  = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'

# EVERY DISK ALLOWANCE THIS RUN HAS GRANTED, PER VOLUME.
#
# Raising a ceiling consumes nothing today, so AvailableFreeSpace has not moved
# by the time the next section asks about the same volume - and one run raises
# ceilings in three places (the Security/Application/System logs, the PowerShell
# channels, the lateral-movement channels) and switches on one unbounded writer
# (transcription). Judged one at a time, all four can pass on a volume that
# cannot take them together, because each one is measured against the same
# unspent figure. At the defaults the ceilings they commit are 2.5 GB of event
# log, 512 MB of PowerShell channel, 320 MB of lateral-movement channel and 2 GB
# of transcript backstop: about 5.3 GB, less whatever those files already hold.
#
# Test-EventLogDiskHeadroom's own help already states the rule for the channels
# inside one call ("Channels are summed PER VOLUME before the comparison: three
# channels that each fit on their own can still overflow the volume together").
# This extends the same rule ACROSS the calls, which is the half that was
# missing and the half -MinimumFreeDiskPercent is documented to promise.
$script:AuthorisedGrowthByVolume = @{}

function Get-AuthorisedGrowth {
    # What earlier sections of THIS run already booked on this volume.
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

function Set-PowerShellLogging {
    param([Parameter(Mandatory = $true)][string] $TranscriptPath)
    $changes = 0

    Write-Section 'PowerShell logging'

    if (Set-TrackedRegistryValue -Path $script:KeyScriptBlock -Name 'EnableScriptBlockLogging' `
        -Kind 'DWord' -Value 1 -Description 'ScriptBlock logging (event 4104)') { $changes++ }

    if ($IncludeInvocationLogging) {
        if (Set-TrackedRegistryValue -Path $script:KeyScriptBlock -Name 'EnableScriptBlockInvocationLogging' `
            -Kind 'DWord' -Value 1 -Description 'ScriptBlock invocation logging (high volume)') { $changes++ }
    }

    if (Set-TrackedRegistryValue -Path $script:KeyModuleLogging -Name 'EnableModuleLogging' `
        -Kind 'DWord' -Value 1 -Description 'Module logging (event 4103)') { $changes++ }

    # The ADMX declares the list's location but not this convention. The
    # '*' = '*' pair IS what enables all modules: proven on the lab, 4103
    # events appear after -Apply. See verification/facts.json.
    if (Set-TrackedRegistryValue -Path $script:KeyModuleNames -Name '*' `
        -Kind 'String' -Value '*' -Description 'Module logging scope: all modules') { $changes++ }

    # -DisableTranscription writes 0 rather than skipping the value: an explicit
    # off is tracked in the manifest and therefore reversible, where "leave it
    # alone" would silently inherit whatever a GPO or an earlier run had set.
    $transcriptOn = 1
    if ($DisableTranscription) { $transcriptOn = 0 }
    if (Set-TrackedRegistryValue -Path $script:KeyTranscription -Name 'EnableTranscripting' `
        -Kind 'DWord' -Value $transcriptOn -Description ('PowerShell transcription: ' +
        $(if ($DisableTranscription) { 'DISABLED by -DisableTranscription' } else { 'enabled' }))) { $changes++ }
    if ($DisableTranscription) {
        Write-Info ('transcription is off by request. Existing transcripts under ' + $TranscriptPath +
                    ' are LEFT IN PLACE - this script does not delete evidence it did not write ' +
                    'this run, and no rotation task is registered.')
        return $changes
    }

    if (Set-TrackedRegistryValue -Path $script:KeyTranscription -Name 'OutputDirectory' `
        -Kind 'String' -Value $TranscriptPath -Description ('Transcript directory: ' + $TranscriptPath)) { $changes++ }

    if (Set-TrackedRegistryValue -Path $script:KeyTranscription -Name 'EnableInvocationHeader' `
        -Kind 'DWord' -Value 1 -Description 'Transcript invocation headers (timestamps each command)') { $changes++ }

    return $changes
}


function Set-ProcessCommandLineAuditing {
    Write-Section 'Command line in process creation events'
    $changes = 0
    if (Set-TrackedRegistryValue -Path $script:KeyAuditSettings -Name 'ProcessCreationIncludeCmdLine_Enabled' `
        -Kind 'DWord' -Value 1 -Description 'Command line included in event 4688') { $changes++ }
    return $changes
}

function Format-ByteCount {
    <#
        Byte counts an operator can check against what Explorer or 'dir' shows.
        Operator-facing only; never fed back into a comparison.

        NOT the same function as Enable-VssPreservation's, and the difference is
        deliberate rather than drift: that copy has GB and MB tiers only and no
        sign, while this one adds a KB tier and a sign, because the figures it
        prints include a per-volume growth that can be well under a megabyte
        once a channel is nearly at its target, and a projected free space that
        goes NEGATIVE exactly when the guard refuses. 524800 bytes therefore
        reads as '512.5 KB' here and '524800 bytes' there. The comment here used
        to claim the two were identical, which a two-file diff disproves.
    #>
    param([Parameter(Mandatory = $true)][decimal] $Value)
    # Projected free space goes NEGATIVE precisely when the guard refuses, so
    # the sign is handled here rather than left to print a raw byte count next
    # to formatted ones - that is the number the operator most needs to read.
    $sign = ''
    $abs  = $Value
    if ($Value -lt 0) { $sign = '-'; $abs = [decimal] 0 - $Value }
    if ($abs -ge 1073741824) { return ($sign + [string] [math]::Round($abs / 1073741824, 2) + ' GB') }
    if ($abs -ge 1048576)    { return ($sign + [string] [math]::Round($abs / 1048576, 2) + ' MB') }
    if ($abs -ge 1024)       { return ($sign + [string] [math]::Round($abs / 1024, 2) + ' KB') }
    return ($sign + [string] $abs + ' bytes')
}

function Get-EventChannelFileState {
    <#
        Where a channel's .evtx actually lives, and how much of the volume it
        already occupies.

        The path is READ, never assumed. A channel can be relocated to another
        disk, and sizing it then authorises growth on a volume this script
        never measured. Enable-VssPreservation carried exactly that defect as
        V-1: the guard took free space from the volume being PROTECTED while
        the bytes landed on the volume HOLDING the storage area.

        Verified on the lab (Server 2019, 17763.9121): 'wevtutil gl Security'
        emits, indented under a 'logging:' heading,

            logFileName: %SystemRoot%\System32\Winevt\Logs\Security.evtx
            maxSize: 1073741824

        with the environment variable left unexpanded.

        # UNVERIFIED: whether the 'logFileName' key name is localised on a
        # non-English host. If it were, the match fails, Resolved stays $false,
        # and the caller REFUSES to size that channel. It never falls back to a
        # guessed default path - guessing is precisely how the wrong volume
        # gets measured, which is the defect this function exists to avoid.
    #>
    param([Parameter(Mandatory = $true)][string] $Channel)

    $state = [PSCustomObject] @{
        Channel    = $Channel
        Resolved   = $false
        Path       = $null
        VolumeRoot = $null
        FileBytes  = [decimal] 0
        Detail     = 'not read'
    }

    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @('gl', $Channel)
    if ($result.ExitCode -ne 0) {
        $state.Detail = ('wevtutil gl exited ' + [string] $result.ExitCode)
        return $state
    }

    $raw = $null
    foreach ($line in $result.Output) {
        if (([string] $line) -match '^\s*logFileName:\s*(?<path>\S.*?)\s*$') {
            $raw = $Matches['path']
            break
        }
    }
    if ([string]::IsNullOrEmpty($raw)) {
        $state.Detail = 'wevtutil gl reported no logFileName'
        return $state
    }

    $expanded = [System.Environment]::ExpandEnvironmentVariables($raw)
    try {
        $full = [System.IO.Path]::GetFullPath($expanded)
        $root = [System.IO.Path]::GetPathRoot($full)
    }
    catch {
        $state.Detail = ('logFileName does not resolve to a path: ' + $raw)
        return $state
    }
    if ([string]::IsNullOrEmpty($root)) {
        $state.Detail = ('logFileName has no volume root: ' + $full)
        return $state
    }

    $state.Path       = $full
    $state.VolumeRoot = $root
    $item = Get-Item -LiteralPath $full -ErrorAction SilentlyContinue
    if ($null -ne $item) { $state.FileBytes = [decimal] $item.Length }
    $state.Resolved = $true
    $state.Detail   = 'ok'
    return $state
}

function Test-EventLogDiskHeadroom {
    <#
        The arithmetic, stated so it can be argued with. A refusal an operator
        cannot check is a refusal they will work around.

        THE NAME IS NARROWER THAN THE JOB, and is kept because docs/VALIDATION.md
        cites it in a dated row. This is the ONE piece of disk arithmetic in the
        script: the event logs, both sets of sized channels and the transcript
        backstop all come through here. A second copy of it is how two guards
        stop agreeing about what -MinimumFreeDiskPercent means, which this file
        has already paid for once (see Set-TrackedChannelSize).

        Raising MaxSize consumes nothing today. It AUTHORISES the channel to
        grow to that size later, so the worst case is the whole target minus
        what the file already occupies:

            growth        = sum, over the channels on THIS volume, of
                            max(0, targetBytes - currentFileBytes)
            projectedFree = free - growth - alreadyAuthorised

        and the floor is applied to projectedFree, NOT to today's free space.
        Applying it to today's free space would wave through every resize whose
        entire point is to consume more disk later - which is how a hardening
        script causes the outage it was deployed to prevent. Same reasoning as
        Test-ShadowStorageHeadroom in Enable-VssPreservation.

        Channels are summed PER VOLUME before the comparison: three channels
        that each fit on their own can still overflow the volume together. That
        holds ACROSS calls as well as within one, which is what
        -AlreadyAuthorisedBytes carries: raising a ceiling leaves
        AvailableFreeSpace untouched, so without it every section of the run
        would ask about the same unspent bytes and every section would be told
        yes. It is MANDATORY rather than defaulted precisely so a new caller
        cannot reintroduce that by omission - pass Get-AuthorisedGrowth for the
        volume, and book the result with Add-AuthorisedGrowth when it lands.

        The guard self-resolves. Once a log has actually grown into its
        allowance, growth falls towards zero and the volume passes - so this
        does not become a permanent finding on a host that simply has a big log.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $VolumeRoot,
        [Parameter(Mandatory = $true)][decimal] $GrowthBytes,
        [Parameter(Mandatory = $true)][int] $FloorPercent,
        [Parameter(Mandatory = $true)][decimal] $AlreadyAuthorisedBytes
    )

    $free     = [decimal] 0
    $capacity = [decimal] 0
    try {
        $drive    = New-Object System.IO.DriveInfo($VolumeRoot)
        $free     = [decimal] $drive.AvailableFreeSpace
        $capacity = [decimal] $drive.TotalSize
    }
    catch {
        return [PSCustomObject] @{
            VolumeRoot = $VolumeRoot; FreeBytes = [decimal] 0; CapacityBytes = [decimal] 0
            GrowthBytes = $GrowthBytes; AlreadyAuthorisedBytes = $AlreadyAuthorisedBytes
            ProjectedFree = [decimal] 0; FloorBytes = [decimal] 0
            Allowed = $false
            Reason  = ('free space on ' + $VolumeRoot + ' could not be read, so the cost is unknown')
        }
    }

    $projected = $free - $GrowthBytes - $AlreadyAuthorisedBytes
    $floor     = [decimal] [math]::Floor($capacity * $FloorPercent / 100)
    $allowed   = ($projected -ge $floor)

    # Named in the reason, not just folded into the arithmetic: an operator told
    # "the volume cannot take 256 MB" on a volume with 3 GB free will work around
    # the guard unless the other 4 GB this run already committed is on the line
    # with it.
    $booked = ''
    if ($AlreadyAuthorisedBytes -gt 0) {
        $booked = (' once the ' + (Format-ByteCount -Value $AlreadyAuthorisedBytes) +
                   ' this run already authorised on this volume is counted with it')
    }

    $reason = ('worst case leaves ' + (Format-ByteCount -Value $projected) + ' free' + $booked +
               ', at or above the ' + [string] $FloorPercent + '% floor of ' +
               (Format-ByteCount -Value $floor))
    if (-not $allowed) {
        $reason = ('worst case would leave ' + (Format-ByteCount -Value $projected) + ' free' + $booked +
                   ', under the ' + [string] $FloorPercent + '% floor of ' +
                   (Format-ByteCount -Value $floor))
    }

    return [PSCustomObject] @{
        VolumeRoot             = $VolumeRoot
        FreeBytes              = $free
        CapacityBytes          = $capacity
        GrowthBytes            = $GrowthBytes
        AlreadyAuthorisedBytes = $AlreadyAuthorisedBytes
        ProjectedFree          = $projected
        FloorBytes             = $floor
        Allowed                = $allowed
        Reason                 = $reason
    }
}

function Add-TranscriptDiskAllowance {
    <#
        The disk guard for transcription, which is the one thing this script
        turns on that had none.

        -MinimumFreeDiskPercent reached only the ceiling raisers: the script
        would refuse to grow a CIRCULAR, self-limiting event log by 256 MB
        without measuring the volume, and then point a 2 GB-by-default
        unbounded file writer at the same volume without looking. The parameter
        block already names the risk ("Transcription is the ONLY unbounded thing
        this toolkit turns on... Transcripts are files, and PowerShell never
        removes them") and the event-log guard's rationale applies word for word
        ("a smaller log is a degraded recorder, a full system disk is a dead
        server").

        The allowance is -TranscriptMaxBytes minus what the directory already
        holds, because that backstop is what the rotation task enforces. It is
        the worst case only as far as the backstop is: rotation runs once a day
        at 03:20, so a host that fills between two runs overshoots it, and the
        finding says so rather than implying the cap is continuous.

        THIS REPORTS, IT DOES NOT REFUSE, and that asymmetry with the channels
        is deliberate. A refused resize leaves a smaller log; a refused
        transcription leaves no record of what an attacker typed, which is the
        evidence this script exists to keep. The levers are named instead, and
        the allowance is booked EITHER WAY - nothing stops these bytes, so the
        event logs and channels judged after this have to fit around them.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $TranscriptPath,
        [Parameter(Mandatory = $true)][long] $MaxBytes
    )

    Write-Section 'Transcript disk headroom'

    # The volume is READ off the resolved path, never assumed to be the system
    # drive - the same rule Get-EventChannelFileState follows, and for the same
    # reason: -ToolkitRoot can put the transcripts on another disk.
    $root = ''
    try { $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($TranscriptPath)) }
    catch { $root = '' }
    if ([string]::IsNullOrEmpty($root)) {
        Write-Finding ('cannot work out which volume holds ' + $TranscriptPath +
                       ', so the disk cost of transcription is unknown and unbudgeted.')
        return
    }

    $existing = [decimal] 0
    if (Test-Path -LiteralPath $TranscriptPath) {
        $measured = Get-ChildItem -LiteralPath $TranscriptPath -Recurse -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum
        if ($null -ne $measured.Sum) { $existing = [decimal] $measured.Sum }
    }
    $growth = ([decimal] $MaxBytes) - $existing
    if ($growth -lt 0) { $growth = [decimal] 0 }

    $head = Test-EventLogDiskHeadroom -VolumeRoot $root -GrowthBytes $growth `
                -FloorPercent $MinimumFreeDiskPercent `
                -AlreadyAuthorisedBytes (Get-AuthorisedGrowth -VolumeRoot $root)
    Add-AuthorisedGrowth -VolumeRoot $root -Bytes $growth

    $summary = ($root + ' - ' + (Format-ByteCount -Value $head.FreeBytes) + ' free, transcripts hold ' +
                (Format-ByteCount -Value $existing) + ' and may grow by a further ' +
                (Format-ByteCount -Value $head.GrowthBytes) + ' before the rotation backstop evicts; ' +
                $head.Reason)
    if ($head.Allowed) {
        Write-Ok $summary
        return
    }
    Write-Finding ($summary + '. Transcription is still enabled - an unrecorded session is worse than ' +
                   'a full disk warning - so ACT ON THIS: lower -TranscriptMaxBytes, lower ' +
                   '-TranscriptKeepDays, lower -MinimumFreeDiskPercent, or add disk. Note the rotation ' +
                   'task only trims once a day at 03:20, so it cannot help a host that fills between runs.')
}

function Set-EventLogSizing {
    <#
        MaxSize is in KILOBYTES. This is measured, not assumed: the lab's
        default Security log reports maxSize 20971520 bytes via
        'wevtutil gl Security', which is exactly the ADMX minValue of 20480
        multiplied by 1024. Writing bytes here would request 1024x too little
        and silently shrink the log a responder depends on.

        Sizing is GATED ON FREE DISK SPACE. A 2 GB Security log on a volume
        that cannot take 2 GB turns a logging improvement into an outage. Each
        VOLUME is judged once, before anything on it is written, and a volume
        that fails is SKIPPED rather than aborting the run: a smaller log is a
        degraded recorder, a full system disk is a dead server.

        The verdict is ALL-OR-NOTHING per volume. If the combined request does
        not fit, no log on that volume is resized - rather than resizing some
        of them in an order nobody chose and leaving the operator to work out
        which ones took. The finding names the combined figure so the cause is
        visible, not just the effect.

        Note the policy value only AUTHORISES the size - the running channel
        picks it up at the next computer policy refresh, not immediately
        (verification/facts.json, fact eventlog-sizing-needs-gpupdate-not-reboot).
    #>
    Write-Section 'Event log capacity'
    $changes = 0

    $channels = @(
        @{ Name = 'Security';    SizeKb = $SecurityLogSizeKb },
        @{ Name = 'Application'; SizeKb = $OtherLogSizeKb },
        @{ Name = 'System';      SizeKb = $OtherLogSizeKb }
    )

    # Resolve every channel to a volume FIRST, so growth is summed per volume
    # before any single channel is judged.
    $growthByVolume = @{}
    $rootByVolume   = @{}
    $sizable        = New-Object System.Collections.ArrayList
    foreach ($channel in $channels) {
        $file = Get-EventChannelFileState -Channel $channel.Name
        if (-not $file.Resolved) {
            Write-Finding ($channel.Name + ' - cannot locate its log file (' + $file.Detail +
                           '), so the disk cost of sizing it is unknown; leaving it alone.')
            continue
        }

        $target = ([decimal] $channel.SizeKb) * 1024
        $growth = $target - $file.FileBytes
        if ($growth -lt 0) { $growth = [decimal] 0 }

        $key = $file.VolumeRoot.ToUpperInvariant()
        if (-not $growthByVolume.ContainsKey($key)) {
            $growthByVolume[$key] = [decimal] 0
            $rootByVolume[$key]   = $file.VolumeRoot
        }
        $growthByVolume[$key] = $growthByVolume[$key] + $growth

        [void] $sizable.Add([PSCustomObject] @{
            Name      = $channel.Name
            SizeKb    = $channel.SizeKb
            VolumeKey = $key
        })
    }

    # One verdict per volume, reported once rather than once per channel, and
    # against what transcription and the sized channels have already booked on
    # that volume in this run.
    $verdict = @{}
    foreach ($key in @($growthByVolume.Keys)) {
        $head = Test-EventLogDiskHeadroom -VolumeRoot $rootByVolume[$key] `
                    -GrowthBytes $growthByVolume[$key] -FloorPercent $MinimumFreeDiskPercent `
                    -AlreadyAuthorisedBytes (Get-AuthorisedGrowth -VolumeRoot $rootByVolume[$key])
        $verdict[$key] = $head
        # Booked only when ALLOWED: a refused volume gets no MaxSize write below,
        # so nothing on it can grow and nothing is owed.
        if ($head.Allowed) {
            Add-AuthorisedGrowth -VolumeRoot $rootByVolume[$key] -Bytes $growthByVolume[$key]
        }
        $summary = ($rootByVolume[$key] + ' - ' + (Format-ByteCount -Value $head.FreeBytes) +
                    ' free, logs may grow by ' + (Format-ByteCount -Value $head.GrowthBytes) +
                    '; ' + $head.Reason)
        if ($head.Allowed) { Write-Ok $summary }
        else { Write-Finding ('REFUSED ' + $summary) }
    }

    foreach ($entry in $sizable) {
        $head = $verdict[$entry.VolumeKey]
        if (-not $head.Allowed) {
            Write-Finding ($entry.Name + ' - not sized to ' + $entry.SizeKb + ' KB: the COMBINED ' +
                           'event log request for ' + $head.VolumeRoot + ' needs ' +
                           (Format-ByteCount -Value $head.GrowthBytes) + ' and the volume cannot ' +
                           'take it, so no log on this volume is resized. Lower -SecurityLogSizeKb ' +
                           'or -OtherLogSizeKb, lower -MinimumFreeDiskPercent, or add disk.')
            continue
        }
        $key = ($script:KeyEventLogBase + '\' + $entry.Name)
        $description = ($entry.Name + ' log size: ' + $entry.SizeKb + ' KB')
        if (Set-TrackedRegistryValue -Path $key -Name 'MaxSize' `
            -Kind 'DWord' -Value $entry.SizeKb -Description $description) { $changes++ }
    }
    return $changes
}

function Set-FirewallLogging {
    <#
        Only the Domain and Standard profiles are touched, because those are the
        only two Windows declares a logging policy for. There is no
        PublicProfile logging policy in WindowsFirewall.admx - a host on a
        public network is not covered, and no amount of writing to an invented
        PublicProfile\Logging key would change that.

        'Standard' is what the modern firewall UI calls the Private profile -
        recorded in verification/facts.json, fact firewall-logging, from
        WindowsFirewall.admx (policies WF_Logging_Name_1 for DomainProfile and
        WF_Logging_Name_2 for StandardProfile).
    #>
    param([Parameter(Mandatory = $true)][string] $LogDirectory)
    Write-Section 'Firewall connection logging'
    $changes = 0

    foreach ($profileName in @('DomainProfile', 'StandardProfile')) {
        $key = ($script:KeyFirewallBase + '\' + $profileName + '\Logging')
        $logFile = [System.IO.Path]::Combine($LogDirectory, ($profileName + '.log'))

        if (Set-TrackedRegistryValue -Path $key -Name 'LogDroppedPackets' `
            -Kind 'DWord' -Value 1 -Description ($profileName + ': log dropped packets')) { $changes++ }
        if (Set-TrackedRegistryValue -Path $key -Name 'LogSuccessfulConnections' `
            -Kind 'DWord' -Value 1 -Description ($profileName + ': log successful connections')) { $changes++ }
        if (Set-TrackedRegistryValue -Path $key -Name 'LogFilePath' `
            -Kind 'String' -Value $logFile -Description ($profileName + ': log path')) { $changes++ }
        if (Set-TrackedRegistryValue -Path $key -Name 'LogFileSize' `
            -Kind 'DWord' -Value $FirewallLogSizeKb -Description ($profileName + ': log size ' + $FirewallLogSizeKb + ' KB')) { $changes++ }
    }
    return $changes
}

function Set-IRAuditPolicy {
    <#
        Reads the current policy, reports or applies the difference, and in
        -Apply records ONE change record carrying the path of a full
        'auditpol /backup' taken before anything is altered. That backup is the
        rollback: restoring it puts the entire policy back, including
        subcategories this script never touched.
    #>
    param([Parameter(Mandatory = $true)][string] $WorkDirectory)
    Write-Section 'Audit policy'

    $probePath = [System.IO.Path]::Combine($WorkDirectory, 'auditpol-current.csv')
    $current = Get-AuditPolicyState -BackupPath $probePath
    Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue

    if ($current.Count -eq 0) {
        Write-Finding 'Audit policy could not be read; not changing it.'
        return 0
    }

    $needed = @()
    foreach ($target in $script:AuditTargets) {
        $guid = $target.Guid.ToUpperInvariant()
        $have = -1
        if ($current.ContainsKey($guid)) { $have = $current[$guid] }
        # Only ever ADD auditing: a host already logging more than we ask for
        # keeps it. -bor means "at least these bits".
        if ($have -lt 0) {
            Write-Finding ($target.Name + ' - subcategory not present on this host')
            continue
        }
        if (($have -bor $target.Setting) -ne $have) {
            $needed += $target
        }
    }

    # AT-2: record the FULL intended audit-subcategory set on every -Apply, not
    # only the ones that needed changing. Test-VisibilityDrift verifies recorded
    # CHANGES, so a subcategory already enabled at apply time produced no change
    # record and was a blind spot - measured, it missed Logon/Logoff/Special
    # Logon being switched off after the fact. This 'expectation' record is NOT a
    # change: it has no previous value, is never rolled back, and does not count
    # toward changeCount, so idempotence is unaffected. The drift detector reads
    # it to verify the whole intended set, not just the changed subset.
    if ($Apply) {
        $present = @()
        foreach ($expTarget in $script:AuditTargets) {
            if ($current.ContainsKey($expTarget.Guid.ToUpperInvariant())) { $present += $expTarget.Guid }
        }
        if ($present.Count -gt 0) {
            Write-ManifestRecord -Record @{
                recordType   = 'expectation'
                runId        = $script:CurrentRunId
                recordedUtc  = (Get-UtcStamp)
                change       = @{ type = 'auditpol'; subcategories = $present
                                  description = 'intended audit-subcategory coverage' }
            }
        }
    }

    if ($needed.Count -eq 0) {
        Write-Ok ('all ' + $script:AuditTargets.Count + ' audit subcategories already cover what IR needs')
        return 0
    }

    if (-not $Apply) {
        foreach ($target in $needed) {
            Write-Finding ($target.Name + ' - would enable (' + $target.Why + ')')
        }
        return 0
    }

    # Capture the whole policy before touching any of it, and record where it
    # went BEFORE the first change - same discipline as a registry value.
    $backupPath = [System.IO.Path]::Combine($WorkDirectory,
                    ('auditpol-backup-' + $script:CurrentRunId + '.csv'))
    $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @('/backup', ('/file:' + $backupPath))
    if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $backupPath)) {
        throw ('Could not back up the audit policy; refusing to change it. auditpol exit ' + $result.ExitCode)
    }

    [void] (Write-ManifestChange -Change @{
        type           = 'auditpol'
        backupPath     = $backupPath
        subcategories  = @($needed | ForEach-Object { $_.Guid })
        description    = ('audit policy: ' + $needed.Count + ' subcategor(y/ies) enabled')
    })

    foreach ($target in $needed) {
        $wanted = $target.Setting
        if ($current.ContainsKey($target.Guid.ToUpperInvariant())) {
            $wanted = $current[$target.Guid.ToUpperInvariant()] -bor $target.Setting
        }
        Set-AuditSubcategory -Guid $target.Guid -Setting $wanted
        Write-Ok ($target.Name + ' - enabled')
    }

    # Confirm by re-reading, the same way a registry write is confirmed.
    $confirmPath = [System.IO.Path]::Combine($WorkDirectory, 'auditpol-confirm.csv')
    $after = Get-AuditPolicyState -BackupPath $confirmPath
    Remove-Item -LiteralPath $confirmPath -Force -ErrorAction SilentlyContinue
    foreach ($target in $needed) {
        $guid = $target.Guid.ToUpperInvariant()
        if (-not $after.ContainsKey($guid) -or (($after[$guid] -bor $target.Setting) -ne $after[$guid])) {
            throw ('Audit subcategory did not read back as set: ' + $target.Name + ' ' + $target.Guid)
        }
    }

    return 1
}

function Grant-FirewallServiceAccess {
    <#
        The firewall service needs write access to its own log directory, and
        the toolkit root's DACL does not give it any.

        Proven on the lab: mpssvc runs as NT Authority\LocalService, so a
        directory granting only SYSTEM and Administrators leaves it unable to
        write, and the log simply never appears - the toolkit would have set
        every registry value correctly and delivered no firewall log at all.
        Granting NT SERVICE\mpssvc Modify fixed it; the log files appeared after
        a reboot.

        This is not a tracked change: the directory was created by this run, so
        there is no previous DACL to lose. If the grant fails the run continues
        with a finding rather than dying - firewall logging is one setting among
        many, and the rest of the script has already delivered value.
    #>
    param([Parameter(Mandatory = $true)][string] $Path)

    try {
        # A service SID, not a built-in group: derived from the service name and
        # not localised, unlike BUILTIN\Administrators.
        $account = New-Object System.Security.Principal.NTAccount('NT SERVICE\mpssvc')
        $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])

        $acl = Get-Acl -LiteralPath $Path
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::Modify,
            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
             [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
        Write-Ok 'firewall service granted write access to its log directory'
    }
    catch {
        Write-Finding ('Could not grant NT SERVICE\mpssvc access to ' + $Path +
                       ' - the firewall log will not appear: ' + $_.Exception.Message)
    }
}

function Invoke-HostCheck {
    <#
        Note the accumulation idiom, and copy it exactly. Never write
        '$changed = $changed -or (...)': -or short-circuits, so once $changed is
        $true every later call is NEVER MADE and the script silently stops
        applying settings after the first one that worked.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $ResolvedRoot,
        [Parameter(Mandatory = $true)][string] $WorkDirectory
    )

    # ResolvedRoot is where the settings will POINT; WorkDirectory is where
    # auditpol is allowed to write its scratch files. They differ in -Audit,
    # which must not write into the toolkit root - but the paths it reports
    # still have to be the ones -Apply would actually set, or the audit lies
    # about what applying would do.
    $transcriptPath = [System.IO.Path]::Combine($ResolvedRoot, 'Transcripts')
    $firewallPath   = [System.IO.Path]::Combine($ResolvedRoot, 'Firewall')

    # The disk-allowance ledger is per HOST CHECK, not per process. Invoke-Main
    # calls this once per mode today, but a second call in one process would
    # otherwise judge every volume against allowances it had already counted and
    # refuse resizes that fit.
    $script:AuthorisedGrowthByVolume = @{}

    $changeCount = 0
    $changeCount += Set-PowerShellLogging -TranscriptPath $transcriptPath
    # Transcription is the one unbounded thing this script turns on, so the
    # rotation that bounds it is registered in the same run - not left to an
    # operator to remember - and IMMEDIATELY after, before anything else can
    # throw. Every call below has failure paths that raise, and each one used to
    # sit in a window where transcription was already on and nothing yet capped
    # it. Sizing five more channels widened that window by five throw sites,
    # which is what moved this.
    if (-not $DisableTranscription) {
        $changeCount += Register-TranscriptRotationTask -TranscriptPath $transcriptPath
        Get-TranscriptRotationFinding -TranscriptPath $transcriptPath
        # BOOKED BEFORE EVERY CEILING BELOW, and the order is the point: this is
        # the only unbounded writer in the run, so its allowance is what the
        # resizes have to fit around rather than the other way round. It follows
        # the rotation registration so that nothing delays the cap being put in
        # place, and it changes nothing itself, so it is not counted.
        Add-TranscriptDiskAllowance -TranscriptPath $transcriptPath -MaxBytes $TranscriptMaxBytes
    }
    $changeCount += Set-ProcessCommandLineAuditing
    $changeCount += Set-EventLogSizing
    $changeCount += Set-FirewallLogging -LogDirectory $firewallPath
    # AT-13: size the reservoir for the source this script just switched on.
    $changeCount += Set-TrackedChannelSize -Channel $script:PowerShellChannel `
        -TargetBytes $PowerShellChannelSizeBytes -SectionTitle 'PowerShell channel retention' `
        -ParameterName 'PowerShellChannelSizeBytes'
    $changeCount += Set-TrackedChannelSize -Channel $script:LateralMovementChannel `
        -TargetBytes $LateralMovementChannelSizeBytes `
        -SectionTitle 'Lateral movement channel retention' `
        -ParameterName 'LateralMovementChannelSizeBytes'
    $changeCount += Set-IRAuditPolicy -WorkDirectory $WorkDirectory
    return $changeCount
}

#endregion

#region Transcript rotation ---------------------------------------------------

$script:TaskFolderPath        = '\IronBlackBox\'
$script:RotationTaskName      = 'IronBlackBox-TranscriptRotation'
$script:RotationLogName       = 'rotation.log'

function Get-TranscriptRotationScriptText {
    <#
        The rotation handler, written to disk and driven by a daily scheduled
        task. Written as text for the same reason Deploy-TamperAlerts writes its
        alert handler that way: a task must point at a file, and generating that
        file here keeps its content and the arguments it is built for from
        drifting apart.

        THREE RULES, and each one exists because of a way this could destroy
        evidence:

        1. TODAY AND YESTERDAY ARE NEVER TOUCHED. A session may still be writing
           into today's folder, and a session that started before midnight writes
           into yesterday's. Compressing or deleting either can truncate a
           transcript mid-write.
        2. THE SIZE CAP IS A BACKSTOP, NOT THE POLICY. If it evicts a day younger
           than -TranscriptKeepDays, that is recorded as FINDING in the log and
           -Audit reports it. AT-13 is the precedent: a size cap without knowing
           the fill rate silently redefines the retention window.
        3. IT NEVER DELETES WHAT IT CANNOT FIRST ARCHIVE. Compression failure
           leaves the folder alone rather than losing it.

        # UNVERIFIED: that PowerShell 5.1 always names transcript day folders
        # exactly yyyyMMdd. Measured on the lab - 20260830, 20260831, 20260901,
        # with no files at the root - but Microsoft does not document the layout,
        # so anything that does not parse as a date is SKIPPED rather than guessed
        # at, and the handler says how many it skipped.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $TranscriptPath,
        [Parameter(Mandatory = $true)][int]    $CompressAfterDays,
        [Parameter(Mandatory = $true)][int]    $KeepDays,
        [Parameter(Mandatory = $true)][long]   $MaxBytes
    )
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $text = @'
# IronBlackBox transcript rotation. Generated by Enable-IRVisibility -Apply.
# Edited by hand? Enable-IRVisibility -Audit reports the drift and -Apply rewrites
# this file. Do not rely on local edits surviving.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0

$root              = '__TRANSCRIPT_PATH__'
$compressAfterDays = __COMPRESS_AFTER__
$keepDays          = __KEEP_DAYS__
$maxBytes          = __MAX_BYTES__

$log = [System.IO.Path]::Combine($root, '__LOG_NAME__')
$stamp = (Get-Date).ToUniversalTime().ToString('o')
$lines = New-Object System.Collections.ArrayList
function Note([string] $Text) { [void] $lines.Add($stamp + '  ' + $Text) }

try {
    if (-not (Test-Path -LiteralPath $root)) { return }

    # Today and yesterday are off limits - a session may still be writing.
    $protected = @((Get-Date).ToString('yyyyMMdd'), (Get-Date).AddDays(-1).ToString('yyyyMMdd'))
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $today = (Get-Date).Date

    # Day folders, and archives from earlier runs. Anything whose name is not a
    # date is skipped, never guessed at.
    $days = @()
    $skipped = 0
    foreach ($item in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        $name = $item.Name
        if ($item.PSIsContainer) { $key = $name } else {
            if ($name -notmatch '^\d{8}\.zip$') { continue }
            $key = $name.Substring(0, 8)
        }
        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($key, 'yyyyMMdd', $invariant,
                [System.Globalization.DateTimeStyles]::None, [ref] $parsed)) {
            if ($item.PSIsContainer) { $skipped++ }
            continue
        }
        if ($protected -contains $key) { continue }
        $bytes = 0
        if ($item.PSIsContainer) {
            $m = Get-ChildItem -LiteralPath $item.FullName -Recurse -File -ErrorAction SilentlyContinue |
                 Measure-Object -Property Length -Sum
            if ($null -ne $m.Sum) { $bytes = [long] $m.Sum }
        } else { $bytes = [long] $item.Length }
        $days += [PSCustomObject]@{
            Key = $key; Date = $parsed; Path = $item.FullName
            IsFolder = [bool] $item.PSIsContainer; Bytes = $bytes
            AgeDays = [int] ($today - $parsed).TotalDays
        }
    }
    if ($skipped -gt 0) { Note ('SKIPPED ' + [string] $skipped + ' directory/ies whose name is not yyyyMMdd') }

    # --- delete past the retention policy -------------------------------------
    foreach ($d in @($days | Where-Object { $_.AgeDays -gt $keepDays })) {
        Remove-Item -LiteralPath $d.Path -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $d.Path)) {
            Note ('DELETED ' + $d.Key + ' (' + [string] $d.AgeDays + ' days old, past the ' +
                  [string] $keepDays + '-day policy, ' + [string] $d.Bytes + ' bytes)')
            $days = @($days | Where-Object { $_.Key -ne $d.Key })
        }
    }

    # --- compress what is older than the compression threshold ----------------
    foreach ($d in @($days | Where-Object { $_.IsFolder -and $_.AgeDays -gt $compressAfterDays })) {
        $zip = $d.Path + '.zip'
        if (Test-Path -LiteralPath $zip) { continue }
        try {
            Compress-Archive -Path ($d.Path + '\*') -DestinationPath $zip -Force -ErrorAction Stop
        } catch {
            Note ('COMPRESS FAILED for ' + $d.Key + ': ' + $_.Exception.Message + ' - folder left in place')
            continue
        }
        # Never delete what could not be archived: prove the archive exists and
        # carries something before the folder goes.
        if ((Test-Path -LiteralPath $zip) -and ((Get-Item -LiteralPath $zip).Length -gt 0)) {
            $after = [long] (Get-Item -LiteralPath $zip).Length
            Remove-Item -LiteralPath $d.Path -Recurse -Force -ErrorAction SilentlyContinue
            Note ('COMPRESSED ' + $d.Key + ' (' + [string] $d.Bytes + ' -> ' + [string] $after + ' bytes)')
        } else {
            Note ('COMPRESS produced no usable archive for ' + $d.Key + ' - folder left in place')
        }
    }

    # --- the backstop ---------------------------------------------------------
    # Recount from disk: compression above changed the sizes.
    $total = 0
    $current = @()
    foreach ($item in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        $name = $item.Name
        if ($item.PSIsContainer) { $key = $name } else {
            if ($name -notmatch '^\d{8}\.zip$') { continue }
            $key = $name.Substring(0, 8)
        }
        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($key, 'yyyyMMdd', $invariant,
                [System.Globalization.DateTimeStyles]::None, [ref] $parsed)) { continue }
        if ($protected -contains $key) { continue }
        $bytes = 0
        if ($item.PSIsContainer) {
            $m = Get-ChildItem -LiteralPath $item.FullName -Recurse -File -ErrorAction SilentlyContinue |
                 Measure-Object -Property Length -Sum
            if ($null -ne $m.Sum) { $bytes = [long] $m.Sum }
        } else { $bytes = [long] $item.Length }
        $total += $bytes
        $current += [PSCustomObject]@{
            Key = $key; Date = $parsed; Path = $item.FullName; Bytes = $bytes
            AgeDays = [int] ($today - $parsed).TotalDays
        }
    }

    if ($total -gt $maxBytes) {
        Note ('OVER CAP: ' + [string] $total + ' bytes exceeds the ' + [string] $maxBytes + '-byte backstop')
        foreach ($d in @($current | Sort-Object Date)) {
            if ($total -le $maxBytes) { break }
            $young = ($d.AgeDays -le $keepDays)
            Remove-Item -LiteralPath $d.Path -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $d.Path) { continue }
            $total -= $d.Bytes
            if ($young) {
                # The whole point of the AT-13 lesson: say so, do not absorb it.
                Note ('FINDING the size backstop evicted ' + $d.Key + ', only ' + [string] $d.AgeDays +
                      ' days old, inside the ' + [string] $keepDays + '-day retention policy. This host ' +
                      'generates more transcript volume than -TranscriptMaxBytes allows, so the REAL ' +
                      'retention here is shorter than the policy says. Raise -TranscriptMaxBytes or ' +
                      'lower -TranscriptKeepDays so the two agree.')
            } else {
                Note ('EVICTED ' + $d.Key + ' (' + [string] $d.AgeDays + ' days old) to get under the cap')
            }
        }
    }

    if ($lines.Count -eq 0) { Note 'nothing to do' }
}
catch {
    Note ('ERROR ' + $_.Exception.Message)
}
finally {
    try {
        Add-Content -LiteralPath $log -Value ($lines.ToArray()) -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}
'@
    # BOTH TEXT SUBSTITUTIONS LAND INSIDE A SINGLE-QUOTED POWERSHELL LITERAL, so
    # an apostrophe in either has to be doubled. -ToolkitRoot reaches here as
    # $TranscriptPath, an apostrophe is a legal NTFS filename character, and
    # Assert-SafeToolkitPath rejects drive-relative paths, UNC, volume roots and
    # system directories but not that - so -ToolkitRoot "C:\ProgramData\Bob's
    # Tools\ibb" closed the literal and the remainder was parsed as CODE in a
    # file a daily task runs as SYSTEM with -ExecutionPolicy Bypass. The benign
    # half was as damaging: the handler became a syntax error, the task failed
    # silently every night, and -Audit called it healthy because it compares the
    # broken file on disk against the identically broken intended text.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_quoting_rules
    # The three numeric substitutions are typed [int]/[long], so they cannot
    # carry a quote and are formatted invariantly instead.
    $text = $text.Replace('__TRANSCRIPT_PATH__', $TranscriptPath.Replace("'", "''"))
    $text = $text.Replace('__COMPRESS_AFTER__', $CompressAfterDays.ToString($invariant))
    $text = $text.Replace('__KEEP_DAYS__', $KeepDays.ToString($invariant))
    $text = $text.Replace('__MAX_BYTES__', $MaxBytes.ToString($invariant))
    $text = $text.Replace('__LOG_NAME__', $script:RotationLogName.Replace("'", "''"))
    return $text
}

function Register-TranscriptRotationTask {
    <#
        Writes the rotation handler and registers a daily task to run it as
        SYSTEM. Idempotent: an existing task whose handler already matches the
        intended text is left alone, and one whose handler has drifted is
        rewritten - the same drift-then-rewrite rule AT-12 put on
        Deploy-TamperAlerts.

        03:20 rather than midnight: the hour every scheduled job on every server
        already fires is the hour a maintenance task is least likely to finish.
    #>
    param([Parameter(Mandatory = $true)][string] $TranscriptPath)

    Write-Section 'Transcript rotation'
    $changes = 0
    $handlerPath = [System.IO.Path]::Combine($TranscriptPath, 'Invoke-TranscriptRotation.ps1')
    $intended = Get-TranscriptRotationScriptText -TranscriptPath $TranscriptPath `
        -CompressAfterDays $TranscriptCompressAfterDays -KeepDays $TranscriptKeepDays `
        -MaxBytes $TranscriptMaxBytes

    # PARSE THE GENERATED HANDLER BEFORE ANYTHING TRUSTS IT. A handler that does
    # not parse is the worst outcome available here, because it fails invisibly:
    # the task fires nightly, powershell.exe exits non-zero into nothing,
    # transcripts grow without limit, and the idempotence check below compares a
    # broken file against identically broken intended text and reports a match.
    # The apostrophe defect in Get-TranscriptRotationScriptText produced exactly
    # that; this gate is what makes the next such mistake loud instead.
    # https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.parser.parseinput
    $parseTokens = $null
    $parseErrors = $null
    [void] [System.Management.Automation.Language.Parser]::ParseInput(
        $intended, [ref] $parseTokens, [ref] $parseErrors)
    if ($null -ne $parseErrors -and $parseErrors.Count -gt 0) {
        throw ('the generated transcript rotation handler does not parse (' +
               $parseErrors[0].Message + '), so it was not written: a task pointing at a broken ' +
               'handler fails every night while looking correctly configured. Check -ToolkitRoot.')
    }

    $existingTask = Get-ToolkitScheduledTask -TaskPath $script:TaskFolderPath -TaskName $script:RotationTaskName
    $onDisk = ''
    if (Test-Path -LiteralPath $handlerPath) {
        try { $onDisk = [System.IO.File]::ReadAllText($handlerPath) } catch { $onDisk = '' }
    }
    $handlerMatches = [string]::Equals($onDisk, $intended, [System.StringComparison]::Ordinal)

    # THE TASK'S OWN EXECUTABLE, ANCHORED. This registered -Execute
    # 'powershell.exe' and left the unqualified name for the Task Scheduler
    # service to resolve - in a task that runs as SYSTEM at Highest every night
    # for the life of the host. Whatever wins that resolution decides what runs
    # with SYSTEM's token. Deploy-TamperAlerts and Enable-VssPreservation already
    # registered theirs against an absolute path; this one did not.
    $hostPath = Get-PowerShellHostPath
    if (-not (Test-Path -LiteralPath $hostPath)) {
        Write-Finding ('Windows PowerShell was not found at ' + $hostPath + ', so the transcript ' +
                       'rotation task cannot be registered against an absolute path. Nothing was ' +
                       'registered: a task pointing at a bare name for the scheduler to resolve is ' +
                       'not worth having.')
        return 0
    }

    # An ALREADY-REGISTERED task is read, not assumed, because -Apply below does
    # not rewrite one that exists - so a host armed by an earlier version still
    # carries the bare name and has to be told.
    #
    # UNVERIFIED: that Get-ScheduledTask exposes an Exec action as
    # .Actions[].Execute. Microsoft documents the cmdlet and the task XML, not
    # that property name. An action shape this cannot read is reported as UNREAD
    # and never as anchored, and unread is Write-Info rather than a finding: a gap
    # in the toolkit's own reading is not something to page an MSP for.
    $registeredExecute = ''
    if ($null -ne $existingTask) {
        try {
            foreach ($taskAction in @($existingTask.Actions)) {
                if ($null -eq $taskAction) { continue }
                if (-not [string]::IsNullOrWhiteSpace([string] $taskAction.Execute)) {
                    $registeredExecute = [string] $taskAction.Execute
                    break
                }
            }
        }
        catch { $registeredExecute = '' }
    }
    $executeAnchored = $true
    if (-not [string]::IsNullOrWhiteSpace($registeredExecute)) {
        # Rooted is the test, not equality with $hostPath: a task registered by a
        # 32-bit host holds a different absolute path that is still anchored.
        $executeAnchored = [System.IO.Path]::IsPathRooted($registeredExecute)
    }
    elseif ($null -ne $existingTask) {
        Write-Info ('the rotation task exists but its action could not be read, so whether it runs an ' +
                    'absolute path cannot be confirmed from here. Check ' + $script:TaskFolderPath +
                    $script:RotationTaskName + ' by hand.')
    }

    if (-not $executeAnchored) {
        Write-Finding ('the transcript rotation task runs "' + $registeredExecute + '", an unqualified ' +
                       'name the Task Scheduler service resolves itself, as SYSTEM at Highest every ' +
                       'night. It was registered by a version of this script that did not anchor it. ' +
                       '-Apply does NOT rewrite an existing task, so clear it by hand and re-run: ' +
                       'Unregister-ScheduledTask -TaskPath ''' + $script:TaskFolderPath + ''' ' +
                       '-TaskName ''' + $script:RotationTaskName + ''' -Confirm:$false')
        return 0
    }

    if ($null -ne $existingTask -and $handlerMatches) {
        Write-Ok ('rotation task already registered and its handler matches: keep ' +
                  [string] $TranscriptKeepDays + ' days, compress after ' +
                  [string] $TranscriptCompressAfterDays + ', backstop ' +
                  (Format-ByteCount -Value $TranscriptMaxBytes))
        return 0
    }
    if (-not $Apply) {
        if ($null -eq $existingTask) {
            Write-Finding ('no transcript rotation task. Transcription is on and PowerShell never removes ' +
                           'a transcript, so without this the directory grows for as long as the host ' +
                           'lives. -Apply registers a daily task at 03:20.')
        } else {
            Write-Finding ('the rotation handler on disk does not match what these parameters ask for; ' +
                           '-Apply rewrites it.')
        }
        return 0
    }

    if (-not (Test-Path -LiteralPath $TranscriptPath)) {
        [void] (New-Item -ItemType Directory -Path $TranscriptPath -Force)
    }
    [System.IO.File]::WriteAllText($handlerPath, $intended, (New-Object System.Text.UTF8Encoding($true)))
    if (-not (Test-Path -LiteralPath $handlerPath)) {
        throw ('failed to write the rotation handler to ' + $handlerPath)
    }

    if ($null -eq $existingTask) {
        $marker = 'IronBlackBox transcript rotation'
        [void] (Write-ManifestChange -Change @{
            type            = 'scheduledtask'
            taskPath        = $script:TaskFolderPath
            taskName        = $script:RotationTaskName
            previousExisted = $false
            marker          = $marker
            description     = 'Daily transcript rotation'
        })
        # -ExecutionPolicy Bypass because the handler is a toolkit-owned file in a
        # directory whose DACL is SYSTEM and Administrators only, and a machine
        # execution policy of Restricted would otherwise make this task fail every
        # night while looking perfectly configured.
        $action = New-ScheduledTaskAction -Execute $hostPath `
            -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $handlerPath + '"')
        $trigger = New-ScheduledTaskTrigger -Daily -At '03:20'
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
            -ExecutionTimeLimit ([System.TimeSpan]::FromHours(2)) -MultipleInstances IgnoreNew
        [void] (Register-ScheduledTask -TaskName $script:RotationTaskName -TaskPath $script:TaskFolderPath `
            -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
            -Description ($marker + ' - keeps ' + [string] $TranscriptKeepDays + ' days, compresses after ' +
                          [string] $TranscriptCompressAfterDays + ', backstop ' +
                          [string] $TranscriptMaxBytes + ' bytes'))
        if ($null -eq (Get-ToolkitScheduledTask -TaskPath $script:TaskFolderPath -TaskName $script:RotationTaskName)) {
            throw 'Register-ScheduledTask returned without error but the task is not registered.'
        }
        Write-Ok ('registered ' + $script:TaskFolderPath + $script:RotationTaskName + ' (daily 03:20, SYSTEM)')
        $changes++
    } else {
        Write-Ok ('rewrote the rotation handler to match the requested parameters; the existing task ' +
                  'already points at it')
    }
    return $changes
}

function Get-TranscriptRotationFinding {
    <#
        Surfaces what the rotation recorded. The handler runs unattended with no
        console, so its FINDING lines have to reach an operator somehow, and the
        mechanism that already reaches an RMM is this script's own exit code.
    #>
    param([Parameter(Mandatory = $true)][string] $TranscriptPath)

    $log = [System.IO.Path]::Combine($TranscriptPath, $script:RotationLogName)
    if (-not (Test-Path -LiteralPath $log)) { return }
    $hits = @()
    try {
        $hits = @(Get-Content -LiteralPath $log -ErrorAction Stop |
                  Where-Object { $_ -like '*FINDING*' })
    } catch { return }
    if ($hits.Count -eq 0) { return }
    Write-Finding ([string] $hits.Count + ' transcript rotation finding(s) recorded in ' + $log +
                   '. Most recent: ' + ($hits[-1]))
}

#endregion

#region Main -----------------------------------------------------------------

function Assert-ManifestPathUnderRoot {
    <#
        THE CONSTRAINT ON A MANIFEST-SUPPLIED FILE PATH.

        docs/DESIGN.md section 4: the manifest is operator-writable input, not
        trusted state. -Rollback read a path out of a record and then either
        Remove-Item'd it or overwrote it with recorded content, as SYSTEM, with no
        check that it was a file this toolkit ever wrote. A planted record turned
        the rollback into "delete or overwrite any file on this host".

        The constraint comes from the SCRIPT: the path must resolve to somewhere
        at or under the toolkit root, which is where this script's baseline lives
        and the only place it writes. Normalised through GetFullPath first, so
        '<root>\..\..\elsewhere' cannot borrow the prefix.

        Defence in depth, honestly: the toolkit root is now ACL'd to SYSTEM and
        Administrators, so anyone who can edit a record is already an
        administrator. This catches a hand-edited record, a bad merge, or an RMM
        variable - the DACL is what makes the manifest trustworthy.

        Returns the normalised path, or $null after writing the finding.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Path,
        [Parameter(Mandatory = $true)][string] $RootPath
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        Write-Finding 'The manifest record names no path; leaving it alone.'
        return $null
    }
    $prefix = $RootPath.TrimEnd('\') + '\'
    $full = $null
    try { $full = [System.IO.Path]::GetFullPath($Path) }
    catch { $full = $null }
    if ([string]::IsNullOrEmpty($full)) {
        Write-Finding ('The manifest names a path that cannot be resolved: ' + $Path +
                       '. Refusing to touch it.')
        return $null
    }
    if (-not $full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Finding ('The manifest names ' + $full + ', which is outside the toolkit root (' +
                       $prefix + '). This script only ever writes inside it, so the record did not ' +
                       'come from it. Refusing to delete or overwrite that file.')
        return $null
    }
    return $full
}

function Restore-VisibilityChange {
    <#
        Routes a change record to the right restorer. The template's
        Restore-TrackedChange only knows registry, and declines anything else -
        correctly, since silently "succeeding" on a change type it cannot undo
        is how a run gets marked rolled back while the host stays modified.
        This script introduces the 'auditpol' type, so it handles that one here
        and delegates the rest.

        Returns 'restored' or 'declined'; throws on failure.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    if ([string] $change.type -eq 'eventchannel') {
        return (Restore-EventChannelChange -ChangeRecord $ChangeRecord)
    }
    if ([string] $change.type -eq 'scheduledtask') {
        $taskOutcome = Remove-TrackedScheduledTask -ChangeRecord $ChangeRecord
        # Said HERE and not inside the shared helper. Only this script's task has
        # transcripts beside it, and the operator has to know they survive the
        # rollback - the toolkit removes the rotation, never the evidence.
        if ($taskOutcome -eq 'restored') {
            Write-Info 'Every transcript on disk was left in place; only the rotation task was removed.'
        }
        return $taskOutcome
    }
    if ($change.type -ne 'auditpol') {
        return (Restore-TrackedChange -ChangeRecord $ChangeRecord)
    }

    # THE SAME CONSTRAINT AS ITS THREE SIBLINGS, which this one was missing.
    # Restore-TrackedChange refuses a key outside what this script owns,
    # Restore-EventChannelChange refuses a channel it does not own, and
    # Remove-TrackedScheduledTask refuses a task outside \IronBlackBox\ - each
    # with a comment saying the manifest is operator-writable input. This path
    # went straight to 'auditpol /restore /file:' as SYSTEM, so a planted record
    # made -Rollback mean "apply this attacker-supplied audit policy" - most
    # usefully a CSV with every Setting Value at 0, which switches all auditing
    # off using the toolkit's own rollback path.
    #
    # RESOLVED FIRST, BEFORE THE FILE IS READ AT ALL. The case-2 comparison
    # below hashes the backup, and it used to hash whatever the record named: a
    # record pointing at a UNC path was enough to make SYSTEM authenticate to
    # somebody else's SMB server on the way to declining the restore.
    $auditRoot = [System.IO.Path]::GetDirectoryName($script:ManifestPath)
    $auditBackup = Assert-ManifestPathUnderRoot -Path ([string] $change.backupPath) -RootPath $auditRoot
    if ($null -eq $auditBackup) { return 'declined' }

    # Case 2 (docs/DESIGN.md section 4.1): the effective policy may already BE
    # the recorded pre-apply policy - either -Apply never landed or this has
    # already been rolled back. Nothing to do, counted 'restored' so the run
    # converges. Before this the branch called auditpol /restore blindly and
    # reported "Restored" either way.
    #
    # CASE 3 IS NOT COVERED HERE, and that is stated rather than hidden:
    # 'auditpol /restore' rewrites the WHOLE policy from the backup, so a
    # subcategory an operator changed AFTER the -Apply is overwritten by it.
    # Narrowing that needs a per-subcategory resolution against the
    # 'expectation' record (AT-2), which is a larger change than this one.
    if (Test-AuditPolicyMatchesBackup -BackupPath $auditBackup) {
        Write-Ok ('the audit policy already equals the state recorded in ' +
                  [System.IO.Path]::GetFileName($auditBackup) +
                  '; nothing to undo.')
        return 'restored'
    }

    Restore-AuditPolicyFromBackup -BackupPath $auditBackup
    Write-Ok ('Restored the audit policy from ' +
              [System.IO.Path]::GetFileName($auditBackup))
    return 'restored'
}

function Invoke-Main {
    $mode = 'Audit'
    if ($Apply)    { $mode = 'Apply' }
    if ($Rollback) { $mode = 'Rollback' }

    Write-Host ''
    Write-Host ('IronBlackBox - ' + $script:ScriptName + ' v' + $script:ScriptVersion + ' [' + $mode + ']') -ForegroundColor White

    # P-1: value checks BEFORE anything is read, locked or changed. These were
    # [Validate*] attributes; a binding-time failure exits 1, which collides with
    # "findings" (docs/DESIGN.md section 3). A throw here reaches exit 2.
    Assert-ParameterRange   -Name 'SecurityLogSizeKb' -Value $SecurityLogSizeKb -Minimum 20480 -Maximum 2147483647
    Assert-ParameterRange   -Name 'OtherLogSizeKb' -Value $OtherLogSizeKb -Minimum 20480 -Maximum 2147483647
    Assert-ParameterRange   -Name 'FirewallLogSizeKb' -Value $FirewallLogSizeKb -Minimum 128 -Maximum 32767
    Assert-ParameterRange   -Name 'PowerShellChannelSizeBytes' -Value $PowerShellChannelSizeBytes -Minimum 1052672 -Maximum 2147483647
    Assert-ParameterRange   -Name 'LateralMovementChannelSizeBytes' -Value $LateralMovementChannelSizeBytes -Minimum 1052672 -Maximum 2147483647
    Assert-ParameterRange   -Name 'TranscriptCompressAfterDays' -Value $TranscriptCompressAfterDays -Minimum 2 -Maximum 3650
    Assert-ParameterRange   -Name 'TranscriptKeepDays' -Value $TranscriptKeepDays -Minimum 2 -Maximum 3650
    Assert-ParameterRange   -Name 'TranscriptMaxBytes' -Value $TranscriptMaxBytes -Minimum 10485760 -Maximum 1099511627776
    # A compression threshold past the retention policy would compress nothing,
    # ever, and read as if it did something. Say so rather than silently no-op.
    if ($TranscriptCompressAfterDays -ge $TranscriptKeepDays) {
        throw ('-TranscriptCompressAfterDays (' + [string] $TranscriptCompressAfterDays + ') must be less ' +
               'than -TranscriptKeepDays (' + [string] $TranscriptKeepDays + '), or nothing would ever be ' +
               'compressed before being deleted.')
    }
    Assert-ParameterRange   -Name 'MinimumFreeDiskPercent' -Value $MinimumFreeDiskPercent -Minimum 0 -Maximum 90

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        # Audit reads the audit policy through 'auditpol /backup', which needs
        # somewhere to write. The toolkit root may not exist yet in this mode,
        # so auditpol scratches in the OS temp directory and cleans up - never
        # writing into the root from a read-only run. The REPORTED paths still
        # come from the real root.
        [void] (Invoke-HostCheck -ResolvedRoot $resolvedRoot `
                    -WorkDirectory ([System.IO.Path]::GetTempPath().TrimEnd('\')))
        Write-Section 'Result'
        if ($script:Findings.Count -gt 0) {
            Write-Info ([string] $script:Findings.Count + ' finding(s). Re-run with -Apply to change them.')
            if ($script:HostLimits.Count -gt 0) {
                Write-Info ([string] $script:HostLimits.Count + ' host limit(s) as well - see '  +
                            '[limit] above. Those are NOT part of the exit code.')
            }
            return 1
        }
        if ($script:HostLimits.Count -gt 0) {
            # Exit 0, deliberately. These are real and printed above, and no -Apply
            # will clear them on this host, so alerting would make an RMM monitor
            # permanently red - and a monitor that is always red gets muted.
            Write-Ok ('No findings. ' + [string] $script:HostLimits.Count + ' host limit(s) ' +
                      'reported above: true on this host and not clearable by any -Apply, so ' +
                      'they do not raise the exit code.')
            return 0
        }
        Write-Ok 'No findings: this host already has the visibility this script sets.'
        return 0
    }

    Enter-ToolkitLock -ToolkitRootPath $resolvedRoot
    try {
        $allowMissingStamp = ($mode -eq 'Rollback')
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -AllowMissingStamp:$allowMissingStamp)
        Assert-ManifestUsable

        if ($mode -eq 'Apply') {
            [void] (Start-ManifestRun -Mode 'Apply' -Parameters @{
                toolkitRoot              = $resolvedRoot
                securityLogSizeKb        = $SecurityLogSizeKb
                otherLogSizeKb           = $OtherLogSizeKb
                firewallLogSizeKb        = $FirewallLogSizeKb
                powerShellChannelSizeBytes = $PowerShellChannelSizeBytes
                lateralMovementChannelSizeBytes = $LateralMovementChannelSizeBytes
                disableTranscription        = [bool] $DisableTranscription
                transcriptCompressAfterDays = $TranscriptCompressAfterDays
                transcriptKeepDays          = $TranscriptKeepDays
                transcriptMaxBytes          = $TranscriptMaxBytes
                minimumFreeDiskPercent   = $MinimumFreeDiskPercent
                includeInvocationLogging = [bool] $IncludeInvocationLogging
            })

            # Transcripts and the firewall log need directories to land in.
            # They inherit the root's DACL (SYSTEM + Administrators only), which
            # is why the firewall service needs an explicit grant on top - see
            # Grant-FirewallServiceAccess.
            foreach ($sub in @('Transcripts', 'Firewall')) {
                $subPath = [System.IO.Path]::Combine($resolvedRoot, $sub)
                if (-not (Test-Path -LiteralPath $subPath)) {
                    [void] (New-Item -Path $subPath -ItemType Directory -Force)
                }
            }
            Grant-FirewallServiceAccess -Path ([System.IO.Path]::Combine($resolvedRoot, 'Firewall'))

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
                $verified = Invoke-HostCheck -ResolvedRoot $resolvedRoot -WorkDirectory $resolvedRoot
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
            Write-Info 'PowerShell logging applies to new sessions, and the audit policy is effective immediately.'
            Write-Info 'Event log sizing needs a computer policy refresh, NOT a reboot: run'
            Write-Info '"gpupdate /target:computer /force". Measured on the lab - the channel keeps its old'
            Write-Info 'maxSize until that refresh, then reports the new value exactly (policy KB x 1024).'
            Write-Info 'Firewall logging DOES need a reboot: unchanged after gpupdate, correct after a restart.'
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

        $target = Get-RollbackTargetRun -ExplicitRunId $RunId
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun)) {
            $target = Get-RollbackTargetRun -ExplicitRunId $AbandonRun
        }
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
                $outcome = Restore-VisibilityChange -ChangeRecord $target.Changes[$i]
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
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun) -and $failures -eq 0) {
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
