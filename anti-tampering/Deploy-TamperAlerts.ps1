<#
.SYNOPSIS
    Detects the destruction commands that precede or accompany ransomware -
    retrospectively by default, and forward-looking on request.

.DESCRIPTION
    Shadow copies deleted, event logs cleared, recovery disabled, Defender
    switched off. These arrive seconds to minutes before the encryption does, and
    on most hosts nothing is watching for them. This script watches.

    TWO MODES OF OPERATION, and the difference matters:

    (a) -Audit, the default, is a RETROSPECTIVE SCAN. It looks back over the
        logs already on the host for any of the indicators below having already
        happened, and reports what it finds. It deploys nothing, needs nothing
        deployed, and is what a responder runs on arrival. It is strictly
        read-only.

    (b) -Apply deploys the FORWARD-LOOKING detection: one scheduled task, running
        as SYSTEM under a toolkit-specific Task Scheduler folder, triggered by
        event subscriptions on the specific event IDs. When one fires, the task
        runs a small handler that appends a line to an alert log under the
        toolkit root for an RMM to pick up. -Apply also runs the retrospective
        scan, because deploying a watcher without looking at what already
        happened is how an already-compromised host gets a clean bill of health.

    WHAT IS WATCHED, AND WHICH EVENT REVEALS IT:

      vssadmin delete shadows, wmic shadowcopy delete, wevtutil cl,
      Clear-EventLog, bcdedit /set, wbadmin delete catalog, cipher /w,
      fsutil usn deletejournal, Set-MpPreference disabling protection or adding
      an exclusion
        -> event 4688, process creation, matched on the command line.
           THIS REQUIRES COMMAND-LINE AUDITING, which Enable-IRVisibility turns
           on. Without it, 4688 carries no command line at all and this whole
           class of detection is BLIND. This script checks for that and says so
           rather than reporting a clean bill of health it has not earned.

      the Security audit log being cleared
        -> event 1102, which Windows logs when the audit log is cleared. Far more
           reliable than spotting the command, because it is logged by the
           logging service itself. This alert moved here out of
           Protect-EventLogs.

      any other log being cleared            -> event 104
      the event logging service shutting down -> event 1100
      audit policy being changed              -> event 4719
      boot configuration at last boot         -> event 4826
      the backup catalog being deleted        -> event 524
      a service start type being changed      -> event 7040
      Defender protection disabled or its
      configuration changed                   -> 5001, 5004, 5007, 5010, 5012, 5013

    THIS IS NOT AN ENFORCEMENT TOOL, deliberately. It detects and records. It
    does not kill processes, does not block commands, and does not remove the
    right to run them. Blocking vssadmin would break every legitimate backup
    product on the host - they are the main legitimate caller - and a hardening
    script that breaks the client's backup has caused the data loss it was
    deployed to prevent. Enforcement is the MSP's decision, made after reading
    this data.

    HONEST LIMITS, all reported as findings rather than buried here:
      - Without command-line auditing, 4688-based detection is nearly useless.
      - Without the Process Creation audit subcategory enabled, there are no 4688
        events at all.
      - Without the toolkit's event log sizing, the events may already have
        rolled out of the log. This script reads the oldest record actually in
        the Security log and reports when it does not reach back as far as
        -LookbackDays.
      - Event 104's channel is not documented by Microsoft, so the retrospective
        scan queries it by provider instead. See the marker in the code.
      - Microsoft documents no event for a Defender EXCLUSION specifically. 5007
        is "The antimalware platform configuration changed" and carries the old
        and new values; reading it is the operator's job.
      - Microsoft documents no event at all for a bcdedit CHANGE. 4826 reports
        boot settings AT BOOT, so bcdedit tampering is visible either in a 4688
        command line or at the next restart, never at the moment it happens.

    NOT IMPLEMENTED, deliberately:
      - An event trigger on 4688. It fires for every process on the host, which
        would make the handler run thousands of times an hour and turn the
        watcher into the incident. The 4688 indicators are covered by the
        retrospective scan, on whatever schedule the RMM already runs it.
      - Removing the handler script or the alert log on -Rollback. The alert log
            is evidence; deleting evidence during a rollback is indefensible.
      - Any change to audit policy, log sizing or Defender. Those belong to
        Enable-IRVisibility, Protect-EventLogs and Protect-DefenderConfig. This
        script reports their absence and changes nothing about them.

.PARAMETER Audit
    Default. Strictly read-only. Runs the retrospective scan and reports whether
    the forward-looking detection is deployed. It changes nothing on the host and
    writes nothing under the toolkit root - not even the scan bookmark, which is
    why -Audit re-reports the same window on every run and says so.

    ONE file is written, outside the toolkit root, and calling that "nothing"
    would be a claim a diff can disprove: reading the Audit Process Creation
    subcategory means running 'auditpol /backup /file:...', which has to be given
    somewhere to write. It writes <system temp>\tamperalerts-auditpol.csv, reads
    the setting value out of it and deletes it. Nothing else, nowhere else.

.PARAMETER Apply
    Deploys the event-triggered task and its handler, recording the task in the
    manifest first, and advances the scan bookmark.

.PARAMETER Rollback
    Removes the task this toolkit registered. Leaves the handler and the alert
    log in place.

.PARAMETER ToolkitRoot
    Base directory for the manifest, the handler, the alert log and the
    bookmarks. Default C:\ProgramData\IronBlackBox. Validated before use.

.PARAMETER LookbackDays
    How far back the retrospective scan looks. Default 30.

.PARAMETER MaxEventsPerSource
    Hard cap on events retrieved per WATCHED-ID source per run. Default 2000.
    These logs run to gigabytes and an unbounded query on a busy domain
    controller is an outage; every query in this script is bounded.

    When the cap binds it decides the real lookback, because Get-WinEvent
    returns the NEWEST events inside the window - so the oldest part of
    -LookbackDays is simply not read. That is why a capped source prints the
    date it was actually examined back to, rather than a vague "there may be
    more": measured at the old default of 500 on an IDLE lab host, one source
    covered under three hours against a heading claiming thirty days.

    The ids these sources watch are rare on a healthy host - a cleared log, a
    deleted backup catalog - so 2000 is chosen to make the cap essentially
    never bind for them. The two noisy ones (7040 service start types, 5007
    Defender configuration) can still reach it on a busy server, and say so.

.PARAMETER MaxCommandLineEvents
    Hard cap on event 4688 records examined for destruction command lines.
    Default 2000, and it is a SAMPLE OF THE MOST RECENT N PROCESS CREATIONS,
    not a window scan. This parameter exists separately from
    -MaxEventsPerSource because the two bound completely different things and
    sharing one number made the script claim a coverage it never had.

    4688 is every process creation on the host. There is no server-side filter
    available for it - Get-BoundedEvent records why named-data keys are
    unusable on 5.1, so the command line has to be matched client-side over
    whatever was retrieved - which means a thirty-day scan of 4688 is not
    something this script can honestly offer at any cap. It offers the recent
    tail instead, and the report says which is which.

    The forward-looking handler is what covers 4688 going forward, on every
    watched event, without a window at all.

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

    Pass it on its own: it names its own target, so a -RunId naming a DIFFERENT
    run alongside it is refused rather than one of the two being dropped.

.EXAMPLE
    .\Deploy-TamperAlerts.ps1
    Scans the existing logs for destruction indicators. Deploys nothing.

.EXAMPLE
    .\Deploy-TamperAlerts.ps1 -LookbackDays 90
    A wider retrospective window, for a responder who has just arrived.

.EXAMPLE
    .\Deploy-TamperAlerts.ps1 -Apply
    Scans, then deploys the event-triggered task.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.0.0
    License : MIT

    Windows PowerShell 5.1, in-box modules only. Requires local administrator;
    enforced in code by Assert-Elevated.

    Complementary to Enable-VssPreservation: that script creates a snapshot worth
    deleting, this one notices the deletion. Neither prevents it, and neither is
    a backup.

    Every event ID and channel name is cited at the point of use in the
    'Detection catalogue' region. Everything Microsoft does not document is
    marked '# UNVERIFIED:' where it is used.
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
    [int] $LookbackDays = 30,

    [Parameter()]
    [int] $MaxEventsPerSource = 2000,

    [Parameter()]
    [int] $MaxCommandLineEvents = 2000,

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

$script:ScriptName    = 'Deploy-TamperAlerts'
$script:ScriptVersion = '1.0.0'

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

#region Detection catalogue ---------------------------------------------------

<#
    Every event ID below is cited. Channel and provider names are recorded as
    Microsoft spells them, because both go into a query string.

      Security 1102  "The audit log was cleared."  provider Microsoft-Windows-Eventlog
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
      Security 1100  "The event logging service has shut down."  same provider
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1100
      104            "The %3 log file was cleared."  source Microsoft-Windows-Eventlog
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc775044(v=ws.10)
      Security 4688  "A new process has been created."  field "Process Command Line",
                     empty unless the Include command line policy is enabled
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
      Security 4719  "System audit policy was changed."  logged regardless of the
                     Audit Policy Change subcategory setting
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719
      Security 4826  "Boot Configuration Data loaded."  fires AT BOOT, not on change
        https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4826
      524            "The System Catalog has been deleted."  source Microsoft-Windows-Backup,
                     documented as caused by "wbadmin delete catalog"
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364817(v=ws.10)
      7040           "The start type of the %1 service was changed from %2 to %3."
                     source Service Control Manager
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc756386(v=ws.10)
      Defender, channel "Microsoft-Windows-Windows Defender/Operational":
        5001 real-time protection is disabled           5004 real-time protection config changed
        5007 antimalware platform configuration changed 5010 antimalware scanning disabled
        5012 antivirus scanning disabled                5013 tamper protection blocked a change
        https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus

    # UNVERIFIED: the CHANNEL for events 104, 524 and 7040. Microsoft's pages give
    # a Source for each and no Channel, and 104 demonstrably appears in channels
    # other than System. So 104 and 524 are queried BY PROVIDER, which needs no
    # channel guess; 7040 is queried on System because Microsoft's own SCM pages
    # send the reader to "Windows Logs and System" in Event Viewer, and a wrong
    # guess there means a missing source rather than a wrong answer.

    # UNVERIFIED: Microsoft documents NO event meaning "a Defender exclusion was
    # added". 5007 is only "The antimalware platform configuration changed", and
    # it carries old and new values. Reporting it as an exclusion would be an
    # invention; it is reported as what Microsoft says it is.
#>

$script:EventSources = @(
    @{ Key = 'audit-log-cleared';   LogName = 'Security'; ProviderName = $null;
       EventId = @(1102); Level = 'alert'
       What = 'the Security audit log was CLEARED (event 1102)' },

    @{ Key = 'log-file-cleared';    LogName = $null; ProviderName = 'Microsoft-Windows-Eventlog';
       EventId = @(104); Level = 'alert'
       What = 'an event log file was cleared (event 104)' },

    @{ Key = 'eventlog-shutdown';   LogName = 'Security'; ProviderName = $null;
       EventId = @(1100); Level = 'context'
       What = 'the event logging service shut down (event 1100 - also logged at every normal shutdown)' },

    @{ Key = 'audit-policy-change'; LogName = 'Security'; ProviderName = $null;
       EventId = @(4719); Level = 'alert'
       What = 'the system audit policy was changed (event 4719)' },

    @{ Key = 'boot-config-loaded';  LogName = 'Security'; ProviderName = $null;
       EventId = @(4826); Level = 'context'
       What = 'boot configuration data loaded (event 4826 - read its fields for test signing, kernel debugging and integrity checks)' },

    @{ Key = 'backup-catalog';      LogName = $null; ProviderName = 'Microsoft-Windows-Backup';
       EventId = @(524); Level = 'alert'
       What = 'the backup System Catalog was deleted (event 524 - documented as caused by wbadmin delete catalog)' },

    @{ Key = 'service-start-type';  LogName = 'System'; ProviderName = 'Service Control Manager';
       EventId = @(7040); Level = 'context'
       What = 'a service start type was changed (event 7040)' },

    @{ Key = 'defender';            LogName = 'Microsoft-Windows-Windows Defender/Operational'; ProviderName = $null;
       EventId = @(5001, 5004, 5007, 5010, 5012, 5013); Level = 'alert'
       What = 'Defender protection was disabled or its configuration changed' }
)

<#
    Command-line indicators, matched against event 4688.

    Each pattern is anchored on the executable name AND the destructive verb, so
    a legitimate read-only invocation does not match: 'vssadmin list shadows' and
    'vssadmin resize shadowstorage' - which Enable-VssPreservation itself runs -
    are not hits, only 'delete shadows' is. That precision is what makes this
    usable on a host running real backup software.

    [^\r\n]* rather than .* so one pattern cannot straddle two lines of a
    multi-line command line.
#>
$script:CommandPatterns = @(
    @{ Key = 'vssadmin-delete';  Level = 'alert'
       Pattern = 'vssadmin(\.exe)?\b[^\r\n]*\bdelete\s+shadows\b'
       What = 'vssadmin delete shadows - volume shadow copies destroyed' },

    @{ Key = 'wmic-shadowcopy';  Level = 'alert'
       Pattern = 'wmic(\.exe)?\b[^\r\n]*\bshadowcopy\b[^\r\n]*\bdelete\b'
       What = 'wmic shadowcopy delete - volume shadow copies destroyed' },

    # Two arms because the class name can come on either side of the verb:
    # 'Get-CimInstance Win32_ShadowCopy | Remove-CimInstance' is the form actually
    # used in the wild, and a pattern that only looked for verb-then-class missed
    # it. Enumerating the class WITHOUT a delete verb does not match, which is
    # what keeps Invoke-TriageCollection's own reads out of the results.
    @{ Key = 'wmi-shadowcopy';   Level = 'alert'
       Pattern = 'Win32_ShadowCopy[^\r\n]*(Remove-CimInstance|Remove-WmiObject|\bDelete\b)|(Remove-CimInstance|Remove-WmiObject)[^\r\n]*Win32_ShadowCopy'
       What = 'Win32_ShadowCopy deleted through WMI or PowerShell' },

    @{ Key = 'wevtutil-clear';   Level = 'alert'
       Pattern = 'wevtutil(\.exe)?\b[^\r\n]*\b(cl|clear-log)\b'
       What = 'wevtutil cl - an event log cleared' },

    @{ Key = 'clear-eventlog';   Level = 'alert'
       Pattern = '\bClear-EventLog\b'
       What = 'Clear-EventLog - an event log cleared' },

    @{ Key = 'bcdedit-set';      Level = 'alert'
       Pattern = 'bcdedit(\.exe)?\b[^\r\n]*/set\b'
       What = 'bcdedit /set - boot or recovery configuration altered' },

    @{ Key = 'wbadmin-delete';   Level = 'alert'
       Pattern = 'wbadmin(\.exe)?\b[^\r\n]*\bdelete\s+(catalog|systemstatebackup|backup)\b'
       What = 'wbadmin delete - backup catalog or backups destroyed' },

    @{ Key = 'cipher-wipe';      Level = 'alert'
       Pattern = 'cipher(\.exe)?\b[^\r\n]*/w'
       What = 'cipher /w - free space overwritten, defeating file carving' },

    @{ Key = 'fsutil-usn';       Level = 'alert'
       Pattern = 'fsutil(\.exe)?\b[^\r\n]*\busn\s+deletejournal\b'
       What = 'fsutil usn deletejournal - the USN journal destroyed' },

    @{ Key = 'defender-tamper';  Level = 'alert'
       Pattern = '(Set-MpPreference|Add-MpPreference)\b[^\r\n]*(DisableRealtimeMonitoring|DisableIOAVProtection|DisableBehaviorMonitoring|Exclusion)'
       What = 'Defender protection disabled or an exclusion added from the command line' }
)

# Audit Process Creation, the subcategory that produces 4688 at all. GUID
# verified on the lab via 'auditpol /list /subcategory:* /r' and already used by
# logging-hardening/Enable-IRVisibility.ps1. Addressed by GUID because the
# display names are localised.
$script:ProcessCreationSubcategory = '{0CCE922B-69AE-11D9-BED3-505054503030}'

# Command line in 4688. Note the key is under Software\Microsoft\..., NOT
# Software\Policies\Microsoft\... - unlike every other policy in this toolkit.
# Verified on the lab (verification/facts.json, audit-process-cmdline).
# Held as the subkey path AND as the display form, rather than one string the
# reader has to Substring: an off-by-one there would read a different key and
# report command-line auditing as off on a host where it is on.
$script:SubKeyAuditSettings  = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$script:KeyAuditSettings     = 'HKLM\' + $script:SubKeyAuditSettings
$script:ValueIncludeCmdLine  = 'ProcessCreationIncludeCmdLine_Enabled'

#endregion
#region Detection prerequisites -----------------------------------------------

function Get-PolicyDwordValue {
    <#
        Reads one HKLM DWORD. This script changes no registry value, so it does
        not carry the template's Registry region - AUTHORING.md: "Reading a value
        needs nothing from this region." What it does need is the same EXPLICIT
        64-BIT VIEW the template uses, and for the same reason: RMMs do launch
        SysWOW64\WindowsPowerShell\v1.0\powershell.exe, and under WOW64
        HKLM\SOFTWARE\... is redirected to HKLM\SOFTWARE\WOW6432Node\... A
        redirected read here would report command-line auditing as OFF on a host
        where it is on, and the script would raise a blindness finding that is
        not true.
        https://learn.microsoft.com/en-us/windows/win32/winprog64/registry-redirector

        Returns $null when the key or value is absent.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $SubKeyPath,
        [Parameter(Mandatory = $true)][string] $Name
    )

    $hive = $null
    $key  = $null
    try {
        $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $key = $hive.OpenSubKey($SubKeyPath, $false)
        if ($null -eq $key) { return $null }
        $value = $key.GetValue($Name, $null)
        if ($null -eq $value) { return $null }
        return [int] $value
    }
    finally {
        if ($null -ne $key)  { $key.Dispose() }
        if ($null -ne $hive) { $hive.Dispose() }
    }
}

function Get-ProcessCreationAuditState {
    <#
        Is the Audit Process Creation subcategory on? Read through
        'auditpol /backup', whose LAST column is a NUMERIC setting value
        (0 none, 1 success, 3 success and failure) - so state is read without
        parsing localised text like "Success and Failure". Columns are read BY
        INDEX because the headers themselves may be localised. Both facts are
        recorded in verification/facts.json and this is the same technique
        Test-VisibilityDrift uses.

        Returns -1 when the state could not be read at all, which is reported as
        "unknown" and never as "off".
    #>
    param([Parameter(Mandatory = $true)][string] $WorkDirectory)

    $probe = [System.IO.Path]::Combine($WorkDirectory, 'tamperalerts-auditpol.csv')
    $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @('/backup', ('/file:' + $probe))
    if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $probe)) { return -1 }

    $lines = @(Get-Content -LiteralPath $probe)
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    $wanted = $script:ProcessCreationSubcategory.ToUpperInvariant()
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $fields = $lines[$i] -split ','
        if ($fields.Count -lt 7) { continue }
        if ($fields[3].Trim().ToUpperInvariant() -ne $wanted) { continue }
        $parsed = 0
        if ([int]::TryParse($fields[$fields.Count - 1].Trim(),
                [System.Globalization.NumberStyles]::Integer,
                    [System.Globalization.CultureInfo]::InvariantCulture, [ref] $parsed)) { return $parsed }
    }
    return -1
}

function Get-LogReach {
    <#
        How far back a channel actually goes, read as the timestamp of its OLDEST
        record. This is the finding AUTHORING.md's log-sizing story needs: a
        Security log that only reaches back four days cannot answer a question
        about a thirty-day window, and reporting "nothing found" for that window
        would be a lie of omission.

        -Oldest is required for a non-classic channel and harmless on a classic
        one; -MaxEvents 1 keeps it to a single record.
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
    #>
    param([Parameter(Mandatory = $true)][string] $LogName)

    try {
        $oldest = @(Get-WinEvent -LogName $LogName -MaxEvents 1 -Oldest -ErrorAction Stop)
        if ($oldest.Count -eq 0) { return $null }
        return $oldest[0].TimeCreated
    }
    catch {
        return $null
    }
}

#endregion

#region Event reading ---------------------------------------------------------

function Get-BoundedEvent {
    <#
        The only way this script reads an event log.

        -FilterHashtable so the filter is applied as the events are retrieved,
        and -MaxEvents so the result is bounded. 'Get-EventLog | Where-Object'
        appears nowhere in this repository: it materialises the whole log first,
        and these logs run to gigabytes on a domain controller.

        Microsoft's documented FilterHashtable keys are LogName, ProviderName,
        Path, Keywords, ID, Level, StartTime, EndTime, UserID and Data. Only
        LogName, ProviderName, ID and StartTime are used here.
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent

        NAMED-DATA KEYS ARE NOT USED. Microsoft's own two pages contradict each
        other about them - the FilterHashtable guide says <named-data> was added
        in PowerShell 6, while the 5.1 cmdlet page says an uninterpretable key is
        treated as an event-data name - so a filter like @{ CommandLine = '...' }
        would be a coin flip on the engine this toolkit targets. The command line
        is matched client-side instead, over a bounded set.

        # UNVERIFIED: Microsoft states only that "filters are applied as the
        # objects are retrieved" and never that FilterHashtable is translated into
        # XPath and evaluated by the log service. The -MaxEvents bound is what
        # makes this safe either way.

        Returns Events plus Error, because Get-WinEvent throws a TERMINATING
        error both for "no events matched" and for "that channel does not exist
        on this SKU". Those are different answers and the caller reports them
        differently; neither is a reason to fail the run.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable] $Filter,
        [Parameter(Mandatory = $true)][int] $MaxEvents
    )
    try {
        $events = @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch {
        return [PSCustomObject] @{ Events = @(); Error = $_.Exception.Message }
    }
    return [PSCustomObject] @{ Events = $events; Error = $null }
}

function Get-NewestRecordId {
    <#
        The RecordId of the newest event a filter can return with its time window
        removed, or $null when that cannot be established.

        Used to reject an impossible high-water mark. It deliberately reuses the
        SOURCE's own filter rather than querying the whole channel: a mark for one
        source was only ever advanced to a record matching that source's filter,
        so the newest such record is the highest value the mark could legitimately
        hold. A channel-wide ceiling would sit above what the mark can reach and
        let a forged value through.

        $null on any doubt - no matching events, a null RecordId, a failed query -
        because a wrong rejection makes a healthy host report its whole history as
        new, and this is the one direction where noise is not free.
    #>
    param([Parameter(Mandatory = $true)][hashtable] $Filter)

    $unbounded = @{}
    foreach ($name in $Filter.Keys) {
        if ($name -eq 'StartTime') { continue }
        $unbounded[$name] = $Filter[$name]
    }
    try {
        $newest = @(Get-WinEvent -FilterHashtable $unbounded -MaxEvents 1 -ErrorAction Stop)
    }
    catch {
        return $null
    }
    if ($newest.Count -eq 0 -or $null -eq $newest[0].RecordId) { return $null }
    return ([decimal] $newest[0].RecordId)
}

function Get-OwnProcessToken {
    <#
        SELF-EXCLUSION, part one: this process and its parent, in both the decimal
        and the '0x' hexadecimal forms that event 4688 uses for process ids, plus
        the instant this process came into existence.

        A watcher that reports its own activity is a loop. This script and its
        handler both run through powershell.exe, which produces a 4688 of its own
        every time, so the process tree that is doing the looking is excluded from
        what it looks at.

        THE START TIME IS THE OTHER HALF OF THE IDENTITY, and without it the
        exclusion was unsound: a process id is not an identity, because Windows
        reuses ids. On ids alone, ANY event in a 30-day window carrying this
        scanner's own id in any field was dropped - including, if the ids
        collided, a 'vssadmin delete shadows' this script exists to report, and
        dropped invisibly, because a source line counts what the query retrieved
        and not what survived the filters. An event written before this process
        existed cannot be this process, so it is never a candidate for exclusion,
        and the reuse window shrinks from thirty days to this run's own lifetime.

        The parent's own 4688 predates that floor and is therefore scanned like
        any other event - which is the right answer: an RMM agent that really did
        run a destruction command is exactly what this script is for.

        CreationDate is documented on Win32_Process and comes out of the query
        already being made for the parent id.
        https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process
    #>
    $ids = New-Object System.Collections.ArrayList
    [void] $ids.Add([int] $PID)
    # MaxValue means "the floor is unknown". Every event is below it, so a host
    # where this query fails excludes NOTHING rather than excluding on an id
    # alone. Same direction of error this file requires of the bookmark: a reused
    # number RE-REPORTS an event - noise - instead of hiding one - blindness.
    $notBefore = [datetime]::MaxValue
    try {
        $self = @(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId=' + [string] $PID))
        if ($self.Count -gt 0 -and $null -ne $self[0].ParentProcessId) {
            [void] $ids.Add([int] $self[0].ParentProcessId)
        }
        if ($self.Count -gt 0 -and $null -ne $self[0].CreationDate) {
            $notBefore = ([datetime] $self[0].CreationDate).ToUniversalTime()
        }
    }
    catch {
        Write-Verbose 'Could not read this process from Win32_Process; nothing will be self-excluded.'
    }
    $tokens = New-Object System.Collections.ArrayList
    foreach ($id in $ids) {
        [void] $tokens.Add([string] $id)
        [void] $tokens.Add('0x' + ([int] $id).ToString('x'))
    }
    return [PSCustomObject] @{ Tokens = @($tokens.ToArray()); NotBefore = $notBefore }
}

function Test-IsOwnProcessId {
    <#
        SELF-EXCLUSION, part two: the UNFORGEABLE half.

        Excluded only when the event was written AFTER this process started AND a
        property value EQUALS one of the process-id tokens read at runtime for
        this process and its parent. An attacker cannot choose to be this
        process, so this test cannot be talked into suppressing anything. It is
        therefore the only exclusion allowed to run before a destructive pattern
        is matched.

        BOTH HALVES ARE REQUIRED. Every property is compared rather than a named
        'process id' field, because Microsoft documents neither the order nor the
        names of 4688's EventData as stable (see Get-CommandPatternMatch) - and it
        is the time floor that makes comparing everything safe: outside this run's
        own lifetime this test cannot fire at all, whatever a hex logon id or a
        recycled process id happens to read.

        TimeCreated is nullable, and an event that cannot say when it happened
        cannot be shown to be ours, so it is not excluded.
        https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventrecord.timecreated
    #>
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)][string[]] $ExcludeToken,
        [Parameter(Mandatory = $true)][datetime] $NotBefore
    )

    if ($null -eq $Record.TimeCreated) { return $false }
    if (([datetime] $Record.TimeCreated).ToUniversalTime() -lt $NotBefore) { return $false }

    foreach ($property in $Record.Properties) {
        if ($null -eq $property.Value) { continue }
        # EventProperty.Value is documented as plain 'object' with no type
        # information at all, so it is stringified rather than cast.
        # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventproperty.value
        $text = [string] $property.Value
        if ([string]::IsNullOrEmpty($text)) { continue }
        foreach ($token in $ExcludeToken) {
            if ([string]::Equals($text, $token, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }
    return $false
}

function Test-PropertyIsToolkitPath {
    <#
        SELF-EXCLUSION, part three: the WEAK half, and the reason it is weak.

        This used to ask whether any property MENTIONED the toolkit root
        anywhere, and it ran before any pattern was matched. The toolkit root is
        the documented default printed in the README, so that was a one-string
        bypass of every 4688 detection in this script:

            cmd /c "vssadmin delete shadows /all /quiet & rem C:\ProgramData\IronBlackBox"

        The command line contains the root, the event was dropped before
        Get-CommandPatternMatch ever saw it, and the ransomware precursor this
        script exists to catch went unreported.

        So it now asks a much narrower question: is this property value, IN ITS
        ENTIRETY, a path under the toolkit root? That still covers what the
        exclusion was for - Enable-VssPreservation's snapshot handler and this
        script's own alert handler appear in events by full path - while an
        attacker who pads a command line with the root string no longer matches.

        It is also no longer used on the 4688 path at all. See the comment there.
    #>
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)][string] $ToolkitRootPath
    )

    $prefix = $ToolkitRootPath
    if (-not $prefix.EndsWith('\')) { $prefix = $prefix + '\' }

    foreach ($property in $Record.Properties) {
        if ($null -eq $property.Value) { continue }
        $text = ([string] $property.Value).Trim().Trim('"')
        if ([string]::IsNullOrEmpty($text)) { continue }
        # Normalised first, so '<root>\..\..\somewhere' cannot borrow the
        # prefix. GetFullPath throws on a value that is not a single path -
        # a command line with arguments has a colon in the wrong place - and a
        # value this cannot resolve is simply not treated as ours.
        $full = $null
        try { $full = [System.IO.Path]::GetFullPath($text) }
        catch { $full = $null }
        if ([string]::IsNullOrEmpty($full)) { continue }
        if ($full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-CommandPatternMatch {
    <#
        Matches an event's data against $script:CommandPatterns.

        EVERY property value is scanned rather than the command line being read
        out of a known position. Microsoft does not document the ORDER of 4688's
        EventData as stable, and EventProperty.Value is typed 'object' with no
        documented type, so this assumes neither an index nor a type. The cost is
        that the process image path is scanned too; the patterns are anchored on a
        destructive verb, so that costs nothing but a few string comparisons.

        Returns the matching catalogue entries, and the text that matched.
    #>
    param([Parameter(Mandatory = $true)] $Record)

    $hits = New-Object System.Collections.ArrayList
    foreach ($property in $Record.Properties) {
        if ($null -eq $property.Value) { continue }
        $text = [string] $property.Value
        if ([string]::IsNullOrEmpty($text)) { continue }
        foreach ($pattern in $script:CommandPatterns) {
            if ($text -notmatch $pattern.Pattern) { continue }
            [void] $hits.Add([PSCustomObject] @{
                Key = $pattern.Key; Level = $pattern.Level; What = $pattern.What; Text = $text })
        }
    }
    return @($hits.ToArray())
}

#endregion
#region Alert state -----------------------------------------------------------

<#
    TWO bookmark files, deliberately separate:

      tamper-scan-state.json     this script's retrospective scan
      tamper-handler-state.json  the event-triggered handler

    They record different things at different rates - the scan bookmarks per
    source by record number, the handler keeps a single watermark it can advance
    dozens of times an hour - and sharing one file would mean two processes
    racing to rewrite it while each hides events from the other.

    -AUDIT READS THE BOOKMARK AND NEVER WRITES IT. -Audit is strictly read-only
    (docs/DESIGN.md section 2), so it cannot advance a bookmark, which means it
    re-reports the same window on every run. That is stated in the output rather
    than papered over: the report separates "new since the bookmark" from "in the
    window", so a responder running -Audit repeatedly sees both.

    A CORRUPT BOOKMARK IS NOT A REASON TO STOP. It is a reason to re-report the
    window - noisy, never blind. That is the opposite trade-off from the manifest,
    where a corrupt file must stop the run because the cost there is a LOST
    PREVIOUS VALUE rather than a duplicated alert.
#>

$script:AlertStateVersion = 1

function Get-ScanBookmark {
    param([Parameter(Mandatory = $true)][string] $Path)

    $state = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $state }
    try {
        $parsed = (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    catch {
        Write-Finding ('The scan bookmark at ' + $Path + ' is unreadable, so this run cannot tell new ' +
                       'events from already-reported ones. Everything in the window is reported as new.')
        return $state
    }
    if ($null -eq $parsed -or $null -eq $parsed.sources) { return $state }
    foreach ($property in $parsed.sources.PSObject.Properties) {
        $state[$property.Name] = [PSCustomObject] @{
            LastRecordId = [string] $property.Value.lastRecordId
            LastTimeUtc  = [string] $property.Value.lastTimeUtc
            # Absent in a bookmark written before these existed, which Test-EventIsNew
            # reads as "vouches for nothing" and reports everything as new. Noisy for
            # one run after an upgrade, then self-correcting at the next -Apply.
            SinceUtc     = [string] $property.Value.sinceUtc
            Capped       = [bool]   $property.Value.capped
        }
    }
    return $state
}

function Save-ScanBookmark {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][hashtable] $State
    )
    $sources = @{}
    foreach ($key in $State.Keys) {
        $sources[$key] = @{
            lastRecordId = $State[$key].LastRecordId
            lastTimeUtc  = $State[$key].LastTimeUtc
            sinceUtc     = $State[$key].SinceUtc
            capped       = $State[$key].Capped
        }
    }
    $directory = [System.IO.Path]::GetDirectoryName($Path)
    if (-not (Test-Path -LiteralPath $directory)) {
        [void] (New-Item -Path $directory -ItemType Directory -Force)
    }
    $json = (@{ version = $script:AlertStateVersion; savedUtc = (Get-UtcStamp); sources = $sources } |
             ConvertTo-Json -Depth 6)
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function ConvertTo-DecimalOrZero {
    # Invariant integer parse that never throws. Used for record numbers, which
    # are declared unsignedLong in the event schema: [decimal] parses the whole
    # range without overflowing and without depending on whether the engine reads
    # a JSON integer as Int32 (PS 5.1) or Int64 (PS 7).
    param([Parameter()][AllowEmptyString()][string] $Text)
    $value = [decimal] 0
    [void] [decimal]::TryParse($Text, [System.Globalization.NumberStyles]::Integer,
        [System.Globalization.CultureInfo]::InvariantCulture, [ref] $value)
    return $value
}

function Test-EventIsNew {
    <#
        RecordId ordering first, TimeCreated as the fallback.

        # UNVERIFIED: Microsoft documents RecordId only as "The record number
        # assigned to the event when it was logged" and states NOWHERE that it is
        # unique or monotonically increasing within a log. It is also documented
        # nullable (Nullable<Int64>). So a null RecordId falls back to the
        # timestamp.
        #
        # THE COMPARISON DIRECTION IS NOT SAFE BY ITSELF, and an earlier version of
        # this comment claimed it was: '-gt' means a RecordId at or BELOW the mark
        # is classified as already-seen, so a reused or reset number is HIDDEN, not
        # re-reported. That was cosmetic while every alert-level hit reached the
        # exit code. It stopped being cosmetic when already-seen hits were moved
        # out of the exit code, which is why this function now refuses a mark it
        # cannot justify, and why the caller rejects a mark that stands above its
        # own channel. Noise is the acceptable failure here; silence is not.
        https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventrecord.recordid
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable] $State,
        [Parameter(Mandatory = $true)][string] $SourceKey,
        [Parameter(Mandatory = $true)] $Record
    )

    if (-not $State.ContainsKey($SourceKey)) { return $true }
    $mark = $State[$SourceKey]

    # FAIL CLOSED ON A MARK THAT CANNOT VOUCH FOR THIS EVENT. -Apply advances to
    # the newest RecordId it RETRIEVED, which is not the newest that exists: a
    # narrow -LookbackDays, or a source that hit -MaxEventsPerSource, leaves
    # events BELOW the mark that no run ever printed. Two ordinary operator
    # sequences produce that - '-Apply -LookbackDays 1' followed by the default
    # 30-day -Audit, and any source busy enough to cap - and while already-seen
    # hits still counted toward the exit code, mislabelling them cost a prefix.
    # Now it would drop them out of the exit code having never been shown, so a
    # mark has to carry the window it examined and whether that examination was
    # complete. A mark written before those fields existed vouches for nothing.
    if ([string]::IsNullOrWhiteSpace($mark.SinceUtc)) { return $true }
    if ($mark.Capped) { return $true }

    # A LastTimeUtc IN THE FUTURE vouches for nothing, whatever put it there: a
    # mark may only claim a window that has already happened. Set-ScanBookmark
    # clamps its stamp to 'now' so this version cannot write one, but an edited
    # file - or a mark written by an earlier version on a host whose clock was
    # running ahead - still reads that way, and both are handled the same, by
    # treating the event as new. Five minutes of slack absorbs ordinary clock
    # skew between the stamping run and this one, and matches the handler's own
    # guard ($script:ClockSkewSlackMinutes, rendered into it).
    if (-not [string]::IsNullOrWhiteSpace($mark.LastTimeUtc)) {
        $plausibleTime = [datetime]::MinValue
        if (-not [datetime]::TryParse($mark.LastTimeUtc, [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $plausibleTime)) {
            return $true
        }
        if ($plausibleTime.ToUniversalTime() -gt (Get-Date).ToUniversalTime().AddMinutes($script:ClockSkewSlackMinutes)) {
            return $true
        }
    }

    $markSince = [datetime]::MinValue
    if (-not [datetime]::TryParse($mark.SinceUtc,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $markSince)) {
        return $true
    }
    if ($null -eq $Record.TimeCreated -or
        $Record.TimeCreated.ToUniversalTime() -lt $markSince) {
        return $true
    }

    # THE RECORD AXIS OWNS THE VERDICT whenever the record has a RecordId, which on
    # a Windows event log it nearly always does - the nullable case falls through to
    # the time axis below. This used to require the MARK's
    # LastRecordId to be non-blank too - so a forged mark with an empty
    # lastRecordId skipped this branch and handed the verdict to the time axis
    # below, where a planted future lastTimeUtc demoted every real tamper event out
    # of the exit code. Measured on the lab, 2026-09-07: a blank-record forgery
    # demoted a genuine event 1102 with no finding raised.
    #
    # An empty or non-numeric mark now reads as 0 through ConvertTo-DecimalOrZero,
    # so any real record beats it and is reported NEW. That is the noisy direction,
    # which is the only acceptable one for a detector.
    if ($null -ne $Record.RecordId) {
        return (([decimal] $Record.RecordId) -gt (ConvertTo-DecimalOrZero -Text $mark.LastRecordId))
    }
    if ($null -ne $Record.TimeCreated -and -not [string]::IsNullOrWhiteSpace($mark.LastTimeUtc)) {
        $lastTime = [datetime]::MinValue
        if ([datetime]::TryParse($mark.LastTimeUtc,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $lastTime)) {
            return ($Record.TimeCreated.ToUniversalTime() -gt $lastTime)
        }
    }
    return $true
}

function Set-ScanBookmark {
    # Advances one source's high-water mark, and only ever forward - so an event
    # arriving out of order cannot rewind the bookmark and re-report a backlog.
    param(
        [Parameter(Mandatory = $true)][hashtable] $State,
        [Parameter(Mandatory = $true)][string] $SourceKey,
        [Parameter(Mandatory = $true)] $Record,
        # What this mark can vouch for: the window that was examined, and whether
        # that examination was complete. Overwritten on every advance rather than
        # widened, so a later narrow run NARROWS what the mark claims. That
        # re-reports events an earlier wide run already showed - noise - which is
        # the direction this detector is required to fail in.
        [Parameter(Mandatory = $true)][string] $SinceUtc,
        [Parameter(Mandatory = $true)][bool] $Capped
    )

    $recordId = ''
    if ($null -ne $Record.RecordId) {
        $recordId = ([decimal] $Record.RecordId).ToString('0',
            [System.Globalization.CultureInfo]::InvariantCulture)
    }
    $timeUtc = ''
    if ($null -ne $Record.TimeCreated) {
        # CLAMPED TO NOW. TimeCreated is the host clock as it was when the event
        # was written, so a host that ran ahead - a VM restored from a snapshot, a
        # dead CMOS battery, timestomping - leaves future-dated records behind
        # after its clock is corrected. Stamping one straight into the mark made
        # the bookmark claim a window that has not happened, and the reader on the
        # other side treats a future mark as unusable and discards it. So every
        # -Apply wrote a mark the next -Audit threw away with a finding, on a host
        # whose only fault was a clock. A mark may vouch for what has happened and
        # no further; the record axis carries the precision anyway.
        $recordTimeUtc = $Record.TimeCreated.ToUniversalTime()
        $nowUtc = (Get-Date).ToUniversalTime()
        if ($recordTimeUtc -gt $nowUtc) { $recordTimeUtc = $nowUtc }
        $timeUtc = $recordTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ',
            [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if (-not $State.ContainsKey($SourceKey)) {
        $State[$SourceKey] = [PSCustomObject] @{ LastRecordId = $recordId; LastTimeUtc = $timeUtc
                                                 SinceUtc = $SinceUtc; Capped = $Capped }
        return
    }

    $mark = $State[$SourceKey]
    $mark.SinceUtc = $SinceUtc
    $mark.Capped   = $Capped
    if (-not [string]::IsNullOrWhiteSpace($recordId) -and
        (ConvertTo-DecimalOrZero -Text $recordId) -gt (ConvertTo-DecimalOrZero -Text $mark.LastRecordId)) {
        $mark.LastRecordId = $recordId
    }
    # Ordinal string compare, which is a correct chronological compare for this
    # fixed-width ISO-8601 UTC format and needs no date parse.
    if (-not [string]::IsNullOrWhiteSpace($timeUtc) -and
        [string]::Compare($timeUtc, [string] $mark.LastTimeUtc,
            [System.StringComparison]::Ordinal) -gt 0) {
        $mark.LastTimeUtc = $timeUtc
    }
}

#endregion

#region Retrospective scan ----------------------------------------------------

<#
    Defender's own housekeeping, measured, so 5007 stops crying wolf.

    Event 5007 is "Microsoft Defender Antivirus Configuration has changed" and
    carries an old and a new value. It is the ONLY event that can reveal an
    exclusion being added, so it cannot be dropped - but Defender also raises it
    for its own internal bookkeeping, constantly.

    Measured on the lab, on an IDLE Server 2019, inside about five minutes, every
    one of these appeared as a separate 5007 and every one was written into the
    RMM-facing alert log as "TAMPER":

      count  value under HKLM\SOFTWARE\Microsoft\Windows Defender\
      -----  --------------------------------------------------------
         40  Diagnostics\InitializingComponentProgress
         28  CoreService\WdConfigHash
         12  ServiceStartStates
          4  Features\EcsConfigs\ETag\Tag
          4  Diagnostics\CleanupComponentProgress
          3  IsServiceRunning
          2  Features\Controls\260, \248, \203, \_32, \80, \79
          2  ReportingGUID
          2  OldMachineGUID
          1  Features\EcsConfigs\NIS_EnableUsoSupport

    That is EVERY distinct value across 67 events, and not one of them is a
    security setting. An alert feed carrying this is an alert feed nobody reads,
    which costs more than the events are worth.

    The list is measured on one host. Other estates will produce other internals,
    which is precisely why the handling is DEMOTION and not deletion.

    So these are DEMOTED to context rather than deleted: they still appear in the
    retrospective scan's "Context, not alerts" section, they are still in the
    Defender channel, and they no longer reach the RMM. A 5007 naming anything
    else - an exclusion path, real-time protection, a policy value - stays an
    alert.
#>
# How far ahead of 'now' a recorded timestamp may sit before it is treated as
# unusable. Declared ONCE and rendered into the handler through @@CLOCKSKEW@@,
# for the same reason the Defender noise list below is rendered rather than
# retyped: the retrospective scan and the handler judge the same kind of
# impossible timestamp, and two copies of a threshold are two thresholds.
# Five minutes absorbs ordinary NTP correction without absorbing a forgery.
$script:ClockSkewSlackMinutes = 5

$script:DefenderSelfMaintenanceValues = @(
    'Diagnostics\',
    'CoreService\WdConfigHash',
    'ServiceStartStates',
    'IsServiceRunning',
    'Features\EcsConfigs',
    'Features\Controls\',
    'ReportingGUID',
    'OldMachineGUID'
)

function Test-IsDefenderSelfMaintenance {
    <#
        True only when EVERY Defender value the event names is one of the
        housekeeping paths above. An event that names a housekeeping value AND
        something else is NOT noise - it stays an alert - because suppressing a
        real change because it arrived alongside a routine one is exactly the
        failure this predicate is supposed to prevent.

        An event that names no Defender value at all is left alone too: the
        message shape is not something to assume.
    #>
    param([Parameter(Mandatory = $true)] $Record)

    if ([int] $Record.Id -ne 5007) { return $false }
    $text = ''
    try { $text = [string] $Record.FormatDescription() } catch { $text = '' }
    if ([string]::IsNullOrEmpty($text)) { return $false }

    # NOT $matches. PowerShell fills that automatic variable in from -match, and
    # assigning to it is the same class of trap as $mode - see docs/AUTHORING.md.
    $valueHits = [regex]::Matches($text, 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\([^\s=]+)')
    if ($valueHits.Count -eq 0) { return $false }
    foreach ($match in $valueHits) {
        $valuePath = [string] $match.Groups[1].Value
        $known = $false
        foreach ($token in $script:DefenderSelfMaintenanceValues) {
            if ($valuePath.IndexOf($token, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $known = $true
                break
            }
        }
        if (-not $known) { return $false }
    }
    return $true
}

function Remove-ImpossibleBookmarkMark {
    <#
        Drops every high-water mark standing ABOVE the newest record its own
        source can return, and names what it dropped.

        WHY THIS EXISTS. A mark is only ever advanced to a RecordId this script
        retrieved, and Set-ScanBookmark moves it forward only. So a mark above its
        own source's newest record is a state no run of this script can produce.
        Two things produce it: the file was edited, or the channel was recreated
        underneath it - an .evtx replaced with the service stopped, a host cloned
        from an image that already carried this file, a restore from backup.

        WHY IT IS WORTH A QUERY PER SOURCE. A hit at or below the mark is reported
        as already-seen and is deliberately NOT in the exit code. So a mark set to
        Int64.MaxValue would silence that source for good - and because
        Set-ScanBookmark only advances, no -Apply would ever repair it. Every other
        route an administrator has to blinding this detector is either loud or
        itself a finding: delete the bookmark and everything reports as new,
        delete the scheduled task and Register-TrackedAlertTask reports it, edit
        the handler and its hash check reports it. This one must not be the quiet
        exception, and clearing the Security log - the flagship thing this detector
        exists to catch - already requires the privilege needed to write this file.

        The 4688 command-pattern keys are validated against the 4688 query they
        come from, not against their own key, because that is the query whose
        records their marks hold.
    #>
    param([Parameter(Mandatory = $true)][hashtable] $Bookmark)

    $dropped = New-Object System.Collections.ArrayList
    if ($Bookmark.Keys.Count -eq 0) { return @($dropped.ToArray()) }

    $filterByKey = @{}
    foreach ($source in $script:EventSources) {
        $filter = @{ ID = $source.EventId }
        if ($null -ne $source.LogName)      { $filter['LogName'] = $source.LogName }
        if ($null -ne $source.ProviderName) { $filter['ProviderName'] = $source.ProviderName }
        $filterByKey[$source.Key] = $filter
    }
    foreach ($pattern in $script:CommandPatterns) {
        $filterByKey[$pattern.Key] = @{ LogName = 'Security'; ID = 4688 }
    }

    # Cached: several sources share a filter shape, and Get-WinEvent is the
    # expensive part of this whole script.
    $ceilingCache = @{}
    foreach ($key in @($Bookmark.Keys)) {
        if (-not $filterByKey.ContainsKey($key)) { continue }
        $entry  = $Bookmark[$key]
        $stored = ConvertTo-DecimalOrZero -Text $entry.LastRecordId

        # A last-seen time in the future. Dropped, and REPORTED WITHOUT NAMING A
        # CULPRIT, because two different things produce it and this script cannot
        # tell them apart:
        #
        #   - the bookmark file was edited, or
        #   - an event was written while this host's clock was ahead. TimeCreated
        #     is the host clock at write time, so a VM restored from a snapshot, a
        #     dead CMOS battery or deliberate timestomping leaves genuinely
        #     future-dated records behind after the clock is corrected.
        #
        # Set-ScanBookmark now clamps a stamped time to 'now', so this script no
        # longer writes such a mark - but a mark written by an earlier version, on
        # a host whose clock was ahead, is still on disk and is not evidence of
        # tampering. Saying "forged" here would accuse an operator's clock.
        $markTime = [datetime]::MinValue
        if (-not [string]::IsNullOrWhiteSpace($entry.LastTimeUtc) -and
            [datetime]::TryParse($entry.LastTimeUtc, [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $markTime) -and
            $markTime.ToUniversalTime() -gt (Get-Date).ToUniversalTime().AddMinutes($script:ClockSkewSlackMinutes)) {
            [void] $dropped.Add([PSCustomObject] @{ Key = $key
                Detail = ('carried a last-seen time of ' + [string] $entry.LastTimeUtc +
                          ', which is in the FUTURE, and a mark cannot vouch for a window that ' +
                          'has not happened. Either ' +
                          'the bookmark was edited or this host wrote events while its clock was ' +
                          'ahead - Set-TimelineIntegrity is the script for the second one.') })
            [void] $Bookmark.Remove($key)
            continue
        }

        # No usable record number: nothing to range-check against a ceiling, so
        # this source is left alone. It is NOT reported, and an earlier version of
        # this code was wrong to report it.
        #
        # That version called the combination "a window claimed with no record
        # number, which this script cannot have written". Set-ScanBookmark writes
        # exactly that whenever a retrieved record has a null RecordId: the id is
        # stored as '' while SinceUtc and LastTimeUtc are filled. RecordId is
        # documented nullable, Test-EventIsNew carries a deliberate time-axis
        # fallback for precisely that record, and so the shape is legitimate. The
        # accusation would have been permanent: -Audit drops the mark and raises
        # the finding, the next -Apply writes the same mark again, and the monitor
        # is red for ever with nothing an operator can do - the exact outcome
        # Write-HostLimit exists to prevent.
        #
        # The ORDERING is what actually mattered here, and it is preserved: the
        # future-time check above runs FIRST. When this was a bare 'continue'
        # placed before it, a blank lastRecordId skipped the whole function and
        # took shape 1 with it.
        if ($stored -le 0) { continue }

        $filter = $filterByKey[$key]
        $cacheKey = ([string] $filter['LogName'] + '|' + [string] $filter['ProviderName'] +
                     '|' + (@($filter['ID']) -join ','))
        if (-not $ceilingCache.ContainsKey($cacheKey)) {
            $ceilingCache[$cacheKey] = Get-NewestRecordId -Filter $filter
        }
        $ceiling = $ceilingCache[$cacheKey]
        if ($null -eq $ceiling -or $stored -le $ceiling) { continue }

        [void] $dropped.Add([PSCustomObject] @{ Key = $key
            Detail = ('stood at record ' + $stored.ToString('0', [System.Globalization.CultureInfo]::InvariantCulture) +
                      ', ABOVE the newest record that source can return (' +
                      $ceiling.ToString('0', [System.Globalization.CultureInfo]::InvariantCulture) + '). This script only ever ' +
                      'advances a mark to a record it retrieved, so the bookmark was edited or ' +
                      'the channel was recreated under it.') })
        [void] $Bookmark.Remove($key)
    }
    return @($dropped.ToArray())
}

function Invoke-RetrospectiveScan {
    <#
        The default mode's whole job: look back over the logs already on this host
        for the indicators in the catalogue, and report what is there.

        Needs nothing deployed. Works on a host that has never seen this toolkit,
        which is exactly the situation a responder lands in.

        Returns one object per hit, plus per-source diagnostics, so the reporter
        can distinguish "nothing happened" from "that channel does not exist" and
        from "the cap was hit and there may be more".
    #>
    param(
        [Parameter(Mandatory = $true)][datetime] $Since,
        [Parameter(Mandatory = $true)][hashtable] $Bookmark,
        [Parameter(Mandatory = $true)][string] $ToolkitRootPath,
        [Parameter(Mandatory = $true)][bool] $CommandLineAuditingOn
    )

    $own = Get-OwnProcessToken
    $hits = New-Object System.Collections.ArrayList
    $sourceReports = New-Object System.Collections.ArrayList
    $impossibleMarks = @(Remove-ImpossibleBookmarkMark -Bookmark $Bookmark)

    foreach ($source in $script:EventSources) {
        $filter = @{ StartTime = $Since; ID = $source.EventId }
        if ($null -ne $source.LogName)      { $filter['LogName'] = $source.LogName }
        if ($null -ne $source.ProviderName) { $filter['ProviderName'] = $source.ProviderName }

        $query = Get-BoundedEvent -Filter $filter -MaxEvents $MaxEventsPerSource
        $newCount = 0
        # Counted and reported, because an exclusion the report does not mention
        # is a silent drop: Total is what the query RETRIEVED, and without this
        # the operator has no way to see that something was set aside.
        $excludedCount = 0
        foreach ($record in $query.Events) {
            # These sources alert on the event ID alone, so there is no pattern
            # match for the narrow path test to get in front of. The level takes
            # that place instead: an 'alert' source is a signal this script
            # exists to deliver, and a path in the event text does not get to
            # cancel it. 'context' sources are where suppressing the toolkit's
            # own noise is the point and a missed one costs little.
            if (Test-IsOwnProcessId -Record $record -ExcludeToken $own.Tokens -NotBefore $own.NotBefore) {
                $excludedCount++
                continue
            }
            if ($source.Level -ne 'alert' -and
                (Test-PropertyIsToolkitPath -Record $record -ToolkitRootPath $ToolkitRootPath)) { continue }
            $isNew = Test-EventIsNew -State $Bookmark -SourceKey $source.Key -Record $record
            if ($isNew) { $newCount++ }
            $level = $source.Level
            if (Test-IsDefenderSelfMaintenance -Record $record) { $level = 'context' }
            [void] $hits.Add([PSCustomObject] @{
                SourceKey = $source.Key
                Level     = $level
                What      = $source.What
                EventId   = $record.Id
                LogName   = [string] $record.LogName
                When      = $record.TimeCreated
                RecordId  = $record.RecordId
                IsNew     = $isNew
                Detail    = (Get-EventSummary -Record $record)
                Record    = $record
            })
        }
        # OldestExamined is the real floor of what this source was read back to,
        # which is NOT -LookbackDays whenever the cap was hit. Get-WinEvent
        # returns newest-first, so the last element is the oldest retrieved.
        $oldestExamined = $null
        if (@($query.Events).Count -gt 0) {
            $oldestExamined = @($query.Events)[@($query.Events).Count - 1].TimeCreated
        }
        [void] $sourceReports.Add([PSCustomObject] @{
            Key = $source.Key; What = $source.What; Level = $source.Level
            Total = @($query.Events).Count; New = $newCount
            Excluded = $excludedCount
            Capped = (@($query.Events).Count -ge $MaxEventsPerSource)
            CapParameter = 'MaxEventsPerSource'
            CapValue = $MaxEventsPerSource
            OldestExamined = $oldestExamined
            Error = $query.Error
        })
    }

    # 4688 last, and only when it can say anything. With no command line in the
    # event there is nothing for a pattern to match, so the scan is skipped
    # outright rather than run to produce a reassuring zero.
    $processReport = [PSCustomObject] @{
        Key = 'command-line'; What = 'destruction commands in event 4688'; Level = 'alert'
        Total = 0; New = 0; Excluded = 0; Capped = $false
        CapParameter = 'MaxCommandLineEvents'; CapValue = $MaxCommandLineEvents
        OldestExamined = $null; Error = $null
    }
    if (-not $CommandLineAuditingOn) {
        $processReport.Error = 'skipped: command-line auditing is off, so 4688 carries no command line'
    }
    else {
        # Its OWN cap. 4688 is every process creation on the host and cannot be
        # filtered server-side, so it does not belong under the same number as
        # the rare watched ids - sharing one made the script claim a window it
        # never scanned.
        $query = Get-BoundedEvent -Filter @{ LogName = 'Security'; ID = 4688; StartTime = $Since } `
            -MaxEvents $MaxCommandLineEvents
        $processReport.Error = $query.Error
        $processReport.Total = @($query.Events).Count
        $processReport.Capped = (@($query.Events).Count -ge $MaxCommandLineEvents)
        if (@($query.Events).Count -gt 0) {
            $processReport.OldestExamined = @($query.Events)[@($query.Events).Count - 1].TimeCreated
        }
        foreach ($record in $query.Events) {
            # Only the unforgeable exclusion runs ahead of the pattern match.
            #
            # The toolkit-root test deliberately does NOT run here. On this path
            # it bought nothing and cost everything: an event that matches no
            # destructive pattern is skipped two lines below anyway, and an event
            # that DOES match one must never be suppressed by a string an
            # attacker can type into their own command line. The three structural
            # reasons this loop cannot close are unchanged - no event trigger is
            # registered on 4688, the handler only reads logs and appends to a
            # file, and the handler runs no command that matches any pattern in
            # $script:CommandPatterns.
            if (Test-IsOwnProcessId -Record $record -ExcludeToken $own.Tokens -NotBefore $own.NotBefore) {
                $processReport.Excluded++
                continue
            }
            foreach ($match in (Get-CommandPatternMatch -Record $record)) {
                $isNew = Test-EventIsNew -State $Bookmark -SourceKey $match.Key -Record $record
                if ($isNew) { $processReport.New++ }
                [void] $hits.Add([PSCustomObject] @{
                    SourceKey = $match.Key
                    Level     = $match.Level
                    What      = $match.What
                    EventId   = $record.Id
                    LogName   = [string] $record.LogName
                    When      = $record.TimeCreated
                    RecordId  = $record.RecordId
                    IsNew     = $isNew
                    Detail    = (Format-DetailText -Text $match.Text)
                    Record    = $record
                })
            }
        }
    }
    [void] $sourceReports.Add($processReport)

    return [PSCustomObject] @{ Hits = @($hits.ToArray()); Sources = @($sourceReports.ToArray())
                               ImpossibleMarks = $impossibleMarks }
}

function Format-DetailText {
    # One line, bounded. An event's rendered text can be kilobytes and a console
    # report is not the place for it.
    param([Parameter()][AllowEmptyString()][string] $Text = '')
    $flat = ($Text -replace '[\r\n\t]+', ' ').Trim()
    if ($flat.Length -gt 220) { return ($flat.Substring(0, 220) + '...') }
    return $flat
}

function Get-EventSummary {
    <#
        FormatDescription() renders the event in the HOST's language, which is
        right for a human reading a report and wrong for anything that compares
        strings. Nothing compares this - it is display only. When rendering fails
        (a provider whose manifest is not installed), the raw property values are
        joined instead so the operator still sees something.
        https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventrecord.formatdescription
    #>
    param([Parameter(Mandatory = $true)] $Record)

    $text = ''
    try { $text = [string] $Record.FormatDescription() }
    catch { $text = '' }
    if ([string]::IsNullOrWhiteSpace($text)) {
        $parts = New-Object System.Collections.ArrayList
        foreach ($property in $Record.Properties) {
            if ($null -eq $property.Value) { continue }
            [void] $parts.Add([string] $property.Value)
        }
        $text = (($parts.ToArray()) -join ' | ')
    }
    return (Format-DetailText -Text $text)
}

#endregion
#region Scheduled task --------------------------------------------------------

<#
    Task identity is a CONSTANT, not a parameter, and that is a safety decision.

    -Rollback has to remove exactly what a previous -Apply registered and nothing
    else. The name it removes comes out of the manifest record, and the folder is
    toolkit-specific so a task at this path can only be one of ours. Exposing the
    name as a parameter would let one run register '\IronBlackBox\A' and a later
    rollback, invoked with a different argument, go looking for
    '\IronBlackBox\B' - and the interesting failure is not the miss, it is the day
    the argument happens to name somebody else's task.

    The leading AND trailing backslash on -TaskPath is required, in Microsoft's
    own words: "To specify a full TaskPath you need to include the leading and
    trailing \".
    https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask

    # UNVERIFIED: whether -TaskPath creates the folder when it does not exist yet.
    # Microsoft documents the parameter but not that behaviour. If it does not,
    # Register-ScheduledTask throws and this run exits 2 with the real error
    # rather than half-registering something - which is why no folder is
    # pre-created here on a guess.
#>
$script:TaskFolderPath   = '\IronBlackBox\'

$script:AlertTaskName = 'IronBlackBox-TamperAlert'

<#
    THE TRIGGER SET, and what is deliberately absent from it.

    One task, several event triggers. Each trigger is an EventTrigger whose
    Subscription is an event query for the IDs on one channel.

    4688 IS NOT HERE, and that is the single most important design decision in
    the deployment. An event trigger on process creation fires for every process
    on the host - thousands an hour on a busy server - so the handler would run
    continuously, and a watcher that runs continuously because of its own
    activity is the incident rather than the detector. The 4688 indicators are
    covered by the retrospective scan instead, on whatever schedule the RMM
    already runs it.

    524 is not here either: Microsoft documents its Source but not its Channel,
    and an EventTrigger Subscription needs a channel PATH. Guessing one would
    produce a trigger that silently never fires, which is worse than no trigger.
    The retrospective scan queries 524 by provider, where no channel is needed.

    # UNVERIFIED: that events 104 and 7040 are written to the System channel.
    # Microsoft's pages for both give a Source and no Channel. A wrong channel
    # here costs a trigger that never fires, not a wrong answer, and the
    # retrospective scan reaches 104 by provider regardless.
#>
$script:TriggerChannels = @(
    @{ LogName = 'Security'; EventId = @(1102, 1100, 4719, 4826) },
    @{ LogName = 'System';   EventId = @(104, 7040) },
    @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'
       EventId = @(5001, 5004, 5007, 5010, 5012, 5013) }
)

function New-EventSubscription {
    <#
        The Subscription for one EventTrigger.

        The two halves are separately documented and the COMBINATION is not, so
        it is flagged rather than presented as a citation. Microsoft's own
        EventTrigger example is <Select Path='System'>*[System/Level=2]</Select> -
        that is where the Select/Path form and the '*[System/...]' predicate style
        come from - and the element name EventID comes from the event schema's
        SystemPropertiesType.
        https://learn.microsoft.com/en-us/windows/win32/taskschd/eventtrigger-subscription
        https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-systempropertiestype-complextype

        # UNVERIFIED: no single Microsoft page shows an EventID predicate. Every
        # documented example uses System/Level. '*[System/EventID=1102]' is
        # COMPOSED from the two documented halves above. If it turns out to be
        # wrong, the trigger never fires and the lab run says so - which is why
        # -Apply prints the query it registered.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $LogName,
        [Parameter(Mandatory = $true)][int[]] $EventId
    )
    $predicates = New-Object System.Collections.ArrayList
    foreach ($id in $EventId) { [void] $predicates.Add('System/EventID=' + [string] $id) }
    return ('<QueryList><Query Id="0"><Select Path="' + $LogName + '">*[' +
            (($predicates.ToArray()) -join ' or ') + ']</Select></Query></QueryList>')
}

function New-TamperTaskXml {
    <#
        The task definition, as XML, because Register-ScheduledTask has no cmdlet
        that produces an event trigger.

        New-ScheduledTaskTrigger's five parameter sets are Once, Daily, Weekly,
        Startup and Logon - none of them event-log based, despite a sentence in
        its own help that uses "event-based" to mean startup and logon. The only
        other route in circulation is New-CimInstance against MSFT_TaskEventTrigger
        in Root/Microsoft/Windows/TaskScheduler, and that class has NO Microsoft
        reference documentation at all. The XML EventTrigger element does. Given
        this project's cardinal rule, documented XML beats an undocumented CIM
        class.
        https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-eventtrigger-triggergroup-element
        https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-tasktype-complextype

        THE PRINCIPAL, and where it differs from Enable-VssPreservation. That
        script builds its principal with New-ScheduledTaskPrincipal -LogonType
        ServiceAccount, which is a documented value of that cmdlet's LogonTypeEnum.
        The XML schema's logonType simpleType has only four values - S4U,
        Password, InteractiveToken, InteractiveTokenOrPassword - and
        ServiceAccount is NOT among them; it exists only as the COM constant
        TASK_LOGON_SERVICE_ACCOUNT. LogonType is minOccurs="0", so it is OMITTED
        here and Task Scheduler derives the logon type from the well-known SID.
        https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-logontype-simpletype
        https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-runleveltype-simpletype

        # UNVERIFIED: that <UserId> accepts a SID. Microsoft documents no accepted
        # format for it at all, in either the cmdlet or the schema. S-1-5-18 is
        # used because 'NT AUTHORITY\SYSTEM' is localised and AUTHORING.md says to
        # address principals by SID; what actually landed is READ BACK and printed.

        The Subscription is EMBEDDED AS ESCAPED TEXT rather than as nested
        elements. Microsoft's complete-task example nests the QueryList raw, but
        the schema declares Subscription as nonEmptyString, and escaped text is
        what Export-ScheduledTask emits on a real host - so it is the form
        Register-ScheduledTask certainly round-trips. The discrepancy is
        Microsoft's, not this script's.

        Both battery elements are set to false: the documented defaults are
        DisallowStartIfOnBatteries=true and StopIfGoingOnBatteries=true, which on
        a laptop or a UPS-backed server would switch the watcher off at exactly
        the wrong moment.
        https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-settingstype-complextype
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Command,
        [Parameter(Mandatory = $true)][string] $CommandArguments,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $triggerXml = New-Object System.Text.StringBuilder
    foreach ($channel in $script:TriggerChannels) {
        $subscription = New-EventSubscription -LogName $channel.LogName -EventId $channel.EventId
        [void] $triggerXml.AppendLine('    <EventTrigger>')
        [void] $triggerXml.AppendLine('      <Enabled>true</Enabled>')
        [void] $triggerXml.AppendLine('      <Subscription>' +
            [System.Security.SecurityElement]::Escape($subscription) + '</Subscription>')
        [void] $triggerXml.AppendLine('    </EventTrigger>')
    }

    $escapedDescription = [System.Security.SecurityElement]::Escape($Description)
    $escapedCommand     = [System.Security.SecurityElement]::Escape($Command)
    $escapedArguments   = [System.Security.SecurityElement]::Escape($CommandArguments)

    return @"
<?xml version="1.0" ?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>$escapedDescription</Description>
  </RegistrationInfo>
  <Triggers>
$($triggerXml.ToString().TrimEnd())
  </Triggers>
  <Principals>
    <Principal id="IronBlackBox">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="IronBlackBox">
    <Exec>
      <Command>$escapedCommand</Command>
      <Arguments>$escapedArguments</Arguments>
    </Exec>
  </Actions>
</Task>
"@
}

$script:HandlerTemplate = @'
<#
    Generated by IronBlackBox Deploy-TamperAlerts. -Rollback removes the TASK and
    deliberately leaves this file, the alert log and the handler bookmark alone:
    the alert log is evidence, and deleting evidence during a rollback is
    indefensible.

    THE JOB, and its deliberate smallness. This handler READS event logs and
    APPENDS to a text file. It runs no destructive command, changes no setting,
    and kills no process. That is not modesty, it is the anti-loop design: since
    it cannot produce any of the events it watches for, it cannot trigger itself
    through them.

    THE OTHER THREE ANTI-LOOP MEASURES:
      1. No trigger is registered on event 4688, so this handler's own process
         creation cannot wake it.
      2. The rate guard below: a wake-up within $minimumIntervalSeconds of the
         previous one exits immediately. Several triggers firing at once, or an
         event storm, therefore cost one run and not hundreds.
      3. Any event whose rendered text mentions the toolkit root is skipped -
         which covers this handler, the VSS snapshot handler, and anything else
         the toolkit ever schedules from under its own directory.
    The task's MultipleInstancesPolicy is IgnoreNew, so concurrent copies are
    refused by Task Scheduler as well.

    THE THREE LINES THIS WRITES, for whoever builds the RMM rule:
      TAMPER     one watched event, reported. This is the alarm.
      BACKLOG    a channel hit the per-run cap; nothing was dropped, the rest
                 forwards next run. A sustained backlog is itself a signal.
      SCAN-NOTE  a channel yielded nothing and Windows said why, in the host's
                 language. Not an alarm on its own - see the catch block for why
                 this cannot be classified any further - and repeated at most
                 once every $noticeRepeatHours per channel per message.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0

$alertLog    = Join-Path $PSScriptRoot 'tamper-alerts.log'
$statePath   = Join-Path $PSScriptRoot 'tamper-handler-state.json'
$toolkitRoot = Split-Path -Parent $PSScriptRoot
$maxEvents   = 1000
$minimumIntervalSeconds = 15
# Only the ALARM below is slack-gated, never the scan: a lastRunUtc this far in
# the future is past what a backwards clock correction explains. NTP slewing a
# few seconds must not page an MSP; a stamp minutes or years ahead is either a
# real clock event on this host (which Set-TimelineIntegrity exists for) or an
# edited state file, and both belong in the alert log.
$clockSkewSlackSeconds = @@CLOCKSKEW@@
# Rotated generations of the alert log kept beside the live one, at 4 MB each.
$alertLogGenerations = 5

# THE IDS NO BOOKMARK MAY EVER SUPPRESS: a cleared Security log, a cleared
# System log, a deleted backup catalog. Hoisted here because two things now use
# the list - the toolkit-root exclusion further down, which must never apply to
# a destruction signal, and the sweep below, which must never be gated by the
# state file.
#
# WHY THE SWEEP EXISTS. The per-channel bookmark decides whether an event is
# reported, and that bookmark lives in an unsigned JSON file any SYSTEM or
# Administrator process can write. Rejecting an IMPOSSIBLE bookmark - one above
# the channel ceiling - does not help here, because a bookmark that hides a
# destruction event does not have to be impossible: on a quiet channel the next
# RecordId is simply the current newest plus one, so planting that value skips
# the 1102 that follows while sitting inside the legal range. Planting any value
# above an ALREADY-logged 1102 does the same to it. No plausibility check can
# separate that from a bookmark a real run advanced, because in the legal range
# the two are the same value.
#
# So these ids are read from the 24h floor on every wake, whatever the bookmark
# says, and the throttle below is allowed to suppress a repeat only while it can
# prove the event was already reported RECENTLY. Every other answer reports.
$neverSuppressIds = @(1102, 104, 524)
# How long a destruction event may be held back as an already-reported repeat.
# Short on purpose: it bounds what a forged throttle entry can buy an attacker
# to one hour, after which the event is reported again regardless.
$destructionThrottleHours = 1
# How often the same unread-channel message may be repeated for the same
# channel. Some of those conditions are permanent - a host with no Defender
# channel at all - and this handler wakes on every watched event, so an
# unthrottled line there is thousands a day in a log that keeps one 4 MB
# generation. That is how the real TAMPER lines get rotated out.
$noticeRepeatHours = 24

function Get-Stamp {
    return (Get-Date).ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Write-Alert {
    param([Parameter()][AllowEmptyString()][string] $Text = '')
    try {
        if (Test-Path -LiteralPath $alertLog) {
            # FIVE generations, shifted oldest-out-first, not one.
            #
            # With a single '.old' the SECOND rotation overwrote it, so 8 MB of
            # any output at all destroyed every TAMPER line that came before -
            # and output is cheap to cause. A state file reset makes this handler
            # rescan its 24h floor and re-emit up to $maxEvents per channel, so an
            # attacker who repeatedly clears that file (or plants impossible marks
            # so an operator's -Apply resets it) drives flood after flood and
            # walks the real evidence out of the only two files that held it.
            # Five generations is 20 MB and buys the operator four more floods'
            # worth of margin; it does not make the log tamper-proof, which is
            # what the manifest and the forwarded events are for.
            if ((Get-Item -LiteralPath $alertLog).Length -gt 4194304) {
                $oldest = $alertLog + '.' + [string] $alertLogGenerations
                if (Test-Path -LiteralPath $oldest) { Remove-Item -LiteralPath $oldest -Force }
                for ($generation = $alertLogGenerations - 1; $generation -ge 1; $generation--) {
                    $from = $alertLog + '.' + [string] $generation
                    if (Test-Path -LiteralPath $from) {
                        Move-Item -LiteralPath $from `
                            -Destination ($alertLog + '.' + [string] ($generation + 1)) -Force
                    }
                }
                Move-Item -LiteralPath $alertLog -Destination ($alertLog + '.1') -Force
            }
        }
        [System.IO.File]::AppendAllText($alertLog, ((Get-Stamp) + ' ' + $Text + "`r`n"),
            (New-Object System.Text.UTF8Encoding($false)))
    }
    catch { Write-Verbose ('Could not append to ' + $alertLog + ': ' + $_.Exception.Message) }
}

function Get-MarkCeiling {
    <#
        The newest RecordId in a channel, whatever event id it carries. This is
        the ceiling a bookmark into that channel has to respect.

        DELIBERATELY NOT filtered by the watched event ids, and the reasoning is
        worth keeping because the tighter filter looks stricter and is not:

        Silencing this handler needs a mark ABOVE the records that have yet to be
        written, and every future record gets a RecordId above the channel's
        current newest. So a mark can only hide a future event if it exceeds the
        CHANNEL ceiling - which this catches. A mark that sits between the newest
        watched record and the channel ceiling hides nothing at all: no watched
        record has a RecordId in that range, so it suppresses exactly what a mark
        at the newest watched record suppresses, which is history already
        alerted on. Rejecting it would cost a backward scan of the whole channel
        on every wake - Get-WinEvent has to walk back to the last matching record
        - and would fail a host whose toolkit version merely dropped an id from
        the watch list.

        The deploying script's Get-NewestRecordId DOES filter by source, and must:
        there a mark demotes a real hit out of the exit code, so a mark in that
        same range changes the verdict. Here a record at or below the mark is
        already-reported history. Same-looking check, different consequence.

        $null on any doubt - an empty channel, an unreadable one, a null RecordId
        - because a wrong rejection costs a 24h rescan and a false TAMPER line.
    #>
    param([Parameter(Mandatory = $true)][string] $Channel)
    try {
        $newest = @(Get-WinEvent -LogName $Channel -MaxEvents 1 -ErrorAction Stop)
        if ($newest.Count -eq 1 -and $null -ne $newest[0].RecordId) { return [long] $newest[0].RecordId }
    }
    catch { return $null }
    return $null
}

$now   = (Get-Date).ToUniversalTime()
$floor = $now.AddHours(-24)
$state = $null
if (Test-Path -LiteralPath $statePath) {
    try { $state = (Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json) }
    catch { $state = $null }
}

# Rate guard: a wake within $minimumIntervalSeconds of the last run exits without
# scanning. The bookmark is per-channel RecordId (below), so a skipped wake never
# loses anything - the next run continues from the same record.
#
# The elapsed time is required to be NON-NEGATIVE before it can suppress a scan,
# and that is the whole of this block's security value. "-lt $minimumIntervalSeconds"
# alone was satisfied by every negative number, so a lastRunUtc in the FUTURE -
# one edit to one unsigned JSON file, no signature, no hash - made every
# subsequent wake exit here: before the scan, and before the state rewrite that
# would have healed the stamp. Permanent, silent, self-sustaining blindness in
# the component whose whole job is to notice destruction. Compare the handler
# script itself, which -Audit compares byte-for-byte against the template: the state file
# was the one input to this handler that nothing verified.
#
# So a negative elapsed never suppresses the scan. It cannot suppress itself
# either - falling through rewrites lastRunUtc from the real clock at the end of
# this run, so the forgery has to be re-planted after every single wake, and
# every one of those wakes alarms.
if ($null -ne $state -and -not [string]::IsNullOrWhiteSpace([string] $state.lastRunUtc)) {
    $last = [datetime]::MinValue
    if ([datetime]::TryParse([string] $state.lastRunUtc,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $last)) {
        $elapsedSeconds = ($now - $last).TotalSeconds
        if ($elapsedSeconds -ge 0 -and $elapsedSeconds -lt $minimumIntervalSeconds) { exit 0 }
        if ($elapsedSeconds -lt 0 -and [math]::Abs($elapsedSeconds) -gt $clockSkewSlackSeconds) {
            # Reported, not diagnosed: this handler cannot tell an edited state
            # file from a host clock that moved backwards, and says so rather
            # than picking one. Either way the scan below ran.
            #
            # SANITISED like every other attacker-controlled string that reaches
            # this log. DateTime.TryParse tolerates surrounding whitespace,
            # CR and LF included, so "`r`n`r`n2099-01-01T00:00:00Z" parses, trips
            # this alarm, and injects blank lines into a log an RMM reads line by
            # line. It cannot forge a TAMPER line - embedded non-whitespace fails
            # the parse - but the two writers below already collapse newlines and
            # this one had no business being the exception.
            $reportedStamp = (([string] $state.lastRunUtc) -replace '[\r\n\t]+', ' ').Trim()
            Write-Alert ('TAMPER handler state file ' + $statePath + ' says this handler last ran at ' +
                         $reportedStamp + ', which is ' +
                         ([string] [math]::Round([math]::Abs($elapsedSeconds))) + 's in the FUTURE. No run ' +
                         'of this handler can produce that, so either the file was edited or this host''s ' +
                         'clock moved backwards. A future stamp would silence this handler''s rate guard, so it ' +
                         'was ignored: this run scanned normally and has reset the stamp to the current ' +
                         'clock. Check the host clock, and treat an unexplained stamp as tampering with ' +
                         'the tamper detector itself.')
        }
    }
}

# Per-channel high-water RecordId from last run. RecordId is monotonic and unique
# within a channel, so paging by "EventRecordID > N" is exact - unlike a
# timestamp bookmark, which cannot separate events that share a second, the case
# a burst (or an attacker flooding one channel to bury a single real tamper)
# produces. AT-3: the previous code took the NEWEST $maxEvents by timestamp and
# then advanced a timestamp bookmark, which both dropped older events past the
# cap AND could not advance through a dense same-second burst.
$marks = @{}
if ($null -ne $state -and $null -ne $state.channels) {
    foreach ($prop in $state.channels.PSObject.Properties) {
        $val = [long] 0
        if ([long]::TryParse([string] $prop.Value,
                [System.Globalization.NumberStyles]::Integer,
                    [System.Globalization.CultureInfo]::InvariantCulture, [ref] $val)) { $marks[$prop.Name] = $val }
    }
}

# Last SCAN-NOTE per channel, as '<utc stamp>|<message>'. A channel that read
# normally this run keeps no entry, so a condition that comes back is reported
# again immediately rather than sitting inside a stale window.
$notices = @{}
if ($null -ne $state -and $null -ne $state.notices) {
    foreach ($prop in $state.notices.PSObject.Properties) {
        $notices[$prop.Name] = [string] $prop.Value
    }
}

# When each destruction event was last reported, keyed '<channel>|<recordId>'.
# Read like the notices map and judged the same way: this is a record of what
# has already been said, never a licence to stay silent.
$destructionReports = @{}
if ($null -ne $state -and $null -ne $state.destruction) {
    foreach ($prop in $state.destruction.PSObject.Properties) {
        $destructionReports[$prop.Name] = [string] $prop.Value
    }
}
$newDestructionReports = @{}

$watch = @@WATCH@@
$reported = 0
$newMarks = @{}
$newNotices = @{}
$cappedSources = New-Object System.Collections.ArrayList
# Channels whose bookmark was discarded as impossible this run. The SCAN-NOTE
# below tells the reader the bookmark was HELD, which is true on every other
# path and false on this one - two contradictory lines about the same channel in
# the same alert log is how an operator stops trusting the log.
$rescannedChannels = @{}
# '<channel>|<recordId>' already written to the alert log by THIS run, so the
# destruction sweep and the bookmarked pass cannot both report one event.
$emittedThisRun = @{}

foreach ($entry in $watch) {
    $channel = [string] $entry.LogName
    $idClause = '(' + (($entry.EventId | ForEach-Object { 'EventID=' + [string] $_ }) -join ' or ') + ')'
    $haveMark = $marks.ContainsKey($channel)

    # A bookmark this handler wrote names a record that EXISTED in this channel,
    # so a bookmark above the channel's newest record is not one this handler
    # wrote. Left in place it is the quietest possible kill: the query becomes
    # "EventRecordID > <huge>", which matches nothing for ever, and an empty
    # result is indistinguishable from a channel that is simply quiet - so the
    # handler holds the impossible mark, reports nothing, and never fails. The
    # SCAN-NOTE path even states in writing that it is "not itself a failure
    # claim", which would be the detector calmly explaining its own blindness.
    #
    # Checked BEFORE the query on purpose: dropping the mark here lets the
    # existing first-run branch below rescan the channel from the 24h floor,
    # with no second query path to keep in step. Same doctrine as the deploying
    # script's Remove-ImpossibleBookmarkMark - a mark that could not have come
    # from a run is discarded and reported, never trusted and never silently
    # dropped.
    #
    # The ceiling is the channel's newest record, not the newest WATCHED record,
    # and Get-MarkCeiling carries the reasoning: only a mark above the channel
    # ceiling can hide a future event, so the tighter filter rejects marks that
    # suppress nothing while costing a backward scan of the channel every wake.
    if ($haveMark) {
        $ceiling = Get-MarkCeiling -Channel $channel
        if ($null -ne $ceiling -and $marks[$channel] -gt $ceiling) {
            Write-Alert ('TAMPER channel=' + $channel + ' handler bookmark=' + [string] $marks[$channel] +
                         ' is ABOVE the newest record in that channel (' + [string] $ceiling + '). No run ' +
                         'of this handler can produce that, so either ' + $statePath + ' was edited or this ' +
                         'channel''s log file was replaced with an older one - both are tampering with the ' +
                         'tamper detector. The bookmark would have filtered out every future event, so it ' +
                         'was discarded and this channel was rescanned from the last 24 hours; events older ' +
                         'than that were NOT re-examined by this run.')
            $marks.Remove($channel)
            $haveMark = $false
            $rescannedChannels[$channel] = $true
        }
    }

    # THE DESTRUCTION SWEEP, and it runs BEFORE the bookmarked query for a
    # reason that is easy to get wrong: Get-WinEvent raises a terminating error
    # when a filter matches NOTHING, and the catch below ends in 'continue'. A
    # planted bookmark makes 'EventRecordID > <planted>' match nothing, so the
    # bookmarked query throws, the catch continues, and anything placed after it
    # never runs at all - on precisely the hosts where it is needed. Ordering is
    # the whole guarantee here.
    $sweepIds = New-Object System.Collections.ArrayList
    foreach ($id in $entry.EventId) {
        if ($neverSuppressIds -contains [int] $id) { [void] $sweepIds.Add([int] $id) }
    }
    if ($sweepIds.Count -gt 0) {
        $sweep = @()
        try {
            $sweep = @(Get-WinEvent -FilterHashtable @{
                LogName = $channel; ID = @($sweepIds.ToArray()); StartTime = $floor
            } -MaxEvents $maxEvents -Oldest -ErrorAction Stop)
        }
        catch {
            # Silent by design. An empty result and an unreadable channel raise
            # the same localised error, and the bookmarked pass below reports the
            # channel-level condition once, under the repeat guard. A second line
            # from here would double every quiet-channel note.
            $sweep = @()
        }
        foreach ($record in $sweep) {
            $recordKey = ($channel + '|' + [string] $record.RecordId)
            $lastReported = [datetime]::MinValue
            $throttled = $false
            if ($destructionReports.ContainsKey($recordKey)) {
                if ([datetime]::TryParse([string] $destructionReports[$recordKey],
                        [System.Globalization.CultureInfo]::InvariantCulture,
                        [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $lastReported)) {
                    # SUPPRESS ONLY ON PROOF, and only briefly. The stamp has to
                    # be in the past - a future one is the forgery this file has
                    # already been caught carrying twice - and inside the window.
                    # An absent entry, an unparseable one, a future one and an
                    # expired one all report. That is what makes a forged entry
                    # worth at most one hour, renewable only by re-forging it
                    # after every expiry, with every gap reporting.
                    $age = ($now - $lastReported.ToUniversalTime()).TotalHours
                    if ($age -ge 0 -and $age -lt $destructionThrottleHours) { $throttled = $true }
                }
            }
            if ($throttled) {
                # Carry the ORIGINAL stamp, not this run's, or the window would
                # never elapse and the throttle would become the silence.
                $newDestructionReports[$recordKey] = [string] $destructionReports[$recordKey]
                continue
            }
            $sweepText = ''
            try { $sweepText = [string] $record.FormatDescription() } catch { $sweepText = '' }
            $sweepFlat = ($sweepText -replace '[\r\n\t]+', ' ').Trim()
            if ($sweepFlat.Length -gt 400) { $sweepFlat = $sweepFlat.Substring(0, 400) + '...' }
            Write-Alert ('TAMPER channel=' + $channel + ' id=' + [string] $record.Id +
                         ' record=' + [string] $record.RecordId + ' when=' + [string] $record.TimeCreated +
                         ' :: ' + $sweepFlat + ' -- reported by the destruction sweep, which reads this ' +
                         'id from the 24h floor on every wake and is NOT gated by the bookmark. It ' +
                         'repeats at most once every ' + [string] $destructionThrottleHours + 'h until it ' +
                         'falls out of that window, so seeing it again is expected and is not a second ' +
                         'event - compare record numbers.')
            $reported++
            $emittedThisRun[$recordKey] = $true
            $newDestructionReports[$recordKey] = (Get-Stamp)
        }
    }

    $events = @()
    try {
        if ($haveMark) {
            $xpath = '*[System[' + $idClause + ' and EventRecordID > ' + [string] $marks[$channel] + ']]'
            $events = @(Get-WinEvent -LogName $channel -FilterXPath $xpath -MaxEvents $maxEvents -Oldest -ErrorAction Stop)
        }
        else {
            # First run for this channel: bound by a 24h floor so history is not
            # replayed wholesale, oldest-first so the cap keeps the oldest.
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName = $channel; ID = $entry.EventId; StartTime = $floor
            } -MaxEvents $maxEvents -Oldest -ErrorAction Stop)
        }
    }
    catch {
        # NOTHING HERE PARSES THE MESSAGE, and that is the whole point.
        #
        # Get-WinEvent raises a terminating error for at least three different
        # answers - the query matched nothing, this SKU has no such channel, the
        # channel could not be read - and its text is LOCALISED. The previous code
        # picked out the first by regex-matching the English 'No events were
        # found', so on a fr-FR host (the same reason well-known SIDs are used
        # instead of 'BUILTIN\Administrators' further up) every empty query became
        # a read error. Every wake scans all the watched channels and only one of
        # them fired, so that is a line per quiet channel per wake - four wakes a
        # minute at a 15-second rate guard - into a log that keeps one 4 MB
        # generation. That is how a localised host rotates its own TAMPER lines out.
        #
        # The bookmark is held in every one of those cases, so the only decision
        # left is what reaches the alert log - and the honest answer is the one
        # the main script's Get-BoundedEvent gives for the identical ambiguity:
        # report what Windows said and do not interpret it. The repeat guard is
        # what makes that affordable, and a condition that really is a read
        # failure is still reported, and reported again while it lasts.
        if ($haveMark) { $newMarks[$channel] = $marks[$channel] }

        $message = ($_.Exception.Message -replace '[\r\n\t]+', ' ').Trim()
        if ($message.Length -gt 300) { $message = $message.Substring(0, 300) + '...' }
        $lastText = ''
        $lastWhen = [datetime]::MinValue
        if ($notices.ContainsKey($channel)) {
            # Split on the first separator only: the message may contain one.
            $parts = ([string] $notices[$channel]).Split([char[]] '|', 2)
            if ($parts.Count -eq 2) {
                $lastText = $parts[1]
                [void] [datetime]::TryParse($parts[0],
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $lastWhen)
            }
        }
        # A NOTICE STAMPED IN THE FUTURE IS DISCARDED, and this is the third
        # timestamp in this file to need the rule - the same shape as lastRunUtc
        # and the channel marks.
        #
        # It was the worst of the three. The suppression test below is
        # "($now - $lastWhen).TotalHours -ge 24", which a negative delta never
        # satisfies, so a future stamp suppressed the notice on every wake; and
        # the else-branch deliberately re-persists the ORIGINAL stamp, so unlike
        # lastRunUtc it never healed itself. An attacker who renders a channel
        # unreadable, reads the exact localised message Windows gives for it, and
        # writes that message under a future stamp removes the ONLY signal that
        # the channel has gone dark - permanently, with no error anywhere.
        #
        # So a future stamp reads as "no previous notice": report, and alarm,
        # because Get-Stamp writes the current clock and no run can produce it.
        if ($lastWhen -ne [datetime]::MinValue -and
            $lastWhen.ToUniversalTime() -gt $now.AddSeconds($clockSkewSlackSeconds)) {
            Write-Alert ('TAMPER channel=' + $channel + ' the repeat-suppression stamp for this ' +
                         'channel in ' + $statePath + ' is in the FUTURE (' +
                         (($parts[0] -replace '[\r\n\t]+', ' ').Trim()) + '). No run of this handler ' +
                         'can write that, and while it stood it suppressed the only line that reports ' +
                         'this channel going unreadable. It was ignored for this run.')
            $lastText = ''
            $lastWhen = [datetime]::MinValue
        }
        # An unparseable or absent previous notice leaves $lastWhen at MinValue,
        # which reports. Suppression is never the fallback.
        if ($message -ne $lastText -or ($now - $lastWhen).TotalHours -ge $noticeRepeatHours) {
            # The bookmark sentence has to match what actually happened to it. On
            # the impossible-mark path above it was DISCARDED, and telling the
            # reader it was held two lines under a TAMPER saying it was thrown
            # away is how an alert log stops being believed.
            $bookmarkNote = 'The bookmark was held, so no window is skipped.'
            if ($rescannedChannels.ContainsKey($channel)) {
                $bookmarkNote = ('The bookmark for this channel was DISCARDED as impossible earlier ' +
                                 'this run - see the TAMPER line above - so this query covered the ' +
                                 'last 24 hours only and anything older was not re-examined.')
            }
            Write-Alert ('SCAN-NOTE channel=' + $channel + ' returned no events; Windows reported: ' +
                         $message + ' -- that is what Windows says both for a query that matched ' +
                         'nothing and for a channel it cannot read, so this line is not itself a ' +
                         'failure claim. ' + $bookmarkNote + ' Repeated at ' +
                         'most once every ' + [string] $noticeRepeatHours + 'h unless the message changes.')
            $newNotices[$channel] = ((Get-Stamp) + '|' + $message)
        }
        else {
            # The ORIGINAL stamp, not this run's, or the window would never elapse.
            $newNotices[$channel] = [string] $notices[$channel]
        }
        continue
    }

    if ($events.Count -eq 0) {
        if ($haveMark) { $newMarks[$channel] = $marks[$channel] }
        continue
    }

    # Oldest-first, so the last element carries the highest RecordId processed.
    $newMarks[$channel] = [long] $events[$events.Count - 1].RecordId
    if ($events.Count -eq $maxEvents) {
        [void] $cappedSources.Add($channel + ' id=' + (($entry.EventId) -join ','))
    }

    foreach ($record in $events) {
        # Already written by the destruction sweep above. Skipped here rather
        # than in the sweep, because the sweep is the pass that is guaranteed to
        # run and so has to be the one that reports.
        if ($emittedThisRun.ContainsKey($channel + '|' + [string] $record.RecordId)) { continue }
        $text = ''
        try { $text = [string] $record.FormatDescription() } catch { $text = '' }
        # The toolkit-root exclusion exists because this toolkit legitimately
        # changes audit policy (4719), service start types (7040) and Defender
        # preferences (5007), and its own runs should not page an MSP at 3am.
        #
        # It must never reach a DESTRUCTION signal. This toolkit never clears an
        # event log and never deletes a backup catalog, so on those ids the
        # exclusion can only ever be wrong - and since $toolkitRoot is the
        # documented default path printed in the README, an attacker who gets it
        # into the rendered message suppresses the one alert that matters.
        # Anything below is reported no matter what it mentions.
        if ($neverSuppressIds -notcontains [int] $record.Id) {
            # A path prefix, not a bare mention: the root has to be followed by a
            # separator to count as "something of ours appearing in this event".
            if (-not [string]::IsNullOrEmpty($text) -and
                $text.IndexOf($toolkitRoot + '\\', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                continue
            }
        }
        # Defender's own housekeeping never reaches the RMM. The token list is
        # substituted from $script:DefenderSelfMaintenanceValues in the deploying
        # script, so the handler and the retrospective scan cannot drift apart.
        # Same rule as there: noise only when EVERY value the event names is
        # housekeeping.
        if ([int] $record.Id -eq 5007) {
            $found = [regex]::Matches($text, 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\([^\s=]+)')
            if ($found.Count -gt 0) {
                $allKnown = $true
                foreach ($one in $found) {
                    $valuePath = [string] $one.Groups[1].Value
                    $known = $false
                    foreach ($token in @@DEFENDERNOISE@@) {
                        if ($valuePath.IndexOf($token, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $known = $true
                            break
                        }
                    }
                    if (-not $known) { $allKnown = $false; break }
                }
                if ($allKnown) { continue }
            }
        }
        $flat = ($text -replace '[\r\n\t]+', ' ').Trim()
        if ($flat.Length -gt 400) { $flat = $flat.Substring(0, 400) + '...' }
        Write-Alert ('TAMPER channel=' + $channel + ' id=' + [string] $record.Id +
                     ' record=' + [string] $record.RecordId + ' when=' + [string] $record.TimeCreated +
                     ' :: ' + $flat)
        $reported++
    }
}

if ($cappedSources.Count -gt 0) {
    Write-Alert ('BACKLOG ' + [string] $cappedSources.Count + ' source(s) hit the ' +
                 [string] $maxEvents + '-event cap this run (' + (($cappedSources.ToArray()) -join '; ') +
                 '); NO events were dropped - each channel bookmark advanced to the last RecordId ' +
                 'processed, so the remainder forwards next run. A sustained backlog can itself be a signal.')
}

# Persist per-channel RecordId marks and the run time (the latter for the rate
# guard only). A channel absent from $newMarks keeps whatever it had.
foreach ($channel in $marks.Keys) {
    if (-not $newMarks.ContainsKey($channel)) { $newMarks[$channel] = $marks[$channel] }
}
$channelObj = @{}
foreach ($k in $newMarks.Keys) { $channelObj[$k] = ([long] $newMarks[$k]).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
# $newNotices only, deliberately: a channel that read normally this run drops out
# of the map, so the next failure on it is reported at once.
$noticeObj = @{}
foreach ($k in $newNotices.Keys) { $noticeObj[$k] = [string] $newNotices[$k] }
# $newDestructionReports only, and PRUNED by construction: an entry survives
# only if this run saw its record inside the 24h sweep window, so a record that
# has aged past the floor drops out and the map cannot grow without bound. It
# also means a stale entry can never suppress a record the sweep re-finds later.
$destructionObj = @{}
foreach ($k in $newDestructionReports.Keys) { $destructionObj[$k] = [string] $newDestructionReports[$k] }
try {
    [System.IO.File]::WriteAllText($statePath,
        (@{ lastRunUtc = (Get-Stamp); reported = $reported
            cappedSources = $cappedSources.Count; channels = $channelObj
            notices = $noticeObj; destruction = $destructionObj } | ConvertTo-Json -Depth 3),
        (New-Object System.Text.UTF8Encoding($false)))
}
catch { Write-Verbose ('Could not write ' + $statePath + ': ' + $_.Exception.Message) }
exit 0
'@

function New-HandlerScript {
    <#
        Writes the handler under the toolkit root. The directory inherits the
        root's DACL - SYSTEM and Administrators only, inheritance disabled - so no
        extra grant is made: docs/DESIGN.md section 5 wants an explicit narrow
        grant only for a subdirectory needing WIDER access, and this one needs
        none.

        The watch list is RENDERED from $script:TriggerChannels rather than
        written out twice, so the events the task triggers on and the events the
        handler looks for cannot drift apart.
    #>
    param([Parameter(Mandatory = $true)][string] $Directory)

    if (-not (Test-Path -LiteralPath $Directory)) {
        [void] (New-Item -Path $Directory -ItemType Directory -Force)
    }
    $path = [System.IO.Path]::Combine($Directory, 'Write-TamperAlert.ps1')
    # UTF-8 WITH a BOM, for the reason every .ps1 in this repository has one:
    # Windows PowerShell 5.1 reads a BOM-less UTF-8 file as ANSI.
    [System.IO.File]::WriteAllText($path, (Get-HandlerScriptText),
        (New-Object System.Text.UTF8Encoding($true)))
    return $path
}

function Get-HandlerScriptText {
    # AT-12: the handler's intended content, computed the one place so New-HandlerScript
    # (which writes it) and the existing-task path (which checks the deployed copy
    # against it) can never disagree. The watch list and Defender-noise list are
    # rendered from the same script tables the task triggers on.
    $entries = New-Object System.Collections.ArrayList
    foreach ($channel in $script:TriggerChannels) {
        $ids = New-Object System.Collections.ArrayList
        foreach ($id in $channel.EventId) { [void] $ids.Add([string] $id) }
        [void] $entries.Add("    @{ LogName = '" + $channel.LogName + "'; EventId = @(" +
                            (($ids.ToArray()) -join ', ') + ') }')
    }
    $watchLiteral = ("@(" + [System.Environment]::NewLine +
                     (($entries.ToArray()) -join ("," + [System.Environment]::NewLine)) +
                     [System.Environment]::NewLine + ")")

    $quoted = New-Object System.Collections.ArrayList
    foreach ($token in $script:DefenderSelfMaintenanceValues) {
        [void] $quoted.Add("'" + $token.Replace("'", "''") + "'")
    }
    $noiseLiteral = ("@(" + (($quoted.ToArray()) -join ', ') + ")")

    # Seconds, because the handler compares against a TotalSeconds delta.
    # Rendered from the same $script: value the retrospective scan uses, so the
    # two cannot drift apart.
    $skewLiteral = [string] ($script:ClockSkewSlackMinutes * 60)

    return $script:HandlerTemplate.Replace('@@WATCH@@', $watchLiteral).Replace('@@DEFENDERNOISE@@', $noiseLiteral).Replace('@@CLOCKSKEW@@', $skewLiteral)
}

function Test-HandlerStateFile {
    <#
        Cross-checks the handler's own state file for values no run of the
        handler can produce.

        Every OTHER part of the forward-looking detector is verified: the task
        has to exist, its action has to name this root's handler, and the
        handler's bytes are compared against this version's template. The state
        file was the exception - the only input the handler trusts, with no
        signature and no hash - and the shapes below are the ones that SILENCE
        the handler rather than break it. Every timestamp in that file gates a
        suppression, so every one of them is checked here:

          - lastRunUtc in the future satisfied the rate guard on every wake;
          - a channel mark above what the channel can produce filters every
            later event out;
          - a notices stamp in the future suppressed the ONE line that reports a
            watched channel having gone unreadable, and was re-persisted every
            run, so unlike the other two it never healed;
          - a destruction stamp in the future suppresses the repeat of a cleared
            log for as long as it stands.

        A detector that reports nothing and never fails is the exact failure this
        script exists to prevent, so it is checked from the outside too, where an
        MSP's drift report can see it. The three future-stamp fields are the same
        defect three times over, which is why they are enumerated rather than
        special-cased: the next field added to that file needs this check too.

        Shapes that make the handler NOISY are deliberately not reported here.
        A mark it cannot parse is dropped and that channel rescans from its 24h
        floor; a state file it cannot parse is treated as absent, which is a
        first run. Those announce themselves. Only silence needs a witness.

        Returns nothing, and writes NO manifest record: the state file is a
        toolkit-owned derived file like the handler script itself (AT-12), so
        -Apply resets it in place and the count of recorded changes is unmoved.
    #>
    param([Parameter(Mandatory = $true)][string] $AlertDirectory,
          [Parameter()][switch] $ApplyMode)

    $statePath = [System.IO.Path]::Combine($AlertDirectory, 'tamper-handler-state.json')
    if (-not (Test-Path -LiteralPath $statePath)) {
        # The normal state of a host whose watched events have never fired.
        return
    }

    $state = $null
    try { $state = ([System.IO.File]::ReadAllText($statePath) | ConvertFrom-Json) }
    catch { $state = $null }
    if ($null -eq $state) {
        Write-Info ('the handler state file ' + $statePath + ' is not readable as JSON; the handler ' +
                    'treats that as a first run and rescans its 24h floor, so nothing is suppressed')
        return
    }

    $impossible = New-Object System.Collections.ArrayList
    $nowUtc = (Get-Date).ToUniversalTime()

    if (-not [string]::IsNullOrWhiteSpace([string] $state.lastRunUtc)) {
        $last = [datetime]::MinValue
        if ([datetime]::TryParse([string] $state.lastRunUtc,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $last)) {
            # The same slack the handler's own guard uses, from the same $script:
            # value that is rendered into it, so a
            # clock being slewed by NTP between the two runs is not a finding.
            $secondsAhead = ($last - $nowUtc).TotalSeconds
            if ($secondsAhead -gt ($script:ClockSkewSlackMinutes * 60)) {
                [void] $impossible.Add('lastRunUtc is ' + ([string] [math]::Round($secondsAhead)) +
                                       's in the future (' + ([string] $state.lastRunUtc) + ')')
            }
        }
    }

    # The other two timestamp maps, judged by the same rule. Both are keyed
    # collections whose VALUE carries the stamp: notices as '<stamp>|<message>',
    # destruction as a bare stamp. Walked generically so that adding a third such
    # map does not need a third block of near-identical code.
    $stampMaps = @(
        [PSCustomObject] @{ Name = 'notices'; Value = $state.notices; SplitOnPipe = $true
            What = 'suppresses the line that reports a watched channel having gone unreadable' },
        [PSCustomObject] @{ Name = 'destruction'; Value = $state.destruction; SplitOnPipe = $false
            What = 'suppresses the repeat of a cleared log or a deleted backup catalog' }
    )
    foreach ($map in $stampMaps) {
        if ($null -eq $map.Value) { continue }
        foreach ($property in $map.Value.PSObject.Properties) {
            $stampText = [string] $property.Value
            if ($map.SplitOnPipe) {
                $parts = $stampText.Split([char[]] '|', 2)
                if ($parts.Count -ne 2) { continue }
                $stampText = $parts[0]
            }
            $stamp = [datetime]::MinValue
            if (-not [datetime]::TryParse($stampText,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $stamp)) { continue }
            $ahead = ($stamp.ToUniversalTime() - $nowUtc).TotalSeconds
            if ($ahead -gt ($script:ClockSkewSlackMinutes * 60)) {
                [void] $impossible.Add('the ' + $map.Name + ' stamp for "' + $property.Name + '" is ' +
                                       ([string] [math]::Round($ahead)) + 's in the future, which ' +
                                       $map.What)
            }
        }
    }

    if ($null -ne $state.channels) {
        foreach ($entry in $script:TriggerChannels) {
            $channel = [string] $entry.LogName
            $property = $state.channels.PSObject.Properties[$channel]
            if ($null -eq $property) { continue }
            # THE HANDLER'S OWN PARSE, exactly: [long] with NumberStyles::Integer.
            # Reading it any wider makes this function accuse a value the handler
            # never accepts - '1e20', '123.0' and anything past Int64 all parse as
            # [decimal] under NumberStyles::Float, and none of them parse for the
            # handler, which
            # drops such a mark and rescans its 24h floor. That is the LOUD
            # direction, and the docstring above promises not to report it.
            $mark = [long] 0
            if (-not [long]::TryParse([string] $property.Value,
                    [System.Globalization.NumberStyles]::Integer,
                    [System.Globalization.CultureInfo]::InvariantCulture, [ref] $mark)) { continue }
            # THE CHANNEL, not the watched ids - because that is the ceiling the
            # handler applies (see Get-MarkCeiling in the handler template: only a
            # mark above the channel ceiling can hide a future event). Filtering
            # by id here would make this run report marks the handler itself
            # accepts, which is a finding an -Apply cannot clear. A Filter with
            # LogName alone is Get-NewestRecordId's channel-wide form.
            $ceiling = Get-NewestRecordId -Filter @{ LogName = $channel }
            if ($null -ne $ceiling -and $mark -gt $ceiling) {
                [void] $impossible.Add('the mark for ' + $channel + ' is ' + ([string] $mark) +
                                       ', above the newest record in that channel (' +
                                       ([string] $ceiling) + ')')
            }
        }
    }

    if ($impossible.Count -eq 0) {
        Write-Info ('handler state file ' + $statePath + ' holds no value the handler could not have written')
        return
    }

    $detail = (($impossible.ToArray()) -join '; ')
    if (-not $ApplyMode) {
        Write-Finding ('the handler state file ' + $statePath + ' holds ' + [string] $impossible.Count +
                       ' value(s) no run of the handler can produce: ' + $detail + '. Each of these shapes ' +
                       'SILENCES the handler rather than breaking it - against an earlier handler a future ' +
                       'run time satisfied the rate guard on every wake, and a mark above the channel ' +
                       'filtered every later event out, in both cases without a single error. The handler ' +
                       'deployed by this version rejects every one of these shapes and alarms on them, so ' +
                       'detection is ' +
                       'not currently suppressed; what remains is the question of how the values got there. ' +
                       'Treat it as tampering with the tamper detector unless this host''s clock explains ' +
                       'it. -Apply resets the file without waiting for a watched event to fire.')
        return
    }

    # Reset, not repair: deleting is exactly the state the handler converges to
    # on its own, and it is the one outcome that carries nothing forward from a
    # file whose contents are already known to be untrustworthy.
    try {
        Remove-Item -LiteralPath $statePath -Force -ErrorAction Stop
        Write-Ok ('handler state file ' + $statePath + ' held ' + [string] $impossible.Count +
                  ' impossible value(s) (' + $detail + ') and has been reset. The next handler wake ' +
                  'rescans the last 24 hours of watched events, so recent alerts may repeat once; ' +
                  'anything older than that window was NOT re-examined.')
    }
    catch {
        Write-Finding ('the handler state file ' + $statePath + ' holds ' + [string] $impossible.Count +
                       ' impossible value(s) (' + $detail + ') and could not be reset: ' +
                       $_.Exception.Message)
    }
}

function Register-TrackedAlertTask {
    # Registers the event-triggered task, recording it in the manifest first.
    # Returns the number of MANIFEST-RECORDED changes made (0 or 1) - Invoke-Main
    # compares this against the number of change records, so a write with no
    # record must not be counted here. See the handler rewrite below.
    param([Parameter(Mandatory = $true)][string] $AlertDirectory)

    Write-Section 'Forward-looking detection'
    $taskPath = $script:TaskFolderPath
    $taskName = $script:AlertTaskName
    $label    = ('event-triggered alert task ' + $taskPath + $taskName)

    $existing = Get-ToolkitScheduledTask -TaskPath $taskPath -TaskName $taskName
    if ($null -ne $existing) {
        # Idempotence and a refusal at once: an existing task is NEVER
        # overwritten. Register-ScheduledTask -Force is used nowhere in this
        # script - it would silently replace a task somebody else owns, which is
        # the same defect as deleting one.
        Write-Ok ($label + ' - already registered (state ' + [string] $existing.State + ')')

        # STATE IS TESTED, NOT JUST PRINTED.
        #
        # This line used to read `[ ok ] ... already registered (state Disabled)`
        # and stop there. A disabled scheduled task never fires, so the entire
        # forward-looking detector was off while the script reported success -
        # the state string was in the output for a human to notice, which is not
        # the same as checking it. One `schtasks /change /disable` turned the
        # watcher off and left a green run behind it.
        #
        # Reported rather than re-enabled, in both modes, for the reason this
        # branch never overwrites a task: an operator may have disabled it for
        # maintenance, and a toolkit that silently re-enables it is fighting the
        # person running it. The finding names the command, so the lever is
        # explicit and exit 1 clears as soon as it is pulled.
        $taskState = [string] $existing.State
        if ($taskState -eq 'Disabled') {
            Write-Finding ($label + ' exists but is DISABLED, so it never fires and nothing is watching for the destruction commands this script exists to catch. ' +
                           'Nothing was changed - re-enable it with: schtasks.exe /Change /TN "' +
                           $taskPath.TrimStart([char] '\') + $taskName + '" /ENABLE')
            return 0
        }
        if ($taskState -eq 'Unknown') {
            # Not a finding: an unreadable state is not a claim that the task is
            # broken, and saying so would be inventing a fact about the host.
            Write-Info ($label + ' is registered but Task Scheduler reports its state as Unknown, ' +
                        'so whether it will fire could not be established here')
        }

        $handlerPath = [System.IO.Path]::Combine($AlertDirectory, 'Write-TamperAlert.ps1')

        # WHICH handler does this host actually run? Task identity is a CONSTANT
        # and deliberately not derived from -ToolkitRoot (see the doctrine above),
        # so an -Apply pointed at a different root finds this same task already
        # registered. Comparing only the file under THIS root would then refresh a
        # handler nothing executes and report a healthy watcher, while Task
        # Scheduler goes on running the copy under the old root - an effect this
        # run never observed. So the task is asked what it runs.
        $registeredAction = ''
        # UNVERIFIED: that Get-ScheduledTask exposes an Exec action as
        # .Actions[].Execute and .Actions[].Arguments. Microsoft documents the
        # cmdlet and the task XML, not those property names. Read defensively -
        # an action shape this cannot read is reported as UNREAD, never as
        # matching - and unread is Write-Info rather than a finding, because a gap
        # in the toolkit's own reading is not a condition an MSP should be paged
        # for and a wrong guess here would page the whole fleet.
        try {
            foreach ($action in @($existing.Actions)) {
                if ($null -eq $action) { continue }
                $registeredAction = ($registeredAction + ' ' + [string] $action.Execute +
                                     ' ' + [string] $action.Arguments)
            }
        }
        catch { $registeredAction = '' }
        $registeredAction = $registeredAction.Trim()
        $actionKnown = (-not [string]::IsNullOrWhiteSpace($registeredAction))
        if (-not $actionKnown) {
            Write-Info ('the action registered for this task could not be read, so which handler the ' +
                        'host runs is unconfirmed and what follows speaks for the file under this ' +
                        'root only. Read the task with: schtasks /query /tn "' + $taskPath +
                        $taskName + '" /xml')
        }
        elseif ($registeredAction.IndexOf($handlerPath, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            Write-Finding ('the registered task does not run this root''s handler. Its action is "' +
                           $registeredAction + '" and this run owns ' + $handlerPath + '. Nothing ' +
                           'written under ' + $AlertDirectory + ' would be executed by this host, so ' +
                           'no claim is made about it. Roll back the run that registered the task - ' +
                           'its manifest is under the root that deployed it - then -Apply with the ' +
                           'root you want.')
            return 0
        }

        # AT-12: the task existing does NOT mean the handler on disk is current.
        # A toolkit update changes the handler TEMPLATE, and if the task already
        # exists the old code returned here and left the OLD handler running - the
        # fix never landed without a Rollback+Apply. Compare the deployed handler
        # to its intended content and rewrite it on drift. This is not a task
        # change, so it is not a manifest record; it keeps the derived handler in
        # step with the installed toolkit version.
        $intended = Get-HandlerScriptText
        $current = ''
        if (Test-Path -LiteralPath $handlerPath) {
            try { $current = [System.IO.File]::ReadAllText($handlerPath) } catch { $current = '' }
        }
        if ($current -ne $intended) {
            if (-not $Apply) {
                Write-Finding ('the deployed handler ' + $handlerPath + ' differs from this toolkit ' +
                               'version''s template - it would be rewritten on -Apply')
                return 0
            }
            [void] (New-HandlerScript -Directory $AlertDirectory)
            Write-Ok ('handler ' + $handlerPath + ' was out of date and has been rewritten to match ' +
                      'this toolkit version')
            # 0, not 1, and the comment above says why: no manifest record is
            # written for this. Invoke-Main compares the returned count against
            # $script:ChangeIndex, so returning 1 makes 'applied' exceed 'recorded'
            # and prints "A change without a record cannot be rolled back; treat
            # this host as modified and investigate" - on every host that reaches
            # this branch, which is every armed host at the first -Apply after an
            # edit to $script:HandlerTemplate, $script:TriggerChannels or
            # $script:DefenderSelfMaintenanceValues. Nothing changed on the host
            # but a toolkit-owned derived file, which the line above announces.
            return 0
        }
        $runsIt = ''
        if ($actionKnown) { $runsIt = ' and is the file this task runs' }
        Write-Info ('handler ' + $handlerPath + ' matches this toolkit version' + $runsIt)
        return 0
    }

    # Validated before the manifest record goes down, so a refusal does not leave
    # an intent record for a change that was never attempted.
    $hostPath = Get-PowerShellHostPath
    if (-not (Test-Path -LiteralPath $hostPath)) {
        Write-Finding ('Windows PowerShell was not found at ' + $hostPath +
                       '; no task registered and nothing changed.')
        return 0
    }
    if (-not $Apply) {
        Write-Finding ($label + ' - would register, running the handler as SYSTEM on ' +
                       [string] $script:TriggerChannels.Count + ' event subscriptions')
        return 0
    }

    $handlerPath = New-HandlerScript -Directory $AlertDirectory
    $marker      = New-TaskMarker

    # Record before changing. Not after.
    [void] (Write-ManifestChange -Change @{
        type            = 'scheduledtask'
        taskPath        = $taskPath
        taskName        = $taskName
        previousExisted = $false
        marker          = $marker
        description     = $label
    })

    # -ExecutionPolicy Bypass because the handler is a toolkit-owned file in a
    # directory whose DACL is SYSTEM and Administrators only, and because a
    # machine execution policy of Restricted or AllSigned would otherwise make
    # this task fail every time while looking perfectly configured.
    $xml = New-TamperTaskXml -Command $hostPath `
        -CommandArguments ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
                           $handlerPath + '"') `
        -Description ('IronBlackBox ' + $script:ScriptName + ' v' + $script:ScriptVersion +
                      ' - appends tamper indicators to the alert log. Marker: ' + $marker)

    [void] (Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Xml $xml)

    $confirmed = Get-ToolkitScheduledTask -TaskPath $taskPath -TaskName $taskName
    if ($null -eq $confirmed) {
        throw ('Register-ScheduledTask returned without error but ' + $taskPath + $taskName +
               ' cannot be read back.')
    }

    Write-Ok ($label + ' - registered')
    Write-Info ('handler: ' + $handlerPath)
    Write-Info ('alert log: ' + [System.IO.Path]::Combine($AlertDirectory, 'tamper-alerts.log'))
    # Printed rather than asserted: this is how the SID-as-UserId and the composed
    # EventID predicate get answered by the host instead of by a comment.
    if ($null -ne $confirmed.Principal) {
        Write-Info ('principal as registered: UserId=' + [string] $confirmed.Principal.UserId +
                    ' LogonType=' + [string] $confirmed.Principal.LogonType +
                    ' RunLevel=' + [string] $confirmed.Principal.RunLevel)
    }
    foreach ($channel in $script:TriggerChannels) {
        Write-Info ('subscription: ' +
                    (New-EventSubscription -LogName $channel.LogName -EventId $channel.EventId))
    }
    return 1
}

#endregion
#region Reporting -------------------------------------------------------------

function Test-DetectionPrerequisite {
    <#
        What this detector can and cannot see, established BEFORE the scan runs
        so the scan can skip what would be meaningless and the report can say why.

        Every gap here is a finding. A detector that reports "nothing found" while
        the thing it looks at is switched off is worse than no detector, because
        the MSP now believes something.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $WorkDirectory,
        [Parameter(Mandatory = $true)][datetime] $Since
    )

    Write-Section 'What this detector can see'

    $includeCmdLine = Get-PolicyDwordValue -SubKeyPath $script:SubKeyAuditSettings `
        -Name $script:ValueIncludeCmdLine
    $commandLineOn = ($null -ne $includeCmdLine -and $includeCmdLine -eq 1)
    if ($commandLineOn) {
        Write-Ok 'command-line auditing is on, so event 4688 carries the command line'
    }
    else {
        Write-Finding ('Command-line auditing is OFF (' + $script:KeyAuditSettings + '\' +
                       $script:ValueIncludeCmdLine + '). Event 4688 carries no command line, so ' +
                       'detection of vssadmin delete shadows, wevtutil cl, cipher /w, ' +
                       'fsutil usn deletejournal and every other command-line indicator is BLIND. ' +
                       'Run logging-hardening/Enable-IRVisibility.ps1 -Apply. Until then, treat a ' +
                       'quiet result from this script as unproven, not as clean.')
    }

    $auditSetting = Get-ProcessCreationAuditState -WorkDirectory $WorkDirectory
    if ($auditSetting -lt 0) {
        Write-Finding 'Could not read the Audit Process Creation subcategory, so it is unknown whether event 4688 is produced at all.'
    }
    elseif ($auditSetting -eq 0) {
        Write-Finding ('The Audit Process Creation subcategory is OFF, so there are no 4688 events ' +
                       'to search whatever the command-line policy says. Run ' +
                       'logging-hardening/Enable-IRVisibility.ps1 -Apply.')
        $commandLineOn = $false
    }
    else {
        Write-Ok ('the Audit Process Creation subcategory is on (auditpol setting value ' +
                  [string] $auditSetting + ')')
    }

    $reach = Get-LogReach -LogName 'Security'
    if ($null -eq $reach) {
        Write-Finding 'Could not read the oldest record in the Security log, so how far back it reaches is unknown.'
    }
    elseif ($reach.ToUniversalTime() -gt $Since) {
        Write-Finding ('The Security log only reaches back to ' + [string] $reach + ', which is INSIDE ' +
                       'the ' + [string] $LookbackDays + '-day window being searched. Anything older ' +
                       'has already rolled out of the log and cannot be found here. Size the log with ' +
                       'logging-hardening/Enable-IRVisibility.ps1 and configure archiving with ' +
                       'anti-tampering/Protect-EventLogs.ps1.')
    }
    else {
        Write-Ok ('the Security log reaches back to ' + [string] $reach + ', covering the window')
    }

    return [PSCustomObject] @{ CommandLineAuditing = $commandLineOn }
}

# Set by Write-ScanReport: alert-level hits already past the bookmark. Printed and
# counted, never in the exit code - but the Result section MUST disclose it, or a
# host whose every hit is past the bookmark reports a clean all-clear underneath a
# list of tamper indicators. That is worse than the noise the split removed.
$script:ReportedBeforeCount = 0

function Write-ScanReport {
    # One block per source, then the hits. Sources with nothing to say still get a
    # line: "this was looked at and found nothing" is information, and its absence
    # would let a silently broken query look like a clean host.
    param(
        [Parameter(Mandatory = $true)] $Scan,
        [Parameter(Mandatory = $true)][datetime] $Since,
        [Parameter(Mandatory = $true)][bool] $BookmarkExisted
    )

    # "requested", not "since". The heading used to state the window as a fact,
    # and a capped source makes that false for itself - the per-source lines
    # below carry the date each one was really examined back to. A heading that
    # can be contradicted three lines later is worse than a vaguer one.
    Write-Section ('Retrospective scan, window requested from ' + $Since.ToString('yyyy-MM-dd HH:mm',
                   [System.Globalization.CultureInfo]::InvariantCulture) +
                   ' UTC (each source reports what it actually reached)')

    foreach ($source in $Scan.Sources) {
        if ($null -ne $source.Error) {
            # Get-WinEvent throws for "no events matched" as well as for a missing
            # channel, so the message is printed rather than interpreted.
            Write-Info ($source.Key + ': ' + $source.Error)
            continue
        }
        $line = ($source.Key + ': ' + [string] $source.Total + ' event(s), ' +
                 [string] $source.New + ' new since the bookmark')
        # Printed only when it happened, and never left implicit: these events
        # were retrieved and then set aside as this scanner's own activity, so
        # Total and the hits below do not add up without them.
        if ($source.Excluded -gt 0) {
            $line = ($line + ', ' + [string] $source.Excluded +
                     ' set aside as this run''s own process activity')
        }
        if ($source.Capped) {
            # NAMES THE REAL WINDOW FOR THIS SOURCE. The section header above names
            # the window that was REQUESTED, and for a capped source that is simply
            # not what was read: Get-WinEvent was asked for the newest
            # -MaxEventsPerSource events, so the OLDEST part of the window was
            # never read. The old wording - "there may be more" - let an operator
            # keep the 30-day figure and read the cap as a footnote. On a channel
            # this toolkit's own Defender noise measurement clocked at roughly 80
            # events in five minutes, 500 events is about half an hour, so the
            # claim could be off by three orders of magnitude. The floor is now
            # printed as a date, because a date cannot be misread as a caveat.
            $realFloor = 'an unknown point'
            if ($null -ne $source.OldestExamined) {
                $realFloor = ($source.OldestExamined.ToUniversalTime().ToString(
                    'yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC')
            }
            $line = ($line + ' - CAPPED at -' + [string] $source.CapParameter + '=' +
                     [string] $source.CapValue + ', so this source was examined back to ' + $realFloor +
                     ' ONLY, not to the window in the heading above. Anything older was NOT read.')
            if ($source.CapParameter -eq 'MaxCommandLineEvents') {
                # NO "raise the cap" advice on this one. 4688 is not a window scan
                # at any cap, so offering a bigger number as the remedy would be
                # the same false promise the rest of this line exists to remove.
                # See the -MaxCommandLineEvents help.
                $line = ($line + ' For 4688 this is expected: it is every process creation on the ' +
                         'host with no server-side filter available, so this source is the recent ' +
                         'tail rather than the window, and no cap makes it one. The event-triggered ' +
                         'handler is what covers it going forward')
            }
            else {
                $line = ($line + ' Raise -' + [string] $source.CapParameter +
                         ' or narrow -LookbackDays to close the gap')
            }
        }
        Write-Info $line
    }

    foreach ($mark in @($Scan.ImpossibleMarks)) {
        Write-Finding ('the scan bookmark for ' + $mark.Key + ' ' + $mark.Detail +
                       ' The mark was DISCARDED and this source is reported from the start of ' +
                       'the window. Treat it as tampering with the detector until something ' +
                       'else explains it.')
    }

    $alerts  = @($Scan.Hits | Where-Object { $_.Level -eq 'alert' })
    $context = @($Scan.Hits | Where-Object { $_.Level -ne 'alert' })

    if ($alerts.Count -eq 0) {
        Write-Ok 'no tamper indicators found in the window'
    }
    foreach ($hit in @($alerts | Where-Object { $_.IsNew })) {
        Write-Finding ('[NEW] ' + $hit.What + ' -- ' + [string] $hit.When +
                       ' (event ' + [string] $hit.EventId + ', record ' + [string] $hit.RecordId +
                       ') :: ' + $hit.Detail)
    }

    # Past the bookmark, so an -Apply already reported them once and moved on. The
    # window is -LookbackDays and NOT the bookmark, so these come back on every run
    # for as long as the events are in the channel: counting them would hold the exit
    # code at 1 for the whole window after ONE cleared log, and a monitor that is red
    # forever gets muted - which costs the operator every NEW hit underneath it. So
    # they stay loud in the text and stay out of the exit code.
    #
    # This is the Write-HostLimit test applied to history rather than to a host
    # feature: nothing this script DOES removes one of these, because each is a past
    # event and no -Apply rewrites the past. Only time does - the event ages out of
    # -LookbackDays or rolls out of its channel. Shrinking -LookbackDays hides them
    # without clearing them, which is why the count below is always printed.
    $reported = @($alerts | Where-Object { -not $_.IsNew } | Sort-Object -Property When -Descending)
    $script:ReportedBeforeCount = $reported.Count
    if ($reported.Count -gt 0) {
        Write-Section 'Reported before, and NOT part of the exit code'
        $shown = 0
        foreach ($hit in $reported) {
            if ($shown -ge 25) { break }
            Write-Info ($hit.What + ' -- ' + [string] $hit.When +
                        ' (event ' + [string] $hit.EventId + ', record ' + [string] $hit.RecordId +
                        ') :: ' + $hit.Detail)
            $shown++
        }
        if ($reported.Count -gt $shown) {
            Write-Info ('... and ' + [string] ($reported.Count - $shown) +
                        ' more, oldest last - widen or narrow the view with -LookbackDays')
        }
        Write-Info ''
        Write-Info ([string] $reported.Count + ' indicator(s) above were already in the channel at the')
        Write-Info 'last -Apply. They age out of this report when the events fall outside'
        Write-Info '-LookbackDays or roll out of their channel, not before.'
    }

    if ($context.Count -gt 0) {
        Write-Section 'Context, not alerts'
        # Bounded: 4826 fires at every boot and 7040 on every start-type change, so
        # a long-lived host has plenty of both and none of it is an incident.
        $shown = 0
        foreach ($hit in $context) {
            if ($shown -ge 15) { break }
            Write-Info ($hit.What + ' -- ' + [string] $hit.When + ' :: ' + $hit.Detail)
            $shown++
        }
        if ($context.Count -gt $shown) {
            Write-Info ('... and ' + [string] ($context.Count - $shown) + ' more')
        }
    }

    if (-not $Apply) {
        Write-Section 'About the bookmark'
        if ($BookmarkExisted) {
            Write-Info 'A bookmark exists, so "NEW" above means new since the last -Apply.'
        }
        else {
            Write-Info 'No bookmark exists yet, so everything above is reported as new.'
        }
        Write-Info '-Audit is read-only and does NOT advance it, so this run reports the same'
        Write-Info 'window again next time. Only -Apply moves the bookmark forward.'
    }
}

function Write-LimitReport {
    Write-Section 'What this cannot do'
    Write-Info 'It detects and records. It does not kill processes, block commands, or remove the'
    Write-Info 'right to run them. Blocking vssadmin would break every legitimate backup product'
    Write-Info 'on this host - they are its main legitimate caller - and a hardening script that'
    Write-Info 'breaks the backup has caused the data loss it was deployed to stop.'
    Write-Info ''
    Write-Info 'Microsoft documents no event for a bcdedit CHANGE: 4826 reports boot settings AT'
    Write-Info 'BOOT, so bcdedit tampering shows up in a 4688 command line or at the next restart,'
    Write-Info 'never as it happens. Microsoft documents no event meaning "a Defender exclusion was'
    Write-Info 'added" either - 5007 is "the antimalware platform configuration changed" and carries'
    Write-Info 'the old and new values for a human to read.'
}

function Invoke-HostCheck {
    param(
        [Parameter(Mandatory = $true)][string] $AlertDirectory,
        [Parameter(Mandatory = $true)][string] $ToolkitRootPath,
        [Parameter(Mandatory = $true)][string] $WorkDirectory
    )

    $since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays)
    $prerequisites = Test-DetectionPrerequisite -WorkDirectory $WorkDirectory -Since $since

    $bookmarkPath = [System.IO.Path]::Combine($AlertDirectory, 'tamper-scan-state.json')
    $bookmarkExisted = Test-Path -LiteralPath $bookmarkPath
    $bookmark = Get-ScanBookmark -Path $bookmarkPath

    $scan = Invoke-RetrospectiveScan -Since $since -Bookmark $bookmark `
        -ToolkitRootPath $ToolkitRootPath `
        -CommandLineAuditingOn ([bool] $prerequisites.CommandLineAuditing)

    Write-ScanReport -Scan $scan -Since $since -BookmarkExisted ([bool] $bookmarkExisted)

    # The bookmark advances only in -Apply. -Audit is strictly read-only, so it
    # reads the bookmark and leaves it exactly where it was.
    if ($Apply) {
        # Per-source, because -MaxEventsPerSource is reached by a busy source while
        # its quiet neighbours are complete, and a mark may only claim a complete
        # examination when its own source had one.
        $cappedByKey = @{}
        foreach ($report in $scan.Sources) { $cappedByKey[$report.Key] = [bool] $report.Capped }
        $sinceStamp = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ',
            [System.Globalization.CultureInfo]::InvariantCulture)
        foreach ($hit in $scan.Hits) {
            $sourceCapped = $true
            if ($cappedByKey.ContainsKey($hit.SourceKey)) { $sourceCapped = $cappedByKey[$hit.SourceKey] }
            Set-ScanBookmark -State $bookmark -SourceKey $hit.SourceKey -Record $hit.Record `
                -SinceUtc $sinceStamp -Capped $sourceCapped
        }
        Save-ScanBookmark -Path $bookmarkPath -State $bookmark
        Write-Info ('scan bookmark advanced: ' + $bookmarkPath)
    }

    # Counting, never '$changed = $changed -or (...)': -or short-circuits, so a
    # later call would never be made once an earlier one succeeded.
    $changeCount = 0
    $changeCount += Register-TrackedAlertTask -AlertDirectory $AlertDirectory

    # Deliberately NOT added to $changeCount: a reset here writes no manifest
    # record, for the same reason the handler rewrite above writes none, and
    # Invoke-Main compares the count against the number of records.
    #
    # Called unconditionally rather than from inside the existing-task branch: a
    # host whose task was deleted still has its state file on disk, and re-arming
    # it would otherwise pick those marks straight back up.
    Test-HandlerStateFile -AlertDirectory $AlertDirectory -ApplyMode:$Apply

    Write-LimitReport
    return $changeCount
}

#endregion

#region Main -----------------------------------------------------------------

function Invoke-Main {
    $mode = 'Audit'
    if ($Apply)    { $mode = 'Apply' }
    if ($Rollback) { $mode = 'Rollback' }

    Write-Host ''
    Write-Host ('IronBlackBox - ' + $script:ScriptName + ' v' + $script:ScriptVersion +
                ' [' + $mode + ']') -ForegroundColor White

    # P-1: value checks BEFORE anything is read, locked or changed. These were
    # [Validate*] attributes; a binding-time failure exits 1, which collides with
    # "findings" (docs/DESIGN.md section 3). A throw here reaches exit 2.
    Assert-ParameterRange   -Name 'LookbackDays' -Value $LookbackDays -Minimum 1 -Maximum 365
    Assert-ParameterRange   -Name 'MaxEventsPerSource' -Value $MaxEventsPerSource -Minimum 1 -Maximum 20000
    Assert-ParameterRange   -Name 'MaxCommandLineEvents' -Value $MaxCommandLineEvents -Minimum 1 -Maximum 100000

    # -RunId and -AbandonRun both name a run, and the abandon path selects its own
    # target. Two DIFFERENT ids on one command line is two intents, and guessing
    # which one was meant is how the wrong run gets abandoned - so it is refused
    # here, before anything is read or locked, rather than one of them being
    # silently dropped. The same id twice is not a conflict.
    if (-not [string]::IsNullOrWhiteSpace($AbandonRun) -and
        -not [string]::IsNullOrWhiteSpace($RunId) -and $RunId -ne $AbandonRun) {
        throw ('-RunId ' + $RunId + ' and -AbandonRun ' + $AbandonRun + ' name different runs. ' +
               'Pass -AbandonRun on its own: it names the run it abandons.')
    }

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')
    $alertDirectory = [System.IO.Path]::Combine($resolvedRoot, 'alerts')
    # auditpol /backup needs somewhere to write. The system temp directory, the
    # same place Test-VisibilityDrift uses, so a read-only -Audit never writes
    # inside the toolkit root.
    $workDirectory = [System.IO.Path]::GetTempPath().TrimEnd('\')

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        [void] (Invoke-HostCheck -AlertDirectory $alertDirectory -ToolkitRootPath $resolvedRoot `
            -WorkDirectory $workDirectory)
        Write-Section 'Result'
        if ($script:Findings.Count -gt 0) {
            Write-Info ([string] $script:Findings.Count +
                        ' finding(s). Read them before deciding this host is clean.')
            if ($script:HostLimits.Count -gt 0) {
                Write-Info ([string] $script:HostLimits.Count + ' host limit(s) as well - see '  +
                            '[limit] above. Those are NOT part of the exit code.')
            }
            if ($script:ReportedBeforeCount -gt 0) {
                Write-Info ([string] $script:ReportedBeforeCount + ' indicator(s) reported ' +
                            'before as well, listed above. Not part of the exit code either.')
            }
            return 1
        }
        if ($script:HostLimits.Count -gt 0 -or $script:ReportedBeforeCount -gt 0) {
            # Exit 0, deliberately. All of it is real and printed above. None of it is
            # NEW and no -Apply clears any of it, so alerting would leave an RMM
            # monitor permanently red - and one that is always red gets muted, which
            # costs the operator the next hit that IS new. What this must never do is
            # go quiet: 'nothing in the window' below is only reachable when there is
            # genuinely nothing, which is why both counts are named here.
            $notCounted = @()
            if ($script:ReportedBeforeCount -gt 0) {
                $notCounted += ([string] $script:ReportedBeforeCount +
                                ' indicator(s) reported before, listed above')
            }
            if ($script:HostLimits.Count -gt 0) {
                $notCounted += ([string] $script:HostLimits.Count +
                                ' host limit(s), see [limit] above')
            }
            Write-Ok ('Nothing NEW: ' + ($notCounted -join '; ') +
                      '. None of that is part of the exit code.')
            return 0
        }
        Write-Ok 'No findings: nothing in the window, and the detector can see what it claims to.'
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
                lookbackDays       = $LookbackDays
                maxEventsPerSource = $MaxEventsPerSource
                maxCommandLineEvents = $MaxCommandLineEvents
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
                $verified = Invoke-HostCheck -AlertDirectory $alertDirectory -ToolkitRootPath $resolvedRoot `
                    -WorkDirectory $workDirectory
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

        # ONE resolution, not two. Resolving -RunId first and then overwriting the
        # result with the abandon target made a stale -RunId fatal to an operation
        # it has no part in: Get-RollbackTargetRun throws 'has already been rolled
        # back' for an explicit id, so '-Rollback -RunId <finished> -AbandonRun <x>'
        # exited 2 and the abandon - already validated - never ran. -AbandonRun is
        # the escape hatch for a run that declines forever; it does not get to fail
        # on a second argument.
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
                $record = $target.Changes[$i]
                # This script does not carry the template's Registry region, so
                # Restore-TrackedChange does not exist here and cannot be the
                # fallback. The one type this script writes is routed explicitly
                # and anything else is declined by name.
                switch ([string] $record.change.type) {
                    'scheduledtask' { $outcome = Remove-TrackedScheduledTask -ChangeRecord $record; break }
                    default {
                        Write-Finding ('Cannot roll back change type "' + [string] $record.change.type +
                                       '" - not implemented in this script.')
                        $outcome = $script:RollbackDeclined
                    }
                }
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
        Write-Info 'The alert log, the handler and both bookmarks were left in place. The alert log'
        Write-Info 'is evidence; a rollback does not delete evidence.'
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
