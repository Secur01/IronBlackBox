<#
.SYNOPSIS
    Audits, and where it can restores, the forensic artifacts a responder
    depends on: Prefetch, SRUM, UserAssist, NTFS last-access timestamps, and
    the Recycle Bin / shadow-copy settings that get switched off to frustrate
    an investigation.

.DESCRIPTION
    READ THIS FIRST, because the name promises more than the code can deliver.

    This script mostly CANNOT PREVENT an administrator from disabling these
    artifacts. Every one of them is a registry value, a service, or a file
    system flag that anything running as SYSTEM or as a local administrator can
    rewrite in one line. There is no ACL to take away that makes an
    administrator stop being an administrator here, and pretending otherwise
    would be the kind of claim this project exists not to make.

    What it does provide is three things, and they are worth having:

      (a) DETECTION - it reports, per artifact, whether the recording mechanism
          is on, and who can turn it off.
      (b) RESTORATION - with -Apply it turns back on what it can, recording the
          previous value first.
      (c) A MANIFEST RECORD - every restoration is written to
          <ToolkitRoot>\manifest.jsonl, which is what lets
          Test-VisibilityDrift notice the NEXT time one of them is switched
          off. A value the toolkit never recorded is a value nothing can
          compare against.

    The artifacts covered:

    PREFETCH. %SystemRoot%\Prefetch\*.pf is one of the few native records of
    what executed on a host. Be careful what you promise: measured repeatedly on
    this project's lab (Windows Server 2019, NVMe SSD), EnablePrefetcher was
    written, read back, survived the reboot, and was then REMOVED AGAIN by the
    OS a few minutes into normal operation - twice, with no Group Policy applied
    and SysMain running throughout - and no .pf file was ever produced. Windows
    is understood to disable prefetching on fast media; that is consistent with
    what was measured but is NOT proven here, because proving it needs a host
    with rotational media and none was available. So this script reports the
    media type and says what it means, rather than claiming it can protect a
    record the host declines to write. See verification/facts.json,
    'prefetch-does-not-work-on-fast-media'.

    SRUM. The System Resource Usage Monitor database answers "how much did that
    process send over the network, and when". The Diagnostic Policy Service is
    understood to be what writes it, so a stopped or disabled DPS is understood
    to stop the recording - UNVERIFIED, because no Microsoft documentation page
    for either the database's path or that linkage was found (see the markers in
    the code). What is reported is therefore both halves separately: the service
    state, and the database's size and last-write time, so an operator can see
    whether the file is still being written whatever the cause.

    USERASSIST. Per-user GUI execution history, and per-user means HKCU. A
    machine-wide script has no useful HKCU: running as SYSTEM, HKCU is SYSTEM's
    own profile. So this reports on the user hives already LOADED under
    HKEY_USERS, lists the profile directories found on disk, and says plainly
    which users it could not cover. It does NOT mount unloaded hives - below.

    NTFS LAST ACCESS. Last-access timestamps are what let a responder say a
    file was READ, not just written. Turning them off is cheap for an attacker
    and expensive for a timeline. Turning them back on has a real (small)
    performance cost, so it is behind -EnableLastAccessUpdates.

    RECYCLE BIN AND SHADOW COPIES. A Recycle Bin that no longer receives
    deleted files, and a disabled Volume Shadow Copy service, both remove
    recovery paths a responder would otherwise use. Both reported, neither
    changed - see below.

    NOT IMPLEMENTED, deliberately, each for a stated reason:

    - MOUNTING UNLOADED USER HIVES. Reading an unloaded NTUSER.DAT means
      'reg load', which opens the hive read-write, can dirty it, and leaves the
      profile locked if the matching 'reg unload' does not run. -Audit is the
      default mode and is contractually read-only, and a hardening script that
      locks a user's profile on a production server is a worse outcome than an
      incomplete report. So the report says which users were covered and which
      were not, and stops there.

    - WRITING TO ANY USER HIVE. Same reason, plus: the UserAssist and
      NoInstrumentation settings are per-user, so "fixing" them for one loaded
      session says nothing about the next logon. This is a reporting-only area
      by design.

    - CHANGING THE VOLUME SHADOW COPY SERVICE. This project has no citation for
      what that service's shipped start type is on any target SKU, so "putting
      it back" would mean inventing a target state - and backup products drive
      that service, so inventing one is how a backup window breaks. A DISABLED
      VSS is reported as a finding; nothing is changed.

    - REMOVING A NoRecycleFiles POLICY. The policy's registry location could
      not be cited to Microsoft documentation (see the UNVERIFIED marker in the
      code), and this toolkit does not write to a registry path it cannot cite.

.PARAMETER Audit
    Default. Strictly read-only. Reports every artifact's state and the exact
    path and value -Apply would set.

.PARAMETER Apply
    Restores what it can, recording the previous value of each change first.

.PARAMETER Rollback
    Restores the previous values recorded by a prior -Apply.

.PARAMETER ToolkitRoot
    Base directory for the manifest. Default C:\ProgramData\IronBlackBox.

.PARAMETER EnableLastAccessUpdates
    Also turn NTFS last-access timestamp updates back on. Off by default:
    Microsoft documents that disabling last-access updates "improves the speed
    of file and directory access", so turning them back on gives that speed
    back up. Small, but it is a production change with a cost, and this toolkit
    does not make those by default. Requires a restart to take effect.

.PARAMETER SrumStaleHours
    Report a finding when the SRUM database has not been written to for this
    many hours. Default 24. This threshold is this toolkit's choice, not a
    documented Microsoft value.

.PARAMETER RunId
    -Rollback only. The run to roll back.
.PARAMETER AbandonRun
    -Rollback only, and it names a run id rather than being a switch. Stops
    trying to roll back that run, on the record. Cannot be combined with -RunId:
    both name a run, and a command line naming two is refused rather than
    resolved in favour of one of them.

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
    .\Protect-ForensicArtifacts.ps1
    Reports which forensic artifacts this host is recording, and which have
    been switched off. Changes nothing.

.EXAMPLE
    .\Protect-ForensicArtifacts.ps1 -Apply
    Re-enables Prefetch if it was explicitly disabled and restarts the
    Diagnostic Policy Service if it was stopped, recording both first.

.EXAMPLE
    .\Protect-ForensicArtifacts.ps1 -Apply -EnableLastAccessUpdates
    Also turns NTFS last-access timestamp updates back on. Needs a restart.

.EXAMPLE
    .\Protect-ForensicArtifacts.ps1 -Rollback
    Puts back what the most recent -Apply changed.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.1.0
    License : MIT

    Windows PowerShell 5.1. No module dependencies. Requires local
    administrator; enforced in code by Assert-Elevated.

    Sources for every literal in this script are cited at the point of use.
    Anything that could not be cited to learn.microsoft.com carries an
    '# UNVERIFIED:' marker naming what still needs checking.
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

    # Note for anyone extending this script: no parameter here may be called
    # -Mode. The shared Invoke-Main holds the run mode in a local '$mode';
    # PowerShell names are case-insensitive and its scoping is dynamic, so a
    # parameter called $Mode is silently masked inside every function
    # Invoke-Main calls. See verification/facts.json,
    # 'mode-is-a-reserved-variable-name'.
    [Parameter()]
    [switch] $EnableLastAccessUpdates,

    [Parameter()]
    [int] $SrumStaleHours = 24,

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

$script:ScriptName    = 'Protect-ForensicArtifacts'
$script:ScriptVersion = '1.1.0'

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

# Set by the artifact checks, read by Invoke-Main to decide whether a change
# that was applied can actually be demonstrated yet. A change that needs a
# reboot cannot, and docs/AUTHORING.md is explicit that such a run returns 1.
$script:RebootPending = $false

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
#   Prefetch and the NTFS last-access setting.
$script:OwnedRegistryKey = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters',
    'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
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

#region Artifact locations ----------------------------------------------------

<#
    Every literal in this region is either cited to learn.microsoft.com on the
    line above it, or carries an '# UNVERIFIED:' marker naming exactly what
    still needs checking on a real host. Do not "correct" any of them from
    memory - that is rule 0 in docs/AUTHORING.md, and the reason this project exists in
    its current form.
#>

# EnablePrefetcher: key, value name, REG_DWORD, and the meaning of each value
# (0 disabled, 1 application launch, 2 boot, 3 both) are documented at
# https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ms940847(v=winembedded.5)
# It is NOT a Group Policy setting - no ADMX on the target OS declares it,
# checked on the lab (verification/facts.json, 'prefetch-not-a-policy').
$script:PrefetchKey       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
$script:PrefetchValueName = 'EnablePrefetcher'
$script:PrefetchDisabled  = 0
$script:PrefetchBoth      = 3

# The service that writes the .pf files, so the registry setting alone proves
# nothing. Documented linkage, and it is the closest thing to documentation
# found: "the Applaunch Prefetch component was implemented way back in Windows
# XP as a component of the Sysmain Windows service
# (%systemroot%\System32\Sysmain.dll) [...] The prefetch trace data is then
# written to a per-application file in %systemroot%\Prefetch [...] and a .pf
# extension."
# https://learn.microsoft.com/en-us/archive/blogs/chadduffey/what-is-application-launch-prefetching
# That page is an ARCHIVED blog post (dated 2014, written about Windows XP
# onward), not a current documentation page. A support article refers to the
# service by the same name - "the svchost.exe process hosting the
# SysMain(SuperFetch) service" - on Windows 7 SP1:
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/superfetch-sysmain-service-spikes-cpu
#
# UNVERIFIED: that the Windows SERVICE SHORT NAME is exactly 'SysMain' on the
# SKUs this toolkit targets, and that the linkage above still holds there.
# Treated the same way as DPS and VSS below: an absent service is "could not
# check", never "the service is fine", and the name looked for is printed.
$script:SysMainServiceName = 'SysMain'

# NtfsDisableLastAccessUpdate. 'fsutil behavior set disablelastaccess {1|0}'
# "Disables (1) or enables (0) updates to the Last Access Time stamp", and the
# Remarks section states verbatim: "This parameter updates the
# HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate
# registry key." A restart is required for the parameter to take effect.
# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
$script:FileSystemKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
$script:LastAccessValue    = 'NtfsDisableLastAccessUpdate'
$script:LastAccessEnabled  = 0

# The Diagnostic Policy Service is documented, including the "(DPS)"
# abbreviation, at
# https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-diskdiagnostic
# ("This policy setting takes effect only when the DPS is in the running state.
# When the service is stopped or disabled, diagnostic scenarios aren't
# executed.") and
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc774639(v=ws.10)
#
# UNVERIFIED: that the Windows SERVICE SHORT NAME is exactly 'DPS'. The
# abbreviation is documented; the service key name is not, on any Microsoft
# page found. The code below therefore treats a missing service as "could not
# check", never as "the service is fine", and prints the name it looked for.
$script:DpsServiceName = 'DPS'

# UNVERIFIED: the SRUM database path. No learn.microsoft.com page found
# documents %SystemRoot%\System32\sru\SRUDB.dat, nor that the Diagnostic Policy
# Service is what writes it - both are widely reported in the DFIR literature
# and in Microsoft Q&A threads, neither of which this project accepts as a
# citation. Consequence for the code: the file's absence is reported as
# "not found at the expected path", never as "SRUM is not recording".
$script:SrumDatabasePath = '%SystemRoot%\System32\sru\SRUDB.dat'

# Per-user (HKCU-scope) settings, expressed relative to a user hive root.
#
# NoInstrumentation, friendly name "Turn off user tracking", registry key
# Software\Microsoft\Windows\CurrentVersion\Policies\Explorer, ADMX
# StartMenu.admx, User Configuration. Its documented effect: "If you enable
# this policy setting, the system doesn't track the programs that the user
# runs". https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-startmenu
$script:UserPolicyExplorerSubKey = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$script:NoInstrumentationValue   = 'NoInstrumentation'

# Start_TrackProgs, REG_DWORD in
# HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced,
# value 0 turns off "Let Windows track app launches to improve Start and search
# results".
# https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
$script:ExplorerAdvancedSubKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$script:TrackProgsValue        = 'Start_TrackProgs'

# UNVERIFIED: the UserAssist key path
# Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist. It is the
# path every DFIR reference uses and it appears in Microsoft Q&A threads, but
# no learn.microsoft.com documentation page for it was found. Nothing is
# written here; its presence is only reported.
$script:UserAssistSubKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'

# NoRecycleFiles is a real policy: "files and folders that are deleted using
# File Explorer will not be placed in the Recycle Bin and will therefore be
# permanently deleted", ADMX_WindowsExplorer, WindowsExplorer.admx.
# https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsexplorer
#
# UNVERIFIED: its exact registry key name. The Group Policy LOCATION is
# documented (User Configuration > Administrative Templates > Windows
# Components > File Explorer) but the key path is not on that page, so the
# value below is read on a best-effort basis and NEVER written. If it is read
# from the wrong key the result is a missed finding, not a wrong change.
$script:NoRecycleFilesValue = 'NoRecycleFiles'

# UNVERIFIED: that the Volume Shadow Copy service short name is exactly 'VSS'.
# The service itself is documented at
# https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service
# but not its service key name. Treated the same way as DPS above: an absent
# service is "could not check".
$script:VssServiceName = 'VSS'

<#
    The three per-user DWORD flags this script reports, as data rather than as
    three near-identical blocks of code. 'BadWhen' says which value is the one
    that stops something being recorded: NoInstrumentation and NoRecycleFiles
    are switches that turn recording OFF when set, Start_TrackProgs is a switch
    that turns tracking ON and so is bad at zero.
#>
$script:PerUserFlag = @(
    @{ SubKey = $script:UserPolicyExplorerSubKey; Value = $script:NoInstrumentationValue
       BadWhen = 'nonzero'
       Message = '("Turn off user tracking") - the system does not track the programs this user runs' },
    @{ SubKey = $script:ExplorerAdvancedSubKey;   Value = $script:TrackProgsValue
       BadWhen = 'zero'
       Message = '- "Let Windows track app launches to improve Start and search results" is off' },
    @{ SubKey = $script:UserPolicyExplorerSubKey; Value = $script:NoRecycleFilesValue
       BadWhen = 'nonzero'
       Message = '- deleted files bypass the Recycle Bin entirely for this user' }
)

# Well-known SIDs. S-1-5-18 is Local System, S-1-5-19 Local Service,
# S-1-5-20 Network Service; interactive user accounts are S-1-5-21-<domain>-<rid>.
# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
$script:NonUserHiveSid = @('.DEFAULT', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20')

function Get-HiveSubKeyName {
    <#
        Subkey NAMES under a registry key, or $null when the key does not
        exist. Needed because two of the things this script reports on are
        answered by key structure rather than by a value: whether a user hive
        has a UserAssist subtree at all, and which user hives are loaded.

        Goes through Split-RegistryPath rather than the PowerShell registry
        provider so the read happens in an explicit 64-bit view. An RMM that
        launches SysWOW64\powershell.exe would otherwise read the redirected
        WOW6432Node copy and report an empty result as "clean".

        The leading ',' on the return is load-bearing: PowerShell unrolls a
        returned array, so a key with exactly one subkey would come back as a
        bare string and a key with none as $null - indistinguishable from "the
        key does not exist", which is the one distinction this function exists
        to make.
    #>
    param([Parameter(Mandatory = $true)][string] $Path)

    $split = Split-RegistryPath -Path $Path
    $key   = $null
    try {
        $key = $split.Hive.OpenSubKey($split.SubKey, $false)
        if ($null -eq $key) { return $null }
        return ,@($key.GetSubKeyNames())
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $split -and $null -ne $split.Hive) { $split.Hive.Dispose() }
    }
}

function Get-SystemVolumeMediaType {
    <#
        Whether the system volume is fast media. This is the single most
        important thing to know before telling an operator that Prefetch will
        record anything. Returns a descriptive object; 'unknown' when it cannot
        be told, never a guess.
    #>
    $result = [PSCustomObject] @{ MediaType = 'unknown'; BusType = 'unknown'; Detail = '' }
    try {
        $systemDrive = ($env:SystemDrive).TrimEnd(':')
        $partition = Get-Partition -DriveLetter $systemDrive -ErrorAction Stop
        $disk = Get-PhysicalDisk -ErrorAction Stop |
            Where-Object { $_.DeviceId -eq ([string] $partition.DiskNumber) } |
            Select-Object -First 1
        if ($null -ne $disk) {
            $result.MediaType = [string] $disk.MediaType
            $result.BusType   = [string] $disk.BusType
            $result.Detail    = ('disk ' + $disk.DeviceId + ', ' + $result.MediaType + ' over ' + $result.BusType)
        }
    }
    catch {
        $result.Detail = ('could not determine the media type: ' + $_.Exception.Message)
    }
    return $result
}

function Test-IsFastMedia {
    param([Parameter(Mandatory = $true)] $Media)
    # Deliberately conservative: only a positive SSD/NVMe signal counts. An
    # unknown media type is not treated as fast, because warning an operator
    # off a setting that would have worked is its own kind of wrong.
    if ($Media.MediaType -match 'SSD')  { return $true }
    if ($Media.BusType   -match 'NVMe') { return $true }
    return $false
}

function Get-ServiceState {
    <#
        Present / Status / StartType for one service, by service name, without
        throwing when it does not exist. An absent service means "could not
        check" to every caller here, never "fine".
    #>
    param([Parameter(Mandatory = $true)][string] $Name)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return [PSCustomObject] @{ Present = $false; Status = 'absent'; StartType = 'absent' }
    }
    return [PSCustomObject] @{
        Present   = $true
        Status    = [string] $service.Status
        StartType = [string] $service.StartType
    }
}

function Set-TrackedServiceState {
    <#
        Brings one service back to running and, if it was disabled, back to
        Automatic - recording the previous start type and status FIRST, the
        same discipline docs/DESIGN.md section 4 requires of a registry value.

        Introduces the 'service' change type, which the template's
        Restore-TrackedChange knows nothing about. Restore-ArtifactChange in
        the Main region routes it; see the comment there.

        Set-Service -StartupType and -Status, and their accepted values, are
        documented for Windows PowerShell 5.1 at
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-5.1

        KNOWN LIMITATION, stated rather than hidden: ServiceController.StartType
        under 5.1 does not distinguish "Automatic" from "Automatic (Delayed
        Start)". A service that shipped as delayed-auto and is restored here
        comes back as plain Automatic. That is a start-type downgrade in
        precision, not in function, and it is recorded as what was read.

        Returns 1 if it changed something, 0 if the host already matched, which
        is what keeps -Apply idempotent.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $current = Get-ServiceState -Name $Name
    if (-not $current.Present) {
        Write-Finding ($Description + ' - no service named ' + $Name +
                       ' on this host, so nothing could be checked or started')
        return 0
    }

    $wantStartType = $current.StartType
    if ($current.StartType -eq 'Disabled') { $wantStartType = 'Automatic' }
    $needStartType = ($wantStartType -ne $current.StartType)
    $needStart     = ($current.Status -ne 'Running')

    if (-not $needStartType -and -not $needStart) {
        Write-Ok ($Description + ' - already Running (StartType ' + $current.StartType + ')')
        return 0
    }

    if (-not $Apply) {
        Write-Finding ($Description + ' - is ' + $current.Status + '/' + $current.StartType +
                       '; would set StartType ' + $wantStartType + ' and start service ' + $Name)
        return 0
    }

    # Record before changing. Not after.
    [void] (Write-ManifestChange -Change @{
        type              = 'service'
        serviceName       = $Name
        previousStartType = $current.StartType
        previousStatus    = $current.Status
        newStartType      = $wantStartType
        newStatus         = 'Running'
        description       = $Description
    })

    if ($needStartType) {
        Set-Service -Name $Name -StartupType $wantStartType
    }
    if ($needStart) {
        Set-Service -Name $Name -Status 'Running'
    }

    # Re-read and assert, rather than trusting that the call returned without
    # an error. A service can be told to start and still fail to stay up.
    $confirmed = Get-ServiceState -Name $Name
    if (-not $confirmed.Present -or $confirmed.Status -ne 'Running' -or
        $confirmed.StartType -ne $wantStartType) {
        Write-Failure ($Description + ' - ' + $Name + ' is ' + $confirmed.Status + '/' +
                       $confirmed.StartType + ' after the change, not Running/' + $wantStartType)
        throw ('Service change could not be confirmed: ' + $Name)
    }

    Write-Ok ($Description + ' - now Running (StartType ' + $wantStartType + ')')
    return 1
}

function Restore-TrackedService {
    <#
        Puts one service back to the start type and status recorded before this
        toolkit changed it. Declines rather than guessing when the host no
        longer holds what the run set - somebody else has been here since, and
        overwriting their change is not a rollback.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change  = $ChangeRecord.change
    $name    = [string] $change.serviceName
    $current = Get-ServiceState -Name $name

    if (-not $current.Present) {
        Write-Finding ('Service ' + $name + ' no longer exists; leaving it alone.')
        return 'declined'
    }
    # Three-way host resolution (docs/DESIGN.md section 4, A-2). Case 2 FIRST: the
    # host already holds the pre-apply state, so there is nothing to undo - the
    # -Apply write may never have landed, or somebody has already put it back.
    # Counted RESTORED per the doctrine - nothing to do and nothing wrong. The
    # A-2 defect was returning plain 'declined' here: that leaves the run
    # retryable, so every future -Rollback re-selects it and it never converges.
    if ($current.StartType -eq [string] $change.previousStartType -and
        $current.Status -eq [string] $change.previousStatus) {
        Write-Ok ('Service ' + $name + ' already holds its recorded previous state (' +
                    [string] $change.previousStatus + '/' + [string] $change.previousStartType +
                    '); nothing to undo.')
        return 'restored'
    }

    # Case 3: the host holds neither the applied state nor the previous one.
    if ($current.Status -ne [string] $change.newStatus -or
        $current.StartType -ne [string] $change.newStartType) {
        Write-Finding ('Service ' + $name + ' is ' + $current.Status + '/' + $current.StartType +
                       ', not the ' + [string] $change.newStatus + '/' + [string] $change.newStartType +
                       ' this run set; leaving it alone.')
        return 'declined'
    }
    # Case 1 falls through: the host holds what -Apply set - restore it.

    # Start type first: if the stop below fails, the service is at least back
    # to its recorded configuration rather than half-restored.
    Set-Service -Name $name -StartupType ([string] $change.previousStartType)

    if ([string] $change.previousStatus -ne 'Running') {
        # No -Force. Force would stop this service's dependents too, which on a
        # production host is a bigger change than the one being undone. A stop
        # that cannot happen safely is reported and the run stays retryable.
        try {
            Set-Service -Name $name -Status 'Stopped'
        }
        catch {
            $stopError = $_.Exception.Message
            # PUT THE START TYPE BACK. Leaving it restored while returning
            # 'declined' makes the decline PERMANENT and the message a lie: the
            # guard at the top of this function compares the host against what
            # the run SET, so the next attempt would find the start type already
            # changed, conclude somebody else had been here, and decline again -
            # forever, accusing a third party of a change this function made.
            # Retryable means the host is left exactly where the retry expects.
            $reverted = $true
            try { Set-Service -Name $name -StartupType ([string] $change.newStartType) }
            catch { $reverted = $false }

            if ($reverted) {
                Write-Finding ('Could not stop ' + $name + ' (' + $stopError + '). Its start type was ' +
                               'put back to ' + [string] $change.newStartType + ' so this rollback stays ' +
                               'retryable; the service is unchanged and still running.')
            }
            else {
                Write-Finding ('Could not stop ' + $name + ' (' + $stopError + '), and its start type ' +
                               'could not be put back either: it now reads ' +
                               [string] $change.previousStartType + ' while the service is still running. ' +
                               'Set it back to ' + [string] $change.newStartType + ' by hand before ' +
                               'retrying this rollback, or the retry will decline.')
            }
            return 'declined'
        }
    }

    Write-Ok ('Restored service ' + $name + ' to ' + [string] $change.previousStatus + '/' +
              [string] $change.previousStartType)
    return 'restored'
}

#endregion

#region Artifact checks -------------------------------------------------------

function Get-NumericRegistryValue {
    <#
        The numeric content of a registry value that was read by
        Get-RegistryValueState, or $null when it does not hold a number.

        WHY THIS EXISTS. Get-RegistryValueState returns Value already encoded for
        the manifest by ConvertTo-ManifestValue, so a REG_BINARY arrives as a
        base64 STRING, a REG_MULTI_SZ as string[] and REG_NONE through the default
        arm as text. A bare [int] cast on any of those throws
        InvalidCastException, which under $ErrorActionPreference = 'Stop' is
        terminating: it escapes to the bottom `catch { exit 2 }` and abandons
        every remaining artifact check. So writing the WRONG TYPE into one of
        these values - NoInstrumentation as a REG_SZ "yes", say - would both
        defeat the artifact and blind the audit for the other four families. A
        wrong type has to be a finding, which needs the read to survive it.

        Kind decides, not the .NET type of Value: only DWord and QWord are
        numbers to this toolkit, and every setting read through here is
        documented as a REG_DWORD. A REG_SZ "1" is something somebody wrote by
        hand, and that is worth saying rather than quietly parsing.
    #>
    param([Parameter(Mandatory = $true)] $State)

    if (-not $State.Exists) { return $null }
    if ($State.Kind -ne 'DWord' -and $State.Kind -ne 'QWord') { return $null }
    # TryParse rather than a cast even here: QWord round-trips as an invariant
    # decimal string, and a cast is the one thing that must not throw.
    $number = [System.Int64] 0
    if (-not [System.Int64]::TryParse([string] $State.Value,
            [System.Globalization.NumberStyles]::Integer,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref] $number)) {
        return $null
    }
    return $number
}

function Test-PrefetchArtifact {
    <#
        Prefetch, honestly.

        Only an EnablePrefetcher value that EXISTS and is 0 is treated as
        something to put back. Two reasons, and both matter:

          - 0 is an explicit "off". Somebody wrote it. That is the tamper
            signature this script is for.
          - An ABSENT value is not. On the SSD-backed hosts this toolkit
            targets, the OS itself was measured removing the value a few
            minutes after it was set (verification/facts.json,
            'prefetch-does-not-work-on-fast-media'), so treating absence as
            tampering would make this script cry wolf on every modern server.
            Absence on a server SKU is Enable-ServerPrefetch's job, and this
            script says so instead of racing it.
    #>
    Write-Section 'Prefetch - what executed on this host'

    $os = Get-CimInstance Win32_OperatingSystem
    Write-Info ($os.Caption + ' (ProductType ' + [string] ([int] $os.ProductType) + ')')

    $media = Get-SystemVolumeMediaType
    if ($media.Detail) { Write-Info ('system volume: ' + $media.Detail) }
    else { Write-Info 'system volume: media type unknown' }

    $prefetchDir = [System.Environment]::ExpandEnvironmentVariables('%SystemRoot%\Prefetch')
    $pfCount = -1
    if (Test-Path -LiteralPath $prefetchDir) {
        $pfCount = @(Get-ChildItem -LiteralPath $prefetchDir -Filter '*.pf' -Force -ErrorAction SilentlyContinue).Count
    }
    if ($pfCount -lt 0) {
        Write-Finding ('the Prefetch directory does not exist: ' + $prefetchDir)
    }
    elseif ($pfCount -eq 0) {
        # A finding on ordinary media, a host limit on fast media. The docstring
        # above already says absence on fast media is not tampering and would
        # make this script cry wolf on every modern server - this is that
        # sentence made arithmetic instead of prose. Nothing this script does
        # clears it there, and a finding that can never clear turns an RMM
        # monitor permanently red, which mutes the tamper signals that CAN.
        if (Test-IsFastMedia -Media $media) {
            Write-HostLimit ('no .pf files in ' + $prefetchDir + ', on a host whose system volume ' +
                             'reports ' + $(if ($media.Detail) { $media.Detail } else { 'fast media' }) +
                             '. Not treated as tampering, and not alerted: see ' +
                             'verification/facts.json, prefetch-does-not-work-on-fast-media.')
        }
        else {
            Write-Finding ('no .pf files in ' + $prefetchDir +
                           ' - this host is recording NO execution history at all')
        }
    }
    else {
        Write-Ok ([string] $pfCount + ' .pf file(s) present - execution history is being recorded')
    }

    # The service state, because the registry setting alone proves nothing: see
    # the citation and the UNVERIFIED marker on $script:SysMainServiceName in the
    # Artifact locations region for the documented linkage to the .pf files. On
    # the lab this service was Running and Automatic the whole time Prefetch
    # produced nothing, which is exactly why the state is reported rather than
    # treated as the answer.
    $sysMain = Get-ServiceState -Name $script:SysMainServiceName
    if (-not $sysMain.Present) {
        Write-Finding ('no service named ' + $script:SysMainServiceName +
                       ' on this host - what writes the .pf files here could not be established')
    }
    elseif ($sysMain.Status -ne 'Running') {
        Write-Finding ($script:SysMainServiceName + ' is ' + $sysMain.Status + ' (StartType ' +
                       $sysMain.StartType + ') - the service this toolkit has measured writing the prefetch ' +
                       'component is not running, so expect no new .pf file while it is stopped')
    }
    else {
        Write-Ok ($script:SysMainServiceName + ' is Running (StartType ' + $sysMain.StartType + ')')
    }

    $state = Get-RegistryValueState -Path $script:PrefetchKey -Name $script:PrefetchValueName
    $label = ($script:PrefetchKey + '\' + $script:PrefetchValueName)

    if (-not $state.Exists) {
        Write-Info ($label + ' is absent')
        if (Test-IsFastMedia -Media $media) {
            Write-Info 'On this host that is expected rather than suspicious: the OS was measured'
            Write-Info 'removing this value on SSD/NVMe media a few minutes after it was written.'
            Write-Info 'Absence of .pf is itself the DFIR-relevant finding, and it is not tampering.'
        }
        Write-Finding ('Prefetch is not explicitly enabled (' + $label +
                       ' absent). This script does not write it: use Enable-ServerPrefetch, which owns that setting.')
        return 0
    }

    $value = Get-NumericRegistryValue -State $state
    if ($null -eq $value) {
        # Not overwritten: Set-TrackedRegistryValue records the previous value
        # and its kind, and an unsupported kind would throw there. A value of the
        # wrong type is reported and left for a human, which also preserves it as
        # evidence of whoever wrote it.
        Write-Finding ($label + ' is a ' + [string] $state.Kind + ' holding "' + [string] $state.Value +
                       '", which is not a numeric type this can interpret. Whether prefetching is on ' +
                       'cannot be read from it, and this script does not overwrite a value of an ' +
                       'unexpected type - decide by hand.')
        return 0
    }
    if ($value -ne $script:PrefetchDisabled) {
        Write-Ok ($label + ' = ' + [string] $value + ' (prefetching is enabled)')
        return 0
    }

    # Write-Info, not Write-Finding: the finding is raised by
    # Set-TrackedRegistryValue below when it reports what -Apply WOULD change.
    # Raising one here as well would leave a finding outstanding after a
    # successful -Apply, and this script's exit code would then never reach 0
    # on the one host it had just repaired.
    Write-Info ($label + ' = 0 - prefetching has been EXPLICITLY DISABLED. Somebody wrote that.')
    if (Test-IsFastMedia -Media $media) {
        Write-Info 'Note before acting: this volume reports fast media, where the OS itself was'
        Write-Info 'measured dropping this value. Putting it back is recorded and reversible, but'
        Write-Info 'verify afterwards with Test-VisibilityDrift rather than assuming it held.'
    }

    $changes = 0
    if (Set-TrackedRegistryValue -Path $script:PrefetchKey -Name $script:PrefetchValueName `
        -Kind 'DWord' -Value $script:PrefetchBoth `
        -Description ('EnablePrefetcher = ' + [string] $script:PrefetchBoth +
                      ' (application launch and boot prefetching)')) {
        $changes++
        # Treated as needing a restart. UNVERIFIED that a restart is SUFFICIENT:
        # on the lab the value survived a reboot and no .pf was ever produced
        # anyway, so what a restart delivers there was never observed. Flagging
        # it is the conservative choice - it makes the run return 1 rather than
        # claim an effect nobody has seen.
        $script:RebootPending = $true
    }
    return $changes
}

function Test-SrumArtifact {
    <#
        SRUM: the Diagnostic Policy Service and the database it writes.

        "Is it growing" cannot be answered by one observation, so this does not
        pretend to. It reports the size and the last-write time and compares
        that time against -SrumStaleHours, whose default is this toolkit's
        choice and is printed so the operator can disagree with it.
    #>
    Write-Section 'SRUM - per-process resource and network usage history'

    $changes = 0
    $dps = Get-ServiceState -Name $script:DpsServiceName
    if (-not $dps.Present) {
        Write-Finding ('no service named ' + $script:DpsServiceName +
                       ' on this host - SRUM state could not be established')
    }
    elseif ($dps.Status -ne 'Running' -or $dps.StartType -eq 'Disabled') {
        # Write-Info, not Write-Finding: Set-TrackedServiceState raises the
        # finding itself when it reports what -Apply would do. Two findings for
        # one problem would leave one outstanding after the repair succeeded.
        Write-Info ('the Diagnostic Policy Service (' + $script:DpsServiceName + ') is ' +
                    $dps.Status + '/' + $dps.StartType +
                    ' - while it is not running, SRUM stops recording')
        $changes += Set-TrackedServiceState -Name $script:DpsServiceName `
            -Description 'Diagnostic Policy Service (SRUM data collection)'
    }
    else {
        Write-Ok ('the Diagnostic Policy Service (' + $script:DpsServiceName +
                  ') is Running (StartType ' + $dps.StartType + ')')
    }

    $srumPath = [System.Environment]::ExpandEnvironmentVariables($script:SrumDatabasePath)
    if (-not (Test-Path -LiteralPath $srumPath)) {
        Write-Finding ('no SRUM database at the expected path ' + $srumPath +
                       ' - either it has been deleted or this build keeps it elsewhere (see the UNVERIFIED note in the code)')
        return $changes
    }

    $file = Get-Item -LiteralPath $srumPath -Force
    $sizeMb = [math]::Round($file.Length / 1MB, 2)
    $lastWriteUtc = $file.LastWriteTimeUtc
    $ageHours = [math]::Round(((Get-Date).ToUniversalTime() - $lastWriteUtc).TotalHours, 1)
    Write-Info ($srumPath + ' is ' + [string] $sizeMb + ' MB, last written ' +
                $lastWriteUtc.ToString('yyyy-MM-ddTHH:mm:ssZ',
                    [System.Globalization.CultureInfo]::InvariantCulture))

    if ($ageHours -gt $SrumStaleHours) {
        Write-Finding ('the SRUM database has not been written to for ' + [string] $ageHours +
                       ' hours (threshold ' + [string] $SrumStaleHours +
                       ', a value chosen by this toolkit) - it is not recording')
    }
    else {
        Write-Ok ('the SRUM database was written ' + [string] $ageHours +
                  ' hour(s) ago, so it is still being updated')
    }
    return $changes
}

function Test-UserAssistArtifact {
    <#
        UserAssist is per-user, and this script runs machine-wide as SYSTEM.
        So it reports on the hives already LOADED under HKEY_USERS, lists the
        profile directories it found, and states plainly which users it could
        not cover. It does not mount an unloaded hive: see the header.

        Nothing in here is a change. HKEY_USERS is read only.
    #>
    Write-Section 'UserAssist - per-user GUI execution history'

    # Enumerated through an explicit 64-bit view rather than through
    # Get-HiveSubKeyName, because Split-RegistryPath refuses a bare hive by
    # design: OpenSubKey('') hands back the hive itself, which the caller would
    # then dispose - closing this process's handle to HKEY_USERS and breaking
    # every later registry read. That guard is right and is not weakened here.
    $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    try { $loaded = @($hive.GetSubKeyNames()) }
    finally { $hive.Dispose() }

    $userSids = @($loaded | Where-Object {
        $_ -notlike '*_Classes' -and $script:NonUserHiveSid -notcontains $_
    })

    # Profile directories are enumerated BEFORE the per-user loop, because
    # whether "no hive is loaded" is a finding depends on whether there is
    # anything to be missing. A server with nobody signed in and no profiles is
    # not hiding anything; a server with six profiles and no loaded hive means
    # this script covered none of them.
    #
    # Default / Public / All Users are skipped: they are not a signed-in user's
    # session history. If a real account is genuinely named one of those it is
    # skipped too, which is a reporting gap and never a wrong change.
    $usersRoot = [System.IO.Path]::Combine(($env:SystemDrive + '\'), 'Users')
    $skipProfile = @('Default', 'Default User', 'All Users', 'Public')
    $profileDir = @()
    if (Test-Path -LiteralPath $usersRoot) {
        $profileDir = @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $skipProfile -notcontains $_.Name } |
            Where-Object { Test-Path -LiteralPath ([System.IO.Path]::Combine($_.FullName, 'NTUSER.DAT')) })
    }

    if ($userSids.Count -eq 0) {
        if ($profileDir.Count -gt 0) {
            Write-Finding ('no user hive is loaded, so none of the ' + [string] $profileDir.Count +
                           ' profile(s) on this host could be checked for UserAssist state')
        }
        else {
            Write-Info 'no user hive is loaded and no user profile was found; there is nothing to check here'
        }
    }

    foreach ($sid in $userSids) {
        $who = $sid
        try {
            $account = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate(
                [System.Security.Principal.NTAccount])
            $who = ($sid + ' (' + $account.Value + ')')
        }
        catch {
            # An orphaned or unresolvable SID is normal on a host whose domain
            # is unreachable. Report the SID rather than failing the check.
            Write-Verbose ('Could not resolve ' + $sid + ': ' + $_.Exception.Message)
        }

        $assist = Get-HiveSubKeyName -Path ('HKU:\' + $sid + '\' + $script:UserAssistSubKey)
        if ($null -eq $assist) {
            Write-Finding ($who + ': no UserAssist subtree - GUI execution history is not being recorded')
        }
        else {
            Write-Ok ($who + ': UserAssist present with ' + [string] $assist.Count + ' subkey(s)')
        }

        $clean = 0
        foreach ($flag in $script:PerUserFlag) {
            $read = Get-RegistryValueState -Path ('HKU:\' + $sid + '\' + $flag.SubKey) -Name $flag.Value
            if (-not $read.Exists) { $clean++; continue }
            $number = Get-NumericRegistryValue -State $read
            if ($null -eq $number) {
                # NOT counted clean: a value of the wrong type is present, and
                # what it does to tracking cannot be read off it either way.
                Write-Finding ($who + ': ' + $flag.Value + ' is a ' + [string] $read.Kind + ' holding "' +
                               [string] $read.Value + '", which is not a numeric type this can interpret - ' +
                               'whether it suppresses tracking for this user cannot be told from it')
                continue
            }
            $bad = ($number -ne 0)
            if ($flag.BadWhen -eq 'zero') { $bad = ($number -eq 0) }
            if ($bad) {
                Write-Finding ($who + ': ' + $flag.Value + ' = ' + [string] $number + ' ' + $flag.Message)
            }
            else {
                $clean++
            }
        }
        if ($clean -eq $script:PerUserFlag.Count) {
            Write-Ok ($who + ': no policy or preference is suppressing this user''s activity tracking')
        }
    }

    # What was NOT covered. This is the honest half of the report.
    #
    # The two counts are compared as a HEURISTIC, not as an identity: a loaded
    # hive does not have to have a profile directory under C:\Users, and a
    # profile directory does not have to correspond to a loaded hive. It is good
    # enough to answer "did this run see everybody", which is the only question
    # being asked.
    Write-Info ''
    Write-Info ('COVERAGE: read ' + [string] $userSids.Count + ' loaded user hive(s); found ' +
                [string] $profileDir.Count + ' profile director(y/ies) with an NTUSER.DAT under ' +
                $usersRoot + '.')
    if ($profileDir.Count -gt $userSids.Count) {
        Write-Info 'Profiles whose hive is not loaded were NOT examined. This script does not mount'
        Write-Info 'them: reg load opens the hive read-write, can dirty it, and leaves the profile'
        Write-Info 'locked if the unload does not run. Collect NTUSER.DAT offline instead.'
        foreach ($dir in $profileDir) { Write-Info ('  profile on disk: ' + $dir.FullName) }
    }
    return 0
}

function Test-LastAccessArtifact {
    <#
        NTFS last-access timestamps: what lets a responder say a file was READ.

        Reported from two independent places - the registry value Microsoft
        documents fsutil as writing, and fsutil's own query - because they can
        disagree and the disagreement is worth seeing.

        Only changed with -EnableLastAccessUpdates, because re-enabling has a
        documented performance cost and this toolkit does not spend a client's
        performance by default.
    #>
    Write-Section 'NTFS last-access timestamps'

    $changes = 0
    $label = ($script:FileSystemKey + '\' + $script:LastAccessValue)
    $state = Get-RegistryValueState -Path $script:FileSystemKey -Name $script:LastAccessValue

    # fsutil's output text is localised, so nothing here matches on words: the
    # raw line is printed for the operator and the DECISION is taken from the
    # registry value. Matching English output would silently read nothing on a
    # French or German host, which is the trap docs/AUTHORING.md warns about.
    $query = Invoke-NativeCommand -FilePath (Get-NativeToolPath -FileName 'fsutil.exe') `
        -Arguments @('behavior', 'query', 'disablelastaccess')
    if ($query.ExitCode -eq 0) {
        foreach ($line in $query.Output) {
            if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Info ('fsutil: ' + $line.Trim()) }
        }
    }
    else {
        Write-Info ('fsutil behavior query disablelastaccess exited ' + [string] $query.ExitCode +
                    ': ' + ($query.Output -join ' '))
    }

    if (-not $state.Exists) {
        Write-Info ($label + ' is absent, so the volume default applies')
    }
    else {
        Write-Info ($label + ' = ' + [string] $state.Value)
    }

    # Microsoft documents exactly two values for this setting: 1 disables
    # last-access updates, 0 enables them.
    # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
    # That page's syntax really is 'disablelastaccess {1|0}' - it says nothing
    # about any other value.
    #
    # MEASURED, and it settles what the documentation does not. On the lab
    # (Server 2019 17763, stock AMI, this value never touched by anything):
    #
    #   NtfsDisableLastAccessUpdate = 0x80000003
    #   fsutil behavior query disablelastaccess -> "DisableLastAccess = 3
    #                                              (System Managed, Enabled)"
    #   Backdate a file's LastAccessTime by 10 days, read the file, re-read the
    #   timestamp: UNCHANGED. Last-access updates are NOT happening.
    #
    # So 0x80000003 is the shipped default AND it means updates are off. Note
    # how the fsutil wording invites the opposite conclusion: "Enabled" there
    # qualifies DisableLastAccess, not the timestamps. Reading it the natural
    # way would have a responder trusting access times that Windows never wrote.
    #
    # Hence: 0 means recorded, anything else means not recorded. Treating the
    # stock default as "unrecognised, take no view" was worse than useless - it
    # reported an undocumented-value finding on every untouched Server 2019
    # while saying nothing about the visibility gap that was actually there.
    $disabled = $false
    $raw = $null
    if ($state.Exists) {
        $raw = Get-NumericRegistryValue -State $state
        if ($null -eq $raw) {
            Write-Finding ($label + ' is a ' + [string] $state.Kind + ' holding "' + [string] $state.Value +
                           '", which is not a numeric type this can interpret. Whether ' +
                           'last-access timestamps are being recorded cannot be read from it: query it ' +
                           'by hand before trusting any access time on this host.')
            return 0
        }
        if ($raw -ne 0) { $disabled = $true }
    }

    if (-not $disabled) {
        Write-Ok 'last-access timestamp updates are not disabled by this value'
        return 0
    }

    # Printed in hex as well as decimal: a DWORD with the high bit set reads
    # back as a negative Int32, so the decimal form on its own looks like
    # nonsense to whoever has to decide what to do about it.
    #
    # The hex is folded to unsigned by arithmetic rather than by casting to
    # [int]: a REG_QWORD holding the same setting would overflow that cast, and a
    # terminating cast here is exactly the exit-2-instead-of-a-finding failure
    # Get-NumericRegistryValue above exists to stop.
    $rawValue = $raw
    $pattern  = $rawValue
    if ($pattern -lt 0) { $pattern = $pattern + 4294967296 }
    Write-Info ($label + ' = ' + [string] $rawValue + ' (0x' + ('{0:X8}' -f $pattern) +
                ') - NTFS last-access timestamps are NOT being recorded. ' +
                'A responder cannot tell that a file was read, only that it was written.')
    # 0x80000003 is the ONE out-of-range value there is a measurement for, so it
    # is the only one told it is a shipped default. The guard used to be
    # `-ne 1`, which said "stock default on Server 2019" about 2, about 5, about
    # 0x80000001 and about every other SKU - inventing a Windows fact, in
    # operator output, about the very value a tamper check exists to notice.
    #
    # Matched on the folded bit pattern because the same DWORD reads back two
    # ways depending on the tool: -2147483645 signed, which is what .NET hands
    # back, and 2147483651 unsigned, which is how docs/VALIDATION.md records it.
    if ($pattern -eq 2147483651) {
        Write-Info ('That value is outside the {0,1} pair fsutil documents. It was measured as the ' +
                    'shipped default on this project''s lab (Server 2019, build 17763, stock image), ' +
                    'where reading a file did NOT move its LastAccessTime - see docs/VALIDATION.md. ' +
                    'Reported as not-recorded rather than as tampering.')
    }
    elseif ($rawValue -ne 1) {
        Write-Info ('That value is outside the {0,1} pair fsutil documents, and it is not the ' +
                    '0x80000003 this project measured as a shipped default, so nothing here can say ' +
                    'whether it was shipped or written. Somebody may have chosen it: treated as ' +
                    'not-recorded either way, and worth asking about.')
    }

    if (-not $EnableLastAccessUpdates) {
        # A finding here, unlike the branches above, because this run is not
        # going to fix it: the operator has to opt in. Reporting it as
        # information would exit 0 on a host whose read history is off.
        Write-Finding ('NTFS last-access timestamps are disabled and this run will not change it ' +
                       '(-EnableLastAccessUpdates was not passed).')
        Write-Info 'Re-enabling costs a little file and directory access speed'
        Write-Info ('(Microsoft: "Disabling the Last Access Time feature improves the speed of file ' +
                    'and directory access"), so it is opt-in: re-run with -EnableLastAccessUpdates.')
        Write-Info ('-Apply -EnableLastAccessUpdates would set ' + $label + ' = 0 (REG_DWORD).')
        return 0
    }

    if (Set-TrackedRegistryValue -Path $script:FileSystemKey -Name $script:LastAccessValue `
        -Kind 'DWord' -Value $script:LastAccessEnabled `
        -Description 'NtfsDisableLastAccessUpdate = 0 (last-access timestamps recorded again)') {
        $changes++
        # "You must restart your computer for this parameter to take effect."
        # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
        $script:RebootPending = $true
    }
    return $changes
}

function Test-RecycleAndShadowArtifact {
    <#
        Two recovery paths a responder uses, reported and never changed.

        The Recycle Bin policy is read from the machine scope as well as the
        loaded user hives, even though the policy Microsoft documents is User
        Configuration - a value present in the machine scope is worth SEEING
        whether or not Windows honours it there.
    #>
    Write-Section 'Recycle Bin and shadow copies'

    # UNVERIFIED: whether a machine-scope NoRecycleFiles is honoured at all.
    # ADMX_WindowsExplorer declares the policy under User Configuration; the
    # machine key is read here for reporting only.
    $machinePolicy = Get-RegistryValueState `
        -Path ('HKLM:\' + $script:UserPolicyExplorerSubKey) -Name $script:NoRecycleFilesValue
    $machineFlag = Get-NumericRegistryValue -State $machinePolicy
    if ($machinePolicy.Exists -and $null -eq $machineFlag) {
        Write-Finding ('HKLM:\' + $script:UserPolicyExplorerSubKey + '\' + $script:NoRecycleFilesValue +
                       ' is a ' + [string] $machinePolicy.Kind + ' holding "' +
                       [string] $machinePolicy.Value + '", not a REG_DWORD - the value is present but ' +
                       'what it does to the Recycle Bin cannot be read from it')
    }
    elseif ($null -ne $machineFlag -and $machineFlag -ne 0) {
        Write-Finding ('HKLM:\' + $script:UserPolicyExplorerSubKey + '\' + $script:NoRecycleFilesValue +
                       ' = ' + [string] $machinePolicy.Value +
                       ' - "Do not move deleted files to the Recycle Bin" is set in the machine scope')
    }
    else {
        Write-Ok 'no machine-scope NoRecycleFiles policy (per-user results are in the UserAssist section)'
    }

    $vss = Get-ServiceState -Name $script:VssServiceName
    if (-not $vss.Present) {
        Write-Finding ('no service named ' + $script:VssServiceName +
                       ' on this host - shadow copy state could not be established')
    }
    elseif ($vss.StartType -eq 'Disabled') {
        Write-Finding ('the Volume Shadow Copy service (' + $script:VssServiceName +
                       ') is DISABLED - no shadow copy can be created, by a backup product or by a responder. ' +
                       'This script does not change it: there is no cited shipped start type to restore it to, ' +
                       'and backup products drive this service. Decide by hand.')
    }
    else {
        Write-Ok ('the Volume Shadow Copy service (' + $script:VssServiceName + ') is ' +
                  $vss.Status + '/' + $vss.StartType)
    }

    # 'vssadmin list shadows' lists existing shadow copies.
    # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-list-shadows
    #
    # THE ONE PLACE THIS SCRIPT'S -Audit IS NOT PURELY PASSIVE, AND IT SAYS SO.
    # Asking what shadow copies exist DEMAND-STARTS the Volume Shadow Copy
    # service, because that service is what answers the question. Measured on
    # the lab from a Stopped/Manual baseline, three ways, all identical:
    #
    #   Get-CimInstance Win32_ShadowCopy    -> VSS Running
    #   vssadmin list shadows               -> VSS Running
    #   vssadmin list shadowstorage         -> VSS Running
    #
    # There is no read path that avoids it. The service's START TYPE is not
    # touched - it stays Manual - and nothing is written; what changes is that a
    # demand-start service is left running. That is worth declaring rather than
    # hiding, because docs/DESIGN.md calls -Audit strictly read-only and a
    # monitored host may alert on the transition. The information is worth the
    # side effect: whether a point-in-time copy exists decides whether deleted
    # evidence is recoverable at all.
    Write-Info ('note: enumerating shadow copies demand-starts the ' + $script:VssServiceName +
                ' service - measured, unavoidable, and the only thing -Audit does that is not a ' +
                'pure read. The start type is not changed.')
    #
    # The output text is localised, so no word in it is matched and no count is
    # claimed. GUIDs are not localised, so their PRESENCE is used as the only
    # signal: at least one shadow copy was listed, or none was.
    $shadows = Invoke-NativeCommand -FilePath (Get-NativeToolPath -FileName 'vssadmin.exe') `
        -Arguments @('list', 'shadows')
    $hasGuid = $false
    foreach ($line in $shadows.Output) {
        if ($line -match '\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}') {
            $hasGuid = $true
            break
        }
    }
    if ($hasGuid) {
        Write-Ok 'vssadmin listed at least one shadow copy'
    }
    else {
        Write-Finding ('vssadmin list shadows reported no shadow copy (exit ' + [string] $shadows.ExitCode +
                       ') - there is no point-in-time copy to recover deleted evidence from')
    }
    return 0
}

function Invoke-HostCheck {
    <#
        Note the accumulation idiom and copy it exactly. Never write
        '$changed = $changed -or (...)': -or short-circuits, so once $changed is
        $true every later call is NEVER MADE and the script silently stops
        acting after the first thing it fixed.
    #>
    $changeCount = 0
    $changeCount += Test-PrefetchArtifact
    $changeCount += Test-SrumArtifact
    $changeCount += Test-UserAssistArtifact
    $changeCount += Test-LastAccessArtifact
    $changeCount += Test-RecycleAndShadowArtifact

    Write-Section 'What this script cannot do'
    Write-Info 'None of the above is PREVENTED from being switched off again. Every one of these'
    Write-Info 'is a registry value, a service or a file system flag that any administrator can'
    Write-Info 'rewrite. What you have instead is a manifest record of what was restored, which'
    Write-Info 'is what lets Test-VisibilityDrift report it the next time it is turned off.'
    return $changeCount
}

#endregion

#region Main -----------------------------------------------------------------

function Restore-ArtifactChange {
    <#
        Routes a change record to the right restorer.

        The template's Restore-TrackedChange only knows the 'registry' type and
        DECLINES anything else - correctly, because silently "succeeding" on a
        change type it cannot undo is how a run gets marked rolled back while
        the host stays modified. This script introduces the 'service' type, so
        it handles that one here and delegates the rest, exactly as
        Enable-IRVisibility does for its 'auditpol' type.

        Returns 'restored' or 'declined'; throws on a failed write.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    if ($change.type -eq 'service') {
        return (Restore-TrackedService -ChangeRecord $ChangeRecord)
    }
    return (Restore-TrackedChange -ChangeRecord $ChangeRecord)
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
    Assert-ParameterRange   -Name 'SrumStaleHours' -Value $SrumStaleHours -Minimum 1 -Maximum 8760

    # -RunId and -AbandonRun both NAME a run, and naming the run is the whole
    # safety property of both (docs/DESIGN.md section 4.2). They used to be
    # last-writer-wins, with -RunId silently ignored; a conflicting pair of names
    # is refused instead, before anything is read, locked or changed.
    if ((Test-ParameterSupplied -Name 'RunId') -and (Test-ParameterSupplied -Name 'AbandonRun')) {
        throw ('-RunId and -AbandonRun both name a run and cannot be combined. Pass ' +
               '-Rollback -AbandonRun <runId> on its own to abandon that run.')
    }

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        [void] (Invoke-HostCheck)
        Write-Section 'Result'
        if ($script:Findings.Count -gt 0) {
            Write-Info ([string] $script:Findings.Count + ' finding(s). Re-run with -Apply to restore what this script can.')
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
        Write-Ok 'No findings: every artifact this script checks is being recorded.'
        return 0
    }

    Enter-ToolkitLock -ToolkitRootPath $resolvedRoot
    try {
        $allowMissingStamp = ($mode -eq 'Rollback')
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -AllowMissingStamp:$allowMissingStamp)
        Assert-ManifestUsable

        if ($mode -eq 'Apply') {
            [void] (Start-ManifestRun -Mode 'Apply' -Parameters @{
                toolkitRoot             = $resolvedRoot
                enableLastAccessUpdates = [bool] $EnableLastAccessUpdates
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
                $verified = Invoke-HostCheck
            }
            catch {
                Write-Failure $_.Exception.Message
                $status = 'completed-with-failures'
            }
            # A run that changed nothing still records itself: on a host already
            # clean there is otherwise no evidence the toolkit ran here, and
            # Test-VisibilityDrift has no reference state to compare against.
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

            if ($script:RebootPending) {
                # docs/AUTHORING.md: a script that applied its setting but
                # cannot demonstrate the effect returns 1, not 0. Both the
                # Prefetch value and NtfsDisableLastAccessUpdate need a restart
                # before anything observable changes, so this run cannot yet
                # prove it worked.
                Write-Info 'A RESTART is required before the change(s) above take effect, so this run'
                Write-Info 'cannot demonstrate them. Re-run -Audit after the restart, and use'
                Write-Info 'Test-VisibilityDrift to catch the OS or an attacker dropping them again.'
                return 1
            }
            if ($script:Findings.Count -gt 0) {
                Write-Info ([string] $script:Findings.Count +
                            ' finding(s) remain that this script deliberately does not fix.')
                return 1
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

        # ONE resolution, on whichever id applies. This used to resolve -RunId
        # first and then resolve again for -AbandonRun, throwing the first result
        # away: the discarded call still throws for a run id that is unknown or
        # already rolled back, so -Rollback -RunId <old run> -AbandonRun <stuck
        # run> died at exit 2 naming a run the operator had not asked about, and
        # the abandon never happened. The two parameters can no longer be
        # combined (see the refusal at the top of Invoke-Main), so one of them is
        # empty here.
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
                $outcome = Restore-ArtifactChange -ChangeRecord $target.Changes[$i]
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
