<#
.SYNOPSIS
    Enables and sizes the NTFS USN change journal, so a mass rename or a mass
    deletion leaves a trace on the volume itself even when the event logs are
    gone.

.DESCRIPTION
    Ransomware renames or deletes thousands of files, then clears the event
    logs. The USN change journal survives that: it lives in NTFS metadata, not
    in a log an attacker thinks to clear, and records one entry per change to
    every file and directory on the volume. A journal is usually already active,
    so the useful question is not "is it on" but "how far back does it go" - one
    that wraps in an hour is worthless for an incident found next week. SIZE is
    therefore the setting this script treats as the important one.

    Every command line, unit and parameter is cited to learn.microsoft.com. The
    one thing Microsoft does not document - the text layout of `fsutil usn
    queryjournal` output - is parsed defensively and marked UNVERIFIED.

    SIZE POLICY: -Apply never shrinks. -MaxSizeBytes and -AllocationDeltaBytes
    are FLOORS, not targets; a volume that already has a larger journal is left
    alone and reported as satisfactory. Shrinking discards the records that no
    longer fit, which on a host running for months deletes the history this
    toolkit exists to preserve. "At least this big" is also what makes -Apply
    idempotent, since NTFS is documented to grow the journal past the requested
    maximum before trimming it at the next checkpoint.

    THE ROLLBACK PROBLEM, stated plainly. `fsutil usn deletejournal` destroys
    journal history, and shrinking discards records too, so -Rollback here is
    deliberately asymmetric. If the volume HAD a journal before this run, it
    restores the recorded previous maximum size and allocation delta, and says
    out loud that shrinking discards records. If the volume had NO journal
    before this run, it REFUSES to delete the one this script created and
    records a finding saying why: since the last -Apply that journal has been
    accumulating real forensic history, and destroying evidence to satisfy a
    rollback is exactly backwards. No switch is offered to do it. An operator
    who truly wants it gone can run `fsutil usn deletejournal /d <volume>` by
    hand and own that decision.

    What this script deliberately does NOT do:
      - It never deletes or disables a journal, in any mode.
      - It does not shrink a journal in -Apply, even when asked to.
      - It does not resize a journal whose current size it could not read.
        Without a previous maximum there is no way to be sure a write would not
        shrink it, so it reports a finding instead.
      - It does not touch volumes without a drive letter. `fsutil usn` takes "a
        drive letter (followed by a colon)", and Win32_LogicalDisk enumerates
        lettered drives only, so the two agree by construction and a
        directory-mounted volume is out of reach here.
      - It does not call `fsutil usn enablerangetracking` - a separate feature
        with its own cost and no rollback story in this script.
      - It does not read or export journal records. That is a collector's job,
        and the collectors are not part of this repository - see docs/SCRIPTS.md.

    What needs a reboot:
      NOTHING. Microsoft documents that when a journal already exists,
      `createjournal` "updates the change journal's maxsize and allocationdelta
      parameters. This enables you to expand the number of records that an
      active journal maintains without having to disable it." The script proves
      the effect by re-reading the journal after the write rather than assuming.

.PARAMETER CreateJournalWhenStateUnknown
    Act on a volume whose journal state could not be read. By default a
    non-zero `fsutil usn queryjournal` exit means UNKNOWN and the volume is
    left alone, because `createjournal` UPDATES an existing journal rather than
    creating one - so acting blind can shrink a real journal and discard its
    history, with a null previous size recorded and no rollback possible.
    Microsoft documents a state in which a journal exists and every query
    against it errors (while it is being disabled, which "can take several
    minutes, and it can continue after the system restarts"). Pass this only
    after confirming by hand that the volume has no journal.

.PARAMETER Audit
    Default. Strictly read-only. Reports each volume's journal state and the
    exact fsutil command line -Apply would run. Writes nothing anywhere.

.PARAMETER Apply
    Creates or grows the journal, recording the previous size to the manifest
    first.

.PARAMETER Rollback
    Restores the recorded previous sizes. Declines to delete a journal this
    script created - see THE ROLLBACK PROBLEM above.

.PARAMETER ToolkitRoot
    Base directory for the manifest. Default C:\ProgramData\IronBlackBox.
    Validated before use.

.PARAMETER Volume
    A single volume, as a drive letter and a colon ("D:"). Defaults to the
    system volume. Mutually exclusive with -AllFixedVolumes.

.PARAMETER AllFixedVolumes
    Act on every fixed NTFS volume with a drive letter. Non-NTFS and non-fixed
    volumes are reported and skipped with the reason.

.PARAMETER MaxSizeBytes
    Journal maximum size floor, in BYTES - the unit `fsutil usn createjournal
    m=<maxsize>` takes. Default 1073741824 (1 GiB): the journal has to still be
    there when an incident is found weeks later, and 1 GiB is negligible against
    a server volume of hundreds of gigabytes. The script reports the size it
    actually finds rather than claiming what Windows ships. Retention in days
    cannot be derived from size alone; see -MeasureChangeRateSeconds.

.PARAMETER AllocationDeltaBytes
    Allocation delta floor, in BYTES. Default 134217728 (128 MiB), one eighth of
    the default maximum. Microsoft documents that NTFS trims the journal once it
    exceeds maxsize plus allocationdelta, so a larger delta means less frequent
    trimming and more overshoot. One eighth is this toolkit's judgement, not a
    Microsoft recommendation.

.PARAMETER MaxFreeSpaceFraction
    Refuse to size a journal larger than this fraction of the volume's free
    space. Default 0.10. A hardening script that fills a production volume is an
    outage delivered by the tool.

.PARAMETER MeasureChangeRateSeconds
    Optionally sample the journal twice, this many seconds apart, to estimate how
    long it retains history. 0 (the default) skips it and the script says plainly
    that retention is not derivable from one observation. Read the caveats
    printed with the estimate before quoting it.

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
    .\Enable-UsnJournalTracking.ps1
    Reports the system volume's journal size and what -Apply would set.

.EXAMPLE
    .\Enable-UsnJournalTracking.ps1 -AllFixedVolumes -Apply
    Grows the journal on every fixed NTFS volume, recording previous sizes.

.EXAMPLE
    .\Enable-UsnJournalTracking.ps1 -MeasureChangeRateSeconds 60
    Audits, and additionally estimates retention from a 60-second sample.

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
    [switch] $CreateJournalWhenStateUnknown,

    [Parameter()]
    [string] $ToolkitRoot = 'C:\ProgramData\IronBlackBox',

    [Parameter()]
    [string] $Volume,

    [Parameter()]
    [switch] $AllFixedVolumes,

    # The lower bound is this toolkit's, not fsutil's: below 16 MiB a journal on
    # a busy volume wraps in minutes and records nothing an investigation can use.
    [Parameter()]
    [long] $MaxSizeBytes = 1073741824,

    [Parameter()]
    [long] $AllocationDeltaBytes = 134217728,

    [Parameter()]
    [double] $MaxFreeSpaceFraction = 0.10,

    [Parameter()]
    [int] $MeasureChangeRateSeconds = 0,

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

$script:ScriptName    = 'Enable-UsnJournalTracking'
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

#region Native tool paths ----------------------------------------------------

# Resolved ONCE, here, and never called by bare name. This script runs as SYSTEM,
# so a bare name would let any machine PATH entry an unprivileged user can write
# to decide which binary runs with SYSTEM's token. Get-NativeToolPath falls back
# to the bare name when no expected directory holds the file - and says so as a
# finding - so an unusual layout degrades loudly instead of silently.
$script:FsutilPath = Get-NativeToolPath -FileName 'fsutil.exe'

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
#   measured: this script calls Set-TrackedRegistryValue nowhere, so a
#   registry record in its manifest did not come from it.
$script:OwnedRegistryKey = @()

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

#region USN journal ------------------------------------------------------------

<#
    Everything here rests on one Microsoft reference page, quoted verbatim:
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn
      fsutil usn [createjournal] m=<maxsize> a=<allocationdelta> <volumepath>
      fsutil usn [queryjournal] <volumepath>
      m= "the maximum size, in bytes, that NTFS allocates for the change journal"
      a= "the size, in bytes, of memory allocation that is added to the end and
          removed from the beginning of the change journal"
      <volumepath> "the drive letter (followed by a colon)"
      "If a change journal already exists on a volume, the createjournal
       parameter updates the change journal's maxsize and allocationdelta
       parameters ... without having to disable it."
      "NTFS examines the change journal and trims it when its size exceeds the
       value of maxsize plus the value of allocationdelta."

    BOTH SIZES ARE IN BYTES, and the unit trap runs the OPPOSITE way from the one
    in Enable-IRVisibility, where the EventLog policy MaxSize is in KILOBYTES
    (verification/facts.json, fact eventlog-maxsize). Passing kilobytes here asks
    for a journal 1024x too small and delivers one that wraps in minutes.
#>

# Win32_LogicalDisk.DriveType value "Local Disk" (3); NTFS is the documented
# example value of its FileSystem property.
# https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk
$script:DriveTypeLocalDisk = 3

function Get-FsutilField {
    <#
        Finds a "Label : value" line by matching the LABEL, returning the text
        after the first colon.

        # UNVERIFIED: the text layout of `fsutil usn queryjournal` output is not
        # a documented stable API - the reference page documents the command and
        # its parameters, not the shape of what it prints - and the labels are
        # localised, so on a non-English Windows none of these patterns match.
        # Every caller therefore treats a missing field as UNKNOWN and refuses
        # to write rather than defaulting to a number. Fixed line offsets are
        # deliberately not used: a build that added a field would shift them
        # silently and the wrong value would land in the manifest as a previous
        # size.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]] $Lines,
        [Parameter(Mandatory = $true)][string] $LabelPattern
    )

    foreach ($line in $Lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $colon = $line.IndexOf(':')
        if ($colon -lt 1) { continue }
        if ($line.Substring(0, $colon) -match $LabelPattern) {
            return $line.Substring($colon + 1)
        }
    }
    return $null
}

function Get-UsnJournalState {
    <#
        Reads one volume's journal. Two flags are the only things callers may
        reason about: JournalActive (queryjournal succeeded) and Readable (AND
        every field this script needs parsed).

        A non-zero exit means the state is UNKNOWN. It does NOT mean "no
        journal", and reading it that way was defect U-1 in
        the review log kept in the development repository.

        Microsoft settles this on the fsutil usn page itself, twice:

          "If a change journal already exists on a volume, the createjournal
           parameter updates the change journal's maxsize and allocationdelta
           parameters."

          "While the system is disabling the journal, it cannot be accessed, and
           all journal operations return errors."
          https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn

        So there is a documented state in which a journal EXISTS and every query
        against it errors - and in which a createjournal would resize a real
        journal rather than create a missing one, trimming its history, while
        the manifest recorded previousMaxSize as null and the console printed
        [ok]. Microsoft adds that disabling "can take several minutes, and it can
        continue after the system restarts", so this is not a narrow window.

        fsutil documents no distinguishable exit codes and its message text is
        localised, so nothing here tries to tell one failure from another. The
        raw output goes into the manifest so a human can see what it said.
    #>
    param([Parameter(Mandatory = $true)][string] $VolumePath)

    $result = Invoke-NativeCommand -FilePath $script:FsutilPath `
                  -Arguments @('usn', 'queryjournal', $VolumePath)

    $state = [PSCustomObject] @{
        VolumePath      = $VolumePath
        JournalActive   = $false
        StateKnown      = $false
        Readable        = $false
        JournalId       = $null
        FirstUsn        = $null
        NextUsn         = $null
        MaxSize         = $null
        AllocationDelta = $null
        ExitCode        = $result.ExitCode
        Raw             = ($result.Output -join ' / ')
    }
    if ($result.ExitCode -ne 0) { return $state }

    $state.JournalActive   = $true
    $state.StateKnown      = $true
    $state.JournalId       = (Get-FsutilField -Lines $result.Output -LabelPattern 'journal\s*id')
    $state.FirstUsn        = ConvertFrom-NativeInteger -Text (Get-FsutilField -Lines $result.Output -LabelPattern '^\s*first\s+usn\s*$')
    $state.NextUsn         = ConvertFrom-NativeInteger -Text (Get-FsutilField -Lines $result.Output -LabelPattern '^\s*next\s+usn\s*$')
    $state.MaxSize         = ConvertFrom-NativeInteger -Text (Get-FsutilField -Lines $result.Output -LabelPattern '^\s*maximum\s+size\s*$')
    $state.AllocationDelta = ConvertFrom-NativeInteger -Text (Get-FsutilField -Lines $result.Output -LabelPattern '^\s*allocation\s+delta\s*$')

    if ($null -ne $state.JournalId) { $state.JournalId = ([string] $state.JournalId).Trim() }
    if ($null -ne $state.MaxSize -and $null -ne $state.AllocationDelta -and $null -ne $state.NextUsn) {
        $state.Readable = $true
    }
    return $state
}

function Get-LetteredVolumeList {
    # Every lettered logical disk, with the two properties that decide whether
    # this script may touch it. Win32_LogicalDisk enumerates LETTERED drives
    # only, which is also fsutil's addressing model.
    # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk
    $list = New-Object System.Collections.ArrayList
    foreach ($disk in @(Get-CimInstance -ClassName Win32_LogicalDisk)) {
        $deviceId = [string] $disk.DeviceID
        if ($deviceId -notmatch '^[A-Za-z]:$') { continue }
        $free = $null
        if ($null -ne $disk.FreeSpace) { $free = [long] $disk.FreeSpace }
        [void] $list.Add([PSCustomObject] @{
            VolumePath = $deviceId.ToUpperInvariant()
            FileSystem = [string] $disk.FileSystem
            DriveType  = [int] $disk.DriveType
            FreeSpace  = $free
        })
    }
    return $list.ToArray()
}

function Format-ByteSize {
    # Reporting only. InvariantCulture is not cosmetic: a forensic report that
    # renders 1,5 on one host and 1.5 on another is not diffable.
    param([Parameter()] $Bytes)
    if ($null -eq $Bytes) { return 'unknown' }
    $mib = [double] $Bytes / 1048576.0
    return ($mib.ToString('N1', [System.Globalization.CultureInfo]::InvariantCulture) + ' MiB (' +
            ([long] $Bytes).ToString([System.Globalization.CultureInfo]::InvariantCulture) + ' bytes)')
}

function Get-CreateJournalArgumentList {
    # The exact argument vector -Apply runs, built in ONE place so -Audit can
    # print the command line -Apply would really use. An audit that reports a
    # different command than apply issues is a defect this repo has paid for.
    param(
        [Parameter(Mandatory = $true)][string] $VolumePath,
        [Parameter(Mandatory = $true)][long] $MaxSize,
        [Parameter(Mandatory = $true)][long] $AllocationDelta
    )
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    return @('usn', 'createjournal',
             ('m=' + $MaxSize.ToString($invariant)),
             ('a=' + $AllocationDelta.ToString($invariant)),
             $VolumePath)
}

function Measure-UsnChangeRate {
    <#
        Two samples of NextUsn, $Seconds apart, turned into bytes per second.
        Returns $null rather than a number whenever the sample cannot be trusted:
        unreadable journal, a journal recreated mid-sample (new journal id), or a
        negative delta.

        # UNVERIFIED: this rests on USN values being byte offsets into the
        # journal stream, so that a difference of NextUsn is a byte count
        # comparable with the journal's maximum size. That is not stated on the
        # fsutil reference page and has not been measured on a lab host here. If
        # it is wrong the retention estimate is wrong by the real ratio - which
        # is why the estimate is printed with its assumption attached and never
        # used to decide anything in code.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $VolumePath,
        [Parameter(Mandatory = $true)][int] $Seconds
    )

    $first = Get-UsnJournalState -VolumePath $VolumePath
    if (-not $first.Readable) { return $null }
    Start-Sleep -Seconds $Seconds
    $second = Get-UsnJournalState -VolumePath $VolumePath
    if (-not $second.Readable) { return $null }
    if ([string] $second.JournalId -ne [string] $first.JournalId) { return $null }

    $delta = ([long] $second.NextUsn) - ([long] $first.NextUsn)
    if ($delta -lt 0) { return $null }
    return [PSCustomObject] @{
        Bytes          = $delta
        Seconds        = $Seconds
        BytesPerSecond = ([double] $delta / [double] $Seconds)
    }
}

function Write-UsnRetentionReport {
    # Says what is observable, and says plainly what is not: retention in TIME
    # is not a property of the journal, it is size divided by the volume's change
    # rate, and that rate is recorded nowhere on the host. So the honest default
    # is to report the size and refuse to convert it into days.
    param(
        [Parameter(Mandatory = $true)] $State,
        [Parameter()] $Rate
    )

    if (-not $State.Readable) { return }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    Write-Info ('journal window: first USN ' + [string] $State.FirstUsn +
                ', next USN ' + [string] $State.NextUsn)

    if ($null -eq $Rate) {
        Write-Info 'retention in days is NOT derivable from a single observation: it depends on this'
        Write-Info 'volume''s file-change rate, which the host does not record. Re-run with'
        Write-Info '-MeasureChangeRateSeconds <n> for a measured estimate, and read its caveats.'
        return
    }
    if ($Rate.BytesPerSecond -le 0) {
        Write-Info ('change rate over ' + [string] $Rate.Seconds + 's was zero, so no retention')
        Write-Info 'estimate can be made from it. A longer sample taken while the host is doing'
        Write-Info 'its normal work would mean something; this one does not.'
        return
    }

    $hours = ([double] $State.MaxSize / $Rate.BytesPerSecond) / 3600.0
    Write-Info ('measured change rate: ' + $Rate.BytesPerSecond.ToString('N0', $invariant) +
                ' bytes/s over ' + [string] $Rate.Seconds + 's')
    Write-Info ('ESTIMATED retention at that rate: ' + $hours.ToString('N1', $invariant) +
                ' hours (' + ($hours / 24.0).ToString('N1', $invariant) + ' days)')
    Write-Info 'That extrapolates one short sample and assumes USN values are byte offsets - see'
    Write-Info 'the UNVERIFIED note in Measure-UsnChangeRate. Order of magnitude, not a guarantee.'
}

function Set-TrackedUsnJournal {
    <#
        The one entry point that changes a journal: records the previous sizes to
        the manifest first, then writes, then re-reads to confirm. Returns $true
        when it changed something, $false when the volume was already
        satisfactory or the change was refused - which keeps -Apply idempotent.
    #>
    param(
        [Parameter(Mandatory = $true)] $VolumeInfo,
        [Parameter(Mandatory = $true)] $State,
        [Parameter(Mandatory = $true)][long] $TargetMaxSize,
        [Parameter(Mandatory = $true)][long] $TargetAllocationDelta
    )

    $volumePath = $VolumeInfo.VolumePath
    $invariant  = [System.Globalization.CultureInfo]::InvariantCulture

    if (-not $State.StateKnown -and -not $CreateJournalWhenStateUnknown) {
        # U-1. queryjournal failed, so whether a journal exists here is UNKNOWN.
        # Running createjournal on an unknown volume is not a create - Microsoft
        # documents it as an UPDATE when a journal is already there, which on a
        # busy file server means trimming real history, recorded with a null
        # previous size so no rollback can ever put it back.
        Write-Finding ($volumePath + ' left alone: fsutil usn queryjournal exited ' +
                       [string] $State.ExitCode + ', so whether a journal exists here is UNKNOWN. ' +
                       'createjournal UPDATES an existing journal rather than creating one, and a ' +
                       'journal being disabled answers every query with an error - so acting on this ' +
                       'could shrink a real journal and discard its history.')
        Write-Info ('fsutil said: ' + $State.Raw)
        Write-Info ('If you have confirmed by hand that this volume has no journal, re-run with ' +
                    '-CreateJournalWhenStateUnknown.')
        return $false
    }

    if ($State.JournalActive -and -not $State.Readable) {
        # The dangerous case, and the reason this branch exists. Without a
        # previous maximum there is no way to know whether a write would GROW or
        # SHRINK the journal, and shrinking discards records. So the script
        # stops. This is what a localised fsutil looks like from in here.
        Write-Finding ($volumePath + ' has an active journal whose size could not be read; left alone,' +
                       ' because resizing blind could shrink it and discard history')
        Write-Info ('fsutil said: ' + $State.Raw)
        return $false
    }

    $newMaxSize         = $TargetMaxSize
    $newAllocationDelta = $TargetAllocationDelta
    $reason = ''

    if ($State.Readable) {
        # FLOORS, not targets. Never shrink - see the size policy in the header.
        if ([long] $State.MaxSize -gt $newMaxSize) { $newMaxSize = [long] $State.MaxSize }
        if ([long] $State.AllocationDelta -gt $newAllocationDelta) {
            $newAllocationDelta = [long] $State.AllocationDelta
        }
        if ($newMaxSize -eq [long] $State.MaxSize -and
            $newAllocationDelta -eq [long] $State.AllocationDelta) {
            Write-Ok ($volumePath + ' journal already at or above target: max ' +
                      (Format-ByteSize -Bytes $State.MaxSize) + ', delta ' +
                      (Format-ByteSize -Bytes $State.AllocationDelta))
            return $false
        }
        $reason = ('journal is ' + (Format-ByteSize -Bytes $State.MaxSize) + ', below the ' +
                   (Format-ByteSize -Bytes $TargetMaxSize) + ' floor')
        # Say it before it happens, not only when somebody tries to undo it.
        Write-Info ('note: enlarging a USN journal is effectively one-way. Measured on Windows Server ' +
                    '2019, fsutil usn createjournal with a SMALLER maxsize exits 0 and changes nothing, ' +
                    'so -Rollback cannot put this back. The cost of keeping it is disk space; the ' +
                    'benefit is more file-change history.')
    }
    else {
        # There is deliberately NO "this volume has no journal" arm here, and the
        # one that used to sit here could not execute. Get-UsnJournalState sets
        # JournalActive and StateKnown from the same exit code, so they are always
        # equal - and the guard above has already returned for an active journal
        # that is unreadable. What is left is exactly one state: queryjournal
        # failed and -CreateJournalWhenStateUnknown was passed. This script never
        # observes an absent journal, only an UNKNOWN one (U-1).
        $reason = ('journal state UNKNOWN (queryjournal exited ' + [string] $State.ExitCode +
                   ') and -CreateJournalWhenStateUnknown was passed, so the operator has taken ' +
                   'responsibility for the possibility that this resizes an existing journal')
    }

    # Free space guard. A hardening script that fills a production volume has
    # delivered the outage it was deployed to prevent. NTFS is documented to let
    # the journal grow past maxsize before trimming at the next checkpoint, so
    # the budget checked is maxsize PLUS allocationdelta.
    $budget = $newMaxSize + $newAllocationDelta
    if ($null -eq $VolumeInfo.FreeSpace) {
        Write-Finding ($volumePath + ' skipped: free space is unknown, so the ' +
                       (Format-ByteSize -Bytes $budget) + ' journal budget cannot be checked')
        return $false
    }
    $allowed = [long] ([double] $VolumeInfo.FreeSpace * $MaxFreeSpaceFraction)
    if ($budget -gt $allowed) {
        # U-2: name the lever. The default budget needs ~11.25 GiB free before it
        # will act, so a 60 GB volume with 8 GB free - ordinary for the audience -
        # is skipped on every run forever. An operator who is told which parameter
        # to lower can act; one told only "skipped" cannot.
        Write-Finding ($volumePath + ' skipped: a ' + (Format-ByteSize -Bytes $budget) + ' journal exceeds ' +
                       $MaxFreeSpaceFraction.ToString('P0', $invariant) + ' of the ' +
                       (Format-ByteSize -Bytes $VolumeInfo.FreeSpace) + ' free on it. Lower ' +
                       '-MaxSizeBytes (and -AllocationDeltaBytes) to fit, or raise -MaxFreeSpaceFraction, ' +
                       'or free space.')
        return $false
    }

    $arguments   = Get-CreateJournalArgumentList -VolumePath $volumePath `
                       -MaxSize $newMaxSize -AllocationDelta $newAllocationDelta
    $commandLine = 'fsutil.exe ' + ($arguments -join ' ')

    # The reason for the change is reported as a FINDING only in -Audit, and as
    # information in -Apply. Emitting it in both would leave every successful
    # -Apply with a non-zero finding count, so a fixed host would report exit 1 -
    # "findings remain" - to an RMM. Set-TrackedRegistryValue in the template
    # splits it the same way, and this has to match it.
    if (-not $Apply) {
        Write-Finding ($volumePath + ' ' + $reason + '; would run: ' + $commandLine)
        return $false
    }
    Write-Info ($volumePath + ' ' + $reason)

    # Record before changing. Not after. Sizes go in as INVARIANT DECIMAL
    # STRINGS rather than JSON numbers: these are 64-bit values, and PS 5.1
    # deserializes a JSON integer as Int32 where PS 7 uses Int64 - the same trap
    # docs/DESIGN.md section 4 records for REG_QWORD, and 1073741824 plus a
    # delta is comfortably past Int32.
    $previousMaxSize = $null
    $previousDelta   = $null
    if ($State.Readable) {
        $previousMaxSize = ([long] $State.MaxSize).ToString($invariant)
        $previousDelta   = ([long] $State.AllocationDelta).ToString($invariant)
    }

    [void] (Write-ManifestChange -Change @{
        type                    = 'usnjournal'
        volume                  = $volumePath
        journalExisted          = [bool] $State.JournalActive
        # Recorded beside it because journalExisted alone gets misread as "the
        # volume had no journal". It is $false only on the
        # -CreateJournalWhenStateUnknown path, where queryjournal had FAILED and
        # absence was never established. Without this field neither a human
        # reading the manifest nor Restore-UsnJournalChange can tell "absent"
        # from "unreadable", and the two deserve different words.
        journalStateKnown       = [bool] $State.StateKnown
        journalId               = $State.JournalId
        previousMaxSize         = $previousMaxSize
        previousAllocationDelta = $previousDelta
        previousRaw             = $State.Raw
        newMaxSize              = $newMaxSize.ToString($invariant)
        newAllocationDelta      = $newAllocationDelta.ToString($invariant)
        description             = ($volumePath + ' USN journal max ' + $newMaxSize.ToString($invariant) +
                                   ' bytes, delta ' + $newAllocationDelta.ToString($invariant) + ' bytes')
    })

    $result = Invoke-NativeCommand -FilePath $script:FsutilPath -Arguments $arguments
    if ($result.ExitCode -ne 0) {
        Write-Failure ($commandLine + ' failed with exit code ' + [string] $result.ExitCode)
        throw ('fsutil usn createjournal failed on ' + $volumePath + ': ' + ($result.Output -join ' '))
    }

    # Confirm by re-reading, the discipline a registry write gets. A
    # confirmation that cannot be made is a FINDING (exit 1), not an execution
    # error (exit 2): the write was accepted, so the change is real and
    # recorded, and what is missing is the proof.
    $after = Get-UsnJournalState -VolumePath $volumePath
    if (-not $after.Readable) {
        Write-Finding ($volumePath + ' journal was resized but the result could not be read back')
    }
    elseif ($State.Readable -and [long] $after.MaxSize -eq [long] $State.MaxSize) {
        # THE HOST REFUSED, AND SAID SO WITH EXIT 0. Measured on the lab
        # (Server 2019, 80 GB volume, 54 GB free, journal at 4 GiB): requesting
        # 5, 6 and 8 GiB each exited 0 and left Maximum Size, Allocation Delta
        # and First Usn untouched. Requesting SMALLER sizes does the same. So
        # createjournal's exit code says nothing whatever about whether the size
        # changed - only a read-back does.
        #
        # This returns $false, which matters twice over: it stops -Apply
        # reporting "1 change(s) applied" when nothing changed, and it stops the
        # run being non-idempotent forever - the previous version re-attempted
        # the same refused resize on every single run and counted a change every
        # time.
        Write-Finding ($volumePath + ' journal is UNCHANGED at ' +
                       (Format-ByteSize -Bytes $after.MaxSize) + ': fsutil exited 0 and did not honour ' +
                       'the ' + (Format-ByteSize -Bytes $newMaxSize) + ' requested. Measured on Server ' +
                       '2019, createjournal silently declines sizes it will not apply - both larger and ' +
                       'smaller - so its exit code proves nothing. Nothing was lost; the journal is as ' +
                       'it was. Pick a size the host accepts, or accept the current one.')
        return $false
    }
    elseif ([long] $after.MaxSize -lt $newMaxSize) {
        Write-Finding ($volumePath + ' journal reads back as ' + (Format-ByteSize -Bytes $after.MaxSize) +
                       ', below the ' + (Format-ByteSize -Bytes $newMaxSize) + ' requested - the host ' +
                       'honoured part of it. Re-running will ask again; if that is not wanted, pass ' +
                       '-MaxSizeBytes with the size the host actually accepted.')
    }
    else {
        Write-Ok ($volumePath + ' journal now max ' + (Format-ByteSize -Bytes $after.MaxSize) +
                  ', delta ' + (Format-ByteSize -Bytes $after.AllocationDelta))
    }
    return $true
}

function Restore-UsnJournalChange {
    <#
        Rolls back one 'usnjournal' record. Returns 'restored' or 'declined';
        throws on a failed write.

        THE DECISION THIS SCRIPT IS BUILT AROUND. When the record says the volume
        had no journal before the -Apply, the only way to undo the change is
        `fsutil usn deletejournal`, which destroys every record the journal has
        accumulated since - on a host hardened months ago, exactly the history
        this toolkit exists to create. Rollback undoes a configuration change; it
        does not destroy evidence. So this declines, says why, and offers no
        switch to override it.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $volumePath = [string] $change.volume
    # The manifest is operator-writable input, not trusted state: a planted
    # record must not turn -Rollback into an arbitrary elevated fsutil call.
    if ($volumePath -notmatch '^[A-Za-z]:$') {
        throw ('Refusing to roll back a usnjournal change with a malformed volume: ' + $volumePath)
    }

    if (-not $change.journalExisted) {
        # Two different kinds of record reach here and they do NOT support the
        # same sentence. journalStateKnown $true means queryjournal answered;
        # anything else - including a record written before that field existed -
        # means it FAILED, so the state was UNKNOWN and absence was never
        # established (U-1). Telling the operator the volume "had no journal" on
        # the strength of the second kind asserts the one thing this script's
        # headline decision says cannot be determined. The decision is the same
        # either way: this toolkit never deletes a journal.
        if ($change.journalStateKnown -eq $true) {
            Write-Finding ($volumePath + ' had no USN journal before this run, and rollback will NOT delete' +
                           ' the one that was created - it now holds real file-change history')
        }
        else {
            Write-Finding ($volumePath + ': this run could not read whether a journal already existed here,' +
                           ' so rollback cannot know whether the journal now on the volume is one this' +
                           ' script created - and will NOT delete it either way; it holds real' +
                           ' file-change history since the -Apply')
            if (-not [string]::IsNullOrWhiteSpace([string] $change.previousRaw)) {
                Write-Info ('fsutil said, before the -Apply: ' + [string] $change.previousRaw)
            }
        }
        Write-Info ('Run "fsutil usn deletejournal /d ' + $volumePath + '" by hand if you truly want it gone.')
        # PERMANENT, not retryable: this toolkit will never delete a journal, so
        # retrying can only ever produce this same message. Marking it permanent
        # is what lets the run finish and stop being re-offered - and stops
        # Test-VisibilityDrift treating every other change in the run as drift.
        return $script:RollbackDeclinedPermanent
    }

    $previousMaxSize = ConvertFrom-NativeInteger -Text ([string] $change.previousMaxSize)
    $previousDelta   = ConvertFrom-NativeInteger -Text ([string] $change.previousAllocationDelta)
    if ($null -eq $previousMaxSize -or $null -eq $previousDelta) {
        Write-Finding ($volumePath + ': the recorded previous journal size is missing or unreadable, so' +
                       ' there is nothing to restore it to; declining rather than guessing a size')
        return 'declined'
    }

    $current = Get-UsnJournalState -VolumePath $volumePath
    if (-not $current.JournalActive) {
        Write-Finding ($volumePath + ' has no active journal now, so this run''s change is gone;' +
                       ' creating one at the old size would be a new change, not a restore')
        return 'declined'
    }
    if (-not $current.Readable) {
        Write-Finding ($volumePath + ' journal size cannot be read, so a restore cannot be verified' +
                       ' and is not attempted')
        Write-Info ('fsutil said: ' + $current.Raw)
        return 'declined'
    }

    # THE THREE-WAY RESOLUTION, per the rollback doctrine in the Manifest region.
    $intendedMaxSize = ConvertFrom-NativeInteger -Text ([string] $change.newMaxSize)
    if ($null -eq $intendedMaxSize) {
        # Fail closed, exactly as the previousMaxSize guard above does. This test
        # used to be a conjunct of the resolution below, so a record whose
        # newMaxSize was missing or unparseable skipped the resolution ENTIRELY
        # and fell through to an elevated fsutil resize - never asking whether the
        # host holds what the run set, what it held before, or neither. The
        # manifest is operator-writable input, which is what makes that the
        # dangerous direction to fall in.
        Write-Finding ($volumePath + ': the record does not say what size this run set, so the host' +
                       ' cannot be resolved against it; declining rather than resizing on a record' +
                       ' that cannot be read')
        return $script:RollbackDeclined
    }
    if ([long] $current.MaxSize -ne $intendedMaxSize) {
        # Case 2: the journal is already the size recorded BEFORE this run. On
        # this OS that is the COMMON case, not an edge one - fsutil exits 0
        # whether it honoured the requested size or silently ignored it, so a
        # recorded change may never have landed. Measured: a run that asked for
        # 5 GiB against a 4 GiB journal recorded the change, changed nothing, and
        # then every rollback of it declined "not the 5,120.0 MiB this run set"
        # forever - fourteen such runs on the lab, none of which could ever be
        # closed.
        if ([long] $current.MaxSize -eq [long] $previousMaxSize) {
            # The SIZE needs nothing. The allocation delta is the other half of
            # the same record - -Apply raises both - and this arm used to return
            # 'restored' without ever looking at it, closing the run on a journal
            # still carrying the enlarged delta. When the delta is still raised,
            # fall through to the write and let the read-back decide.
            if ([long] $current.AllocationDelta -eq [long] $previousDelta) {
                Write-Ok ($volumePath + ' journal is already ' + (Format-ByteSize -Bytes $current.MaxSize) +
                          ' with the allocation delta recorded before this run - either the resize ' +
                          'never landed or it has already been undone. Nothing to restore.')
                return $script:RollbackRestored
            }
            Write-Info ($volumePath + ' journal size is already back to ' +
                        (Format-ByteSize -Bytes $current.MaxSize) + ', but its allocation delta is ' +
                        (Format-ByteSize -Bytes $current.AllocationDelta) + ' rather than the ' +
                        (Format-ByteSize -Bytes $previousDelta) + ' recorded before this run.')
        }
        else {
            # Case 3: neither size. Something else moved it.
            Write-Finding ($volumePath + ' journal is ' + (Format-ByteSize -Bytes $current.MaxSize) +
                           ', which is neither the ' + (Format-ByteSize -Bytes $intendedMaxSize) +
                           ' this run set nor the ' + (Format-ByteSize -Bytes $previousMaxSize) +
                           ' recorded before it; leaving it alone')
            return $script:RollbackDeclined
        }
    }

    Write-Info ($volumePath + ': restoring the journal to ' + (Format-ByteSize -Bytes $previousMaxSize) +
                '. If the host honours it, the records that no longer fit are discarded - and ' +
                'measured on Server 2019 it does not honour a shrink at all, so the likely outcome ' +
                'is that nothing changes and this rollback declines.')
    $arguments = Get-CreateJournalArgumentList -VolumePath $volumePath `
                     -MaxSize $previousMaxSize -AllocationDelta $previousDelta
    $result = Invoke-NativeCommand -FilePath $script:FsutilPath -Arguments $arguments
    if ($result.ExitCode -ne 0) {
        throw ('fsutil usn createjournal failed restoring ' + $volumePath + ': ' + ($result.Output -join ' '))
    }

    # A read-back that disagrees is a FAILED restore, and this used to print the
    # disagreement and then report success in the very next line - 'restored'
    # after saying the size had not been restored. An RMM would have been told
    # the host was back to baseline.
    #
    # MEASURED on the lab (Server 2019 17763), and it is why this is not a
    # transient: fsutil usn createjournal will NOT SHRINK a journal. From
    # maxsize 0x40000000, 'createjournal m=33554432 a=8388608' and then
    # 'm=67108864 a=16777216' both exited 0 and left Maximum Size, Allocation
    # Delta and First Usn completely unchanged. Microsoft says createjournal
    # "updates the change journal's maxsize and allocationdelta", which does not
    # say a smaller value is honoured - on this OS it is not.
    #
    # So ENLARGING a USN journal is effectively IRREVERSIBLE here, and the honest
    # answer is to say so once rather than send an operator round a retry loop
    # that cannot succeed. Nothing is lost by it: the journal is larger than it
    # was, which costs disk and keeps more history.
    $after = Get-UsnJournalState -VolumePath $volumePath
    if (-not $after.Readable) {
        # NOTHING WAS VERIFIED, so nothing is claimed. An unreadable read-back
        # used to fall straight through to the 'restored' line at the end of this
        # function, and that single 'restored' is what makes Get-RollbackRunStatus
        # return 'completed', which removes the run from the eligible set for
        # good. The apply side of this file already treats an unreadable
        # read-back as a finding rather than a success; the two halves have to
        # agree. Retryable, not permanent: Microsoft documents that a journal
        # being disabled answers every query with an error, and that state ends,
        # so a later -Rollback can still resolve this record.
        Write-Finding ($volumePath + ': the restore was issued but its result could not be read back,' +
                       ' so whether the journal is back at ' +
                       (Format-ByteSize -Bytes $previousMaxSize) + ' is unknown. Nothing is claimed' +
                       ' and this run stays rollback-eligible.')
        Write-Info ('fsutil said: ' + $after.Raw)
        return $script:RollbackDeclined
    }
    if ([long] $after.MaxSize -ne $previousMaxSize) {
        Write-Finding ($volumePath + ': NOT restored. The size reads back as ' +
                       (Format-ByteSize -Bytes $after.MaxSize) + ' rather than the ' +
                       (Format-ByteSize -Bytes $previousMaxSize) + ' recorded before this run. ' +
                       'fsutil usn createjournal does not shrink a journal - measured on Windows ' +
                       'Server 2019, a smaller maxsize exits 0 and changes nothing - so enlarging one ' +
                       'cannot be undone on this host. Retrying will not help. The journal is larger ' +
                       'than it was, which costs disk and keeps MORE history, not less.')
        # PERMANENT: fsutil will not shrink a journal on this OS, measured, so no
        # number of retries changes the outcome.
        return $script:RollbackDeclinedPermanent
    }
    if ([long] $after.AllocationDelta -ne $previousDelta) {
        # The delta goes onto the host in the same createjournal call and was
        # never checked, so a restore that put the size back and left the delta
        # enlarged reported 'restored' - half the recorded state resolved against
        # nothing. Permanent for the same measured reason as the size: in the lab
        # run quoted above, a smaller m= and a= exited 0 and left Maximum Size,
        # Allocation Delta and First Usn all unchanged.
        Write-Finding ($volumePath + ': the journal size is back at ' +
                       (Format-ByteSize -Bytes $after.MaxSize) + ' but the allocation delta reads back' +
                       ' as ' + (Format-ByteSize -Bytes $after.AllocationDelta) + ' rather than the ' +
                       (Format-ByteSize -Bytes $previousDelta) + ' recorded before this run. Measured on' +
                       ' Windows Server 2019, createjournal does not shrink either value, so this part' +
                       ' cannot be undone here and retrying will not help. The cost is disk space and' +
                       ' less frequent trimming, not lost history.')
        return $script:RollbackDeclinedPermanent
    }
    Write-Ok ('Restored the USN journal size and allocation delta on ' + $volumePath)
    return $script:RollbackRestored
}

#endregion

#region Checks -----------------------------------------------------------------

function Select-TargetVolumeList {
    # Which volumes this run may act on, with a printed reason for every one it
    # will not. "Skipped silently" is how a fleet ends up half hardened.
    #
    # The -Volume / -AllFixedVolumes mutual exclusion is enforced in the P-1
    # pre-flight block of Invoke-Main, not here. Throwing from this function put
    # the check after Enter-ToolkitLock and after Start-ManifestRun had already
    # appended a run record, so a pure argument error cost two manifest records
    # and was reported to the RMM as a host execution failure.
    $requested = $null
    if (-not $AllFixedVolumes) {
        if ($Volume) {
            $requested = $Volume.ToUpperInvariant()
        }
        else {
            $systemDrive = $env:SystemDrive
            if ([string]::IsNullOrWhiteSpace($systemDrive)) {
                throw 'SystemDrive is not set and no -Volume was given; refusing to guess a volume.'
            }
            $requested = $systemDrive.TrimEnd('\').ToUpperInvariant()
        }
    }

    $selected = New-Object System.Collections.ArrayList
    foreach ($candidate in Get-LetteredVolumeList) {
        if ($null -ne $requested -and $candidate.VolumePath -ne $requested) { continue }
        if ($candidate.DriveType -ne $script:DriveTypeLocalDisk) {
            Write-Info ($candidate.VolumePath + ' skipped: DriveType ' + [string] $candidate.DriveType +
                        ' is not a local fixed disk (3), so its journal is not an artifact this host owns')
            continue
        }
        if ($candidate.FileSystem -ne 'NTFS') {
            $fs = $candidate.FileSystem
            if ([string]::IsNullOrWhiteSpace($fs)) { $fs = '(none reported)' }
            Write-Info ($candidate.VolumePath + ' skipped: file system is ' + $fs +
                        ' - the USN change journal is an NTFS feature and does not exist elsewhere')
            continue
        }
        [void] $selected.Add($candidate)
    }

    if ($selected.Count -eq 0 -and $null -ne $requested) {
        Write-Finding ($requested + ' is not a fixed NTFS volume with a drive letter on this host,' +
                       ' so there is no journal to arm there')
    }
    return $selected.ToArray()
}

function Invoke-HostCheck {
    # Note the accumulation idiom, and copy it exactly. Never write
    # '$changed = $changed -or (...)': -or short-circuits, so once $changed is
    # $true every later call is NEVER MADE and the script silently stops
    # applying settings after the first one that worked.
    Write-Section 'Volume selection'
    $targets = Select-TargetVolumeList
    if ($targets.Count -eq 0) { return 0 }
    Write-Info ([string] $targets.Count + ' fixed NTFS volume(s) selected')

    $changeCount = 0
    foreach ($target in $targets) {
        Write-Section ('USN journal on ' + $target.VolumePath)
        $state = Get-UsnJournalState -VolumePath $target.VolumePath

        if ($state.Readable) {
            Write-Info ('current: max ' + (Format-ByteSize -Bytes $state.MaxSize) +
                        ', allocation delta ' + (Format-ByteSize -Bytes $state.AllocationDelta))
        }
        elseif ($state.JournalActive) {
            Write-Info ('fsutil returned journal data that could not be parsed: ' + $state.Raw)
        }
        else {
            Write-Info ('fsutil usn queryjournal ' + $target.VolumePath + ' exited ' +
                        [string] $state.ExitCode + ', so the journal state here is UNKNOWN - not ' +
                        'proven absent: ' + $state.Raw)
        }

        $rate = $null
        if ($MeasureChangeRateSeconds -gt 0 -and $state.Readable) {
            Write-Info ('sampling the change rate for ' + [string] $MeasureChangeRateSeconds + 's...')
            $rate = Measure-UsnChangeRate -VolumePath $target.VolumePath -Seconds $MeasureChangeRateSeconds
        }
        Write-UsnRetentionReport -State $state -Rate $rate

        if (Set-TrackedUsnJournal -VolumeInfo $target -State $state `
                -TargetMaxSize $MaxSizeBytes -TargetAllocationDelta $AllocationDeltaBytes) {
            $changeCount++
        }
    }
    return $changeCount
}

#endregion

#region Main -----------------------------------------------------------------

function Restore-UsnChange {
    <#
        Routes a change record to the right restorer. The template's
        Restore-TrackedChange only knows 'registry' and declines anything else -
        correctly, since silently "succeeding" on a change type it cannot undo is
        how a run gets marked rolled back while the host stays modified. This
        script introduces 'usnjournal', so it handles that one here and delegates
        the rest.

        Returns 'restored' or 'declined'; throws on failure.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    if ($ChangeRecord.change.type -ne 'usnjournal') {
        return (Restore-TrackedChange -ChangeRecord $ChangeRecord)
    }
    return (Restore-UsnJournalChange -ChangeRecord $ChangeRecord)
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
    Assert-ParameterPattern -Name 'Volume' -Value $Volume -Pattern '^[A-Za-z]:$' `
        -Describe 'a drive letter followed by a colon, for example C:'
    Assert-ParameterRange   -Name 'MaxSizeBytes' -Value $MaxSizeBytes -Minimum 16777216 -Maximum 137438953472
    Assert-ParameterRange   -Name 'AllocationDeltaBytes' -Value $AllocationDeltaBytes -Minimum 1048576 -Maximum 17179869184
    Assert-ParameterRange   -Name 'MaxFreeSpaceFraction' -Value $MaxFreeSpaceFraction -Minimum 0.01 -Maximum 0.90
    Assert-ParameterRange   -Name 'MeasureChangeRateSeconds' -Value $MeasureChangeRateSeconds -Minimum 0 -Maximum 3600
    # Mutual exclusion cannot be expressed in the param block: -Volume and
    # -AllFixedVolumes sit outside the mode parameter sets, so PowerShell binds
    # both happily. Checked here with the other value checks so a bad argument
    # costs nothing - no lock, no manifest record, no host access.
    if ($AllFixedVolumes -and $Volume) {
        throw 'Use either -Volume or -AllFixedVolumes, not both. Nothing was read or changed.'
    }

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        [void] (Invoke-HostCheck)
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
        Write-Ok 'No findings: every selected volume has a journal at or above the size floor.'
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
                volume                   = $Volume
                allFixedVolumes          = [bool] $AllFixedVolumes
                maxSizeBytes             = $MaxSizeBytes.ToString([System.Globalization.CultureInfo]::InvariantCulture)
                allocationDeltaBytes     = $AllocationDeltaBytes.ToString([System.Globalization.CultureInfo]::InvariantCulture)
                maxFreeSpaceFraction     = $MaxFreeSpaceFraction
                measureChangeRateSeconds = $MeasureChangeRateSeconds
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
            Write-Info 'No reboot is needed: createjournal updates an active journal in place.'
            Write-Info 'The journal starts from now - it does NOT retroactively record what was'
            Write-Info 'renamed or deleted before this run.'
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
                $outcome = Restore-UsnChange -ChangeRecord $target.Changes[$i]
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
            Write-Info ([string] $declinedPermanent + ' change(s) cannot be undone by this toolkit and never will be. Read the finding(s) above for')
            Write-Info 'which and why. Two of the cases are designed outcomes rather than malfunctions:'
            Write-Info 'a journal this run CREATED is never deleted, because it now holds real history;'
            Write-Info 'and a journal this run ENLARGED cannot be shrunk back, because fsutil does not'
            Write-Info 'shrink. Neither is retryable into success - the host is simply left with more'
            Write-Info 'forensic history than it started with.'
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
