<#
.SYNOPSIS
Registers the scheduled task that takes VSS snapshots, and nothing else.

.DESCRIPTION
Split out of Enable-VssPreservation on 2026-09-07. That script did two jobs:
it arranged the shadow storage association a snapshot needs, and it registered
the task that takes them. docs/AUTHORING.md's own test - more than 700 lines of
script-specific logic means the script is doing two jobs - was met literally.

This half owns the task. Enable-VssPreservation still owns the shadow storage
association, and it MUST run first: a snapshot with no storage area fails.
docs/DEPLOYMENT.md carries the order.

WHAT THE SPLIT DID NOT MOVE. Enable-VssPreservation keeps its 'scheduledtask'
rollback branch and the shared restorer, because a host armed before the split
holds a run whose records include BOTH a shadowstorage and a scheduledtask
change under that script's name. Taking the branch away would have left those
records declined-retryable forever - the run never leaves the eligible set, so
-Rollback selects it again on every run and never converges, which is exactly
the R-1 defect docs/DESIGN.md section 4.1 was written to remove. A script has to
be able to undo what it applied, including under its old shape.

.PARAMETER Audit
Default. Strictly read-only. Reports whether the task exists, what it is
scheduled to do, and what -Apply would change.

.PARAMETER Apply
Registers the task and writes the handler script, recording both to the manifest
first.

.PARAMETER Rollback
Unregisters the task this script registered. The handler script is left on disk:
it is a toolkit-owned file under the toolkit root, it holds no state, and
removing it would delete something a later -Apply has to write again.

.PARAMETER ToolkitRoot
Base directory for the manifest and the handler script. Default
C:\ProgramData\IronBlackBox. Validated before use - see Assert-SafeToolkitPath.

.PARAMETER Volume
The volume to snapshot. Empty means the system volume. Stamped into the handler
script, so it is resolved and validated before anything is written.

.PARAMETER SnapshotTimes
Times of day, 24-hour HH:mm, one trigger each. Default 06:30 and 18:30.

.PARAMETER SnapshotRandomDelayMinutes
Random delay added to each trigger, so a fleet armed by one RMM policy does not
ask every host for a snapshot in the same second. 0 disables it.

.PARAMETER RunId
-Rollback only. The run to roll back. Defaults to the most recent
rollback-eligible run for this script.

.PARAMETER AbandonRun
-Rollback only. Marks a run abandoned when every remaining change is
permanently un-undoable. See docs/DESIGN.md section 4.2.

.EXAMPLE
.\Enable-VssSnapshotSchedule.ps1
Reports the current schedule. Changes nothing.

.EXAMPLE
.\Enable-VssSnapshotSchedule.ps1 -Apply -SnapshotTimes '07:00','19:00'
Registers the task with two daily triggers.

.EXAMPLE
.\Enable-VssSnapshotSchedule.ps1 -Rollback
Unregisters the task, leaving the handler script and every existing snapshot.

.NOTES
Author  : Secur01
Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
Version : 1.1.0
License : MIT

Windows PowerShell 5.1, in-box modules only. Requires local administrator;
enforced in code by Assert-Elevated.

This script does NOT create a snapshot itself and does not verify that one was
ever taken. Enable-VssPreservation reports the shadow copies that exist; a task
that is registered is not a snapshot that happened, and only the event log and
that report can tell them apart.
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
    [AllowEmptyString()]
    [string] $Volume = '',
    [Parameter()]
    [string[]] $SnapshotTimes = @('06:30', '18:30'),
    [Parameter()]
    [int] $SnapshotRandomDelayMinutes = 15,
    [Parameter(ParameterSetName = 'Rollback')]
    [string] $RunId,
    [Parameter(ParameterSetName = 'Rollback')]
    [string] $AbandonRun
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0
$script:SuppliedParameter = $PSBoundParameters
$script:ScriptName    = 'Enable-VssSnapshotSchedule'
$script:ScriptVersion = '1.1.0'
$script:ManifestPath = $null
$script:CurrentRunId        = $null
$script:ChangeIndex  = 0
$script:Findings     = New-Object System.Collections.ArrayList
$script:HostLimits   = New-Object System.Collections.ArrayList
$script:LockHandle   = $null

# Registry: this script writes no registry value, so it carries no registry
# restorer and declares no owned key. Restore-TrackedChange refuses any registry
# record on an empty list, which is the behaviour wanted here - a planted
# registry change must not become a write.
$script:OwnedRegistryKey = @()

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

#region VSS volume [shared] --------------------------------------------------

# Shared by the two halves of the VSS split, and marked [shared] so
# tools/check.ps1 compares the copies. Both have to agree on what "the volume"
# means: Enable-VssPreservation arranges shadow storage for it,
# Enable-VssSnapshotSchedule stamps it into the handler script, and a
# disagreement would arm a snapshot of one volume against storage for another.
#
# Named both ways round on purpose. The first version of this comment said "this
# one" and "that one", so the two copies read as mirror images and differed - and
# the gate caught it, which is the whole point of marking the region.

function Resolve-VolumeRoot {
    <#
        Defaults to the volume holding %SystemRoot% - the same derivation
        Invoke-TriageCollection uses for its shadow copy, so it is already
        exercised on the lab.

        An explicit -Volume must be a DRIVE LETTER root. That is a real
        restriction and it is deliberate: everything below correlates volumes
        through Win32_Volume.DriveLetter, so a \\?\Volume{guid}\ path or a
        mount point would find no association and this script would report
        "unknown" rather than configure anything. Rejecting it here says so
        plainly instead of failing three functions later.
    #>
    param([Parameter()][AllowEmptyString()][string] $Requested)

    if ([string]::IsNullOrWhiteSpace($Requested)) {
        return ([System.IO.Path]::GetPathRoot($env:SystemRoot))
    }
    $candidate = $Requested.Trim().TrimEnd('\')
    if ($candidate -match '^[A-Za-z]$') { $candidate = $candidate + ':' }
    if ($candidate -notmatch '^[A-Za-z]:$') {
        throw ('-Volume must be a local drive root such as "C:\", got: ' + $Requested)
    }
    return ($candidate + '\')
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

#region Snapshot task -------------------------------------------------------

$script:TaskFolderPath   = '\IronBlackBox\'
$script:SnapshotTaskName = 'IronBlackBox-VssSnapshot'

$script:SnapshotHandlerTemplate = @'
<#
    Generated by IronBlackBox Enable-VssSnapshotSchedule. -Rollback removes the TASK
    and deliberately leaves this FILE alone: it is inert without the task, and an
    operator may have edited it.

    This handler only ever CREATES a shadow copy. It never deletes one, never
    resizes shadow storage, and never invokes vssadmin - because a task running
    as SYSTEM should do the smallest possible thing, and because a handler that
    ran a destruction command would be indistinguishable, in event 4688, from the
    attack Deploy-TamperAlerts exists to detect.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0
$logPath = Join-Path $PSScriptRoot 'vss-snapshot.log'

function Write-HandlerLine {
    param([Parameter()][AllowEmptyString()][string] $Text = '')
    $stamp = (Get-Date).ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
    try {
        if (Test-Path -LiteralPath $logPath) {
            # Rotate at 2 MB so an unattended task cannot grow a log without bound.
            if ((Get-Item -LiteralPath $logPath).Length -gt 2097152) {
                Move-Item -LiteralPath $logPath -Destination ($logPath + '.old') -Force
            }
        }
        [System.IO.File]::AppendAllText($logPath, ($stamp + ' ' + $Text + "`r`n"),
            (New-Object System.Text.UTF8Encoding($false)))
    }
    catch { Write-Verbose ('Could not append to ' + $logPath + ': ' + $_.Exception.Message) }
}

try {
    $volume = '@@VOLUME@@'
    $result = Invoke-CimMethod -CimClass (Get-CimClass -ClassName Win32_ShadowCopy) `
        -MethodName Create -Arguments @{ Volume = $volume; Context = 'ClientAccessible' }
    if ($result.ReturnValue -ne 0) {
        Write-HandlerLine ('FAILED to snapshot ' + $volume + ': Win32_ShadowCopy.Create returned ' +
                           [string] $result.ReturnValue)
        exit 1
    }
    Write-HandlerLine ('created shadow copy ' + [string] $result.ShadowID + ' of ' + $volume)
    exit 0
}
catch {
    Write-HandlerLine ('ERROR snapshotting: ' + $_.Exception.Message)
    exit 2
}
'@

function Get-SnapshotHandlerScriptText {
    <#
        The handler's intended content for one volume, computed in ONE place so
        that the function which writes it and the check which compares a deployed
        copy against it cannot disagree. Same reason Deploy-TamperAlerts has
        Get-HandlerScriptText.
    #>
    param([Parameter(Mandatory = $true)][string] $VolumeRoot)
    return $script:SnapshotHandlerTemplate.Replace('@@VOLUME@@', $VolumeRoot)
}

function Get-DeployedHandlerVolume {
    <#
        The volume a deployed handler was written for, or '' when it cannot be
        read out. The handler stamps it into a single-quoted assignment, which is
        what this reads back.

        It exists so that "the handler differs" can be told apart from "the
        handler is for a different volume" - two conditions with opposite
        correct answers, and treating them alike would silently re-point a
        client's snapshot task at another disk.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $HandlerText)
    # SINGLE-quoted deliberately. In a double-quoted PowerShell string a
    # backslash escapes nothing, so '\$volume' interpolates the variable
    # $volume - empty here - and the pattern silently degrades to
    # ^\s*\s*=\s*'...', which matches the FIRST quoted assignment in the
    # handler instead of the volume one. Single quotes take the text as written.
    $found = [regex]::Match($HandlerText, '(?m)^\s*\$volume\s*=\s*''([^'']*)''')
    if ($found.Success) { return [string] $found.Groups[1].Value }
    return ''
}

function New-SnapshotHandlerScript {
    <#
        Writes the handler under the toolkit root. The directory inherits the
        root's DACL - SYSTEM and Administrators only, inheritance disabled - so no
        extra grant is made: docs/DESIGN.md section 5 wants an explicit narrow
        grant only for a subdirectory needing WIDER access, and this one needs
        none.

        UTF-8 WITH a BOM, for the reason every .ps1 in this repository has one:
        Windows PowerShell 5.1 reads a BOM-less UTF-8 file as ANSI.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [Parameter(Mandatory = $true)][string] $VolumeRoot
    )
    if (-not (Test-Path -LiteralPath $Directory)) {
        [void] (New-Item -Path $Directory -ItemType Directory -Force)
    }
    $path = [System.IO.Path]::Combine($Directory, 'New-VssSnapshot.ps1')
    [System.IO.File]::WriteAllText($path, (Get-SnapshotHandlerScriptText -VolumeRoot $VolumeRoot),
        (New-Object System.Text.UTF8Encoding($true)))
    return $path
}

function ConvertTo-DailyTriggerTime {
    <#
        'HH:mm' to a DateTime for -At. InvariantCulture and an ESCAPED colon, both
        deliberate: in a CUSTOM .NET format string ':' is the culture's time
        separator placeholder - the trap AUTHORING.md records for Get-UtcStamp -
        so on fi-FI 'HH:mm' would parse against '.' instead. 'HH\:mm' pins the
        literal character.
        https://learn.microsoft.com/en-us/dotnet/standard/base-types/custom-date-and-time-format-strings
    #>
    param([Parameter(Mandatory = $true)][string] $Text)

    $parsed = [datetime]::MinValue
    $ok = [datetime]::TryParseExact($Text.Trim(), 'HH\:mm',
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::None, [ref] $parsed)
    if (-not $ok) { throw ('-SnapshotTimes entries must be 24-hour HH:mm, got: ' + $Text) }
    return $parsed
}

function Register-TrackedSnapshotTask {
    # Registers the snapshot task, recording it in the manifest first. Returns the
    # number of changes made (0 or 1).
    param(
        [Parameter(Mandatory = $true)][string] $HandlerDirectory,
        [Parameter(Mandatory = $true)][string] $VolumeRoot
    )

    Write-Section 'Scheduled snapshot task'
    $taskPath = $script:TaskFolderPath
    $taskName = $script:SnapshotTaskName
    # The jitter is named in the label because the operator reading an RMM log has
    # to be able to tell a snapshot that ran at 06:41 from one that ran late.
    $schedule = ($SnapshotTimes -join ', ')
    if ($SnapshotRandomDelayMinutes -gt 0) {
        $schedule = ($schedule + ' plus up to ' + [string] $SnapshotRandomDelayMinutes +
                     ' min random delay')
    }
    $label = ('scheduled snapshot task ' + $taskPath + $taskName + ' at ' + $schedule)

    $existing = Get-ToolkitScheduledTask -TaskPath $taskPath -TaskName $taskName
    if ($null -ne $existing) {
        # Idempotence and a refusal at once: an existing task is NEVER overwritten.
        # Register-ScheduledTask -Force is used nowhere in this script - it would
        # silently replace a task somebody else owns, which is the same defect as
        # deleting one.
        Write-Ok ($label + ' - already registered (state ' + [string] $existing.State + ')')

        # STATE IS TESTED, NOT JUST PRINTED.
        #
        # This line used to read `[ ok ] ... already registered (state Disabled)`
        # and stop there. A disabled scheduled task never fires, so no snapshot
        # was ever taken while the script reported success - the state string was
        # in the output for a human to notice, which is not the same as checking
        # it. One `schtasks /change /disable` turned the snapshots off and left a
        # green run behind it.
        #
        # Reported rather than re-enabled, in both modes, for the reason this
        # branch never overwrites a task: an operator may have disabled it for
        # maintenance, and a toolkit that silently re-enables it is fighting the
        # person running it. The finding names the command, so the lever is
        # explicit and exit 1 clears as soon as it is pulled.
        $taskState = [string] $existing.State
        if ($taskState -eq 'Disabled') {
            Write-Finding ($label + ' exists but is DISABLED, so it never fires and no scheduled snapshot is ever taken. ' +
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

        # AT-12, ported from Deploy-TamperAlerts: THE TASK EXISTING DOES NOT MEAN
        # THE HANDLER ON DISK IS CURRENT.
        #
        # This branch used to return here. So a toolkit update that changed the
        # handler template never reached an armed host: the task existed, the
        # script said "already registered", and the OLD handler went on running
        # until somebody did a full -Rollback then -Apply. The sibling script
        # learned this and this one did not, which is how a fix lands in one copy
        # of a pattern and not the other. Found 2026-09-08, when correcting the
        # handler's header - a correction that would have reached no armed host.
        $handlerPath = [System.IO.Path]::Combine($HandlerDirectory, 'New-VssSnapshot.ps1')
        $intended = Get-SnapshotHandlerScriptText -VolumeRoot $VolumeRoot
        $current = ''
        if (Test-Path -LiteralPath $handlerPath) {
            try { $current = [System.IO.File]::ReadAllText($handlerPath) } catch { $current = '' }
        }
        if ($current -eq $intended) {
            Write-Info ('handler ' + $handlerPath + ' matches this toolkit version')
            return 0
        }

        # A DIFFERENT VOLUME IS NOT VERSION DRIFT, and must not be rewritten.
        #
        # The volume is stamped INTO the handler, and the registered task's
        # description names it too. Rewriting the handler for a new volume would
        # re-point what gets snapshotted while leaving a task that says otherwise
        # - a silent change of target on a client's host, which is the same class
        # of act as Register-ScheduledTask -Force, refused everywhere else in this
        # script. So it is reported and left alone, in both modes.
        $deployedVolume = Get-DeployedHandlerVolume -HandlerText $current
        if (-not [string]::IsNullOrEmpty($deployedVolume) -and
            -not $deployedVolume.Equals($VolumeRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Finding ('the deployed handler ' + $handlerPath + ' snapshots ' + $deployedVolume +
                           ' and this run resolved ' + $VolumeRoot + '. That is a change of TARGET, not ' +
                           'a toolkit update, so nothing was rewritten: the registered task names the ' +
                           'old volume and re-pointing the handler under it would change what is ' +
                           'snapshotted without changing what the task says. Run -Rollback and then ' +
                           '-Apply with the volume you want.')
            return 0
        }

        if (-not $Apply) {
            Write-Finding ('the deployed handler ' + $handlerPath + ' differs from this toolkit ' +
                           'version''s template - it would be rewritten on -Apply')
            return 0
        }
        [void] (New-SnapshotHandlerScript -Directory $HandlerDirectory -VolumeRoot $VolumeRoot)
        Write-Ok ('handler ' + $handlerPath + ' was out of date and has been rewritten to match ' +
                  'this toolkit version')
        # 0, not 1: no manifest record is written for this. Invoke-Main compares
        # the returned count against $script:ChangeIndex, so returning 1 would
        # make 'applied' exceed 'recorded' and print "A change without a record
        # cannot be rolled back; treat this host as modified and investigate" on
        # every armed host at the first -Apply after a template edit. Nothing
        # changed but a toolkit-owned derived file, which the line above states.
        return 0
    }

    # Everything that can fail is validated BEFORE the manifest record goes down,
    # so a refusal does not leave an intent record for a change never attempted.
    $triggerTimes = New-Object System.Collections.ArrayList
    foreach ($entry in $SnapshotTimes) {
        [void] $triggerTimes.Add((ConvertTo-DailyTriggerTime -Text $entry))
    }
    if ($triggerTimes.Count -eq 0) {
        Write-Finding '-SnapshotTimes is empty, so there is no schedule to register.'
        return 0
    }
    $hostPath = Get-PowerShellHostPath
    if (-not (Test-Path -LiteralPath $hostPath)) {
        Write-Finding ('Windows PowerShell was not found at ' + $hostPath +
                       '; no task registered and nothing changed.')
        return 0
    }
    if (-not $Apply) {
        Write-Finding ($label + ' - would register, running the handler as SYSTEM')
        return 0
    }

    $handlerPath = New-SnapshotHandlerScript -Directory $HandlerDirectory -VolumeRoot $VolumeRoot
    $marker = New-TaskMarker

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
    # -NonInteractive and -NoProfile because it runs as SYSTEM with no profile and
    # nobody to answer a prompt.
    $action = New-ScheduledTaskAction -Execute $hostPath `
        -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $handlerPath + '"')

    # -RandomDelay, because a fixed wall-clock trigger is a FLEET hazard even when
    # it is a sensible time on one host: every endpoint deployed with the defaults
    # would call Win32_ShadowCopy.Create at the same second, and on a virtualised
    # estate sharing a datastore that is a storage I/O spike this toolkit caused.
    # Passed only when non-zero: 0 means "exactly at the time given", and adding a
    # zero TimeSpan to say that would be asserting behaviour Microsoft does not
    # document for it.
    $triggers = New-Object System.Collections.ArrayList
    foreach ($when in $triggerTimes) {
        if ($SnapshotRandomDelayMinutes -gt 0) {
            [void] $triggers.Add((New-ScheduledTaskTrigger -Daily -At $when `
                -RandomDelay (New-TimeSpan -Minutes $SnapshotRandomDelayMinutes)))
        }
        else {
            [void] $triggers.Add((New-ScheduledTaskTrigger -Daily -At $when))
        }
    }

    # S-1-5-18 rather than a name, because 'NT AUTHORITY\SYSTEM' is localised and
    # AUTHORING.md says to address principals by SID.
    # # UNVERIFIED: Microsoft documents neither -UserId's accepted formats nor
    # # that a SID is one of them. The only indirect acknowledgement is
    # # Register-ScheduledTask's -Password note that "the well-known security
    # # identifiers (SIDs) for all three accounts" count as well-known system
    # # accounts. What actually landed is READ BACK and printed below.
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest

    # Both battery parameters are needed: the documented defaults are to refuse to
    # start and to stop when a host goes onto battery, which on a laptop or a
    # UPS-backed server silently skips the snapshot at exactly the wrong moment.
    # There is no -DisallowStartIfOnBatteries; the positive form is the only one.
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    [void] (Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action `
        -Trigger @($triggers.ToArray()) -Principal $principal -Settings $settings `
        -Description ('IronBlackBox ' + $script:ScriptName + ' v' + $script:ScriptVersion +
                      ' - creates a VSS shadow copy of ' + $VolumeRoot + '. Marker: ' + $marker))

    $confirmed = Get-ToolkitScheduledTask -TaskPath $taskPath -TaskName $taskName
    if ($null -eq $confirmed) {
        throw ('Register-ScheduledTask returned without error but ' + $taskPath + $taskName +
               ' cannot be read back.')
    }
    Write-Ok ($label + ' - registered')
    Write-Info ('handler: ' + $handlerPath)
    # Printed rather than asserted: this is how the SID-as-UserId question above
    # gets answered by the host instead of by a comment.
    if ($null -ne $confirmed.Principal) {
        Write-Info ('principal as registered: UserId=' + [string] $confirmed.Principal.UserId +
                    ' LogonType=' + [string] $confirmed.Principal.LogonType +
                    ' RunLevel=' + [string] $confirmed.Principal.RunLevel)
    }
    return 1
}

function Write-SnapshotReport {
    <#
        What is armed, and what this script cannot answer.

        THE DEPENDENCY IS STATED AND NOT MEASURED. A snapshot needs a shadow
        storage association on the volume; without one the task runs on schedule
        and every snapshot fails, which looks like nothing at all in an audit that
        only reads the task. Measuring it here would mean a second copy of
        Enable-VssPreservation's storage logic, and two copies of a measurement is
        how they come to disagree. So this names the script that owns the answer
        instead of guessing at it.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $VolumeRoot,
        [Parameter(Mandatory = $true)][bool] $TaskExists
    )

    Write-Section 'Snapshot schedule'
    Write-Info ('target volume: ' + $VolumeRoot)
    $schedule = ($SnapshotTimes -join ', ')
    if ($SnapshotRandomDelayMinutes -gt 0) {
        $schedule = ($schedule + ' plus up to ' + [string] $SnapshotRandomDelayMinutes +
                     ' minute(s) of random delay')
    }
    if ($TaskExists) {
        Write-Ok ($script:TaskFolderPath + $script:SnapshotTaskName + ' is registered')
    }
    else {
        Write-Info ($script:TaskFolderPath + $script:SnapshotTaskName + ' is not registered')
    }
    Write-Info ('requested schedule: ' + $schedule)

    Write-Section 'What this script does not check'
    Write-Info 'A snapshot needs a shadow storage association on the target volume. This script'
    Write-Info 'does not read one, so a registered task here is not a snapshot that will succeed:'
    Write-Info 'run Enable-VssPreservation, which owns that association and reports the shadow'
    Write-Info 'copies that actually exist. Arm it FIRST - see docs/DEPLOYMENT.md.'
}

function Invoke-HostCheck {
    param([Parameter(Mandatory = $true)][string] $HandlerDirectory)

    # Resolved before anything is written, because the volume is stamped INTO the
    # handler script: a task registered against an unresolvable volume is a task
    # that fails every night while looking correctly configured.
    $volumeRoot = Resolve-VolumeRoot -Requested $Volume
    $taskExists = ($null -ne (Get-ToolkitScheduledTask -TaskPath $script:TaskFolderPath `
        -TaskName $script:SnapshotTaskName))

    Write-SnapshotReport -VolumeRoot $volumeRoot -TaskExists $taskExists

    return (Register-TrackedSnapshotTask -HandlerDirectory $HandlerDirectory -VolumeRoot $volumeRoot)
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
    Assert-ParameterNotEmpty -Name 'SnapshotTimes' -Value $SnapshotTimes
    # THE SHAPE, checked here and not only where it is parsed.
    # ConvertTo-DailyTriggerTime rejects a bad time too, but it runs inside
    # Register-TrackedSnapshotTask - after the handler script has been written and
    # a change recorded. A mistyped time must cost nothing, which is what this
    # region is for. Leading and trailing whitespace stays acceptable because the
    # parser Trim()s.
    #
    # Worth keeping the original bite on the record: before the 2026-09-07 split
    # this logic lived in Enable-VssPreservation, where the parse ran AFTER the
    # shadow storage area had been recorded, resized and read back. So
    # '-Apply -SnapshotTimes 6:30pm' resized a client's shadow storage, printed
    # [ ok ], then threw on the time string and reported exit 2 with no task
    # registered. This script no longer touches shadow storage, but the ordering
    # rule that came out of it is why the check is up here.
    Assert-ParameterPattern -Name 'SnapshotTimes' -Value $SnapshotTimes `
        -Pattern '^\s*([01]\d|2[0-3]):[0-5]\d\s*$' -Describe '24-hour HH:mm (two-digit hour, e.g. 06:30)'
    # 0 is meaningful (fire exactly on time) and 240 is already wider than any
    # fleet needs; past that the delay competes with the next trigger rather than
    # smoothing this one.
    Assert-ParameterRange   -Name 'SnapshotRandomDelayMinutes' -Value $SnapshotRandomDelayMinutes `
        -Minimum 0 -Maximum 240

    # -RunId and -AbandonRun BOTH name a run, and the rollback path below resolves
    # one target. It used to resolve -RunId and then overwrite it from -AbandonRun,
    # so '-Rollback -RunId A -AbandonRun B' discarded A without a word. Abandoning
    # naming its run is the first of the four properties docs/DESIGN.md section 4.2
    # relies on, so two different run ids is refused rather than silently resolved
    # in favour of one. The same id twice is redundant, not ambiguous, and passes.
    if (-not [string]::IsNullOrWhiteSpace($RunId) -and
        -not [string]::IsNullOrWhiteSpace($AbandonRun) -and $RunId -ne $AbandonRun) {
        throw ('-RunId names ' + $RunId + ' and -AbandonRun names ' + $AbandonRun +
               ', which are two different runs. Give one run id. Nothing was read or changed.')
    }

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')
    $handlerDirectory = [System.IO.Path]::Combine($resolvedRoot, 'vss')

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        [void] (Invoke-HostCheck -HandlerDirectory $handlerDirectory)
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
        # Scoped to what was actually read. The pre-split wording said "shadow
        # storage and the snapshot task are configured", and this script does not
        # read shadow storage at all - the section above says so in as many words,
        # and then the verdict line contradicted it. A task armed over a volume
        # with no storage association runs on schedule and fails every night, so
        # "no findings" here is exactly the case where the distinction matters.
        Write-Ok ('No findings: the snapshot task is registered as this script would register ' +
                  'it. Whether a snapshot can actually SUCCEED was NOT checked here - that ' +
                  'needs a shadow storage association on the target volume, which ' +
                  'Enable-VssPreservation owns and reports.')
        return 0
    }

    Enter-ToolkitLock -ToolkitRootPath $resolvedRoot
    try {
        $allowMissingStamp = ($mode -eq 'Rollback')
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -AllowMissingStamp:$allowMissingStamp)
        Assert-ManifestUsable

        if ($mode -eq 'Apply') {
            [void] (Start-ManifestRun -Mode 'Apply' -Parameters @{
                toolkitRoot            = $resolvedRoot
                volume                 = $Volume
                snapshotTimes          = @($SnapshotTimes)
                snapshotRandomDelayMinutes = $SnapshotRandomDelayMinutes
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
            try { $verified = Invoke-HostCheck -HandlerDirectory $handlerDirectory }
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

        # One resolution, one target. -AbandonRun names the run it abandons, so it
        # IS the explicit run id when it is supplied; the P-1 check above has
        # already refused a command line where the two name different runs.
        $explicitRunId = $RunId
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun)) { $explicitRunId = $AbandonRun }
        $target = Get-RollbackTargetRun -ExplicitRunId $explicitRunId
        if ($null -eq $target) {
            Write-Section 'Result'
            Write-Info 'Nothing to roll back: no eligible run for this script in the manifest.'
            return 0
        }

        Write-Section ('Rolling back run ' + $target.RunId)
        [void] (Start-ManifestRun -Mode 'Rollback' -Parameters @{
            targetRunId = $target.RunId
        })
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
                # One type, routed explicitly. Anything else is declined by name
                # rather than handed to a restorer that does not understand it -
                # including a 'shadowstorage' record, which belongs to
                # Enable-VssPreservation and is that script's to undo.
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
            Write-Info ([string] $declinedPermanent + ' change(s) cannot be undone by this toolkit and never will be. The run stays retryable.')
            Write-Info 'A declined shadow storage resize is usually the right answer - read the finding.'
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
