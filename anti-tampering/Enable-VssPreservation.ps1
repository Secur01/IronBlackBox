<#
.SYNOPSIS
    Gives VSS dedicated shadow storage, and refuses to do it if that would fill
    the volume.

.DESCRIPTION
    ONE change, reversible, recorded in the manifest before it is made:

    SHADOW STORAGE. Sets the maximum size of the shadow copy storage area on a
    volume to a percentage of that volume (-ShadowStoragePercent). Without a
    deliberate allocation, VSS recycles snapshots as soon as the default area
    fills and the point-in-time copy a responder needs is gone.

    THE SCHEDULED SNAPSHOT IS A DIFFERENT SCRIPT. Until 2026-09-07 this script
    also registered the SYSTEM task that creates the shadow copies, under
    -SnapshotTimes and -SnapshotRandomDelayMinutes. Both the task and those
    parameters now belong to Enable-VssSnapshotSchedule, and storage is arranged
    BEFORE the task that writes into it - see docs/DEPLOYMENT.md section 3.

    An allocated storage area with no task is inert but harmless: it holds
    whatever snapshots something else creates. A task with no storage area is
    the harmful order, which is why the ordering runs this way round.

    THE FREE-SPACE GUARD IS A HARD RULE. Raising the shadow storage maximum is a
    licence for VSS to consume that much of the volume, later, when nobody is
    watching. A hardening script that fills a client's system volume has caused
    an outage, not prevented one. Before resizing, this script computes the worst
    case - the area growing all the way to its new maximum - and REFUSES if that
    would leave less than -MinimumFreeDiskPercent free. The arithmetic is printed
    so the operator can check it; see Test-ShadowStorageHeadroom.

    WHAT THIS CANNOT DO, and it is the most important sentence here: it does not
    and cannot prevent 'vssadmin delete shadows'. No shadow storage
    configuration stops an administrator, or ransomware running as one, from
    destroying every snapshot on the host in one command. What this script buys
    is a snapshot worth deleting; Deploy-TamperAlerts is what makes the deletion
    a DETECTED event instead of a silent success. The two are complementary and
    neither replaces the other - and neither is a substitute for off-host
    backups.

    ROLLBACK IS DELIBERATELY CAUTIOUS. Shrinking shadow storage back can DELETE
    the shadow copies it holds - Microsoft warns exactly this: "Resizing the
    storage association may cause shadow copies to disappear."
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-resize-shadowstorage
    Those snapshots may be the client's only recovery point, and some of them
    were probably taken after this toolkit ran. So -Rollback reports the
    situation as a finding and DECLINES the shrink while shadow copies exist,
    unless -ForceShrink is passed. A declined change keeps the run retryable,
    which is right for a decision a human still has to make. The same guard
    applies to -Apply, because a percentage smaller than what the host already
    has set is a shrink too.

    NOT IMPLEMENTED, deliberately:
      - Removing a shadow storage association. 'vssadmin delete shadowstorage'
        is not in Microsoft's documented command set and removing an association
        discards the snapshots in it. If this run CREATED the association,
        -Rollback says so and leaves it.
      - Changing the VSS service start type. A disabled VSS service is reported
        as a finding, not repaired: enabling a service is a different change with
        a different rollback and belongs in its own script.
      - Deleting shadow copies. This script never deletes a snapshot. VSS
        recycles the oldest itself, capped by MaxShadowCopies (default 64).
        https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore
      - Removing the handler script on -Rollback. It is inert once the task is
        gone and an operator may have edited it.

.PARAMETER Audit
    Default. Strictly read-only. Reports shadow storage, existing shadow copies,
    the VSS service state, free space, and whether the snapshot task exists.

.PARAMETER Apply
    Sets shadow storage, recording the change to the manifest first. It does NOT
    register the snapshot task any more - Enable-VssSnapshotSchedule does, and
    this run reports the task's absence as a finding rather than fixing it.

.PARAMETER Rollback
    Restores the previous shadow storage maximum.

    It also still removes a snapshot task recorded by THIS script, and that
    branch is deliberate rather than left over: a host armed before 2026-09-07
    carries a 'scheduledtask' record under this script's name, and dropping the
    branch would strand that host with a task no script would undo. Nothing this
    version registers writes such a record, so on a host armed after the split
    the branch simply never fires.

.PARAMETER ToolkitRoot
    Base directory for the manifest. A snapshot handler written by a pre-split
    run may also live here; this version writes none.
    Default C:\ProgramData\IronBlackBox. Validated before use.

.PARAMETER Volume
    Volume to configure, as a path root such as 'C:\'. Defaults to the volume
    holding %SystemRoot%.

.PARAMETER ShadowStoragePercent
    Shadow storage maximum, as a percentage of the volume. Default 12.

    12 is a judgement, not a Microsoft recommendation - no Microsoft page
    recommends a percentage, so this is the toolkit's own number and is stated as
    such. It is the midpoint of the 10-15% band that leaves a useful number of
    snapshots on a typical MSP file or application server while leaving 88% of
    the volume to the workload. Below roughly 10% a busy server's write churn
    overruns the area within a day or two; above roughly 15% the allocation
    competes with the data it protects. This parameter exists precisely because
    12 is not right everywhere.

.PARAMETER MinimumFreeDiskPercent
    Refuse to resize if the worst case would leave less than this percentage of
    the volume free. Default 20.

    Stricter than the 15 Protect-EventLogs uses, deliberately: 15 there is a
    REPORTING threshold, this one is a REFUSAL. Raising the maximum authorises
    VSS to consume up to it, so the worst case has to be survivable rather than
    merely noticed.

.PARAMETER ForceShrink
    Allow a resize that LOWERS the shadow storage maximum while shadow copies
    exist. Without it, both -Apply and -Rollback report and decline. Read the
    DESCRIPTION first: the snapshots this may destroy can be the client's only
    recovery point.

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
    .\Enable-VssPreservation.ps1
    Reports shadow storage, snapshots, service state and headroom. Changes
    nothing.

.EXAMPLE
    .\Enable-VssPreservation.ps1 -Apply
    Sets shadow storage to 12% of the system volume, if the free-space guard
    allows it. Run Enable-VssSnapshotSchedule -Apply next to register the task
    that writes into it.

.EXAMPLE
    .\Enable-VssPreservation.ps1 -Rollback
    Restores the previous maximum, declining the resize if it would destroy
    existing snapshots. On a host armed before the 2026-09-07 split it also
    removes the snapshot task that run recorded.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.0.1
    License : MIT

    Windows PowerShell 5.1, in-box modules only. Requires local administrator;
    enforced in code by Assert-Elevated.

    Windows facts and their provenance:
      - Win32_ShadowStorage properties AllocatedSpace, UsedSpace, MaxSpace
        (uint64, MaxSpace read/write) and Volume / DiffVolume (Win32_Volume REF):
        https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/win32-shadowstorage
      - Win32_ShadowStorage.Create(Volume, DiffVolume, MaxSpace) return codes:
        https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/create-method-in-class-win32-shadowstorage
      - Win32_ShadowCopy.Create(Volume, Context) with out parameter ShadowID:
        https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/create-method-in-class-win32-shadowcopy
      - Win32_ShadowCopy properties ID, DeviceObject, VolumeName, InstallDate:
        https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/win32-shadowcopy
      - Win32_Volume properties DeviceID, DriveLetter, and DriveLetter being NULL
        for volumes without one:
        https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vdswmi/win32-volume
      - vssadmin resize shadowstorage /for= /on= /maxsize=, MaxSizeSpec 1 MB or
        greater, bytes when no unit is given, and the disappearing-shadow warning:
        https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-resize-shadowstorage
      - Minimum shadow copy storage area 320 MB above 500 MB volumes (32 MB
        below), and MaxShadowCopies default 64:
        https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore
      - Register-ScheduledTask, New-ScheduledTaskPrincipal (-LogonType
        ServiceAccount, -RunLevel Highest), New-ScheduledTaskSettingsSet, and the
        leading-and-trailing backslash rule for -TaskPath:
        https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask
        https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal
        https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset
      - New-ScheduledTaskTrigger -Daily / -At, and -RandomDelay as a TimeSpan
        accepted in every parameter set including Daily:
        https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger
      - VSS service short name, from the documented registry key
        HKLM\SYSTEM\CurrentControlSet\Services\VSS:
        https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore

    Everything Microsoft does not document is marked '# UNVERIFIED:' where it is
    used. Every one of them is about undocumented BEHAVIOUR or an uncited literal
    path, never about an event ID, a class name or a property name - those are all
    cited above.
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
    [int] $ShadowStoragePercent = 12,

    [Parameter()]
    [int] $MinimumFreeDiskPercent = 20,

    [Parameter()]
    [switch] $ForceShrink,

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

$script:ScriptName    = 'Enable-VssPreservation'
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
$script:VssadminPath = Get-NativeToolPath -FileName 'vssadmin.exe'

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

#region VSS state -------------------------------------------------------------

<#
    WHICH SOURCE, AND WHY.

    Every number this script DECIDES on comes from WMI. None comes from vssadmin
    text. Win32_ShadowStorage gives AllocatedSpace, UsedSpace and MaxSpace as
    uint64, and Win32_ShadowCopy gives ID, DeviceObject, VolumeName and
    InstallDate as typed properties, so the free-space arithmetic works on
    integers from the object model.

    vssadmin has no documented output format at all. 'vssadmin list
    shadowstorage' is not in Microsoft's current command reference; it survives
    only on the archived Server 2012 R2 page, which gives syntax and no sample
    output, and the only output label Microsoft writes down anywhere is "Maximum
    Shadow Copy Storage space", in a Server 2008 R2 troubleshooting article. The
    labels are localised. Deciding a resize on undocumented translated text would
    be betting a client's system volume on a regex.

    So vssadmin output IS collected and printed verbatim - the brief asks for it,
    and it is what a technician compares against by hand - but nothing parsed
    from it reaches a branch. The only extraction is a list of size-shaped
    tokens, shown beside the WMI numbers as a cross-check and used for nothing.

    https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/win32-shadowstorage
    https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/win32-shadowcopy
    https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc788045(v=ws.11)
#>

function ConvertTo-ByteString {
    <#
        Byte counts go into the manifest as INVARIANT DECIMAL STRINGS, for the
        reason docs/DESIGN.md section 4 gives for REG_QWORD: a JSON integer
        deserializes as Int32 under PS 5.1 and Int64 under PS 7, so any count
        above 2^31 - which is every volume worth protecting - would be read back
        as a different number by whichever engine runs the -Rollback.

        [decimal], not [int64]: MaxSpace is a uint64 and an unbounded area can
        hold UInt64.MaxValue, which overflows Int64. Decimal carries 28
        significant digits; 2^64 needs 20.
    #>
    param([Parameter(Mandatory = $true)] $Value)
    return ([decimal] $Value).ToString('0', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-ByteString {
    param([Parameter()][AllowEmptyString()][string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    return [decimal]::Parse($Value,
        [System.Globalization.NumberStyles]::Integer,
        [System.Globalization.CultureInfo]::InvariantCulture)
}

function Format-ByteCount {
    # Operator-facing only. Never fed back into a comparison.
    param([Parameter(Mandatory = $true)] $Value)
    $d = [decimal] $Value
    if ($d -ge 1073741824) { return ([string] [math]::Round($d / 1073741824, 2) + ' GB') }
    if ($d -ge 1048576)    { return ([string] [math]::Round($d / 1048576, 2) + ' MB') }
    return ([string] $d + ' bytes')
}

function Test-ByteCountNear {
    <#
        Equality within one 32 MB allocation unit. MinDiffAreaFileSize is
        documented to round up to the next multiple of 32 MB, so the storage area
        is managed in 32 MB units.

        # UNVERIFIED: whether MaxSpace itself is rounded the same way. The
        # tolerance makes this tolerant of rounding in either direction instead of
        # asserting a rule Microsoft does not state. Without it, a host that
        # rounds would look "changed" on every single -Apply - the idempotence
        # defect this project cares most about.
        https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore
    #>
    param([Parameter(Mandatory = $true)] $Left, [Parameter(Mandatory = $true)] $Right)
    $delta = [decimal] $Left - [decimal] $Right
    if ($delta -lt 0) { $delta = -$delta }
    return ($delta -le 33554432)
}

function Get-VolumeCapacity {
    <#
        Capacity and free space from System.IO.DriveInfo, the same source
        Protect-EventLogs uses for its headroom check: no CIM session, no
        localised property. The volume must be Fixed - configuring shadow storage
        on removable or network media is not something this toolkit does.
    #>
    param([Parameter(Mandatory = $true)][string] $VolumeRoot)

    $drive = New-Object System.IO.DriveInfo($VolumeRoot)
    if (-not $drive.IsReady) { throw ('Volume ' + $VolumeRoot + ' is not ready.') }
    if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) {
        throw ('Volume ' + $VolumeRoot + ' is ' + $drive.DriveType +
               ', not a local fixed disk. Refusing to configure shadow storage on it.')
    }
    return [PSCustomObject] @{
        Root          = $VolumeRoot
        Spec          = $VolumeRoot.TrimEnd('\')
        CapacityBytes = [decimal] $drive.TotalSize
        FreeBytes     = [decimal] $drive.AvailableFreeSpace
    }
}

function Get-VolumeDeviceId {
    <#
        The \\?\Volume{guid}\ identity of a drive letter, used to correlate
        Win32_ShadowStorage and Win32_ShadowCopy back to the volume the operator
        named. Win32_Volume.DriveLetter is documented as NULL for volumes without
        one; its exact rendering ('C:' versus 'C:\') is NOT documented, so both
        sides are normalised rather than compared literally.
    #>
    param([Parameter(Mandatory = $true)][string] $VolumeRoot)

    $wanted = $VolumeRoot.TrimEnd('\').TrimEnd(':').ToUpperInvariant()
    foreach ($instance in @(Get-CimInstance -ClassName Win32_Volume)) {
        if ([string]::IsNullOrWhiteSpace($instance.DriveLetter)) { continue }
        $letter = ([string] $instance.DriveLetter).TrimEnd('\').TrimEnd(':').ToUpperInvariant()
        if ($letter -eq $wanted) { return [string] $instance.DeviceID }
    }
    return $null
}

function Get-VolumeRootFromDeviceId {
    <#
        The drive-letter root of a \\?\Volume{guid}\ device ID, or $null when
        it has no letter.

        Needed because the shadow storage area does not have to live on the
        volume being protected. 'vssadmin resize shadowstorage' takes /for= and
        /on= separately, and relocating the diff area to a second disk is
        ordinary practice on a file server - which is exactly the case the free
        space guard used to get wrong (the review log kept in the development repository, V-1).

        Win32_Volume.DriveLetter is documented as NULL for a volume without one,
        and its exact rendering ('D:' versus 'D:\') is not documented, so both
        sides are normalised rather than compared literally - the same treatment
        Get-VolumeDeviceId gives the reverse lookup.
    #>
    param([Parameter(Mandatory = $true)][string] $DeviceId)

    foreach ($instance in @(Get-CimInstance -ClassName Win32_Volume)) {
        if ([string]::Equals([string] $instance.DeviceID, $DeviceId,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            if ([string]::IsNullOrWhiteSpace($instance.DriveLetter)) { return $null }
            return (([string] $instance.DriveLetter).TrimEnd('\') + '\')
        }
    }
    return $null
}

function Get-CimReferenceDeviceId {
    <#
        Win32_ShadowStorage.Volume and .DiffVolume are declared 'Win32_Volume
        REF'. What a REF looks like once Get-CimInstance has returned it is
        undocumented: the cmdlet page says only that it returns CimInstance
        objects, and the CimType page that defines Reference = 15 as a type
        distinct from String = 14 has an entirely empty description column.

        # UNVERIFIED: whether a Win32_Volume REF surfaces as a nested CimInstance
        # or as an object-path string under Windows PowerShell 5.1. Both are
        # handled, neither is assumed, and a third shape returns $null - which
        # makes the caller REFUSE to resize rather than resize the wrong volume.
        # That is the failure direction that matters.
        https://learn.microsoft.com/en-us/dotnet/api/microsoft.management.infrastructure.cimtype
    #>
    param($Reference)

    if ($null -eq $Reference) { return $null }
    if ($Reference -is [Microsoft.Management.Infrastructure.CimInstance]) {
        foreach ($property in $Reference.CimInstanceProperties) {
            if ($property.Name -eq 'DeviceID') { return [string] $property.Value }
        }
        return $null
    }
    # Object-path form: backslashes are doubled inside a WMI object path, so the
    # captured DeviceID is unescaped before it can be compared with what
    # Win32_Volume reports.
    $match = [regex]::Match([string] $Reference, 'DeviceID\s*=\s*"(?<id>[^"]+)"')
    if ($match.Success) { return $match.Groups['id'].Value.Replace('\\', '\') }
    return $null
}

function Get-ShadowStorageForVolume {
    # The shadow copy storage association for one volume, or Exists = $false.
    # Correlated = $false means the volume itself could not be identified, which
    # is a different and worse answer than "no association".
    param([Parameter(Mandatory = $true)][string] $VolumeRoot)

    $deviceId = Get-VolumeDeviceId -VolumeRoot $VolumeRoot
    $state = [PSCustomObject] @{
        Exists = $false; DeviceId = $deviceId; MaxSpace = [decimal] 0
        UsedSpace = [decimal] 0; AllocatedSpace = [decimal] 0
        DiffDeviceId = $null; Correlated = ($null -ne $deviceId)
    }
    if ($null -eq $deviceId) { return $state }

    foreach ($storage in @(Get-CimInstance -ClassName Win32_ShadowStorage)) {
        $refId = Get-CimReferenceDeviceId -Reference $storage.Volume
        if ($null -eq $refId) { continue }
        if (-not [string]::Equals($refId, $deviceId, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $state.Exists         = $true
        $state.MaxSpace       = [decimal] $storage.MaxSpace
        $state.UsedSpace      = [decimal] $storage.UsedSpace
        $state.AllocatedSpace = [decimal] $storage.AllocatedSpace
        $state.DiffDeviceId   = (Get-CimReferenceDeviceId -Reference $storage.DiffVolume)
        return $state
    }
    return $state
}

function Get-ShadowCopyForVolume {
    <#
        Existing shadow copies of one volume. Win32_ShadowCopy.VolumeName is
        "Name of the original volume for which a shadow copy is made" - the
        \\?\Volume{guid}\ form, not a drive letter - so it is matched against the
        volume's DeviceID.

        This count is what the shrink guard turns on, so an error in the LOW
        direction is the dangerous one. Callers treat an uncorrelated volume as
        "snapshots exist", never as zero.
    #>
    param([Parameter(Mandatory = $true)][string] $DeviceId)

    $matched = New-Object System.Collections.ArrayList
    foreach ($shadow in @(Get-CimInstance -ClassName Win32_ShadowCopy)) {
        $name = [string] $shadow.VolumeName
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if (-not [string]::Equals($name.TrimEnd('\'), $DeviceId.TrimEnd('\'),
                                  [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        [void] $matched.Add([PSCustomObject] @{
            Id = [string] $shadow.ID; InstallDate = $shadow.InstallDate })
    }
    return @($matched.ToArray())
}

function Get-VssServiceState {
    <#
        Reported, never changed. A disabled VSS service makes the snapshot task
        useless - a finding worth an RMM alert - but enabling a service is a
        different change with a different rollback, and it belongs in its own
        script rather than smuggled into this one.
    #>
    $services = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='VSS'")
    if ($services.Count -eq 0) {
        return [PSCustomObject] @{ Found = $false; State = 'absent'; StartMode = 'absent' }
    }
    return [PSCustomObject] @{
        Found     = $true
        State     = [string] $services[0].State
        StartMode = [string] $services[0].StartMode
    }
}

#endregion
#region Shadow storage --------------------------------------------------------

# Microsoft's documented minimum size of the shadow copy storage area when
# MinDiffAreaFileSize is not set: 320 MB above 500 MB volumes, 32 MB below.
# Asking for less than the OS will honour would record a maximum in the manifest
# that the host never held.
# https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore
$script:MinimumAreaBytesLargeVolume = 335544320
$script:MinimumAreaBytesSmallVolume = 33554432
$script:SmallVolumeThresholdBytes   = 524288000

# vssadmin's own documented floor: "The MaxSizeSpec value must be 1 MB or greater".
# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-resize-shadowstorage
$script:VssAdminMinimumBytes = 1048576

function Test-ShadowStorageHeadroom {
    <#
        The hard rule from docs/AUTHORING.md and docs/DESIGN.md section 7, made
        arithmetic. Returns Allowed plus every number that went into the verdict,
        because a refusal an operator cannot check is a refusal they will work
        around.

        THE ARITHMETIC, stated so it can be argued with:

        AllocatedSpace is what the storage area already occupies, so it has
        already been subtracted from FreeSpace. Raising MaxSpace consumes nothing
        today - it AUTHORISES VSS to grow that area by (target - allocated) more
        bytes later. The worst case is therefore

            projectedFree = free - max(0, target - allocated)

        and the floor is applied to THAT, not to today's free space. Applying it
        to today's free space would wave through every resize whose entire point
        is to consume more disk later, which is exactly how a hardening script
        causes the outage it was deployed to prevent.

        TWO VOLUMES, NOT ONE (the review log kept in the development repository, V-1). The size is a
        percentage of the volume being PROTECTED - that is the sizing convention
        and it is unchanged - but the bytes land on the volume that HOLDS the
        area, which 'vssadmin resize shadowstorage /for= /on=' lets you make a
        different disk entirely. Deporting the diff area to a second disk is
        ordinary on a file server. The guard used to take free space and the
        floor from the protected volume in every case, so with the area on D: it
        measured C: and waved through a resize that could fill D:. Free space and
        the floor now come from the volume that will actually hold the data.
    #>
    param(
        [Parameter(Mandatory = $true)] $VolumeState,
        [Parameter(Mandatory = $true)] $StorageState,
        [Parameter(Mandatory = $true)][int] $Percent,
        [Parameter(Mandatory = $true)][int] $FloorPercent,
        [Parameter()] $DiffVolumeState = $null
    )

    # Absent a resolved diff volume the protected volume is the right answer:
    # with no association this script creates one with DiffVolume set to the
    # protected volume itself (see Set-TrackedShadowStorage). The caller refuses
    # outright when an EXISTING association names a diff volume it cannot
    # resolve, so this default is never used to paper over an unknown.
    $spaceState = $VolumeState
    if ($null -ne $DiffVolumeState) { $spaceState = $DiffVolumeState }

    $capacity = [decimal] $VolumeState.CapacityBytes
    $free     = [decimal] $spaceState.FreeBytes
    $target   = [decimal] [math]::Floor($capacity * $Percent / 100)

    $allocated = [decimal] 0
    if ($StorageState.Exists) { $allocated = [decimal] $StorageState.AllocatedSpace }

    $growth = $target - $allocated
    if ($growth -lt 0) { $growth = [decimal] 0 }
    $projected = $free - $growth
    # The floor is a share of the volume the bytes land on, not of the volume
    # being protected: keeping 10% of C: free says nothing about D:.
    $floor     = [decimal] [math]::Floor([decimal] $spaceState.CapacityBytes * $FloorPercent / 100)

    $minimumArea = $script:MinimumAreaBytesSmallVolume
    if ($capacity -gt $script:SmallVolumeThresholdBytes) {
        $minimumArea = $script:MinimumAreaBytesLargeVolume
    }

    $allowed = $true
    $reason  = 'the volume keeps enough free space in the worst case'
    if ($target -lt $script:VssAdminMinimumBytes) {
        $allowed = $false
        $reason = ((Format-ByteCount -Value $target) + ' is under the documented 1 MB resize minimum')
    }
    elseif ($target -lt $minimumArea) {
        $allowed = $false
        $reason = ((Format-ByteCount -Value $target) + ' is under the documented minimum storage area of ' +
                   (Format-ByteCount -Value $minimumArea) + ' for a volume this size')
    }
    elseif ($projected -lt $floor) {
        $allowed = $false
        $reason = ('worst case would leave ' + (Format-ByteCount -Value $projected) + ' free on ' +
                   $spaceState.Spec + ', under the ' + [string] $FloorPercent + '% floor of ' +
                   (Format-ByteCount -Value $floor))
    }

    return [PSCustomObject] @{
        Allowed = $allowed; Reason = $reason; TargetBytes = $target; GrowthBytes = $growth
        FreeBytes = $free; ProjectedFree = $projected; FloorBytes = $floor; MinimumArea = $minimumArea
        MeasuredVolume = $spaceState.Spec
    }
}

function Set-ShadowStorageMaximum {
    <#
        Two documented routes, chosen by whether an association already exists.

        None: Win32_ShadowStorage.Create(Volume, DiffVolume, MaxSpace), whose
        return codes are documented - including 5, "Shadow copy storage area
        already exists", treated here as "somebody created it between the read
        and the write" and falling through to the resize.

        Exists: 'vssadmin resize shadowstorage /for= /on= /maxsize=', with the
        size in bare bytes because "If no unit is specified, MaxSizeSpec uses
        bytes by default" - no suffix, no unit ambiguity.

        Set-CimInstance on MaxSpace is NOT used even though the property is
        documented read/write: no Microsoft page documents the modification,
        while vssadmin resize is the documented operation.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $VolumeSpec,
        [Parameter(Mandatory = $true)] $MaxSpaceBytes,
        [Parameter(Mandatory = $true)][bool] $AssociationExists,
        # The volume that HOLDS the area, for /on=. Absent, it is the protected
        # volume - which is right for the Create path below and for a host whose
        # area was never relocated.
        [Parameter()][AllowEmptyString()][string] $DiffVolumeSpec = ''
    )

    $onSpec = $VolumeSpec
    if (-not [string]::IsNullOrWhiteSpace($DiffVolumeSpec)) { $onSpec = $DiffVolumeSpec }

    if (-not $AssociationExists) {
        $class = Get-CimClass -ClassName Win32_ShadowStorage
        $created = Invoke-CimMethod -CimClass $class -MethodName Create -Arguments @{
            Volume     = ($VolumeSpec + '\')
            DiffVolume = ($VolumeSpec + '\')
            MaxSpace   = [uint64] $MaxSpaceBytes
        }
        if ($created.ReturnValue -eq 0) { return }
        if ($created.ReturnValue -ne 5) {
            # 10 is listed because it was MEASURED and is not in Microsoft's
            # documented set: a client SKU answers 10 for a volume it will not
            # create an association on. Set-TrackedShadowStorage now reports that
            # case as a host limit before reaching here, so a 10 arriving at this
            # throw means something else and deserves the exit 2.
            throw ('Win32_ShadowStorage.Create failed for ' + $VolumeSpec + ' with return code ' +
                   [string] $created.ReturnValue + ' (1 access denied, 2 invalid argument, 3 volume ' +
                   'not found, 4 volume not supported, 11 insufficient storage; 10 is undocumented ' +
                   'and was measured on a client SKU, which cannot create an association at all).')
        }
        Write-Info 'An association appeared between the read and the write; resizing it instead.'
    }

    # /for= is the PROTECTED volume and /on= is the volume holding the area, and
    # they are genuinely allowed to differ - relocating the diff area to a second
    # disk is ordinary on a file server. Both used to be $VolumeSpec, which meant
    # that on a host with the area on D: this command said /for=C: /on=C: and
    # asked Windows to RELOCATE the area onto C:. Microsoft documents that
    # resizing may make shadow copies disappear, so that discarded the very
    # snapshots this script exists to preserve - and the headroom guard three
    # functions up had already measured D:, so the two disagreed about which disk
    # the write was even for. V-1 was fixed in the guard and not here.
    $result = Invoke-NativeCommand -FilePath $script:VssadminPath -Arguments @(
        'resize', 'shadowstorage', ('/for=' + $VolumeSpec), ('/on=' + $onSpec),
        ('/maxsize=' + (ConvertTo-ByteString -Value $MaxSpaceBytes)))
    if ($result.ExitCode -ne 0) {
        throw ('vssadmin resize shadowstorage failed for /for=' + $VolumeSpec + ' /on=' + $onSpec +
               ' (exit ' + [string] $result.ExitCode + '): ' + ($result.Output -join ' '))
    }
}

function Test-ShadowStorageCreatable {
    <#
        Can this host CREATE a shadow storage association at all?

        MEASURED 2026-09-09, side by side. 'vssadmin' offers these verbs:

          Windows 11 Pro 26200   Delete Shadows, List Providers, List Shadows,
                                 List ShadowStorage, List Volumes, List Writers,
                                 Resize ShadowStorage
          Server 2019 17763      the same PLUS Add ShadowStorage,
                                 Delete ShadowStorage and Query Reverts

        A client SKU can RESIZE an association it already has and cannot ADD
        one. Win32_ShadowStorage.Create is present as a method there and returns
        10 - a value none of the codes this script names covers - so the script
        threw and the run exited 2. On an MSP fleet that is a "broken
        deployment" alert on every workstation, for a capability Windows never
        offered, which no -Apply can ever supply. It is a host limit, and this
        function is what lets it be reported as one.

        DECIDED BY ProductType, not by parsing vssadmin's help. The verb list is
        the evidence above, but its text is localised - it reads differently on
        the French Windows this project's own client base runs - and a gate that
        reads localised prose to decide what a script may do is the defect this
        repository has already been caught on twice. ProductType is a documented
        integer: 1 workstation, 2 domain controller, 3 server.
        https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem

        Returns $true when creation should be possible, and on any doubt: a
        wrong $false would silently skip the work on a host that can do it,
        which is the worse direction.
    #>
    $productType = 0
    try { $productType = [int] (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType }
    catch {
        Write-Info ('the host product type could not be read (' + $_.Exception.Message +
                    '), so shadow storage creation is attempted rather than skipped')
        return $true
    }
    if ($productType -eq 1) { return $false }
    return $true
}

function Set-TrackedShadowStorage {
    <#
        The one entry point that changes shadow storage. Records the previous
        maximum first, then writes, then reads back. Returns the number of changes
        made (0 or 1) so the caller can count - AUTHORING.md: '$changed = $changed
        -or (...)' short-circuits and silently stops calling the rest.
    #>
    param(
        [Parameter(Mandatory = $true)] $VolumeState,
        [Parameter(Mandatory = $true)] $StorageState,
        [Parameter(Mandatory = $true)] $Headroom,
        [Parameter(Mandatory = $true)][int] $ExistingShadowCount,
        [Parameter()] $DiffVolumeState = $null
    )

    Write-Section 'Shadow storage maximum'
    $target = $Headroom.TargetBytes
    $label  = ('shadow storage on ' + $VolumeState.Spec + ' -> ' + (Format-ByteCount -Value $target) +
               ' (' + [string] $ShadowStoragePercent + '% of the volume)')

    if (-not $StorageState.Correlated) {
        Write-Finding ('Cannot correlate ' + $VolumeState.Spec + ' to a Win32_Volume DeviceID, so its ' +
                       'association cannot be identified. Refusing to resize anything rather than ' +
                       'resizing the wrong volume.')
        return 0
    }

    # NOTHING TO DO IS TESTED BEFORE ANYTHING IS REFUSED. The headroom refusal
    # below used to come first, so a host that already held the target - a host
    # needing no change whatsoever - printed 'REFUSED ... under the 20% floor' and
    # returned a finding, in -Audit and -Apply alike. That is not a rare corner: the
    # refusal arithmetic is projectedFree = free - (target - allocated), so on a
    # correctly hardened volume whose workload has since eaten the disk it fires on
    # free space alone, for ever. An RMM red every night on a compliant host is the
    # cry-wolf failure docs/AUTHORING.md names, and nothing was being refused - nothing was
    # being asked for.
    if ($StorageState.Exists -and (Test-ByteCountNear -Left $StorageState.MaxSpace -Right $target)) {
        Write-Ok ($label + ' - already set (host holds ' +
                  (Format-ByteCount -Value $StorageState.MaxSpace) + ')')
        # Still said out loud, because "the area you authorised may no longer be
        # survivable if VSS grows into it" is worth knowing. Said as an observation:
        # no -Apply of this script frees disk space, so it prints and is counted
        # without touching the exit code - docs/DESIGN.md section 3.1.
        if (-not $Headroom.Allowed) {
            Write-HostLimit ('The maximum already set on ' + $VolumeState.Spec + ' would NOT be ' +
                             'granted today: ' + $Headroom.Reason + '. Nothing was changed and nothing ' +
                             'was asked for, so this is an observation and not a refusal - but VSS ' +
                             'growing into an area it is already allowed to fill is exactly what the ' +
                             'floor exists to prevent.')
        }
        return 0
    }

    if (-not $Headroom.Allowed) {
        # A refused resize is a finding, not a failure: the host is left exactly
        # as it was and the RMM is told why. Reached only when the host does not
        # already hold the target, so there is a real change being refused.
        Write-Finding ('REFUSED ' + $label + ' - ' + $Headroom.Reason + '. Free space, ' +
                       '-ShadowStoragePercent or -MinimumFreeDiskPercent has to change first.')
        return 0
    }

    # THE SHRINK GUARD, and it applies to -Apply as well as to -Rollback. A
    # percentage smaller than what the host already has set is a shrink, and
    # Microsoft's warning is unambiguous: "Resizing the storage association may
    # cause shadow copies to disappear." Those snapshots may be the client's only
    # recovery point. A hardening script does not get to destroy them as a side
    # effect of applying a default.
    # V-2: the guard used to arm only when snapshots existed AT THIS INSTANT, so
    # on a host between backup jobs -Apply silently lowered the maximum with no
    # finding at all - contradicting this script's own .DESCRIPTION. A shrink is
    # a shrink either way: with snapshots present it may destroy them, and with
    # none present it still reduces how much history the NEXT ones can keep.
    # Both need the operator to say so.
    if ($StorageState.Exists -and $target -lt $StorageState.MaxSpace) {
        $consequence = ('it would LOWER the maximum from ' +
                        (Format-ByteCount -Value $StorageState.MaxSpace) + ' to ' +
                        (Format-ByteCount -Value $target))
        if ($ExistingShadowCount -gt 0) {
            $consequence = ($consequence + ' while ' + [string] $ExistingShadowCount +
                            ' shadow copy/copies exist, and Microsoft documents that resizing may ' +
                            'make them disappear')
        }
        else {
            $consequence = ($consequence + '. No shadow copy exists right now, so nothing is destroyed ' +
                            'today - but this is still a reduction in how much history the next ' +
                            'snapshots can keep, and a host between backup jobs looks exactly like ' +
                            'this one')
        }
        if (-not $ForceShrink) {
            Write-Finding ('DECLINED ' + $label + ' - ' + $consequence + '. Pass -ForceShrink if the ' +
                           'reduction is intended.')
            return 0
        }
        Write-Info ('-ForceShrink: ' + $consequence + '.')
    }

    # NO ASSOCIATION AND NO WAY TO MAKE ONE: a client SKU. Reported as a host
    # limit before the -Apply gate, so -Audit says it too instead of promising a
    # change it could never make, and before the manifest record, so no intent is
    # recorded for a change that will not be attempted.
    if (-not $StorageState.Exists -and -not (Test-ShadowStorageCreatable)) {
        Write-HostLimit ('shadow storage cannot be CREATED on this host: it is a client SKU, where ' +
                         'vssadmin offers Resize ShadowStorage but not Add ShadowStorage, and ' +
                         'Win32_ShadowStorage.Create answers with return code 10. Measured on ' +
                         'Windows 11 Pro build 26200. No -Apply of this script can supply a ' +
                         'capability Windows does not have, so this is not a finding and does not ' +
                         'raise the exit code. What still works here: an association Windows or ' +
                         'System Restore has already made can be RESIZED, and ' +
                         'Enable-VssSnapshotSchedule''s snapshot task is unaffected.')
        return 0
    }

    if (-not $Apply) {
        Write-Finding ($label + ' - would set (host holds ' +
                       (Format-ByteCount -Value $StorageState.MaxSpace) + ', association exists: ' +
                       [string] $StorageState.Exists + ')')
        return 0
    }

    # Record before changing. Not after.
    $previousValue = $null
    if ($StorageState.Exists) { $previousValue = (ConvertTo-ByteString -Value $StorageState.MaxSpace) }
    # The recorded diffVolume is the one the bytes actually land on, not a copy
    # of the protected volume. It used to be the latter, so a -Rollback of a
    # relocated area read the wrong disk out of the manifest.
    $diffSpec = $VolumeState.Spec
    if ($null -ne $DiffVolumeState) { $diffSpec = [string] $DiffVolumeState.Spec }
    [void] (Write-ManifestChange -Change @{
        type                  = 'shadowstorage'
        volume                = $VolumeState.Spec
        diffVolume            = $diffSpec
        previousExisted       = $StorageState.Exists
        previousMaxSpaceBytes = $previousValue
        newMaxSpaceBytes      = (ConvertTo-ByteString -Value $target)
        description           = $label
    })

    Set-ShadowStorageMaximum -VolumeSpec $VolumeState.Spec -MaxSpaceBytes $target `
        -AssociationExists ([bool] $StorageState.Exists) -DiffVolumeSpec $diffSpec

    $confirmed = Get-ShadowStorageForVolume -VolumeRoot $VolumeState.Root
    if (-not $confirmed.Exists) {
        throw ('Shadow storage was set on ' + $VolumeState.Spec + ' but no association reads back.')
    }
    if (-not (Test-ByteCountNear -Left $confirmed.MaxSpace -Right $target)) {
        throw ('Shadow storage on ' + $VolumeState.Spec + ' reads back as ' +
               (Format-ByteCount -Value $confirmed.MaxSpace) + ', not the requested ' +
               (Format-ByteCount -Value $target) + '.')
    }
    Write-Ok ($label + ' - set (host now reports ' + (Format-ByteCount -Value $confirmed.MaxSpace) + ')')
    return 1
}

function Assert-ManifestVolumeUsable {
    <#
        THE CONSTRAINT ON A MANIFEST-SUPPLIED VOLUME.

        docs/DESIGN.md section 4: "The manifest is operator-writable input, not
        trusted state." -Rollback reads a volume out of it and hands it to
        'vssadmin resize shadowstorage', which Microsoft documents as able to make
        shadow copies disappear. The task path beside it in this script is
        validated for exactly that reason and the volume was not.

        The constraint comes from the SCRIPT, never from the record: a volume is
        acceptable only if it passes the same resolution -Volume passes on the
        apply path - a local drive-letter root, ready, and Fixed. A record naming
        a UNC path, a \\?\Volume{guid}\ path, a removable disk or a letter that
        is not present on this host is declined instead of being passed to
        vssadmin to interpret.

        Honest about what this is: with the toolkit root now ACL'd to SYSTEM and
        Administrators, anyone who can plant a manifest record is already an
        administrator, so this is defence in depth and a guard against an RMM
        variable or an operator typo - not the control that makes the manifest
        trustworthy. The DACL is that control.

        Returns the normalised root, or $null after writing the finding.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $Spec)

    if ([string]::IsNullOrWhiteSpace($Spec)) {
        Write-Finding 'The manifest record names no volume; leaving it alone.'
        return $null
    }
    $root = $null
    try { $root = Resolve-VolumeRoot -Requested $Spec }
    catch {
        Write-Finding ('The manifest names a volume this script would never target: ' +
                       $_.Exception.Message + ' Leaving it alone.')
        return $null
    }
    try { [void] (Get-VolumeCapacity -VolumeRoot $root) }
    catch {
        Write-Finding ('The manifest names ' + $root + ', which this host cannot offer as a local ' +
                       'fixed volume: ' + $_.Exception.Message + ' Refusing to resize shadow storage ' +
                       'on it.')
        return $null
    }
    return $root
}

function Restore-ShadowStorage {
    <#
        THE MOST IMPORTANT JUDGEMENT IN THIS SCRIPT.

        Shrinking shadow storage back can delete the shadow copies it holds, and
        some of those snapshots were probably taken AFTER this toolkit ran, by the
        very task this rollback is also removing. Destroying a client's only
        recovery point in order to undo a configuration change is not a rollback,
        it is an incident.

        So:
          - The host must still hold the maximum this run set. Otherwise something
            else changed it and this rollback has no business guessing. Declined.
          - If the association did not exist before this run, there is nothing to
            restore it to. 'vssadmin delete shadowstorage' is not a documented
            command and removing an association discards the snapshots in it, so
            the association is LEFT IN PLACE. Declined, with instructions.
          - If restoring would LOWER the maximum while shadow copies exist:
            declined unless -ForceShrink. A declined change makes the whole
            rollback 'failed', which keeps it retryable - the right state for a
            decision a human still has to make.
          - Restoring the same or a higher maximum cannot destroy a snapshot, so
            it just happens.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change     = $ChangeRecord.change
    $volumeRoot = Assert-ManifestVolumeUsable -Spec ([string] $change.volume)
    if ($null -eq $volumeRoot) { return 'declined' }
    $intended   = ConvertFrom-ByteString -Value ([string] $change.newMaxSpaceBytes)
    $current    = Get-ShadowStorageForVolume -VolumeRoot $volumeRoot

    if (-not $current.Correlated) {
        Write-Finding ('Cannot correlate ' + $change.volume + ' to a volume on this host; leaving it alone.')
        return 'declined'
    }
    if (-not $current.Exists) {
        # WHICH CASE "no association at all" IS depends on what was there BEFORE
        # this run, so previousExisted is tested first. It used to be tested only
        # after this branch had already returned 'restored' for every absent
        # association, whatever the record said had been there.
        #
        # previousExisted = $true: this run resized an association that already
        # existed. The host now holds neither the maximum the run set nor the one
        # it recorded, because something removed the association outright - section
        # 4.1 case 3, declined and RETRYABLE. Counting it 'restored' closed the
        # rollback as completed, dropped the run out of the eligible set and stopped
        # Test-VisibilityDrift expecting a setting a third party had destroyed. It
        # also printed a falsehood: the change did take effect.
        if ([bool] $change.previousExisted) {
            Write-Finding ('There is no shadow storage association on ' + $change.volume + ' at all, ' +
                           'yet this run resized one that existed before it. The host holds neither ' +
                           'what this run set nor what was recorded before it, so something else ' +
                           'removed the association; leaving it alone. Re-creating one is not a ' +
                           'rollback - it would authorise an area nobody asked for.')
            return 'declined'
        }
        # previousExisted = $false: an unconfirmed write resolving against the host,
        # the way the template resolves a registry change. No association is exactly
        # the recorded previous state, whether the Create never landed or somebody
        # has since removed it - section 4.1 case 2, nothing to undo.
        Write-Ok ('No association on ' + $change.volume + ', which is the state recorded before this ' +
                  'run; nothing to undo.')
        return 'restored'
    }
    # Case 2 (docs/DESIGN.md section 4.1), BEFORE case 3: the association already
    # holds the maximum recorded BEFORE this run. Either the resize never landed or
    # it has already been undone; both mean nothing to do, and the doctrine counts
    # them 'restored' so the run converges. Without this the case-3 test below
    # caught it and declined as RETRYABLE, so every future -Rollback re-selected
    # the run and it never finished - that is A-2. Note this cannot destroy a
    # snapshot: it performs no write at all.
    if ([bool] $change.previousExisted) {
        $previousRecorded = ConvertFrom-ByteString -Value ([string] $change.previousMaxSpaceBytes)
        if ($null -ne $previousRecorded -and
            (Test-ByteCountNear -Left $current.MaxSpace -Right $previousRecorded)) {
            Write-Ok ('Shadow storage on ' + $change.volume + ' already holds its recorded previous ' +
                      'maximum (' + (Format-ByteCount -Value $previousRecorded) + '); nothing to undo.')
            return 'restored'
        }
    }

    # Case 3: the host holds neither the applied maximum nor the previous one.
    if (-not (Test-ByteCountNear -Left $current.MaxSpace -Right $intended)) {
        Write-Finding ('Shadow storage on ' + $change.volume + ' now reports ' +
                       (Format-ByteCount -Value $current.MaxSpace) + ', not the ' +
                       (Format-ByteCount -Value $intended) + ' this run set. Something else changed ' +
                       'it; leaving it alone.')
        return 'declined'
    }

    $shadows = @()
    if ($null -ne $current.DeviceId) { $shadows = @(Get-ShadowCopyForVolume -DeviceId $current.DeviceId) }

    if (-not $change.previousExisted) {
        Write-Finding ('This run CREATED the shadow storage association on ' + $change.volume +
                       ' and it now holds ' + [string] $shadows.Count + ' shadow copy/copies. Removing ' +
                       'an association discards the snapshots in it and "vssadmin delete shadowstorage" ' +
                       'is not a documented command, so it is being left in place. Remove it by hand if ' +
                       'that is really wanted.')
        # PERMANENT: 'vssadmin delete shadowstorage' is not a documented command, so
        # this toolkit has no way to remove an association it created - not now and
        # not on a retry. Marking it permanent lets the run finish, which is what
        # stops Test-VisibilityDrift reporting the changes that WERE restored.
        return $script:RollbackDeclinedPermanent
    }

    $previous = ConvertFrom-ByteString -Value ([string] $change.previousMaxSpaceBytes)
    if ($null -eq $previous) {
        Write-Finding ('The manifest records a previous maximum for ' + $change.volume +
                       ' that cannot be read back as a number; leaving it alone.')
        return 'declined'
    }

    if ($previous -lt $current.MaxSpace -and $shadows.Count -gt 0) {
        if (-not $ForceShrink) {
            Write-Finding ('DECLINED restoring shadow storage on ' + $change.volume + ' from ' +
                           (Format-ByteCount -Value $current.MaxSpace) + ' down to ' +
                           (Format-ByteCount -Value $previous) + ': Microsoft documents that resizing ' +
                           'may make shadow copies disappear, and ' + [string] $shadows.Count +
                           ' exist right now - some of them probably NEWER than this toolkit run. ' +
                           'Re-run -Rollback with -ForceShrink only if they are genuinely expendable.')
            return 'declined'
        }
        Write-Info ('-ForceShrink: shrinking with ' + [string] $shadows.Count +
                    ' shadow copy/copies present. They may not survive this.')
    }

    # The recorded diff volume gets the same constraint as the protected one, and
    # an older record that carries none falls back to the protected volume - which
    # is what those runs actually configured.
    $rollbackDiff = ''
    $recordedDiff = ''
    if ($null -ne $change.PSObject.Properties['diffVolume']) { $recordedDiff = [string] $change.diffVolume }
    if (-not [string]::IsNullOrWhiteSpace($recordedDiff)) {
        $diffRoot = Assert-ManifestVolumeUsable -Spec $recordedDiff
        if ($null -eq $diffRoot) { return 'declined' }
        $rollbackDiff = $diffRoot.TrimEnd('\')
    }
    Set-ShadowStorageMaximum -VolumeSpec ($volumeRoot.TrimEnd('\')) -MaxSpaceBytes $previous `
        -AssociationExists $true -DiffVolumeSpec $rollbackDiff

    $confirmed = Get-ShadowStorageForVolume -VolumeRoot $volumeRoot
    if (-not (Test-ByteCountNear -Left $confirmed.MaxSpace -Right $previous)) {
        throw ('Restored shadow storage on ' + $change.volume + ' reads back as ' +
               (Format-ByteCount -Value $confirmed.MaxSpace) + ', not ' +
               (Format-ByteCount -Value $previous) + '.')
    }
    Write-Ok ('Restored shadow storage on ' + $change.volume + ' to ' + (Format-ByteCount -Value $previous))
    return 'restored'
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
$script:SnapshotTaskName = 'IronBlackBox-VssSnapshot'


#endregion
#region Reporting -------------------------------------------------------------

function Write-VssReport {
    # The audit half. It runs in every mode - including -Apply - so the operator
    # reads the state the decision below was made from instead of inferring it.
    param(
        [Parameter(Mandatory = $true)] $VolumeState,
        [Parameter(Mandatory = $true)] $StorageState,
        [Parameter(Mandatory = $true)] $Shadows,
        [Parameter(Mandatory = $true)] $ServiceState,
        [Parameter(Mandatory = $true)] $Headroom,
        [Parameter(Mandatory = $true)][bool] $TaskExists
    )

    Write-Section ('Volume ' + $VolumeState.Spec)
    Write-Info ('capacity ' + (Format-ByteCount -Value $VolumeState.CapacityBytes) +
                ', free ' + (Format-ByteCount -Value $VolumeState.FreeBytes))

    Write-Section 'Shadow storage, from Win32_ShadowStorage'
    if ($StorageState.Exists) {
        Write-Info ('maximum   ' + (Format-ByteCount -Value $StorageState.MaxSpace))
        Write-Info ('allocated ' + (Format-ByteCount -Value $StorageState.AllocatedSpace))
        Write-Info ('used      ' + (Format-ByteCount -Value $StorageState.UsedSpace))
        if ($null -ne $StorageState.DiffDeviceId) {
            Write-Info ('diff area on ' + [string] $StorageState.DiffDeviceId)
        }
    }
    elseif ($StorageState.Correlated) {
        # V-3: in -Apply this is the pre-state the run is ABOUT to create, so it is
        # information, not a finding - otherwise a first successful -Apply on a
        # host that never had a dedicated shadow area exits 1 on the very thing it
        # then fixes. In -Audit it stays a finding: a host with no dedicated VSS
        # area recycles snapshots at the host default, which is worth reporting.
        $noAssoc = ('No shadow storage association exists for ' + $VolumeState.Spec + ', so VSS has ' +
                    'no dedicated area and recycles snapshots at whatever default the host chose.')
        if ($Apply) { Write-Info ($noAssoc + ' This run will create one.') }
        else { Write-Finding $noAssoc }
    }
    else {
        Write-Finding ('Could not correlate ' + $VolumeState.Spec + ' to a Win32_Volume DeviceID; its ' +
                       'shadow storage state is unknown.')
    }

    # Verbatim, for the operator to compare by hand. Nothing below is parsed into
    # a decision - see the 'VSS state' region comment for why.
    Write-Section 'Shadow storage, as vssadmin prints it'
    $listed = Invoke-NativeCommand -FilePath $script:VssadminPath `
        -Arguments @('list', 'shadowstorage', ('/for=' + $VolumeState.Spec))
    if ($listed.ExitCode -ne 0) {
        Write-Info ('vssadmin exited ' + [string] $listed.ExitCode + ' - reported, not acted on')
    }
    $lines = @($listed.Output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $shown = 0
    $sizeTokens = New-Object System.Collections.ArrayList
    foreach ($line in $lines) {
        if ($shown -lt 30) { Write-Info ('| ' + $line); $shown++ }
        foreach ($token in [regex]::Matches($line, '\d+([.,]\d+)?\s*(bytes|KB|MB|GB|TB|PB|EB)\b',
                 [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            [void] $sizeTokens.Add($token.Value.Trim())
        }
    }
    if ($lines.Count -gt $shown) { Write-Info '| ... (output truncated)' }
    if ($sizeTokens.Count -gt 0) {
        Write-Info ('size-shaped tokens in that text (cross-check only, never parsed into a decision): ' +
                    (($sizeTokens.ToArray()) -join ' | '))
    }

    Write-Section 'Existing shadow copies'
    if ($Shadows.Count -eq 0) {
        Write-Info ('no shadow copies of ' + $VolumeState.Spec + ' exist')
    }
    else {
        # Bounded: a volume can legitimately hold up to MaxShadowCopies (default
        # 64), and a wall of 64 GUIDs is not a report.
        Write-Info ([string] $Shadows.Count + ' shadow copy/copies of ' + $VolumeState.Spec)
        $listedCount = 0
        foreach ($shadow in $Shadows) {
            if ($listedCount -ge 10) { break }
            Write-Info ('  ' + $shadow.Id + '  ' + [string] $shadow.InstallDate)
            $listedCount++
        }
        if ($Shadows.Count -gt $listedCount) {
            Write-Info ('  ... and ' + [string] ($Shadows.Count - $listedCount) + ' more')
        }
    }

    Write-Section 'Volume Shadow Copy service'
    if (-not $ServiceState.Found) {
        Write-Finding 'The VSS service is not present on this host. Nothing here can work.'
    }
    else {
        Write-Info ('VSS state ' + $ServiceState.State + ', start mode ' + $ServiceState.StartMode)
        # # UNVERIFIED: whether Win32_Service.StartMode is localised on a
        # # non-English Windows. This comparison only recognises the English token,
        # # so a localised host UNDER-reports rather than mis-reports - the safe
        # # direction for a finding that would otherwise cry wolf.
        if ([string]::Equals($ServiceState.StartMode, 'Disabled',
                             [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Finding ('The VSS service is disabled, so no snapshot can be taken however this ' +
                           'script is configured. This script does not enable services; enable it ' +
                           'deliberately, then re-run.')
        }
    }

    Write-Section 'Free-space guard'
    Write-Info ('target maximum     ' + (Format-ByteCount -Value $Headroom.TargetBytes) +
                ' (' + [string] $ShadowStoragePercent + '% of the volume)')
    Write-Info ('additional growth  ' + (Format-ByteCount -Value $Headroom.GrowthBytes) +
                ' beyond what the area already occupies')
    Write-Info ('free now           ' + (Format-ByteCount -Value $Headroom.FreeBytes))
    Write-Info ('free in worst case ' + (Format-ByteCount -Value $Headroom.ProjectedFree))
    Write-Info ('floor              ' + (Format-ByteCount -Value $Headroom.FloorBytes) +
                ' (' + [string] $MinimumFreeDiskPercent + '% of the volume)')
    if ($Headroom.Allowed) { Write-Ok ('guard passes - ' + $Headroom.Reason) }
    else { Write-Info ('guard REFUSES - ' + $Headroom.Reason) }

    Write-Section 'Snapshot task'
    if ($TaskExists) { Write-Ok ($script:TaskFolderPath + $script:SnapshotTaskName + ' is registered') }
    else { Write-Info ($script:TaskFolderPath + $script:SnapshotTaskName + ' is not registered') }

    Write-Section 'What this does not protect against'
    Write-Info 'Nothing here prevents "vssadmin delete shadows". An administrator, or ransomware'
    Write-Info 'running as one, can destroy every snapshot on this host in one command, and no'
    Write-Info 'shadow storage setting changes that. Deploy-TamperAlerts is what turns that'
    Write-Info 'deletion into a detected event. Neither script is a backup.'
}

function Invoke-HostCheck {
    # No -HandlerDirectory any more. It was Mandatory and unused: the snapshot
    # handler this script used to write moved to Enable-VssSnapshotSchedule on
    # 2026-09-07, and the parameter stayed behind. A required argument that
    # nothing reads is a false statement about what the function needs.
    param()

    $volumeRoot   = Resolve-VolumeRoot -Requested $Volume
    $volumeState  = Get-VolumeCapacity -VolumeRoot $volumeRoot
    $storageState = Get-ShadowStorageForVolume -VolumeRoot $volumeRoot
    $serviceState = Get-VssServiceState

    # If the volume could not be correlated, the shadow copy count is UNKNOWN, not
    # zero. The shrink guard turns on this number, so the unknown case has to
    # behave like "snapshots exist" - guessing zero is the one error that silently
    # authorises a destructive resize.
    $shadows = @()
    $shadowCountForGuard = 1
    if ($null -ne $storageState.DeviceId) {
        $shadows = @(Get-ShadowCopyForVolume -DeviceId $storageState.DeviceId)
        $shadowCountForGuard = $shadows.Count
    }

    # Which volume will actually hold the bytes. With no association this script
    # creates one on the protected volume itself, so $null here means "the same
    # volume" and the guard measures that. With an association that names a diff
    # volume this run cannot resolve to a usable root, the answer is UNKNOWN and
    # the resize is refused - measuring the wrong disk is how a guard passes a
    # change that fills the right one.
    $diffVolumeState = $null
    $diffUnresolved  = $null
    if ($storageState.Exists -and $null -ne $storageState.DiffDeviceId) {
        $diffRoot = Get-VolumeRootFromDeviceId -DeviceId ([string] $storageState.DiffDeviceId)
        if ($null -eq $diffRoot) {
            $diffUnresolved = ('the shadow storage area is on ' + [string] $storageState.DiffDeviceId +
                               ', which has no drive letter, so its free space cannot be measured')
        }
        else {
            try { $diffVolumeState = Get-VolumeCapacity -VolumeRoot $diffRoot }
            catch {
                $diffUnresolved = ('the shadow storage area is on ' + $diffRoot + ' and it could not ' +
                                   'be read: ' + $_.Exception.Message)
            }
        }
    }

    $headroom = Test-ShadowStorageHeadroom -VolumeState $volumeState -StorageState $storageState `
        -Percent $ShadowStoragePercent -FloorPercent $MinimumFreeDiskPercent `
        -DiffVolumeState $diffVolumeState
    if ($null -ne $diffUnresolved) {
        $headroom.Allowed = $false
        $headroom.Reason  = ($diffUnresolved + ' - refusing rather than measuring the protected volume ' +
                             'and hoping they are the same disk')
    }
    elseif ($null -ne $diffVolumeState -and $diffVolumeState.Spec -ne $volumeState.Spec) {
        Write-Info ('the shadow storage area for ' + $volumeState.Spec + ' lives on ' +
                    $diffVolumeState.Spec + ', so free space and the floor are measured there')
    }
    $taskExists = ($null -ne (Get-ToolkitScheduledTask -TaskPath $script:TaskFolderPath `
        -TaskName $script:SnapshotTaskName))

    Write-VssReport -VolumeState $volumeState -StorageState $storageState -Shadows $shadows `
        -ServiceState $serviceState -Headroom $headroom -TaskExists $taskExists

    # Counting, never '$changed = $changed -or (...)': -or short-circuits, so the
    # second call would never be made once the first succeeded.
    $changeCount = 0
    $changeCount += Set-TrackedShadowStorage -VolumeState $volumeState -StorageState $storageState `
        -Headroom $headroom -ExistingShadowCount $shadowCountForGuard `
        -DiffVolumeState $diffVolumeState
    # THE TASK IS NO LONGER THIS SCRIPT'S TO REGISTER. It moved to
    # Enable-VssSnapshotSchedule on 2026-09-07, so this reports what it can see and
    # names the owner. The 'scheduledtask' branch of the rollback below STAYS: a
    # host armed before the split holds a run carrying both a shadowstorage and a
    # scheduledtask record under this script's name, and dropping the branch would
    # leave those declined-retryable forever - a run that never leaves the eligible
    # set, which is the R-1 defect docs/DESIGN.md section 4.1 removed.
    Write-Section 'Scheduled snapshot task'
    if ($taskExists) {
        Write-Ok ($script:TaskFolderPath + $script:SnapshotTaskName +
                  ' is registered. Enable-VssSnapshotSchedule owns it.')
    }
    else {
        Write-Finding ('no scheduled snapshot task. A storage area with nothing writing to it ' +
                       'holds no point-in-time copy, so arm Enable-VssSnapshotSchedule after ' +
                       'this script - see docs/DEPLOYMENT.md.')
    }
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
    Assert-ParameterRange   -Name 'ShadowStoragePercent' -Value $ShadowStoragePercent -Minimum 1 -Maximum 50
    Assert-ParameterRange   -Name 'MinimumFreeDiskPercent' -Value $MinimumFreeDiskPercent -Minimum 5 -Maximum 90
    # -SnapshotTimes and -SnapshotRandomDelayMinutes moved to Enable-VssSnapshotSchedule.


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
        Write-Ok 'No findings: shadow storage and the snapshot task are configured.'
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
                shadowStoragePercent   = $ShadowStoragePercent
                minimumFreeDiskPercent = $MinimumFreeDiskPercent
                forceShrink            = [bool] $ForceShrink
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
            try { $verified = Invoke-HostCheck }
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
            forceShrink = [bool] $ForceShrink
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
                # Two types, routed explicitly: the association and the snapshot
                # task. Anything else is declined by name rather than handed to a
                # restorer that does not understand it.
                switch ([string] $record.change.type) {
                    'shadowstorage' { $outcome = Restore-ShadowStorage -ChangeRecord $record; break }
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
