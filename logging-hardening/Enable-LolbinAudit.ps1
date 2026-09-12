<#
.SYNOPSIS
    Puts AppLocker into AUDIT MODE ONLY over the living-off-the-land binaries
    attackers use to execute and download, so the host records what ran without
    blocking anything.

.DESCRIPTION
    Attackers do not need to bring a payload when Windows ships seventeen signed
    Microsoft executables that will download and run one for them. This script
    makes their use visible: AppLocker deny rules over those binaries, in
    AuditOnly enforcement mode, so every hit lands as event 8003 - "was allowed
    to run but would have been prevented from running if the AppLocker policy
    were enforced" - and nothing at all is blocked.
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker

    AUDIT MODE ONLY, AND THERE IS NO ENFORCEMENT SWITCH. This is a hard rule,
    stated in docs/AUTHORING.md and docs/DESIGN.md section 7: "AppLocker, NTLM and LDAP
    scripts are audit-only by design. Enforcement is the MSP's decision, made
    after reading the audit data. Do not add enforcement switches." The reason is
    concrete rather than philosophical. An AppLocker enforcement rule pushed to a
    fleet by a script can stop a line-of-business application dead - msiexec.exe
    alone is in the list below, and blocking it ends every software install on
    the estate - and the technician looking at a broken application at 9am has no
    way to know which script did it. So: no -Enforce parameter, and do not add
    one. Flipping enforcement is a decision an MSP makes deliberately, in Group
    Policy, having first read the 8003 events this script produces.

    THE ONE RULE TO READ BEFORE DEPLOYING THIS. To get a targeted signal, the
    generated policy contains a baseline rule that ALLOWS ALL EXECUTABLES
    (FilePathRule, path "*"), under which the LOLBin deny rules produce their
    8003 events. Without it, AppLocker's "Implicit deny. All files not covered by
    an allow rule are blocked" would make EVERY process on the host an 8003 and
    bury the signal completely, and any later flip to enforcement would brick the
    machine instead of blocking seventeen binaries.
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understand-applocker-rules-and-enforcement-setting-inheritance-in-group-policy
    The cost is real and is the single most consequential thing this script
    writes: an allow-everything rule left behind in the local policy would
    neuter a real allowlist built later. It carries an unmistakable name so it
    can be found, and -Rollback removes it with the rest.

    MERGE, NEVER REPLACE. The policy is applied with 'Set-AppLockerPolicy
    -XmlPolicy <file> -Merge'. Microsoft: "Merges the rules in the specified
    AppLocker policy with the AppLocker rules in the target GPO... If the Merge
    parameter is not specified, then the new policy will overwrite the existing
    policy." Overwriting a host that already carries an AppLocker policy would
    destroy it.
    https://learn.microsoft.com/en-us/powershell/module/applocker/set-applockerpolicy

    AND IT REFUSES TO PROCEED ON AN ENFORCING HOST. The same page says of -Merge
    that "the enforcement setting specified by the AppLocker policy in the target
    GPO will be preserved" - so merging AuditOnly rules into a GPO whose Exe
    collection is already enforcing does NOT make them audit-only; it makes them
    ENFORCED, and seventeen deny rules take effect immediately. Worse, Microsoft
    is explicit that "Any rule collection with the enforcement mode set as 'not
    configured' is enforced", so an unset enforcement mode is not a safe state
    either. This script therefore reads the current policy first and refuses to
    apply anything when a rule collection carrying rules is enforcing or unset.
    After applying, it re-reads the policy and verifies the Exe collection really
    is AuditOnly, restoring the previous policy and failing if it is not.

    WHAT THIS SCRIPT DELIBERATELY DOES NOT DO:
      - Enforce anything, ever. See above.
      - Touch the Dll, Msi, Script or Appx rule collections. Only Exe. DLL rules
        in particular carry a documented performance cost and are a separate
        decision.
      - Build an application allowlist. This is targeted LOLBin visibility, not
        application control; the baseline rule above allows everything else on
        purpose.
      - Size or enable the AppLocker channel. Channel sizing is the event log
        policy's job, in Enable-IRVisibility.
      - Stop AppIDSvc on -Rollback. It restores the service's recorded start
        type, but a running protected service is left running: stopping it would
        deactivate any OTHER AppLocker policy on the host, which this script did
        not put there.
      - Deploy to a domain GPO. Set-AppLockerPolicy without -Ldap targets the
        LOCAL GPO, which is the only thing this script can capture and restore.

    UNVERIFIED, AND THE ITEM MOST WORTH CHECKING FIRST: whether the AppLocker
    PowerShell module is present in-box on Windows Server 2019 without an
    additional Windows feature or RSAT. Microsoft's requirements page confirms
    AppLocker itself "Can be configured / Can be enforced" on Server 2019 and
    lists no prerequisite feature, but it also says Group Policy deployment needs
    "at least one device with the Group Policy Management Console (GPMC) or
    Remote Server Administration Tools (RSAT) installed", and it does not state
    where the cmdlets come from.
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/requirements-to-use-applocker
    So the cmdlets are DETECTED at runtime rather than assumed, and their absence
    is a finding with no changes made. tools/check.ps1 proves syntax and API
    surface and nothing else (docs/DESIGN.md section 9); docs/VALIDATION.md is
    the only file allowed to say where this script has run, and its row is the
    one to read before deploying.

.PARAMETER Audit
    Default. Strictly read-only. Reports the AppLocker cmdlets' availability, the
    Application Identity service's state, the AppLocker channel, the current
    policy's enforcement mode per rule collection, and every rule -Apply would
    merge in.

.PARAMETER Apply
    Merges the audit-only LOLBin rules into the LOCAL AppLocker policy and sets
    the Application Identity service to start automatically, recording the
    previous policy and the previous service start type first.

.PARAMETER Rollback
    Restores the local AppLocker policy captured before a prior -Apply, after
    verifying the backup's hash and that nothing else has changed the policy
    since, and restores the service start type.

.PARAMETER ToolkitRoot
    Base directory for the manifest and for the policy XML files this script
    writes under <ToolkitRoot>\AppLocker. Default C:\ProgramData\IronBlackBox.
    Validated before use.

.PARAMETER AppLockerChannelSizeBytes
    Floor for the maximum size of "Microsoft-Windows-AppLocker/EXE and DLL", in
    BYTES - not kilobytes; the EventLog policy value of the same name is
    kilobytes and this channel is not sized through it. Default 134217728
    (128 MiB), accepted range 1052672 to 2147483647. It is a FLOOR: a channel
    already at or above the value is left alone, so nothing is ever shrunk and no
    recorded event is discarded. The default is not arbitrary - the baseline
    ALLOW ALL rule raises 8002 on every process start, and at the channel's
    shipped 1,052,672 bytes that was measured to be roughly two minutes of
    history on an idle Server 2019.

.PARAMETER MinimumFreeDiskPercent
    Free-space floor, as a percentage of the volume that holds the channel's own
    .evtx file, below which -Apply reports the sizing as refused rather than
    growing the channel. Default 10, accepted range 0 to 90. A bigger log on a
    volume that cannot take it turns a logging improvement into an outage.

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
    .\Enable-LolbinAudit.ps1
    Reports what is in place and what applying would add. Changes nothing.

.EXAMPLE
    .\Enable-LolbinAudit.ps1 -Apply
    Merges the audit-only rules, starts the Application Identity service, and
    records the previous policy for rollback.

.EXAMPLE
    .\Enable-LolbinAudit.ps1 -Rollback
    Puts the local AppLocker policy and the service start type back.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.1.1
    License : MIT

    Windows PowerShell 5.1. No module INSTALLS - the AppLocker module is in-box
    where it exists at all, and its absence is reported rather than fixed.
    Requires local administrator; enforced in code by Assert-Elevated,
    deliberately not by #Requires -RunAsAdministrator (docs/DESIGN.md section 3).
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

    # AT-4: the AppLocker EXE and DLL channel ships at 1,052,672 bytes, which
    # holds roughly two minutes of history because the baseline ALLOW ALL rule
    # raises 8002 on every process start - so an 8003 LOLBin hit is overwritten
    # before anyone reads it. This sizes the channel so the audit data survives.
    # Default 128 MiB; Microsoft's WEF baseline sizes the same channel to ~100 MB.
    # A FLOOR: a channel already larger is left alone, so nothing is ever shrunk.
    [Parameter()]
    [long] $AppLockerChannelSizeBytes = 134217728,

    # Sizing is gated on free disk space, like Enable-IRVisibility: a bigger log
    # on a volume that cannot take it turns a logging improvement into an outage.
    [Parameter()]
    [int] $MinimumFreeDiskPercent = 10,

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

$script:ScriptName    = 'Enable-LolbinAudit'
$script:ScriptVersion = '1.1.1'

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
#   the Application Identity service start type, nothing else.
$script:OwnedRegistryKey = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc'
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

#region AppLocker environment -------------------------------------------------

# The channel AppLocker's EXE and DLL events land in. Cited verbatim: Microsoft's
# Get-AppLockerFileInformation reference says of -LogPath, "By default, if this
# parameter is not specified, the local Microsoft-Windows-AppLocker/EXE and DLL
# channel is used."
# https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerfileinformation
$script:AppLockerChannel = 'Microsoft-Windows-AppLocker/EXE and DLL'

# Every event channel this script's -Rollback is allowed to write, which is
# exactly the one it sizes. The constraint comes from the SCRIPT, never from the
# manifest record - see Restore-AppLockerChannelChange.
$script:OwnedChannel = @($script:AppLockerChannel)

# "The Application Identity service determines and verifies the identity of an
# app. Stopping this service prevents AppLocker policies from being enforced."
# https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-the-application-identity-service
$script:AppIdServiceName = 'AppIDSvc'
$script:AppIdServiceKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc'

# Service start types as REG_DWORD under the service key: "0x2 (Automatic):
# Loaded automatically by the Service Control Manager during system startup",
# "0x3 (Demand)", "0x4 (Disabled)".
# https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree
$script:StartAutomatic = 2

# Every AppLocker rule this script writes is addressed to Everyone, S-1-1-0 -
# a well-known SID, never the localised name, for the reason docs/DESIGN.md
# section 4 gives about BUILTIN\Administrators on fr-FR Windows.
# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
$script:EveryoneSid = 'S-1-1-0'

function Get-FileSha256 {
    # Upper-case hex, or $null when the file is absent. The recorded previous
    # policy is identified by this hash, and -Rollback refuses to install a
    # backup whose hash does not match what was recorded.
    param([Parameter(Mandatory = $true)][string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return ([string] (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash).ToUpperInvariant()
}

function Get-MissingAppLockerCmdlet {
    # Detected, never assumed - see the header's UNVERIFIED note on whether the
    # AppLocker module is in-box on Server 2019. Get-Command auto-loads from
    # PSModulePath; nothing here installs anything (docs/AUTHORING.md).
    $missing = New-Object System.Collections.ArrayList
    foreach ($name in @('Get-AppLockerPolicy', 'Set-AppLockerPolicy', 'Get-AppLockerFileInformation')) {
        if ($null -eq (Get-Command -Name $name -ErrorAction SilentlyContinue)) { [void] $missing.Add($name) }
    }
    return $missing.ToArray()
}

function Get-AppIdServiceState {
    <#
        The service's live status and its persisted start type, read from the
        registry rather than from Get-Service.

        Microsoft: "Starting with Windows 10, the Application Identity service is
        now a protected process. As a result, you can no longer manually set the
        service Startup type to Automatic by using the Services snap-in", and
        recommends 'sc.exe config appidsvc start=auto' - then warns that "The
        Startup type of the Application Identity service cannot be set to Manual
        using sc.exe. Therefore, we recommend to perform a system backup before
        changing it."
        https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-the-application-identity-service

        A one-way change with a documented "back up first" warning is exactly what
        this toolkit's manifest exists for, so the start type is written through
        Set-TrackedRegistryValue instead: the previous REG_DWORD is recorded
        before the change and -Rollback restores it, which sc.exe cannot do.
    #>
    $service = Get-Service -Name $script:AppIdServiceName -ErrorAction SilentlyContinue
    $state = [PSCustomObject] @{
        Present = ($null -ne $service); Status = 'absent'; StartValue = -1
    }
    if ($null -ne $service) { $state.Status = [string] $service.Status }

    $registry = Get-RegistryValueState -Path $script:AppIdServiceKey -Name 'Start'
    if ($registry.Exists) { $state.StartValue = [int] $registry.Value }
    return $state
}

function Write-AppLockerChannelReport {
    <#
        The audit events land here, so a disabled channel means the whole exercise
        produces nothing. Properties are read defensively: this script must not
        assert that a property exists on an object it has never seen on Windows.

        Microsoft's own warning is worth relaying: "The AppLocker event logs are
        very verbose and can result in a large number of events depending on the
        policies deployed, particularly in the AppLocker - EXE and DLL event log."
        https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker
    #>
    Write-Section 'AppLocker EXE and DLL channel'

    $log = Get-WinEvent -ListLog $script:AppLockerChannel -ErrorAction SilentlyContinue
    if ($null -eq $log) {
        Write-Finding ($script:AppLockerChannel + ' does not exist on this host - the audit would ' +
                       'produce nothing even with the policy in place')
        return
    }
    $enabled = 'unknown'
    if ($null -ne $log.PSObject.Properties['IsEnabled']) { $enabled = [string] $log.IsEnabled }
    $parts = New-Object System.Collections.ArrayList
    [void] $parts.Add('enabled=' + $enabled)
    foreach ($name in @('MaximumSizeInBytes', 'FileSize', 'RecordCount')) {
        $value = 'unknown'
        if ($null -ne $log.PSObject.Properties[$name] -and $null -ne $log.$name) {
            $value = [string] $log.$name
        }
        [void] $parts.Add($name + '=' + $value)
    }
    $detail = ($script:AppLockerChannel + ' - ' + (($parts.ToArray()) -join ', '))
    if ($enabled -eq 'False') {
        Write-Finding ($detail + ' - DISABLED, so the audit records nothing')
    }
    else { Write-Ok $detail }

    # THE MEASUREMENT THAT DECIDES WHETHER THIS SCRIPT IS WORTH DEPLOYING.
    # The baseline ALLOW ALL EXE rule stops the deny rules from turning every
    # process into an 8003, but it does not make the host quiet: an allowed
    # execution raises 8002, "was allowed to run", once per process start.
    #
    # Measured on the lab, Server 2019 17763, IDLE apart from two SSH sessions:
    # 75 events spanning 2.0 minutes - 71 of them 8002, 3 of them 8003 - with
    # FileSize already equal to MaximumSizeInBytes. At the channel's default
    # 1,052,672 bytes the whole log rolls over about every two minutes, so an
    # 8003 hit survives roughly that long. On a busy server it is seconds.
    #
    # Sizing the channel is deliberately NOT done here (see the header), but a
    # default-sized channel makes the audit data effectively unrecoverable, and
    # saying nothing about it would be the quiet kind of failure this toolkit
    # exists to prevent.
    $maximum = 0
    $fileSize = 0
    if ($null -ne $log.PSObject.Properties['MaximumSizeInBytes'] -and $null -ne $log.MaximumSizeInBytes) {
        $maximum = [int64] $log.MaximumSizeInBytes
    }
    if ($null -ne $log.PSObject.Properties['FileSize'] -and $null -ne $log.FileSize) {
        $fileSize = [int64] $log.FileSize
    }
    if ($maximum -gt 0 -and $maximum -le 8388608) {
        Write-Finding ($script:AppLockerChannel + ' holds only ' + [string] $maximum + ' bytes. The ' +
                       'baseline ALLOW ALL EXE rule raises event 8002 on EVERY process start, so this ' +
                       'channel rolls over fast - measured at roughly two minutes of history on an idle ' +
                       'Server 2019 - and an 8003 LOLBin hit is overwritten with it. Size this channel ' +
                       '(Event Log policy or wevtutil sl /ms:) before relying on the audit data, or ' +
                       'forward 8003 off the host as it happens.')
    }
    if ($maximum -gt 0 -and $fileSize -ge $maximum) {
        Write-Finding ($script:AppLockerChannel + ' is at its maximum size already (' + [string] $fileSize +
                       ' of ' + [string] $maximum + ' bytes): it is overwriting its oldest events right ' +
                       'now, and any 8003 older than the current window is gone.')
    }
}

function Set-AppLockerChannelSize {
    <#
        AT-4. Sizes Microsoft-Windows-AppLocker/EXE and DLL via wevtutil sl /ms:,
        the way modern channels are sized (the EventLog policy value the classic
        logs use does not reach this channel, which is why Enable-IRVisibility
        cannot do it). Records the previous size first, writes, reads back.

        A FLOOR: a channel already at or above the target is left alone, so a
        second -Apply reports no change and no events are ever discarded by
        shrinking. Gated on free disk space on the channel's own volume.

        /ms: takes BYTES (Microsoft, wevtutil docs). The EventLog *policy* value
        of the same name is kilobytes - the unit trap this repo writes both of -
        but this channel is not sized through that policy at all.
    #>
    Write-Section 'AppLocker channel retention'

    $log = Get-WinEvent -ListLog $script:AppLockerChannel -ErrorAction SilentlyContinue
    if ($null -eq $log) {
        Write-Finding ($script:AppLockerChannel + ' does not exist on this host, so it cannot be sized')
        return 0
    }
    $currentMax = 0
    if ($null -ne $log.PSObject.Properties['MaximumSizeInBytes'] -and $null -ne $log.MaximumSizeInBytes) {
        $currentMax = [long] $log.MaximumSizeInBytes
    }
    if ($currentMax -ge $AppLockerChannelSizeBytes) {
        Write-Ok ($script:AppLockerChannel + ' already at ' + [string] $currentMax +
                  ' bytes, at or above the ' + [string] $AppLockerChannelSizeBytes + '-byte floor')
        return 0
    }

    # Disk headroom on the channel's own volume. Growth is the worst case: the
    # file may fill to the new maximum.
    $growth = $AppLockerChannelSizeBytes - $currentMax
    $volumeRoot = 'C:\'
    $logPath = ''
    if ($null -ne $log.PSObject.Properties['LogFilePath'] -and $log.LogFilePath) {
        $logPath = [System.Environment]::ExpandEnvironmentVariables([string] $log.LogFilePath)
    }
    if (-not [string]::IsNullOrWhiteSpace($logPath)) {
        $root = [System.IO.Path]::GetPathRoot($logPath)
        if (-not [string]::IsNullOrWhiteSpace($root)) { $volumeRoot = $root }
    }
    $free = -1
    $total = -1
    try {
        $drive = New-Object System.IO.DriveInfo($volumeRoot)
        $free = [long] $drive.AvailableFreeSpace
        $total = [long] $drive.TotalSize
    } catch {
        Write-Finding ($script:AppLockerChannel + ' - cannot read free space on ' + $volumeRoot +
                       ' (' + $_.Exception.Message + '), so it is not sized rather than risk a full disk')
        return 0
    }
    $projectedFree = $free - $growth
    $floorBytes = [long] ([math]::Floor(($total * $MinimumFreeDiskPercent) / 100))
    if ($projectedFree -lt $floorBytes) {
        Write-Finding ('REFUSED sizing ' + $script:AppLockerChannel + ' to ' +
                       [string] $AppLockerChannelSizeBytes + ' bytes: ' + $volumeRoot + ' has ' +
                       [string] $free + ' bytes free, sizing needs ' + [string] $growth +
                       ', which would leave ' + [string] $projectedFree + ' below the ' +
                       [string] $MinimumFreeDiskPercent + '% floor of ' + [string] $floorBytes +
                       ' bytes. Lower -AppLockerChannelSizeBytes or add disk.')
        return 0
    }

    if (-not $Apply) {
        Write-Finding ($script:AppLockerChannel + ' is ' + [string] $currentMax + ' bytes; would run: ' +
                       'wevtutil.exe sl "' + $script:AppLockerChannel + '" /ms:' +
                       [string] $AppLockerChannelSizeBytes)
        return 0
    }

    $enabled = $true
    if ($null -ne $log.PSObject.Properties['IsEnabled'] -and $null -ne $log.IsEnabled) {
        $enabled = [bool] $log.IsEnabled
    }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture

    # Record before changing. Not after. Sizes are invariant decimal strings, not
    # JSON numbers: PS 5.1 deserializes a JSON integer as Int32 and a channel
    # size can exceed Int32.
    [void] (Write-ManifestChange -Change @{
        type            = 'eventchannel'
        channel         = $script:AppLockerChannel
        previousEnabled = $enabled
        previousMaxSizeBytes = ([long] $currentMax).ToString($invariant)
        newEnabled      = $true
        newMaxSizeBytes      = ([long] $AppLockerChannelSizeBytes).ToString($invariant)
        description     = ($script:AppLockerChannel + ' sized to ' +
                           [string] $AppLockerChannelSizeBytes + ' bytes')
    })

    $wevtArgs = @('sl', $script:AppLockerChannel, '/e:true',
                  ('/ms:' + ([long] $AppLockerChannelSizeBytes).ToString($invariant)))
    # THROUGH THE WRAPPER, not '& ... 2>&1' plus $LASTEXITCODE. This script sets
    # $ErrorActionPreference = 'Stop', under which the first stderr line a native
    # tool writes becomes a terminating NativeCommandError - so for the COMMON
    # failure mode the two lines below never ran, and the crafted message naming
    # the exit code and the channel was unreachable. Invoke-NativeCommand exists
    # to hold that off; this file carried it unused.
    $wevt = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments $wevtArgs
    if ($wevt.ExitCode -ne 0) {
        Write-Failure ('wevtutil sl exited ' + [string] $wevt.ExitCode + ' sizing ' + $script:AppLockerChannel)
        throw ('wevtutil sl failed for ' + $script:AppLockerChannel + ': ' +
               (($wevt.Output -join ' ').Trim()))
    }

    # Confirm by re-reading. A confirmation that cannot be made is a finding
    # (exit 1), not an execution error: the write was accepted and recorded.
    $after = Get-WinEvent -ListLog $script:AppLockerChannel -ErrorAction SilentlyContinue
    $newMax = 0
    if ($null -ne $after -and $null -ne $after.PSObject.Properties['MaximumSizeInBytes'] -and
        $null -ne $after.MaximumSizeInBytes) {
        $newMax = [long] $after.MaximumSizeInBytes
    }
    if ($newMax -lt $AppLockerChannelSizeBytes) {
        Write-Finding ($script:AppLockerChannel + ' was sized but read back ' + [string] $newMax +
                       ' bytes, below the requested ' + [string] $AppLockerChannelSizeBytes)
        return 1
    }
    Write-Ok ($script:AppLockerChannel + ' sized to ' + [string] $newMax +
              ' bytes (was ' + [string] $currentMax + '); 8003 audit history now survives')
    return 1
}

function Get-AppLockerPolicyXml {
    <#
        The policy as an XML string, or '' when it cannot be read.

        -Local is the LOCAL GPO, which is what Set-AppLockerPolicy writes without
        -Ldap and therefore the only thing this script can restore exactly.
        -Effective is "the merge of the local AppLocker policy and any applied
        AppLocker domain policies on the local computer" - captured for the record
        because it is what is actually in force, but NEVER used as a restore
        source: writing a domain GPO's rules back into the local GPO would
        duplicate them locally and leave the host different from how it started.
        https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy
    #>
    param([Parameter(Mandatory = $true)][ValidateSet('Local', 'Effective')][string] $Scope)

    try {
        if ($Scope -eq 'Local') { return [string] (Get-AppLockerPolicy -Local -Xml) }
        return [string] (Get-AppLockerPolicy -Effective -Xml)
    }
    catch {
        Write-Finding ('Get-AppLockerPolicy -' + $Scope + ' -Xml failed: ' + $_.Exception.Message)
        return ''
    }
}

function Get-PolicyFact {
    <#
        Decodes a policy XML string into the two things every decision here needs:
        the enforcement mode of each rule collection, and a rule Id -> signature
        map used for comparison.

        Comparison is by Id and by a canonical condition signature, never by XML
        text. Same reasoning as verification/facts.json,
        sddl-text-is-not-comparable: a serialiser is free to reorder attributes,
        change quoting and re-case values, so a text compare reports a change that
        did not happen and rewrites the policy on every run.

        An absent EnforcementMode attribute is reported as 'NotConfigured', which
        Microsoft states IS enforced when the collection carries rules.
    #>
    param([Parameter()][AllowEmptyString()][string] $Xml = '')

    $facts = [PSCustomObject] @{
        Parsed = $false; Enforcement = @{}; RuleCount = @{}; Rules = @{}
    }
    if ([string]::IsNullOrWhiteSpace($Xml)) { return $facts }

    $document = New-Object System.Xml.XmlDocument
    # A policy XML read back from the host is still input; an external entity
    # reference in it must not be fetched by a SYSTEM process.
    $document.XmlResolver = $null
    try { $document.LoadXml($Xml) }
    catch {
        Write-Finding ('the AppLocker policy XML could not be parsed: ' + $_.Exception.Message)
        return $facts
    }
    if ($null -eq $document.DocumentElement) { return $facts }
    $facts.Parsed = $true

    # local-name() rather than a bare element name: if Get-AppLockerPolicy ever
    # emits the policy in a namespace, a bare XPath silently matches NOTHING and
    # this function would report an empty policy on a host that has one - which
    # would make the enforcement guard below fail OPEN. UNVERIFIED whether the
    # emitted XML carries a namespace; matching on local names is correct either
    # way.
    foreach ($collection in $document.DocumentElement.SelectNodes('*[local-name()="RuleCollection"]')) {
        $type = [string] $collection.GetAttribute('Type')
        # Not named $mode. docs/AUTHORING.md reserves that name: Invoke-Main holds the run
        # mode in a local $mode and PowerShell's scoping is dynamic, so a local
        # of the same name here is the same class of shadowing that trap warns
        # about - harmless today only because every use assigns before reading.
        $enforcementMode = [string] $collection.GetAttribute('EnforcementMode')
        if ([string]::IsNullOrWhiteSpace($enforcementMode)) { $enforcementMode = 'NotConfigured' }
        $facts.Enforcement[$type] = $enforcementMode
        $count = 0
        foreach ($rule in $collection.ChildNodes) {
            if ($rule.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $id = [string] $rule.GetAttribute('Id')
            if ([string]::IsNullOrWhiteSpace($id)) { continue }
            $count++
            $facts.Rules[$id.ToUpperInvariant()] = (Get-RuleSignature -RuleElement $rule -CollectionType $type)
        }
        $facts.RuleCount[$type] = $count
    }
    return $facts
}

function Get-RuleSignature {
    # Canonical, case-folded description of one rule: collection, element name,
    # action, and the condition. Two rules with the same signature are the same
    # rule as far as this script is concerned, which is what keeps -Apply
    # idempotent without comparing XML text.
    param(
        [Parameter(Mandatory = $true)] $RuleElement,
        [Parameter(Mandatory = $true)][string] $CollectionType
    )

    $parts = New-Object System.Collections.ArrayList
    [void] $parts.Add($CollectionType)
    [void] $parts.Add($RuleElement.LocalName)
    [void] $parts.Add([string] $RuleElement.GetAttribute('Action'))
    [void] $parts.Add([string] $RuleElement.GetAttribute('UserOrGroupSid'))

    $conditions = '*[local-name()="Conditions"]/'
    foreach ($path in $RuleElement.SelectNodes($conditions + '*[local-name()="FilePathCondition"]')) {
        [void] $parts.Add('path=' + [string] $path.GetAttribute('Path'))
    }
    foreach ($publisher in $RuleElement.SelectNodes($conditions + '*[local-name()="FilePublisherCondition"]')) {
        $low = '*'
        $high = '*'
        $range = $publisher.SelectSingleNode('*[local-name()="BinaryVersionRange"]')
        if ($null -ne $range) {
            $low  = [string] $range.GetAttribute('LowSection')
            $high = [string] $range.GetAttribute('HighSection')
        }
        [void] $parts.Add('pub=' + [string] $publisher.GetAttribute('PublisherName') +
                          '|' + [string] $publisher.GetAttribute('ProductName') +
                          '|' + [string] $publisher.GetAttribute('BinaryName') +
                          '|' + $low + '-' + $high)
    }
    foreach ($hash in $RuleElement.SelectNodes($conditions +
            '*[local-name()="FileHashCondition"]/*[local-name()="FileHash"]')) {
        [void] $parts.Add('hash=' + [string] $hash.GetAttribute('Data'))
    }
    return ((($parts.ToArray()) -join ';')).ToUpperInvariant()
}

function Get-EnforcingCollection {
    <#
        Rule collections that carry rules and are NOT in AuditOnly - the hosts
        this script must not touch.

        Two documented facts make this check mandatory rather than defensive.
        Microsoft on -Merge: "the enforcement setting specified by the AppLocker
        policy in the target GPO will be preserved", so merging AuditOnly rules
        into an enforcing GPO produces ENFORCED rules. And on inheritance: "Any
        rule collection with the enforcement mode set as 'not configured' is
        enforced", so an unset mode is not a safe state either.
        https://learn.microsoft.com/en-us/powershell/module/applocker/set-applockerpolicy
        https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understand-applocker-rules-and-enforcement-setting-inheritance-in-group-policy
    #>
    param([Parameter(Mandatory = $true)] $Facts)

    $enforcing = New-Object System.Collections.ArrayList
    foreach ($type in $Facts.Enforcement.Keys) {
        $count = 0
        if ($Facts.RuleCount.ContainsKey($type)) { $count = [int] $Facts.RuleCount[$type] }
        if ($count -le 0) { continue }
        if ($Facts.Enforcement[$type] -eq 'AuditOnly') { continue }
        [void] $enforcing.Add($type + '=' + [string] $Facts.Enforcement[$type] +
                              ' (' + [string] $count + ' rule(s))')
    }
    return $enforcing.ToArray()
}

#endregion

#region LOLBin rules ----------------------------------------------------------

<#
    The list. Every entry is a signed Microsoft executable an attacker uses to
    EXECUTE code or DOWNLOAD it - nothing is here for completeness. Rule Ids are
    fixed and hard-coded, not generated: that is what makes a second -Apply report
    zero changes, and what lets -Rollback tell this script's rules apart from
    anybody else's.

    Ids match the schema's GuidType pattern
    (https://learn.microsoft.com/en-us/windows/client-management/mdm/applocker-xsd).
#>
$script:BaselineRuleId = '1b0bb1a0-0000-4000-8000-000000000000'

$script:Lolbins = @(
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000001'; Name = 'certutil.exe';    Group = 'system32'
       Why = 'downloads any URL with -urlcache -f, and base64-decodes a payload with -decode' },
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000002'; Name = 'mshta.exe';       Group = 'system32'
       Why = 'executes HTA/VBScript/JScript, including straight from a remote URL' },
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000003'; Name = 'rundll32.exe';    Group = 'system32'
       Why = 'executes an exported function of any DLL, and script via the javascript: protocol' },
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000004'; Name = 'regsvr32.exe';    Group = 'system32'
       Why = 'runs a remote scriptlet via /i:<url> scrobj.dll - the Squiblydoo technique' },
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000005'; Name = 'bitsadmin.exe';   Group = 'system32'
       Why = 'downloads a file, and runs a command on job completion, as a BITS job' },
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000006'; Name = 'wmic.exe';        Group = 'wbem'
       Why = 'executes a remote XSL scriptlet via /format:, and spawns processes locally or remotely' },
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000007'; Name = 'cscript.exe';     Group = 'system32'
       Why = 'runs VBScript and JScript from the console host' },
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000008'; Name = 'wscript.exe';     Group = 'system32'
       Why = 'runs VBScript and JScript from the windowed host - the classic mail attachment' },
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000009'; Name = 'msbuild.exe';     Group = 'dotnet'
       Why = 'compiles and runs inline C# from a project file, so a .csproj is a payload' },
    @{ Id = '1b0bb1a0-0000-4000-8000-00000000000a'; Name = 'installutil.exe'; Group = 'dotnet'
       Why = 'runs an assembly''s installer/uninstaller class, executing code outside the normal path' },
    @{ Id = '1b0bb1a0-0000-4000-8000-00000000000b'; Name = 'regasm.exe';      Group = 'dotnet'
       Why = 'runs an assembly''s ComRegisterFunction code on registration' },
    @{ Id = '1b0bb1a0-0000-4000-8000-00000000000c'; Name = 'regsvcs.exe';     Group = 'dotnet'
       Why = 'same registration-callback execution as regasm, by a different binary' },
    @{ Id = '1b0bb1a0-0000-4000-8000-00000000000d'; Name = 'cmstp.exe';       Group = 'system32'
       Why = 'installs a Connection Manager INF whose command section runs an arbitrary scriptlet' },
    @{ Id = '1b0bb1a0-0000-4000-8000-00000000000e'; Name = 'odbcconf.exe';    Group = 'system32'
       Why = 'loads and executes an arbitrary DLL via its REGSVR action' },
    @{ Id = '1b0bb1a0-0000-4000-8000-00000000000f'; Name = 'forfiles.exe';    Group = 'system32'
       Why = 'spawns an arbitrary command per matched file, hiding the real parent process' },
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000010'; Name = 'pcalua.exe';      Group = 'system32'
       Why = 'the Program Compatibility Assistant launcher starts any process on request' },
    @{ Id = '1b0bb1a0-0000-4000-8000-000000000011'; Name = 'msiexec.exe';     Group = 'system32'
       Why = 'installs an MSI from a local path or a URL, running its embedded custom actions' }
)

function Get-LolbinSubdirectory {
    <#
        The directory a LOLBin sits in, relative to System32. Empty for the ones
        that really are in System32; 'wbem' for wmic.exe. Used for BOTH the
        on-disk search and the %SYSTEM32% path fallback, so the two can never
        disagree about where a binary lives.
    #>
    param([Parameter(Mandatory = $true)][hashtable] $Lolbin)

    if ($Lolbin.Group -eq 'wbem') { return 'wbem' }
    return ''
}

function Get-LolbinFile {
    <#
        Every on-disk copy of one LOLBin, so the publisher information is read
        from the real file rather than guessed.

        Sysnative is searched alongside System32 because of the WOW64 FILE system
        redirector: from a 32-bit process - and RMMs do launch
        SysWOW64\WindowsPowerShell\v1.0\powershell.exe - '%SystemRoot%\System32'
        resolves to SysWOW64, and Sysnative is the documented way to reach the
        real System32.
        https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
    #>
    param([Parameter(Mandatory = $true)][hashtable] $Lolbin)

    $systemRoot = $env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($systemRoot)) { $systemRoot = 'C:\Windows' }
    $systemRoot = $systemRoot.TrimEnd('\')
    $found = New-Object System.Collections.ArrayList

    if ($Lolbin.Group -eq 'dotnet') {
        # msbuild, installutil, regasm and regsvcs live under the .NET Framework
        # version directories, not System32, and there is one copy per installed
        # runtime and per bitness.
        $dotnetRoot = [System.IO.Path]::Combine($systemRoot, 'Microsoft.NET')
        if (Test-Path -LiteralPath $dotnetRoot) {
            foreach ($file in @(Get-ChildItem -LiteralPath $dotnetRoot -Filter $Lolbin.Name `
                        -Recurse -File -ErrorAction SilentlyContinue)) {
                [void] $found.Add([string] $file.FullName)
            }
        }
        return $found.ToArray()
    }

    # wmic.exe is NOT in System32. Measured on the lab (Server 2019 17763):
    # C:\Windows\System32\wbem\wmic.exe and C:\Windows\SysWOW64\wbem\wmic.exe,
    # both Authenticode Valid with BinaryName 'WMIC.EXE'. Searching System32
    # alone found nothing, so the script declared the single most-used LOLBin in
    # this list "not present" and wrote a path rule at %SYSTEM32%\wmic.exe -
    # a path wmic will never occupy. The rule covered nothing and the console
    # said it was covered.
    $subdirectory = Get-LolbinSubdirectory -Lolbin $Lolbin

    foreach ($directory in @('System32', 'Sysnative', 'SysWOW64')) {
        $base = [System.IO.Path]::Combine($systemRoot, $directory)
        if ($subdirectory -ne '') { $base = [System.IO.Path]::Combine($base, $subdirectory) }
        $candidate = [System.IO.Path]::Combine($base, $Lolbin.Name)
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { [void] $found.Add($candidate) }
    }
    return $found.ToArray()
}

function Get-LolbinPublisher {
    <#
        The publisher triple AppLocker itself would use, read from the file by
        Microsoft's own cmdlet rather than composed here. Get-AppLockerFileInformation
        "gets the AppLocker file information from a list of files... File
        information includes the publisher information, file hash, and file path",
        and "Files that are not signed will not have any publisher information".
        https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerfileinformation

        Composing a publisher string by hand would mean asserting Microsoft's
        exact certificate subject and product name from memory, which docs/AUTHORING.md
        forbids - and getting either wrong yields a rule that matches nothing.

        UNVERIFIED: the property NAMES on the Publisher object (PublisherName,
        ProductName, BinaryName). Microsoft's reference documents the returned
        FileInformation type's Publisher property but not its members, so each is
        read defensively and any gap falls back to a path rule.

        Returns $null when a publisher rule cannot be built.
    #>
    param([Parameter(Mandatory = $true)][string] $Path)

    $information = $null
    try { $information = Get-AppLockerFileInformation -Path $Path -ErrorAction Stop }
    catch {
        Write-Verbose ('Get-AppLockerFileInformation failed for ' + $Path + ': ' + $_.Exception.Message)
        return $null
    }
    if ($null -eq $information) { return $null }
    # -Path takes a list, so a single file can still come back as a one-element
    # collection; PowerShell unrolls it, but an array here would silently make
    # every property read below return an array too.
    if ($information -is [array]) {
        if ($information.Count -eq 0) { return $null }
        $information = $information[0]
    }

    $publisher = $information.Publisher
    if ($null -eq $publisher) { return $null }
    $values = @{}
    foreach ($name in @('PublisherName', 'ProductName', 'BinaryName')) {
        $values[$name] = ''
        if ($null -ne $publisher.PSObject.Properties[$name] -and $null -ne $publisher.$name) {
            $values[$name] = [string] $publisher.$name
        }
    }
    foreach ($name in @('PublisherName', 'ProductName', 'BinaryName')) {
        if ([string]::IsNullOrWhiteSpace($values[$name])) { return $null }
    }
    return $values
}

function Get-DesiredLolbinRule {
    <#
        One rule descriptor per LOLBin plus the baseline, built from what is
        actually on this host.

        Publisher conditions are preferred over path conditions for a documented
        reason: "Path rules that use the deny action, are less effective than
        other types of rules, because a user (or malware acting as a user) can
        easily copy the file to a different location to run it."
        https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-path-rule-condition-in-applocker
        A publisher condition keyed on BinaryName follows the binary when it is
        copied or renamed; a path condition does not, and a renamed certutil.exe
        in %TEMP% is the whole point.

        The path fallback uses %SYSTEM32%, which Microsoft maps to "System32 and
        sysWOW64" - one condition covering both bitnesses.
    #>
    $rules = New-Object System.Collections.ArrayList

    # The baseline. Read the header before changing anything about this rule.
    # Microsoft's asterisk semantics: "The asterisk (*) character used by itself
    # represents any path."
    [void] $rules.Add(@{
        Id       = $script:BaselineRuleId
        Action   = 'Allow'
        Kind     = 'path'
        Path     = '*'
        Baseline = $true
        Name     = 'IronBlackBox baseline: ALLOW ALL EXE'
        Description = ('Required so the LOLBin deny rules below produce targeted 8003 events instead ' +
                       'of every process on the host doing so. Removed by Enable-LolbinAudit -Rollback. ' +
                       'This rule allows everything: it would neuter a real application allowlist.')
    })

    foreach ($lolbin in $script:Lolbins) {
        $files = @(Get-LolbinFile -Lolbin $lolbin)
        $subdirectory = Get-LolbinSubdirectory -Lolbin $lolbin
        $fallbackRelativePath = $lolbin.Name
        if ($subdirectory -ne '') { $fallbackRelativePath = ($subdirectory + '\' + $lolbin.Name) }
        $rule = @{
            Id     = $lolbin.Id
            Action = 'Deny'
            Name   = ('IronBlackBox LOLBin audit: ' + $lolbin.Name)
            Description = ($lolbin.Name + ' - ' + $lolbin.Why + ' (AUDIT ONLY: nothing is blocked)')
            Kind   = 'path'
            Path   = ('%SYSTEM32%\' + $fallbackRelativePath)
        }
        if ($files.Count -eq 0) {
            if ($lolbin.Group -eq 'dotnet') {
                # No copy on this host and no fixed path to express: the .NET
                # binaries live under a per-runtime version directory whose name
                # is not knowable in advance. A guessed wildcard would either
                # match nothing or deny the whole Microsoft.NET tree, so the rule
                # is SKIPPED and reported rather than invented.
                Write-Finding ($lolbin.Name + ' - not present on this host and its path cannot be ' +
                               'expressed without one; no rule written for it')
                continue
            }
            # A %SYSTEM32% path rule for a System32 binary that is not here today
            # costs nothing and covers it if a later update brings it back.
            $rule.Missing = $true
            [void] $rules.Add($rule)
            continue
        }
        $publisher = Get-LolbinPublisher -Path $files[0]
        if ($null -ne $publisher) {
            $rule.Kind = 'publisher'
            $rule.Publisher = $publisher
        }
        elseif ($lolbin.Group -eq 'dotnet') {
            # No publisher information and no %SYSTEM32% to fall back on: pin the
            # first copy found by absolute path, and say what that misses.
            $rule.Path = [string] $files[0]
            $rule.PathOnlyCovers = $files.Count
        }
        [void] $rules.Add($rule)
    }
    return $rules.ToArray()
}

function New-LolbinPolicyXml {
    <#
        The policy document. Element and attribute names are the schema's:
        AppLockerPolicy/RuleCollection[@Type,@EnforcementMode], FilePathRule and
        FilePublisherRule with Id/Name/Description/UserOrGroupSid/Action, and
        Conditions/FilePathCondition[@Path] or
        Conditions/FilePublisherCondition[@PublisherName,@ProductName,@BinaryName]
        with a BinaryVersionRange.
        https://learn.microsoft.com/en-us/windows/client-management/mdm/applocker-xsd

        EnforcementMode is written EXPLICITLY as AuditOnly. Leaving it out would
        mean NotConfigured, and Microsoft states a rule collection with rules and
        no enforcement mode IS enforced - which for this policy would mean
        blocking seventeen binaries on a production host.

        Values go through SecurityElement::Escape: publisher subjects carry
        commas, registered-trademark characters and quotes, and an unescaped one
        would produce invalid XML or, worse, a rule that silently means something
        else.
    #>
    param([Parameter(Mandatory = $true)] $Rules)

    $builder = New-Object System.Text.StringBuilder
    [void] $builder.AppendLine('<AppLockerPolicy Version="1">')
    [void] $builder.AppendLine('  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">')
    foreach ($rule in $Rules) {
        $element = 'FilePathRule'
        if ($rule.Kind -eq 'publisher') { $element = 'FilePublisherRule' }
        [void] $builder.AppendLine('    <' + $element +
            ' Id="' + [System.Security.SecurityElement]::Escape([string] $rule.Id) + '"' +
            ' Name="' + [System.Security.SecurityElement]::Escape([string] $rule.Name) + '"' +
            ' Description="' + [System.Security.SecurityElement]::Escape([string] $rule.Description) + '"' +
            ' UserOrGroupSid="' + $script:EveryoneSid + '"' +
            ' Action="' + [string] $rule.Action + '">')
        [void] $builder.AppendLine('      <Conditions>')
        if ($rule.Kind -eq 'publisher') {
            [void] $builder.AppendLine('        <FilePublisherCondition' +
                ' PublisherName="' + [System.Security.SecurityElement]::Escape([string] $rule.Publisher['PublisherName']) + '"' +
                ' ProductName="' + [System.Security.SecurityElement]::Escape([string] $rule.Publisher['ProductName']) + '"' +
                ' BinaryName="' + [System.Security.SecurityElement]::Escape([string] $rule.Publisher['BinaryName']) + '">')
            # LowSection/HighSection "*" is the documented wildcard, so a Windows
            # update that changes the binary's version does not silently orphan
            # the rule.
            [void] $builder.AppendLine('          <BinaryVersionRange LowSection="*" HighSection="*" />')
            [void] $builder.AppendLine('        </FilePublisherCondition>')
        }
        else {
            [void] $builder.AppendLine('        <FilePathCondition Path="' +
                [System.Security.SecurityElement]::Escape([string] $rule.Path) + '" />')
        }
        [void] $builder.AppendLine('      </Conditions>')
        [void] $builder.AppendLine('    </' + $element + '>')
    }
    [void] $builder.AppendLine('  </RuleCollection>')
    [void] $builder.AppendLine('</AppLockerPolicy>')
    return $builder.ToString()
}

#endregion

#region LolbinAudit changes ---------------------------------------------------

function Save-AppLockerArtifact {
    # Writes one of this run's policy files under <ToolkitRoot>\AppLocker and
    # returns its path. Only ever called from -Apply: -Audit writes nothing,
    # anywhere (docs/DESIGN.md section 2).
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [Parameter(Mandatory = $true)][string] $FileName,
        [Parameter()][AllowEmptyString()][string] $Content = ''
    )
    if (-not (Test-Path -LiteralPath $Directory)) {
        [void] (New-Item -Path $Directory -ItemType Directory -Force)
    }
    $target = [System.IO.Path]::Combine($Directory, $FileName)
    # No BOM: Set-AppLockerPolicy -XmlPolicy has to read this back, and this is a
    # policy document rather than a PowerShell source file.
    [System.IO.File]::WriteAllText($target, $Content, (New-Object System.Text.UTF8Encoding($false)))
    return $target
}

function Test-ExeCollectionEnforcing {
    # $true when merging into this policy could produce ENFORCED deny rules:
    # either the Exe collection is explicitly Enabled, or it is NotConfigured
    # while carrying rules - which Microsoft states is enforced.
    param([Parameter(Mandatory = $true)] $Facts)

    if (-not $Facts.Enforcement.ContainsKey('Exe')) { return $false }
    # Not named $mode - see the note in Get-PolicyFact.
    $exeEnforcement = [string] $Facts.Enforcement['Exe']
    if ($exeEnforcement -eq 'Enabled') { return $true }
    if ($exeEnforcement -ne 'AuditOnly') {
        $count = 0
        if ($Facts.RuleCount.ContainsKey('Exe')) { $count = [int] $Facts.RuleCount['Exe'] }
        return ($count -gt 0)
    }
    return $false
}

function Set-LolbinAuditPolicy {
    <#
        Merges the audit-only rules into the LOCAL AppLocker policy, or reports
        that it would. Returns the number of changes made.

        The post-apply verification is not optional. Microsoft's -Merge
        documentation says the TARGET GPO's enforcement setting "will be
        preserved", and does not say what happens when the target has none - so
        whether this policy's AuditOnly actually lands is unknown until it is read
        back. If the Exe collection is anything but AuditOnly afterwards, the
        previous policy is restored immediately and the run fails: seventeen
        enforced deny rules on a production host is not a state to leave behind
        while reporting success.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $WorkDirectory,
        [Parameter()][AllowEmptyString()][string] $LocalXml = '',
        [Parameter()][AllowEmptyString()][string] $EffectiveXml = '',
        [Parameter(Mandatory = $true)] $LocalFacts,
        [Parameter(Mandatory = $true)][string] $DesiredXml,
        [Parameter(Mandatory = $true)] $DesiredFacts,
        [Parameter(Mandatory = $true)][bool] $Blocked
    )

    $exeMode = 'absent'
    if ($LocalFacts.Enforcement.ContainsKey('Exe')) { $exeMode = [string] $LocalFacts.Enforcement['Exe'] }

    $outstanding = New-Object System.Collections.ArrayList
    foreach ($id in $DesiredFacts.Rules.Keys) {
        if (-not $LocalFacts.Rules.ContainsKey($id)) { [void] $outstanding.Add($id); continue }
        if ($LocalFacts.Rules[$id] -cne $DesiredFacts.Rules[$id]) { [void] $outstanding.Add($id) }
    }

    if ([string]::IsNullOrWhiteSpace($LocalXml)) {
        # Without the current local policy there is nothing to record as the
        # previous value and nothing for -Rollback to restore. docs/DESIGN.md
        # section 4: a lost previous value is an unrecoverable change.
        Write-Finding ('the current LOCAL AppLocker policy could not be read, so no previous value ' +
                       'could be recorded - refusing to change the policy')
        return 0
    }
    if ($outstanding.Count -eq 0 -and $exeMode -eq 'AuditOnly') {
        Write-Ok ('all ' + [string] $DesiredFacts.Rules.Count +
                  ' audit rules are already in the local policy, Exe enforcement is AuditOnly')
        return 0
    }
    if ($Blocked) {
        # "not KNOWN to be in AuditOnly", because $Blocked now also covers a
        # policy XML that would not parse - where the mode was never determined
        # rather than determined to be enforcing. Saying which it was is the job
        # of the finding Invoke-HostCheck already printed above this one.
        Write-Finding ('REFUSING to merge: the Exe rule collection is not known to be in AuditOnly ' +
                       '(local=' + $exeMode +
                       '). Merging preserves the target GPO''s enforcement setting, so these deny rules ' +
                       'would be ENFORCED and 17 signed Windows binaries would stop working. Put the Exe ' +
                       'collection into Audit only in Group Policy first, then re-run.')
        return 0
    }
    if (-not $Apply) {
        Write-Finding ('would merge ' + [string] $outstanding.Count + ' of ' +
                       [string] $DesiredFacts.Rules.Count + ' rule(s) and set Exe enforcement to ' +
                       'AuditOnly (currently ' + $exeMode + ')')
        Write-Info 'command: Set-AppLockerPolicy -XmlPolicy <generated> -Merge'
        return 0
    }

    # Capture both policies and the intended one BEFORE the change, then record,
    # then change - the order docs/DESIGN.md section 4 requires.
    $previousLocalFile = Save-AppLockerArtifact -Directory $WorkDirectory `
        -FileName ('local-before-' + $script:CurrentRunId + '.xml') -Content $LocalXml
    $previousEffectiveFile = Save-AppLockerArtifact -Directory $WorkDirectory `
        -FileName ('effective-before-' + $script:CurrentRunId + '.xml') -Content $EffectiveXml
    $policyFile = Save-AppLockerArtifact -Directory $WorkDirectory `
        -FileName ('lolbin-audit-' + $script:CurrentRunId + '.xml') -Content $DesiredXml

    [void] (Write-ManifestChange -Change @{
        type                      = 'applockerpolicy'
        # The whole policy inline in a JSONL record would be unwieldy, so the
        # bodies live in files under the toolkit root and the record carries their
        # paths and hashes. -Rollback verifies the hash before restoring.
        previousLocalPolicyPath   = $previousLocalFile
        previousLocalPolicyHash   = (Get-FileSha256 -Path $previousLocalFile)
        previousEffectivePath     = $previousEffectiveFile
        previousEffectiveHash     = (Get-FileSha256 -Path $previousEffectiveFile)
        previousExeEnforcement    = $exeMode
        previousRuleIds           = @($LocalFacts.Rules.Keys)
        appliedPolicyPath         = $policyFile
        appliedPolicyHash         = (Get-FileSha256 -Path $policyFile)
        ruleIds                   = @($DesiredFacts.Rules.Keys)
        description               = ('AppLocker Exe collection: ' + [string] $DesiredFacts.Rules.Count +
                                     ' audit-only rule(s) merged into the local policy')
    })

    Set-AppLockerPolicy -XmlPolicy $policyFile -Merge
    Write-Info 'Set-AppLockerPolicy -Merge returned; verifying what actually landed.'

    $afterFacts = Get-PolicyFact -Xml (Get-AppLockerPolicyXml -Scope 'Local')
    $afterMode = 'absent'
    if ($afterFacts.Enforcement.ContainsKey('Exe')) { $afterMode = [string] $afterFacts.Enforcement['Exe'] }
    $stillMissing = New-Object System.Collections.ArrayList
    foreach ($id in $DesiredFacts.Rules.Keys) {
        if (-not $afterFacts.Rules.ContainsKey($id)) { [void] $stillMissing.Add($id) }
    }

    if ($afterMode -ne 'AuditOnly' -or $stillMissing.Count -gt 0) {
        Write-Failure ('the merge did not produce an audit-only policy (Exe enforcement is ' + $afterMode +
                       ', ' + [string] $stillMissing.Count + ' rule(s) missing) - restoring the previous policy')
        Set-AppLockerPolicy -XmlPolicy $previousLocalFile
        throw ('AppLocker merge could not be confirmed as AuditOnly; the previous local policy was ' +
               'restored from ' + $previousLocalFile)
    }

    Write-Ok ([string] $DesiredFacts.Rules.Count + ' audit-only rule(s) in the local policy, Exe ' +
              'enforcement confirmed AuditOnly')
    return 1
}

function Test-LolbinAuditEffective {
    <#
        Proves the policy is LIVE by making it fire, because reading it back out
        of the policy store proves only that the store holds it.

        This is not a hypothetical distinction. On the lab, on a host where
        AppLocker had never been active, -Apply merged the policy, re-read it,
        confirmed Exe enforcement AuditOnly, started AppIDSvc and reported
        success - and certutil.exe then ran with ZERO events in the channel. The
        policy was inert. After a computer Group Policy refresh it fired, and on
        every later -Apply it fired immediately. A technician deploying that to a
        fleet would have had no LOLBin visibility at all and no way to know.

        Test-AppLockerPolicy cannot close this gap: it evaluates a policy OBJECT
        in-process and would answer "Denied" for a policy the kernel is not
        enforcing. Only an actual execution proves an actual evaluation.

        The canary is 'certutil.exe -?' - it prints its own usage text, touches
        nothing, and is proven on the lab to raise 8003 exactly like a real
        invocation, because AppLocker evaluates at process creation and does not
        care about the arguments. It writes one 8003 naming CERTUTIL.EXE into the
        channel, which is a deliberate, explained entry rather than a mystery.

        Returns nothing; reports Ok or a Finding.
    #>
    param([Parameter(Mandatory = $true)][array] $Rules)

    Write-Section 'Proof that the policy is live'

    $certutil = $null
    foreach ($lolbin in $script:Lolbins) {
        if ($lolbin.Name -ne 'certutil.exe') { continue }
        $files = @(Get-LolbinFile -Lolbin $lolbin)
        if ($files.Count -gt 0) { $certutil = [string] $files[0] }
    }
    if ($null -eq $certutil) {
        Write-Finding 'certutil.exe is not on this host, so the policy could not be proven live by effect'
        return
    }

    $canaryName = [System.IO.Path]::GetFileName($certutil)
    $since = (Get-Date).AddSeconds(-5)
    try { & $certutil -? | Out-Null }
    catch {
        Write-Finding ('the canary execution failed (' + $_.Exception.Message + '), so the policy could ' +
                       'not be proven live')
        return
    }

    # The channel is written asynchronously by the service, so a hit can lag the
    # execution. Poll rather than sleep once and guess.
    $observed = 0
    $unrelated = 0
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        Start-Sleep -Seconds 2
        $events = @()
        try {
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName = $script:AppLockerChannel; Id = 8003; StartTime = $since
            } -ErrorAction Stop)
        }
        catch { $events = @() }
        # THE CANARY'S OWN 8003, not just any 8003 in the window. Sixteen other
        # LOLBins carry deny rules from this same policy, so on a host where one
        # of them fires inside these twenty seconds the count alone reported
        # "running certutil.exe raised event 8003" without this function ever
        # having observed its own canary - attributing somebody else's event to
        # itself, in the one place the script argues that a read-back is not an
        # observation.
        #
        # Matched on the rendered message because the 8003 event's data field
        # NAMES are not documented anywhere this project can cite; the docstring
        # above records that the event names CERTUTIL.EXE, which was measured.
        # UNVERIFIED: whether a named event-data field would be a stabler key.
        # Failing to match leaves the proof UNPROVEN rather than falsely proven,
        # which is the safe direction for this function.
        $observed = 0
        foreach ($record in $events) {
            $message = ''
            if ($null -ne $record.Message) { $message = [string] $record.Message }
            if ($message.IndexOf($canaryName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $observed++
            }
        }
        $unrelated = $events.Count - $observed
        if ($observed -gt 0) { break }
    }

    if ($observed -gt 0) {
        Write-Ok ('policy proven LIVE: running ' + $canaryName + ' raised an event 8003 naming it in ' +
                  $script:AppLockerChannel + '. ' + [string] $Rules.Count + ' rule(s) are in force and ' +
                  'nothing was blocked.')
        return
    }

    if ($unrelated -gt 0) {
        Write-Finding ('a policy IS being evaluated on this host - ' + [string] $unrelated + ' event 8003(s) ' +
                       'appeared in the window - but none of them names ' + $canaryName + ', so THIS ' +
                       'script''s rule for it is not proven live. Read ' + $script:AppLockerChannel +
                       ' before treating this host as audited.')
        return
    }

    Write-Finding ('the policy is in the local store and AppIDSvc is running, but running ' + $canaryName +
                   ' raised NO 8003 event - the policy is NOT being evaluated. This is the documented ' +
                   'first-activation case: run "gpupdate /target:computer /force" and re-run this script ' +
                   'with -Apply, or reboot. Do not treat this host as audited until a re-run reports the ' +
                   'policy live.')
}

function Set-AppIdServiceAutomatic {
    <#
        Without a running Application Identity service the policy is inert, and
        reporting success would be a lie: "Stopping this service prevents
        AppLocker policies from being enforced."

        The start type is a tracked REG_DWORD write, not sc.exe - see
        Get-AppIdServiceState for why. Starting the service is NOT tracked: it is
        transient state, and -Rollback deliberately leaves a running protected
        service running rather than deactivating an AppLocker policy this script
        did not put on the host.

        The $Enforcing guard is the important part. If any rule collection is
        carrying rules in an enforcing mode while AppIDSvc is stopped, that policy
        is inert right now - and starting the service would activate somebody
        else's enforcement, breaking applications this script never looked at.
        That is refused, loudly.
    #>
    param(
        [Parameter(Mandatory = $true)] $State,
        # Not Mandatory: the common case is an empty array, and a Mandatory
        # parameter's null/empty rejection is not worth risking on a value whose
        # emptiness is the GOOD state.
        [Parameter()][string[]] $Enforcing = @()
    )
    Write-Section 'Application Identity service (AppIDSvc)'

    if (-not $State.Present) {
        Write-Finding 'AppIDSvc is not present on this host - AppLocker cannot evaluate anything'
        return 0
    }
    Write-Info ('status ' + $State.Status + ', Start value ' + [string] $State.StartValue +
                ' (2=Automatic, 3=Manual, 4=Disabled)')

    if ($Enforcing.Count -gt 0) {
        Write-Finding ('REFUSING to enable or start AppIDSvc: ' + (($Enforcing) -join '; ') +
                       '. That policy is inert while the service is stopped, and starting the service ' +
                       'would begin enforcing it. Resolve the enforcing collection first.')
        return 0
    }

    $changes = 0
    if (Set-TrackedRegistryValue -Path $script:AppIdServiceKey -Name 'Start' `
        -Kind 'DWord' -Value $script:StartAutomatic `
        -Description 'AppIDSvc start type Automatic') { $changes++ }

    if ($State.Status -eq 'Running') {
        Write-Ok 'AppIDSvc is running'
        return $changes
    }
    if (-not $Apply) {
        Write-Finding 'AppIDSvc is not running - would start it so the audit policy is evaluated'
        return $changes
    }
    try {
        Start-Service -Name $script:AppIdServiceName
        Write-Ok 'AppIDSvc started (not a tracked change - transient state)'
    }
    catch {
        Write-Finding ('AppIDSvc could not be started, so the policy stays inert until reboot: ' +
                       $_.Exception.Message)
    }
    return $changes
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

    Write-Section 'AppLocker availability'
    $missing = @(Get-MissingAppLockerCmdlet)
    if ($missing.Count -gt 0) {
        Write-Finding ('these AppLocker cmdlets are not available on this host: ' + ($missing -join ', ') +
                       '. Nothing was read or changed - see this script''s UNVERIFIED note on whether ' +
                       'the AppLocker module is in-box on Server SKUs.')
        return 0
    }
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-Ok ('AppLocker cmdlets available on ' + [string] $operatingSystem.Caption +
              ' (ProductType ' + [string] $operatingSystem.ProductType + ')')

    Write-Section 'Current AppLocker policy'
    $localXml     = Get-AppLockerPolicyXml -Scope 'Local'
    $effectiveXml = Get-AppLockerPolicyXml -Scope 'Effective'
    $localFacts     = Get-PolicyFact -Xml $localXml
    $effectiveFacts = Get-PolicyFact -Xml $effectiveXml
    foreach ($pair in @(@('local', $localFacts), @('effective', $effectiveFacts))) {
        $facts = $pair[1]
        if ($facts.Enforcement.Count -eq 0) {
            Write-Info ($pair[0] + ': no rule collections')
            continue
        }
        foreach ($type in $facts.Enforcement.Keys) {
            $count = 0
            if ($facts.RuleCount.ContainsKey($type)) { $count = [int] $facts.RuleCount[$type] }
            Write-Info ($pair[0] + ': ' + $type + ' EnforcementMode=' + [string] $facts.Enforcement[$type] +
                        ', ' + [string] $count + ' rule(s)')
        }
    }
    $enforcing = @(Get-EnforcingCollection -Facts $effectiveFacts)
    if ($enforcing.Count -gt 0) {
        Write-Finding ('rule collections already ENFORCING on this host: ' + ($enforcing -join '; '))
    }
    # FAIL CLOSED on a policy that will not parse, which is where this guard used
    # to fail OPEN. Get-PolicyFact returns Parsed=$false with an EMPTY Enforcement
    # map when LoadXml throws, and Test-ExeCollectionEnforcing answers $false for
    # a map carrying no 'Exe' key - so an unparseable local policy produced
    # $blocked = $false, and the merge went ahead against a GPO whose enforcement
    # mode had never been determined. Microsoft preserves the target GPO's
    # enforcement setting on -Merge (see the header), which is how seventeen deny
    # rules land ENFORCED. The generated policy is already checked this way at
    # $desiredFacts.Parsed below; the host's own policy was not.
    #
    # An EMPTY string is a different case and is already handled: it means the
    # read itself failed, and Set-LolbinAuditPolicy refuses because there would be
    # no previous value to record.
    $unparseable = New-Object System.Collections.ArrayList
    if (-not [string]::IsNullOrWhiteSpace($localXml) -and -not $localFacts.Parsed) {
        [void] $unparseable.Add('local')
    }
    if (-not [string]::IsNullOrWhiteSpace($effectiveXml) -and -not $effectiveFacts.Parsed) {
        [void] $unparseable.Add('effective')
    }
    if ($unparseable.Count -gt 0) {
        Write-Finding ('the ' + (($unparseable.ToArray()) -join ' and ') + ' AppLocker policy XML could ' +
                       'not be parsed, so this host''s Exe enforcement mode is UNKNOWN. Nothing is ' +
                       'merged: a merge preserves the target GPO''s enforcement setting, and guessing ' +
                       'here is how audit-only deny rules become enforced ones.')
    }
    # Blocked when either view could turn a merge into enforcement, or when
    # either view could not be read well enough to tell. Both reads above are
    # pure, so -or short-circuiting is harmless here.
    $blocked = (Test-ExeCollectionEnforcing -Facts $localFacts) -or
               (Test-ExeCollectionEnforcing -Facts $effectiveFacts) -or
               ($unparseable.Count -gt 0)

    Write-AppLockerChannelReport

    Write-Section 'LOLBin audit rules'
    $desired      = @(Get-DesiredLolbinRule)
    $desiredXml   = New-LolbinPolicyXml -Rules $desired
    $desiredFacts = Get-PolicyFact -Xml $desiredXml
    if (-not $desiredFacts.Parsed) { throw 'the generated AppLocker policy XML did not parse.' }

    foreach ($rule in $desired) {
        $condition = ('path ' + [string] $rule.Path)
        if ($rule.Kind -eq 'publisher') {
            $condition = ('publisher ' + [string] $rule.Publisher['BinaryName'] + ' / ' +
                          [string] $rule.Publisher['PublisherName'])
        }
        Write-Info ([string] $rule.Action + ' - ' + [string] $rule.Name + ' - ' + $condition)
        if ($null -ne $rule.Missing) {
            # A host limit, not a finding: whether this Windows build ships this
            # LOLBin is not something any -Apply changes, and the rule IS written
            # regardless, so the outcome is already correct. As a finding it made
            # every host missing any one of the eighteen binaries permanently
            # exit 1 for a condition with no action attached.
            Write-HostLimit ([string] $rule.Name + ' - not present on this host; the rule is written anyway ' +
                             'so a later Windows update that brings it back is covered')
        }
        elseif ($rule.Kind -ne 'publisher' -and $null -eq $rule.Baseline) {
            # Also a host limit. The file's own signature metadata is what it is;
            # no run of this script gives pcalua.exe a BinaryName. The weaker
            # PATH rule is written and works - this text explains WHY it is the
            # weaker one, which an operator wants to read once, not be paged
            # about on every host on every run.
            Write-HostLimit ([string] $rule.Name + ' - no COMPLETE publisher identity, falling back to a PATH ' +
                           'rule. A publisher condition needs PublisherName, ProductName and BinaryName ' +
                           'together, and at least one of the three is empty for this file - the file may ' +
                           'still be signed. Measured case: pcalua.exe on Server 2019 is Authenticode Valid ' +
                           'and Microsoft-signed, but reports an empty BinaryName, and a publisher rule ' +
                           'with no BinaryName would match every Microsoft Windows binary on the host. ' +
                           'A path deny rule does not follow the binary when it is copied or renamed.')
            if ($null -ne $rule.PathOnlyCovers -and [int] $rule.PathOnlyCovers -gt 1) {
                Write-Finding ([string] $rule.Name + ' - ' + [string] $rule.PathOnlyCovers +
                               ' copies exist but the path rule covers only ' + [string] $rule.Path)
            }
        }
    }
    Write-Info ('audit events to watch: 8003 in "' + $script:AppLockerChannel +
                '" - "was allowed to run but would have been prevented from running if the AppLocker ' +
                'policy were enforced". 8004 would mean enforcement, which this script never sets.')

    $changeCount = 0
    $changeCount += Set-LolbinAuditPolicy -WorkDirectory $WorkDirectory -LocalXml $localXml `
        -EffectiveXml $effectiveXml -LocalFacts $localFacts -DesiredXml $desiredXml `
        -DesiredFacts $desiredFacts -Blocked $blocked
    $changeCount += Set-AppIdServiceAutomatic -State (Get-AppIdServiceState) -Enforcing $enforcing
    # $blocked means merging here could produce ENFORCED deny rules, and the
    # header's promise is that this script then changes NOTHING. The resize used
    # to run anyway: -Apply printed "REFUSING to merge", refused to touch
    # AppIDSvc, then enabled and grew the channel, wrote an eventchannel record
    # and reported "1 change(s) applied" a few lines under its own refusal - two
    # console lines an operator reading an RMM log cannot reconcile. Sizing a
    # channel for audit data this run will not produce buys nothing either; it
    # happens on the re-run, once the Exe collection is in Audit only.
    if ($blocked) {
        Write-Info ($script:AppLockerChannel + ' is NOT sized on a host where the merge is refused: ' +
                    'this run changes nothing. Re-run once the Exe collection is in Audit only.')
    }
    else {
        $changeCount += Set-AppLockerChannelSize
    }

    # -Apply ONLY. Invoke-HostCheck runs in every mode and the setters above each
    # branch on $Apply themselves; the canary executes a binary and writes an
    # event, which -Audit is not allowed to do.
    # After the service, never before it: an inert policy and a stopped service
    # look identical from the channel, and the point is to tell them apart.
    if ($Apply -and -not $blocked) { Test-LolbinAuditEffective -Rules @($desiredFacts.Rules.Keys) }
    return $changeCount
}

#endregion

#region Main -----------------------------------------------------------------

function Get-NormalisedIdSet {
    # Rule Ids from a manifest record, upper-cased for comparison. JSON gives
    # back an Object[] of strings, so the cast is not cosmetic.
    param($Value)
    $set = @{}
    if ($null -eq $Value) { return $set }
    foreach ($id in [string[]] $Value) {
        if (-not [string]::IsNullOrWhiteSpace($id)) { $set[$id.ToUpperInvariant()] = $true }
    }
    return $set
}

function Test-SameIdSet {
    param([Parameter(Mandatory = $true)][hashtable] $Left, [Parameter(Mandatory = $true)][hashtable] $Right)
    if ($Left.Count -ne $Right.Count) { return $false }
    foreach ($key in $Left.Keys) { if (-not $Right.ContainsKey($key)) { return $false } }
    return $true
}

function Restore-AppLockerChannelChange {
    <#
        AT-4's inverse: puts the AppLocker channel's recorded previous maximum
        size and enabled state back.

        THREE-way resolution (docs/DESIGN.md section 4.1). This branch used to
        have NONE. It read no current channel state at all, took the previous
        size and enabled flag out of the record, ran wevtutil unconditionally and
        returned 'restored' - there was no code path by which it could ever
        decline. Concretely: -Apply raised the channel from 1,052,672 to
        134,217,728 bytes, an administrator later set it to 512 MiB on purpose,
        and -Rollback shrank it to 1,052,672 and called that a restore,
        discarding a deliberate human decision on the one channel whose whole
        point is retaining evidence. It also could not tell a resize that never
        landed from one an operator has since re-tuned.

        The channel name is constrained by the SCRIPT, through
        $script:OwnedChannel, never by the record. The manifest is
        operator-writable input, and an 'eventchannel' record was one line away
        from turning -Rollback into 'wevtutil sl
        Microsoft-Windows-Sysmon/Operational /e:false' running as SYSTEM - the
        single code path in this script that can switch a channel off on
        instruction from a file. Restore-TrackedChange defends the identical
        boundary for the registry through $script:OwnedRegistryKey.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change    = $ChangeRecord.change
    $channel   = [string] $change.channel
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture

    $owned = $false
    foreach ($candidate in $script:OwnedChannel) {
        if ([string]::Equals($candidate, $channel, [System.StringComparison]::OrdinalIgnoreCase)) {
            $owned = $true
            break
        }
    }
    if (-not $owned) {
        throw ('Refusing to roll back an eventchannel change for "' + $channel + '"; this script only ' +
               'owns ' + (($script:OwnedChannel) -join ', ') + '. A manifest record naming any other ' +
               'channel did not come from this script.')
    }

    # BILINGUAL BY NECESSITY. The manifest is append-only, so a record written
    # before the field names were aligned keeps its original spelling. Renaming
    # the writer above does not rename what is already on disk.
    $previousMax = 0
    $recordedPrevious = [string] $change.previousMaxSizeBytes
    if ([string]::IsNullOrWhiteSpace($recordedPrevious)) { $recordedPrevious = [string] $change.previousMaxSize }
    if (-not [long]::TryParse($recordedPrevious, [System.Globalization.NumberStyles]::Integer,
            $invariant, [ref] $previousMax)) {
        Write-Finding ($channel + ': the recorded previous maximum size is unreadable, so declining ' +
                       'rather than guessing a size for a forensic channel')
        return 'declined'
    }
    # FAIL CLOSED on an unreadable intended size. Without it there is no way to
    # tell whether the host still holds what this run set, and a guard a record
    # can switch off by omitting one field is not a guard.
    $intendedMax = 0
    $recordedNew = [string] $change.newMaxSizeBytes
    if ([string]::IsNullOrWhiteSpace($recordedNew)) { $recordedNew = [string] $change.newMaxSize }
    if (-not [long]::TryParse($recordedNew, [System.Globalization.NumberStyles]::Integer,
            $invariant, [ref] $intendedMax) -or $intendedMax -le 0) {
        Write-Finding ($channel + ': the record does not say what size this run applied, so whether the ' +
                       'host still holds it cannot be told. Leaving it alone.')
        return 'declined'
    }

    # ABSENT and MERELY UNREADABLE get different verdicts. -ErrorAction
    # SilentlyContinue returns $null for both, and 'declined' is retryable - so a
    # channel that is genuinely gone would keep the run eligible forever and
    # Test-VisibilityDrift expecting the change. The discriminator is an
    # enumeration rather than the error text, because matching a message is
    # locale-dependent and this toolkit runs on fr-FR hosts.
    $log = Get-WinEvent -ListLog $channel -ErrorAction SilentlyContinue
    if ($null -eq $log) {
        $known = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                   Where-Object { [string]::Equals([string] $_.LogName, $channel,
                                                   [System.StringComparison]::OrdinalIgnoreCase) })
        if ($known.Count -eq 0) {
            Write-Finding ($channel + ' is not present on this host at all, so there is no channel to ' +
                           'restore a size to and no retry will change that.')
            return $script:RollbackDeclinedPermanent
        }
        Write-Finding ($channel + ' exists on this host but cannot be read, so a restore cannot be ' +
                       'verified; leaving it alone. Retryable - a permission or service problem clears.')
        return 'declined'
    }
    $currentMax = 0
    if ($null -ne $log.PSObject.Properties['MaximumSizeInBytes'] -and $null -ne $log.MaximumSizeInBytes) {
        $currentMax = [long] $log.MaximumSizeInBytes
    }
    $currentEnabled = $true
    if ($null -ne $log.PSObject.Properties['IsEnabled'] -and $null -ne $log.IsEnabled) {
        $currentEnabled = [bool] $log.IsEnabled
    }

    # Both defaults below are facts about THIS SCRIPT rather than readings of the
    # record: Set-AppLockerChannelSize always passes /e:true and always records
    # previousEnabled. A record missing either field is older than the writer or
    # was not written by it, and 'enabled' is the side that never switches a
    # forensic channel off.
    $intendedEnabled = $true
    if ($null -ne $change.PSObject.Properties['newEnabled'] -and $null -ne $change.newEnabled) {
        $intendedEnabled = [bool] $change.newEnabled
    }
    $previousEnabled = $true
    if ($null -ne $change.PSObject.Properties['previousEnabled'] -and $null -ne $change.previousEnabled) {
        $previousEnabled = [bool] $change.previousEnabled
    }

    # Case 2 first: the host already holds its recorded previous state - already
    # undone, or the resize never landed. Both mean leave it alone and count it
    # done, so the run converges instead of declining forever.
    if ($currentMax -eq $previousMax -and $currentEnabled -eq $previousEnabled) {
        Write-Ok ($channel + ' already holds its recorded previous state (' + [string] $previousMax +
                  ' bytes, enabled=' + [string] $previousEnabled + '); nothing to undo.')
        return 'restored'
    }
    # Case 3: neither what the run set nor what it recorded. A third party has
    # been here - an administrator who sized this channel deliberately, or a
    # later run of this script - and shrinking it would discard their decision
    # along with every event that no longer fits.
    if ($currentMax -ne $intendedMax -or $currentEnabled -ne $intendedEnabled) {
        Write-Finding ($channel + ' is ' + [string] $currentMax + ' bytes, enabled=' +
                       [string] $currentEnabled + ' - neither what this run set (' + [string] $intendedMax +
                       ' bytes, enabled=' + [string] $intendedEnabled + ') nor what it recorded before (' +
                       [string] $previousMax + ' bytes, enabled=' + [string] $previousEnabled +
                       '). Something else has changed this channel; leaving it alone.')
        return 'declined'
    }

    # Case 1: the host holds what -Apply set.
    if ($previousMax -lt $currentMax) {
        Write-Info ($channel + ': restoring the smaller previous size DISCARDS the events that no longer ' +
                    'fit. That is what the recorded previous value was.')
    }
    $enabledArg = '/e:true'
    if (-not $previousEnabled) { $enabledArg = '/e:false' }
    # Through the wrapper, for the reason given at the sizing call above.
    $wevt = Invoke-NativeCommand -FilePath $script:WevtutilPath `
        -Arguments @('sl', $channel, $enabledArg, ('/ms:' + $previousMax.ToString($invariant)))
    if ($wevt.ExitCode -ne 0) {
        Write-Failure ('wevtutil sl exited ' + [string] $wevt.ExitCode + ' restoring ' + $channel)
        throw ('wevtutil sl failed restoring ' + $channel + ': ' + (($wevt.Output -join ' ').Trim()))
    }

    # READ IT BACK. A native tool's exit code is not a claim about its output, and
    # here that is measured rather than general: verification/facts.json records
    # 'wevtutil sl <channel> /ms:1052672' NOT sticking while an EventLog policy
    # specified a larger size, with wevtutil still exiting 0. That is this exact
    # call, and reporting 'restored' on the exit code alone would take the run out
    # of the eligible set while the channel kept the size this toolkit set.
    $after = Get-WinEvent -ListLog $channel -ErrorAction SilentlyContinue
    $afterMax = -1
    if ($null -ne $after -and $null -ne $after.PSObject.Properties['MaximumSizeInBytes'] -and
        $null -ne $after.MaximumSizeInBytes) {
        $afterMax = [long] $after.MaximumSizeInBytes
    }
    if ($afterMax -lt 0) {
        Write-Finding ($channel + ': wevtutil exited 0 but the channel size cannot be read back, so the ' +
                       'restore is not confirmed.')
        return 'declined'
    }
    # A one-sided tolerance for the 64 KB block wevtutil is reported to round
    # /ms: up to. It has to be one-sided: '-ge $previousMax' alone would pass a
    # channel that never shrank at all, which is the fail-open this read-back
    # exists to close.
    $roundingBlock = 65536
    if ($afterMax -lt $previousMax -or $afterMax -ge ($previousMax + $roundingBlock)) {
        Write-Finding ($channel + ': wevtutil exited 0 restoring ' + [string] $previousMax +
                       ' bytes but the channel now reads ' + [string] $afterMax + '. Something is ' +
                       'overriding the channel - an EventLog policy MaxSize does exactly this. Leaving ' +
                       'the run retryable rather than reporting a restore that did not land.')
        return 'declined'
    }
    Write-Ok ($channel + ' maximum size restored to ' + [string] $afterMax +
              ' bytes (read back and confirmed)')
    return 'restored'
}

function Restore-LolbinAuditChange {
    <#
        Routes a change record to its inverse. This script's registry change (the
        AppIDSvc start type) goes to the template's Restore-TrackedChange, which
        already resolves an unconfirmed write against the host. Its channel resize
        goes to Restore-AppLockerChannelChange. Only 'applockerpolicy' is handled
        inline here.

        Returns 'restored', 'declined' or 'declined-permanent'; throws on failure.

        The restore is a REPLACE - Set-AppLockerPolicy without -Merge - because an
        exact replace is the only true inverse of a merge, and the merge's own
        documentation says a merge "will remove rules with duplicate rule Ids"
        rather than removing anything. Replacing is destructive, so it is gated:
        the recorded backup's hash must still match, and the local policy's rule
        Id set must be exactly the recorded previous set plus this run's rules. If
        anything else has been added since, the change is DECLINED rather than
        guessed at - the run stays retryable and the operator keeps their rules.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change

    # AT-4: undo a channel resize. Three-way against the host, and constrained to
    # a channel this script owns - see Restore-AppLockerChannelChange.
    if ([string] $change.type -eq 'eventchannel') {
        return (Restore-AppLockerChannelChange -ChangeRecord $ChangeRecord)
    }

    if ([string] $change.type -ne 'applockerpolicy') {
        return (Restore-TrackedChange -ChangeRecord $ChangeRecord)
    }

    $previousPath = [string] $change.previousLocalPolicyPath
    if ([string]::IsNullOrWhiteSpace($previousPath) -or
        -not (Test-Path -LiteralPath $previousPath -PathType Leaf)) {
        Write-Finding ('the recorded previous AppLocker policy is missing: ' + $previousPath)
        return 'declined'
    }
    $recordedHash = [string] $change.previousLocalPolicyHash
    $actualHash = [string] (Get-FileSha256 -Path $previousPath)
    if (-not [string]::Equals($recordedHash, $actualHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Finding ('the recorded previous AppLocker policy does not match its hash - refusing to ' +
                       'apply it. Recorded ' + $recordedHash + ', on disk ' + $actualHash)
        return 'declined'
    }
    if ((Get-MissingAppLockerCmdlet).Count -gt 0) {
        Write-Finding 'the AppLocker cmdlets are not available on this host - cannot restore the policy'
        return 'declined'
    }

    $previousIds = Get-NormalisedIdSet -Value $change.previousRuleIds
    $ourIds      = Get-NormalisedIdSet -Value $change.ruleIds
    $currentFacts = Get-PolicyFact -Xml (Get-AppLockerPolicyXml -Scope 'Local')
    $currentIds = @{}
    foreach ($id in $currentFacts.Rules.Keys) { $currentIds[[string] $id] = $true }

    if (Test-SameIdSet -Left $currentIds -Right $previousIds) {
        Write-Ok 'the local AppLocker policy already holds exactly the recorded previous rules'
        return 'restored'
    }
    $expected = @{}
    foreach ($id in $previousIds.Keys) { $expected[$id] = $true }
    foreach ($id in $ourIds.Keys) { $expected[$id] = $true }
    if (-not (Test-SameIdSet -Left $currentIds -Right $expected)) {
        Write-Finding ('the local AppLocker policy now holds ' + [string] $currentIds.Count +
                       ' rule(s), not the ' + [string] $expected.Count + ' this run left behind. ' +
                       'Something else has changed it, and restoring would discard those rules - ' +
                       'declining. The recorded previous policy is at ' + $previousPath)
        return 'declined'
    }

    Set-AppLockerPolicy -XmlPolicy $previousPath
    $afterFacts = Get-PolicyFact -Xml (Get-AppLockerPolicyXml -Scope 'Local')
    $afterIds = @{}
    foreach ($id in $afterFacts.Rules.Keys) { $afterIds[[string] $id] = $true }
    if (-not (Test-SameIdSet -Left $afterIds -Right $previousIds)) {
        throw ('the AppLocker policy was replaced but reads back with ' + [string] $afterIds.Count +
               ' rule(s) instead of ' + [string] $previousIds.Count + '; the recorded previous policy ' +
               'is preserved at ' + $previousPath)
    }
    $afterMode = 'absent'
    if ($afterFacts.Enforcement.ContainsKey('Exe')) { $afterMode = [string] $afterFacts.Enforcement['Exe'] }
    $recordedMode = [string] $change.previousExeEnforcement
    if (-not [string]::IsNullOrWhiteSpace($recordedMode) -and $afterMode -ne $recordedMode) {
        Write-Finding ('the rules were restored but the Exe enforcement mode reads back as ' + $afterMode +
                       ', not the recorded ' + $recordedMode + ' - check it in Group Policy')
    }
    Write-Ok ('Restored the local AppLocker policy from ' + [System.IO.Path]::GetFileName($previousPath))
    return 'restored'
}

function Invoke-Main {
    $mode = 'Audit'
    if ($Apply)    { $mode = 'Apply' }
    if ($Rollback) { $mode = 'Rollback' }

    Write-Host ''
    Write-Host ('IronBlackBox - ' + $script:ScriptName + ' v' + $script:ScriptVersion + ' [' + $mode + ']') -ForegroundColor White
    Write-Host '  AUDIT MODE ONLY. This script has no enforcement switch and never blocks anything.' -ForegroundColor White

    # P-1: value checks BEFORE anything is read, locked or changed. These were
    # [Validate*] attributes; a binding-time failure exits 1, which collides with
    # "findings" (docs/DESIGN.md section 3). A throw here reaches exit 2.
    Assert-ParameterRange   -Name 'AppLockerChannelSizeBytes' -Value $AppLockerChannelSizeBytes -Minimum 1052672 -Maximum 2147483647
    Assert-ParameterRange   -Name 'MinimumFreeDiskPercent' -Value $MinimumFreeDiskPercent -Minimum 0 -Maximum 90

    # -AbandonRun already names the run to act on, so -RunId adds nothing and
    # naming a DIFFERENT run is two instructions, not one. Refused here rather
    # than resolved and discarded further down: Get-RollbackTargetRun throws on a
    # run that has already finished, which turned the habitual
    # '-Rollback -RunId <x> -AbandonRun <y>' into exit 2 with the abandon never
    # attempted - defeating the one escape hatch docs/DESIGN.md 4.2 exists to
    # provide for a run stuck declining forever.
    if (-not [string]::IsNullOrWhiteSpace($AbandonRun) -and -not [string]::IsNullOrWhiteSpace($RunId) -and
        -not [string]::Equals($RunId, $AbandonRun, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('-RunId ' + $RunId + ' and -AbandonRun ' + $AbandonRun + ' name different runs. ' +
               'Pass -AbandonRun on its own; it already names the run to act on.')
    }

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')
    # The same WorkDirectory -Apply uses, so -Audit reports the real paths - but
    # nothing on the -Audit path writes to it.
    $policyDirectory = [System.IO.Path]::Combine($resolvedRoot, 'AppLocker')

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        [void] (Invoke-HostCheck -ResolvedRoot $resolvedRoot -WorkDirectory $policyDirectory)
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
        Write-Ok 'No findings: the audit-only LOLBin rules are in place and AppIDSvc is running.'
        return 0
    }

    Enter-ToolkitLock -ToolkitRootPath $resolvedRoot
    try {
        $allowMissingStamp = ($mode -eq 'Rollback')
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -AllowMissingStamp:$allowMissingStamp)
        Assert-ManifestUsable

        if ($mode -eq 'Apply') {
            [void] (Start-ManifestRun -Mode 'Apply' -Parameters @{ toolkitRoot = $resolvedRoot })
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
                $verified = Invoke-HostCheck -ResolvedRoot $resolvedRoot -WorkDirectory $policyDirectory
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
            Write-Info ('Nothing is blocked. Read event 8003 in "' + $script:AppLockerChannel +
                        '" before anyone considers enforcement, which this script will not set.')
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

        # One resolution, not two. Resolving -RunId first and then overwriting the
        # result meant the -RunId lookup still ran - and threw - on the abandon
        # path, where its answer was never used.
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun)) {
            $target = Get-RollbackTargetRun -ExplicitRunId $AbandonRun
        }
        else {
            $target = Get-RollbackTargetRun -ExplicitRunId $RunId
        }
        if ($null -eq $target) {
            Write-Section 'Result'
            if (-not [string]::IsNullOrWhiteSpace($AbandonRun)) {
                # Never exit 0 on an abandon that abandoned nothing. The operator
                # named a run; Get-RollbackTargetRun only returns one that carries
                # change records, so this is a run with none. Nothing to give up
                # on - and nothing blocking -Rollback from older runs either -
                # but that is a different fact from 'nothing to roll back', and
                # the instruction must not be dropped silently.
                Write-Failure ('Run ' + $AbandonRun + ' carries no change records, so there is nothing ' +
                               'to abandon. It does not block -Rollback from reaching older runs either.')
                return 2
            }
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
                $outcome = Restore-LolbinAuditChange -ChangeRecord $target.Changes[$i]
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
        # A running AppIDSvc is left running on purpose - see
        # Set-AppIdServiceAutomatic. Only the start type is restored.
        Write-Info 'AppIDSvc keeps running if it was started; only its start type is restored.'
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
