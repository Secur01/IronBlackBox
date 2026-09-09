<#
.SYNOPSIS
    Audits Microsoft Defender's exclusion list, snapshots it as a baseline, and
    on later runs reports the exclusions that have APPEARED since - which is
    usually the first thing an attacker adds. Exclusions only: Defender's own
    posture is Test-DefenderPosture's job.

.DESCRIPTION
    READ-MOSTLY BY DESIGN, and that is not timidity. Removing an exclusion an
    administrator added deliberately breaks the line-of-business application it
    was added for, at a time nobody is expecting it, on a production server.
    docs/AUTHORING.md and docs/DESIGN.md section 7 both say this toolkit does not
    silently change antivirus policy, so the default is audit and every change
    is opt-in and named explicitly.

    The value here is the DIFF, not the list. A point-in-time list of
    exclusions tells an MSP almost nothing - every estate has some, and reading
    thirty of them proves nothing. "This exclusion appeared since the last run"
    is a finding. So:

      - -Audit reads the current exclusions and compares them against
        <ToolkitRoot>\defender-exclusions.baseline.json. A NEW exclusion is
        named precisely and the script exits 1.
      - -Apply records the baseline. That is a change worth recording, so it
        goes through the manifest like any other, and -Rollback puts the
        previous baseline back. It will NOT quietly absorb an exclusion that
        appeared since the last baseline - see -AcceptNewExclusions.
      - -Apply -RemoveExclusion <value> -RemoveExclusionType <kind> removes ONE
        named exclusion, tracked through the manifest so -Rollback can add it
        back. Nothing is ever removed without being named on the command line.

    WHERE THE EXCLUSIONS COME FROM. Get-MpPreference is the documented source,
    and the Defender module is in-box on Windows, so using it does not breach
    this toolkit's zero-module rule - there is nothing to install. It can still
    be absent (Defender uninstalled, a Server SKU with the feature removed), so
    the script checks first and falls back to the registry, and always reports
    WHICH source answered: the two do not have to agree.

    WHAT A CLEAN RESULT DOES NOT PROVE. Microsoft documents
    HideExclusionsFromLocalAdmins, whose effect is that "Exclusions aren't
    visible in Get-MpPreference or Registry Editor" - both of this script's
    sources. An empty exclusion list is therefore not proof that there are no
    exclusions, and the output says so on every run.

    POSTURE IS NOT CHECKED HERE ANY MORE, and that changes what a clean run from
    this script means. Until 2026-09-07 it also reported what decides whether the
    exclusion list matters at all - real-time protection, tamper protection,
    signature staleness, whether Defender is the active antivirus - on the stated
    grounds that a clean exclusion report without those would be a misleading bill
    of health. That reasoning still holds; the checks moved to
    anti-tampering/Test-DefenderPosture.ps1 when this script was split.

    So this script's exit code covers the exclusion list and NOTHING ELSE. An
    operator who alerted on Defender's health through this script must schedule
    Test-DefenderPosture as well, or that alerting is simply gone - see
    docs/DEPLOYMENT.md. The report says so on every run, and the final verdict
    line is scoped to what was actually measured.

    NOT IMPLEMENTED, deliberately:

    - TURNING REAL-TIME OR TAMPER PROTECTION ON. Neither is set here, and since
      the split neither is reported here either (Test-DefenderPosture reports
      them). Real-time protection is antivirus policy, which this script does not
      write. For tamper protection, the methods Microsoft documents are the
      Defender portal, Intune, Configuration Manager and the Windows Security
      app - none of which is a scriptable local interface a non-interactive
      SYSTEM run could drive, and this toolkit does not invent one.

    - REMOVING EXCLUSIONS IN BULK. There is no -RemoveAllExclusions and there
      will not be one. Every removal names one value.

    - WRITING THE BASELINE DURING -Audit. -Audit is contractually read-only, so
      a first run reports "no baseline yet" and exits 0 rather than creating
      one. "The toolkit was never run here" is not drift.

.PARAMETER Audit
    Default. Strictly read-only. Reports the exclusions and the diff against the
    baseline if one exists. Writes nothing at all. Does NOT report Defender's
    posture - Test-DefenderPosture owns that.

.PARAMETER Apply
    Records the exclusion baseline, and removes an exclusion only if
    -RemoveExclusion names one. Both are recorded to the manifest first.

.PARAMETER Rollback
    Restores the previous baseline file, and re-adds any exclusion a prior
    -Apply removed.

.PARAMETER ToolkitRoot
    Base directory for the manifest and the baseline file.
    Default C:\ProgramData\IronBlackBox.

.PARAMETER AcceptNewExclusions
    -Apply only. Absorb into the baseline the exclusions that have appeared
    since it was last recorded, so they stop being reported. Without this,
    -Apply REFUSES to update an existing baseline while any unexplained
    exclusion is present, because absorbing one would make every later run
    report the host clean - the detector switching itself off. Pass this only
    after looking at the exclusions the run names and deciding they are
    legitimate; the manifest records which ones were accepted and by which run.
    Not needed to create the FIRST baseline: there is nothing to absorb then,
    only a reference to establish.

.PARAMETER RemoveExclusion
    -Apply only. One or more exclusion values to REMOVE. Requires
    -RemoveExclusionType. Each removal is recorded to the manifest before it is
    made, so -Rollback can add it back; an exclusion this script removed and
    could not restore would be a real outage.

.PARAMETER RemoveExclusionType
    -Apply only. Which kind of exclusion -RemoveExclusion names: Path,
    Extension, Process or IpAddress. Required with -RemoveExclusion, because an
    exclusion value on its own is ambiguous - "C:\app\svc.exe" is a valid path
    exclusion AND a valid process exclusion, and removing the wrong one leaves
    the host exposed while looking like it worked.

.PARAMETER RunId
    -Rollback only. The run to roll back. Refused alongside an -AbandonRun that
    names a different run: -AbandonRun already names the run to act on.
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
    .\Protect-DefenderConfig.ps1
    Reports the exclusions and any that have appeared since the baseline.
    Changes nothing. Run Test-DefenderPosture for Defender's own health.

.EXAMPLE
    .\Protect-DefenderConfig.ps1 -Apply
    Records the current exclusion list as the baseline to diff against later.

.EXAMPLE
    .\Protect-DefenderConfig.ps1 -Apply -RemoveExclusion 'C:\Users\Public' -RemoveExclusionType Path
    Removes that one path exclusion, recording it so -Rollback can add it back.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.0.1
    License : MIT

    Windows PowerShell 5.1. Requires local administrator; enforced in code by
    Assert-Elevated.

    This script does not carry the template's Registry region: that region
    exists to CHANGE registry values with previous-value capture, and this
    script changes none (docs/DESIGN.md section 6 - do not ship a helper you
    never call). What it needs instead is to ENUMERATE VALUE NAMES under a key,
    because that is how Defender stores exclusions in the registry, and no
    template helper does that. See Get-HklmValueName.

    Every Windows literal is cited to learn.microsoft.com at the point of use,
    or carries an '# UNVERIFIED:' marker naming what still needs checking.
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

    [Parameter(ParameterSetName = 'Apply')]
    [switch] $AcceptNewExclusions,

    # An attribute decorates the parameter that FOLLOWS it, so the Apply
    # attribute above belonged to -AcceptNewExclusions and this parameter
    # carried none - which put it in EVERY set, Rollback included, against the
    # '-Apply only' its help states. '-Rollback -RemoveExclusion <x>' then bound
    # cleanly and died on Assert-RemovalArgument's "needs -RemoveExclusionType
    # as well", pointing the operator at a parameter that could not have helped.
    # The binder now refuses the combination, the same way it already refuses
    # -RemoveExclusionType and -AcceptNewExclusions outside -Apply.
    [Parameter(ParameterSetName = 'Apply')]
    [string[]] $RemoveExclusion,

    [Parameter(ParameterSetName = 'Apply')]
    [string] $RemoveExclusionType,

    # No parameter here may be called -Mode. The shared Invoke-Main holds the
    # run mode in a local '$mode'; PowerShell names are case-insensitive and
    # its scoping is dynamic, so a parameter named $Mode is silently masked
    # inside every function Invoke-Main calls. See verification/facts.json,
    # 'mode-is-a-reserved-variable-name'.
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

$script:ScriptName    = 'Protect-DefenderConfig'
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

# Set by Get-DefenderExclusion so every report line can say which source
# answered. Get-MpPreference and the registry do not have to agree, and
# reporting a registry read as though Defender had confirmed it would be a false
# statement about the host.
$script:ExclusionSource = 'unknown'

# Whether a baseline was actually READ this run. The no-findings verdict has to
# distinguish "nothing was added since the baseline" from "there is no baseline,
# so nothing was compared" - the second is not a clean bill of health, and
# saying it was is the class of false claim docs/AUTHORING.md's cardinal rule forbids.
# Default $false so the honest wording is what a missing assignment produces.
$script:ExclusionBaselineFound = $false

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

#region Defender registry reads [shared] -------------------------------------

# Shared with anti-tampering/Test-DefenderPosture.ps1 and marked [shared] so
# tools/check.ps1 compares the copies. Both halves read the same policy keys -
# Test-DefenderPosture to report posture, Protect-DefenderConfig to diff the
# exclusion list - and a disagreement about how a value is read would make the
# two disagree about the same host.
#
# Not in docs/SCRIPT-TEMPLATE.ps1: its Registry region is 441 lines for WRITING
# values with manifest tracking, and neither of these two writes one.

function Test-DefenderCommandAvailable {
    <#
        Whether one Defender cmdlet is present. The Defender module ships in
        box on Windows, so this is a presence check and never an install
        prompt - docs/AUTHORING.md's zero-module rule forbids Install-Module, not
        in-box cmdlets.
    #>
    param([Parameter(Mandatory = $true)][string] $Name)
    return [bool] (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Get-HklmValueName {
    <#
        The NAMES of the values under one HKLM subkey, or $null when the key is
        absent. Defender stores each exclusion as a value NAME, so this - not a
        value read - is what enumerating exclusions from the registry needs, and
        no helper in docs/SCRIPT-TEMPLATE.ps1 does it.

        Opened through an EXPLICIT 64-bit view. [Microsoft.Win32.Registry]::
        LocalMachine follows the calling process's bitness and RMMs do launch
        SysWOW64\WindowsPowerShell\v1.0\powershell.exe; under WOW64
        HKLM\SOFTWARE\... is redirected to HKLM\SOFTWARE\WOW6432Node\..., so
        this read would come back empty and the host would be reported as having
        no exclusions at all. A false clean bill of health is the worst output
        this script can produce.
        https://learn.microsoft.com/en-us/windows/win32/winprog64/registry-redirector

        The leading ',' on the successful return is load-bearing: PowerShell
        unrolls a returned array, so a key holding one value would come back as
        a bare string and an empty key as $null - indistinguishable from "the
        key does not exist", the one distinction this function exists to make.
    #>
    param([Parameter(Mandatory = $true)][string] $SubKey)

    $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $hive.OpenSubKey($SubKey, $false)
        if ($null -eq $key) { return $null }
        return ,@($key.GetValueNames())
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        $hive.Dispose()
    }
}

#endregion

#region Defender posture ------------------------------------------------------

<#
    The four exclusion kinds in one table, so nothing downstream has to
    remember which spelling belongs to which surface.

    'Property' is the MSFT_MpPreference property Get-MpPreference returns.
    ExclusionPath / ExclusionExtension / ExclusionProcess are documented as
    string arrays on that class:
    https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/dn455323(v=vs.85)
    ExclusionIpAddress is not on that (older) class page, but is documented as a
    String[] parameter of Add-MpPreference and Remove-MpPreference:
    https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference
    https://learn.microsoft.com/en-us/powershell/module/defender/remove-mppreference

    UNVERIFIED: 'RegistrySubKey'. The registry layout - subkeys named Paths /
    Extensions / Processes / IpAddresses, each holding one VALUE per exclusion -
    is what every field reference describes, but no learn.microsoft.com page for
    it was found. What IS documented is the Group Policy location, Computer
    Configuration > Administrative Templates > Windows Components > Microsoft
    Defender Antivirus > Exclusions
    (https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure),
    consistent with the policy path below but not proof of the key names. The
    registry is only ever a FALLBACK, only ever read, and the report always
    names the source - so a wrong guess produces an honest "nothing found via
    registry", never a wrong change.
#>
$script:ExclusionKind = @(
    @{ Name = 'Path';      Property = 'ExclusionPath';      Parameter = 'ExclusionPath';      RegistrySubKey = 'Paths' },
    @{ Name = 'Extension'; Property = 'ExclusionExtension'; Parameter = 'ExclusionExtension'; RegistrySubKey = 'Extensions' },
    @{ Name = 'Process';   Property = 'ExclusionProcess';   Parameter = 'ExclusionProcess';   RegistrySubKey = 'Processes' },
    @{ Name = 'IpAddress'; Property = 'ExclusionIpAddress'; Parameter = 'ExclusionIpAddress'; RegistrySubKey = 'IpAddresses' }
)

# The policy scope is checked before the local scope, and both are reported,
# because Microsoft documents that "exclusions deployed by Group Policy take
# precedence when there's a conflict" while local admin changes are merged in.
# Both paths carry the UNVERIFIED caveat above.
$script:ExclusionRegistryBase = @(
    'SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions',
    'SOFTWARE\Microsoft\Windows Defender\Exclusions'
)

# ForceDefenderPassiveMode: "Path: HKLM\SOFTWARE\Policies\Microsoft\Windows
# Advanced Threat Protection, Name: ForceDefenderPassiveMode, Type: REG_DWORD,
# Value: 1", documented at
# https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility
$script:PassiveModeKey   = 'SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
$script:PassiveModeValue = 'ForceDefenderPassiveMode'

# "Microsoft-Windows-Windows Defender/Operational" is the channel Microsoft's
# own custom-view XML queries name, and event 5007 there is "Event when
# settings are changed" - which is what an exclusion being added looks like in
# the log.
# https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events
$script:DefenderChannel      = 'Microsoft-Windows-Windows Defender/Operational'
$script:SettingsChangeEventId = 5007

# The three values Microsoft documents for AMRunningMode as meaning antivirus
# protection is enabled: "You should see Normal, Passive, or EDR Block Mode if
# antivirus protection is enabled on the endpoint."
# https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility
#
# UNVERIFIED: other strings this property can return. 'SxS Passive Mode' is
# reported in the field; it is not on that page. Anything not in this list is
# therefore reported verbatim as "not one of the three documented values",
# never silently treated as either good or bad.
$script:RunningModeEnabled = @('Normal', 'Passive', 'EDR Block Mode')

#endregion

#region Exclusion severity ----------------------------------------------------

<#
    EVERYTHING IN THIS REGION IS A HEURISTIC, not a Windows fact, and it is not
    cited to Microsoft because there is nothing to cite: it is this project's
    judgement about which exclusions are worth waking somebody up for. Each
    verdict is printed with its reason so the operator can disagree with it on
    the spot. Disagreeing means editing these lists, and that is fine.
#>

# Path exclusions that cover far more than any application needs. A drive root
# turns the antivirus off for that volume; the user-writable directories below
# are where an attacker who has a foothold can already write.
$script:BroadPathPattern = @(
    '^[A-Za-z]:\\?$',                      # a whole volume
    '^\\\\?$',                             # a bare backslash
    '^\*',                                 # a leading wildcard: matches everywhere
    '^[A-Za-z]:\\Users\\?$',
    '^[A-Za-z]:\\Users\\Public',
    '^[A-Za-z]:\\Users\\[^\\]+\\?$',       # a whole user profile
    '^[A-Za-z]:\\ProgramData\\?$',
    '^[A-Za-z]:\\Temp\\?$',
    '^[A-Za-z]:\\Windows\\Temp',
    '^[A-Za-z]:\\Windows\\Tasks',
    '^[A-Za-z]:\\Windows\\?$',
    '\\AppData\\Local\\Temp',
    '\\AppData\\Roaming\\?$',
    '\\Downloads\\?$',
    '%TEMP%', '%TMP%', '%PUBLIC%', '%USERPROFILE%', '%APPDATA%'
)

# Process exclusions naming one of these exclude every file these programs
# touch. They are the interpreters and the signed-binary proxies that malware
# uses precisely because they are already on the host.
$script:InterpreterImage = @(
    'powershell.exe', 'powershell_ise.exe', 'pwsh.exe', 'cmd.exe',
    'wscript.exe', 'cscript.exe', 'mshta.exe', 'hh.exe',
    'rundll32.exe', 'regsvr32.exe', 'regasm.exe', 'regsvcs.exe',
    'installutil.exe', 'msbuild.exe', 'wmic.exe', 'certutil.exe',
    'bitsadmin.exe', 'curl.exe', 'python.exe', 'perl.exe', 'ruby.exe',
    'node.exe', 'java.exe', 'javaw.exe', 'bash.exe', 'wsl.exe',
    'cscript', 'wscript', 'powershell'
)

# File extensions whose exclusion means "do not scan code".
$script:ExecutableExtension = @(
    'exe', 'dll', 'ocx', 'sys', 'scr', 'com', 'pif', 'cpl',
    'ps1', 'psm1', 'psd1', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse',
    'wsf', 'wsh', 'hta', 'jar', 'py', 'msi', 'msp', 'lnk'
)

function Get-ExclusionSeverity {
    # Returns @{ Severity = 'high' | 'normal'; Reason = '...' }. Every
    # comparison here is case-insensitive, for the reason given in
    # Test-ExclusionContain.
    param(
        [Parameter(Mandatory = $true)][string] $Kind,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value
    )

    $trimmed = $Value.Trim()

    if ($Kind -eq 'Path') {
        foreach ($pattern in $script:BroadPathPattern) {
            if ($trimmed -match $pattern) {
                return @{ Severity = 'high'
                    Reason = ('covers a drive root or a broadly user-writable location (matched ' +
                              $pattern + '), so anything an attacker can already write is unscanned') }
            }
        }
        return @{ Severity = 'normal'; Reason = 'a specific path' }
    }

    if ($Kind -eq 'Process') {
        # A process exclusion with no directory separator matches that image
        # name wherever it runs from, which is strictly worse than a full path.
        # Microsoft documents these values as "paths to process images", so a
        # bare name is already outside the documented shape.
        $leaf = $trimmed
        if ($trimmed -match '[\\/]') { $leaf = $trimmed -replace '^.*[\\/]', '' }
        foreach ($image in $script:InterpreterImage) {
            if ([string]::Equals($leaf, $image, [System.StringComparison]::OrdinalIgnoreCase)) {
                return @{ Severity = 'high'
                    Reason = ('excludes every file opened by ' + $leaf +
                              ', a script interpreter or signed-binary proxy - this is the exclusion an attacker wants') }
            }
        }
        if ($trimmed -notmatch '[\\/]') {
            return @{ Severity = 'high'
                Reason = ('names an image with no path, so it matches ' + $leaf +
                          ' running from anywhere, including a directory the attacker chose') }
        }
        return @{ Severity = 'normal'; Reason = 'a specific process image path' }
    }

    if ($Kind -eq 'Extension') {
        $ext = $trimmed.TrimStart('.', '*')
        foreach ($candidate in $script:ExecutableExtension) {
            if ([string]::Equals($ext, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
                return @{ Severity = 'high'
                    Reason = ('excludes .' + $ext +
                              ' everywhere on the host, regardless of location - that is code left unscanned') }
            }
        }
        return @{ Severity = 'normal'; Reason = 'a non-executable extension' }
    }

    if ($trimmed -eq '*' -or $trimmed -match '^0\.0\.0\.0(/0)?$') {
        return @{ Severity = 'high'; Reason = 'covers every address' }
    }
    return @{ Severity = 'normal'; Reason = 'a specific address' }
}

#endregion

#region Exclusion baseline ----------------------------------------------------

# MOVED HERE ON 2026-09-07, from the posture region where they had been filed.
# Nothing in the posture half ever called them: every caller is in this region
# or in Exclusion severity. Their placement was what made the split look
# entangled - reference counts alone said the two halves shared five functions,
# and checking WHICH regions referenced them said they shared one.

function Test-ExclusionContain {
    <#
        Whether a collection of exclusion values already holds this one.

        Case-insensitive, and that is a deliberate departure from this
        project's usual ordinal rule: Windows paths, image names and file
        extensions are case-insensitive, so 'C:\Temp' and 'c:\temp' are the
        same exclusion. Comparing them ordinally would report a brand new
        exclusion every time anything rewrote the casing, and an operator who
        gets a false finding once stops reading the real ones.

        One function rather than the same loop written four times, because four
        copies is four chances for one of them to be ordinal by accident.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array] $Collection,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value
    )
    foreach ($item in $Collection) {
        if ([string]::Equals([string] $item, $Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-DefenderExclusion {
    <#
        The current exclusions, as a hashtable of kind name -> string[].

        Get-MpPreference first, because it is the documented source; the
        registry only as a fallback, and $script:ExclusionSource records which
        one answered so the report can say so. The two are not guaranteed to
        agree, and reporting a registry read as though Defender had confirmed it
        would be a false statement about the host.
    #>
    $result = @{}
    foreach ($kind in $script:ExclusionKind) { $result[$kind.Name] = @() }

    if (Test-DefenderCommandAvailable -Name 'Get-MpPreference') {
        try {
            $preference = Get-MpPreference
            foreach ($kind in $script:ExclusionKind) {
                # @() around the property access, not a bare assignment: the
                # property is absent on builds that predate it (ExclusionIpAddress
                # is not on the documented class page), and @($null) is an empty
                # array where $null would break every .Count below.
                $result[$kind.Name] = @($preference.($kind.Property) |
                    Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } |
                    ForEach-Object { [string] $_ })
            }
            $script:ExclusionSource = 'Get-MpPreference'
            return $result
        }
        catch {
            Write-Info ('Get-MpPreference failed (' + $_.Exception.Message +
                        '); falling back to the registry.')
        }
    }
    else {
        Write-Info 'Get-MpPreference is not available on this host; falling back to the registry.'
    }

    $found = $false
    foreach ($base in $script:ExclusionRegistryBase) {
        foreach ($kind in $script:ExclusionKind) {
            $names = Get-HklmValueName -SubKey ($base + '\' + $kind.RegistrySubKey)
            if ($null -eq $names) { continue }
            $found = $true
            foreach ($name in $names) {
                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                if ($result[$kind.Name] -notcontains $name) {
                    $result[$kind.Name] = @($result[$kind.Name] + $name)
                }
            }
        }
    }
    if ($found) { $script:ExclusionSource = 'registry (HKLM, both policy and local scopes)' }
    else { $script:ExclusionSource = 'registry (no exclusion key present)' }
    return $result
}

function Get-BaselinePath {
    param([Parameter(Mandatory = $true)][string] $ResolvedRoot)
    return [System.IO.Path]::Combine($ResolvedRoot, 'defender-exclusions.baseline.json')
}

function ConvertTo-BaselineContent {
    <#
        The baseline document, as the exact text that goes on disk. Written
        through one function so the file this run compares against and the file
        the next run writes cannot drift apart in formatting.
    #>
    param([Parameter(Mandatory = $true)][hashtable] $Exclusion)

    $body = [ordered] @{}
    foreach ($kind in $script:ExclusionKind) {
        # Sorted so two runs that read the same exclusions in a different order
        # produce the same document, and an operator diffing two baselines by
        # hand sees only real changes.
        $body[$kind.Name] = @(@($Exclusion[$kind.Name]) | Sort-Object)
    }

    return (([ordered] @{
        script      = $script:ScriptName
        version     = $script:ScriptVersion
        hostname    = [System.Net.Dns]::GetHostName()
        capturedUtc = (Get-UtcStamp)
        source      = $script:ExclusionSource
        exclusions  = $body
    } | ConvertTo-Json -Depth 6))
}

function Read-ExclusionBaseline {
    <#
        The exclusions recorded in the baseline file, as a hashtable of kind
        name -> string[], or $null when there is no baseline yet.

        A baseline that exists but cannot be parsed is an ERROR, never an empty
        one - the same rule Read-Manifest follows, and for the same reason:
        treating an unreadable baseline as "no exclusions were known" turns
        every existing exclusion into a fresh finding, and the operator learns
        to ignore this script.
    #>
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $text = [System.IO.File]::ReadAllText($Path)
    try {
        $document = $text | ConvertFrom-Json
    }
    catch {
        throw ('The exclusion baseline exists but is not valid JSON, so this run cannot tell a new ' +
               'exclusion from an old one: ' + $Path)
    }

    $result = @{}
    foreach ($kind in $script:ExclusionKind) {
        # @() on the way out, always. Windows PowerShell 5.1 serialises a
        # one-element array as a bare scalar, so a baseline with exactly one
        # path exclusion reads back as a String and .Count would be the length
        # of that string rather than 1.
        $values = @()
        if ($null -ne $document.exclusions) {
            $values = @($document.exclusions.($kind.Name) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } |
                ForEach-Object { [string] $_ })
        }
        $result[$kind.Name] = $values
    }
    return $result
}

function Test-ExclusionSetEqual {
    # Set equality across all four kinds, used for exactly one thing: deciding
    # whether -Apply needs to rewrite the baseline. Comparing the FILE TEXT
    # instead would never match, because the document carries a capture
    # timestamp - so -Apply would write a change on every run and never be
    # idempotent, which is the one property the mode contract demands.
    param(
        [Parameter(Mandatory = $true)][hashtable] $Left,
        [Parameter(Mandatory = $true)][hashtable] $Right
    )

    foreach ($kind in $script:ExclusionKind) {
        $l = @(@($Left[$kind.Name])  | Sort-Object)
        $r = @(@($Right[$kind.Name]) | Sort-Object)
        if ($l.Count -ne $r.Count) { return $false }
        for ($i = 0; $i -lt $l.Count; $i++) {
            if (-not [string]::Equals([string] $l[$i], [string] $r[$i],
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                return $false
            }
        }
    }
    return $true
}

function Get-AddedExclusion {
    <#
        The exclusions present now that the baseline does not hold, as
        "<kind>: <value>" strings, with no output. Compare-ExclusionBaseline
        does the reporting; this answers the question a second time, quietly,
        after any -RemoveExclusion has changed the host underneath it.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable] $Current,
        [Parameter(Mandatory = $true)][hashtable] $Baseline
    )

    $added = New-Object System.Collections.ArrayList
    foreach ($kind in $script:ExclusionKind) {
        $before = @($Baseline[$kind.Name])
        foreach ($value in @($Current[$kind.Name])) {
            if (Test-ExclusionContain -Collection $before -Value $value) { continue }
            [void] $added.Add($kind.Name + ': ' + $value)
        }
    }
    return $added.ToArray()
}

function Compare-ExclusionBaseline {
    <#
        The reason this script exists. Reports every exclusion present now that
        was not in the baseline, and every one that has gone.

        An ADDED exclusion is a finding. A REMOVED one is information: an
        exclusion disappearing reduces what is unscanned, and alerting on it
        would train the operator to dismiss this script's output.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable] $Current,
        [Parameter(Mandatory = $true)][hashtable] $Baseline,
        [Parameter(Mandatory = $true)][string] $BaselinePath
    )

    $addedCount = 0
    foreach ($kind in $script:ExclusionKind) {
        $before = @($Baseline[$kind.Name])
        $now    = @($Current[$kind.Name])

        foreach ($value in $now) {
            if (Test-ExclusionContain -Collection $before -Value $value) { continue }
            $addedCount++
            $verdict = Get-ExclusionSeverity -Kind $kind.Name -Value $value
            Write-Finding ('NEW ' + $kind.Name + ' exclusion since the baseline: "' + $value +
                           '" [' + $verdict.Severity + '] - ' + $verdict.Reason)
        }

        foreach ($old in $before) {
            if (Test-ExclusionContain -Collection $now -Value $old) { continue }
            Write-Info ('gone since the baseline (' + $kind.Name + '): "' + $old +
                        '" - less is unscanned than before, so this is not a finding')
        }
    }

    if ($addedCount -eq 0) {
        Write-Ok ('no exclusion has been added since the baseline recorded in ' +
                  [System.IO.Path]::GetFileName($BaselinePath))
    }
    else {
        Write-Info ''
        Write-Info ('Event ' + [string] $script:SettingsChangeEventId + ' in ' + $script:DefenderChannel +
                    ' is logged when Defender settings change; that channel is where to look for WHEN')
        Write-Info 'and by whom, which this script cannot tell you from the exclusion list alone.'
    }
    return $addedCount
}

function Set-TrackedBaseline {
    <#
        Writes the baseline, recording the previous file content in the manifest
        FIRST so -Rollback can put it back. The previous content is stored
        inline rather than as a path to a copy: docs/DESIGN.md section 4 wants
        each record self-contained, and a sidecar file somebody deletes takes
        the rollback with it.

        Returns 1 if it wrote, 0 if the recorded exclusions already match -
        which is what keeps a second -Apply at zero changes.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][hashtable] $Current,
        $Baseline,
        [Parameter()][AllowEmptyCollection()][string[]] $Added = @()
    )

    if ($null -ne $Baseline -and (Test-ExclusionSetEqual -Left $Current -Right $Baseline)) {
        Write-Ok 'baseline already records exactly these exclusions'
        return 0
    }

    # THE DEFECT THIS GUARD EXISTS FOR (the review log kept in the development repository, DF-1).
    #
    # -Apply used to report a newly appeared exclusion as a [high] finding and,
    # in the same run, write it into the baseline. The next run compared the
    # host against a baseline that now contained the attacker's exclusion and
    # reported it clean. The one mechanism this script exists to provide would
    # switch itself off, permanently, without a single line that was untrue.
    #
    # So a baseline that already exists is NEVER updated over an unexplained
    # addition. Absorbing one is a decision a person makes, on the command line,
    # having looked at it - and the manifest records which exclusions were
    # accepted and by which run, so the decision is auditable afterwards.
    #
    # A FIRST baseline is different and is still written without the switch:
    # there is nothing to absorb, only a reference to establish. That first
    # snapshot does take whatever is on the host as normal, including anything
    # an attacker put there before the toolkit arrived - which is why the run
    # that creates it prints the full exclusion inventory for a human to read.
    if ($null -ne $Baseline -and $Added.Count -gt 0 -and -not $AcceptNewExclusions) {
        Write-Finding ('REFUSING to update the baseline: ' + [string] $Added.Count +
                       ' exclusion(s) have appeared since it was recorded, and absorbing them would ' +
                       'make the next run report this host clean. They stay findings until somebody ' +
                       'decides otherwise.')
        foreach ($item in $Added) { Write-Info ('  not absorbed - ' + $item) }
        Write-Info ('Remove one with -Apply -RemoveExclusion <value> -RemoveExclusionType <kind>, or, ' +
                    'if they are legitimate, accept them deliberately with -Apply -AcceptNewExclusions.')
        return 0
    }

    $newContent = ConvertTo-BaselineContent -Exclusion $Current

    if (-not $Apply) {
        if ($null -eq $Baseline) {
            Write-Info ('-Apply would create the baseline at ' + $Path)
        }
        else {
            Write-Info ('-Apply would update the baseline at ' + $Path +
                        ' so this run''s exclusions become the new reference')
        }
        return 0
    }

    $existed = Test-Path -LiteralPath $Path
    $previousContent = $null
    if ($existed) { $previousContent = [System.IO.File]::ReadAllText($Path) }

    [void] (Write-ManifestChange -Change @{
        type            = 'defenderbaseline'
        path            = $Path
        fileExisted     = $existed
        previousContent = $previousContent
        newContent      = $newContent
        acceptedNew     = @($Added)
        description     = ('Defender exclusion baseline recorded' +
                           $(if ($Added.Count -gt 0) {
                                 ', accepting ' + [string] $Added.Count + ' new exclusion(s) via -AcceptNewExclusions'
                             } else { '' }))
    })

    # No BOM: this file is read back by ConvertFrom-Json in this script and by
    # whatever the MSP points at it, and a BOM in front of '{' breaks strict
    # JSON parsers.
    [System.IO.File]::WriteAllText($Path, $newContent, (New-Object System.Text.UTF8Encoding($false)))

    $written = [System.IO.File]::ReadAllText($Path)
    if (-not [string]::Equals($written, $newContent, [System.StringComparison]::Ordinal)) {
        Write-Failure ('the baseline did not read back as written: ' + $Path)
        throw ('Baseline write could not be confirmed: ' + $Path)
    }

    Write-Ok ('baseline recorded at ' + $Path)
    return 1
}

function Remove-TrackedExclusion {
    <#
        Removes ONE named exclusion. Never called except from an -Apply that
        named it on the command line.

        Confirmation by re-read is not ceremony here, it is the point:
        Microsoft documents that when tamper protection is on, "Exclusions
        can't be modified or added" and that "changes made to tamper-protected
        settings might appear to succeed but are actually blocked".
        https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection
        So Remove-MpPreference returning without an error proves nothing.

        Returns 1 if it removed something, 0 if the exclusion was not there -
        which makes a repeated -Apply a no-op.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Kind,
        [Parameter(Mandatory = $true)][string] $Value,
        [Parameter(Mandatory = $true)][hashtable] $Current
    )

    $entry = $script:ExclusionKind | Where-Object { $_.Name -eq $Kind } | Select-Object -First 1
    if ($null -eq $entry) { throw ('Unknown exclusion kind: ' + $Kind) }

    if (-not (Test-ExclusionContain -Collection @($Current[$Kind]) -Value $Value)) {
        Write-Ok ($Kind + ' exclusion "' + $Value + '" is not present; nothing to remove')
        return 0
    }

    if (-not (Test-DefenderCommandAvailable -Name 'Remove-MpPreference')) {
        # Refuse rather than improvise. Deleting the registry value directly
        # would leave Defender's own view of its configuration unchanged until
        # something reloaded it, and this script has no citation for that path.
        throw ('Remove-MpPreference is not available on this host, so the ' + $Kind +
               ' exclusion "' + $Value + '" cannot be removed safely. Nothing was changed.')
    }

    if (-not $Apply) {
        Write-Finding ($Kind + ' exclusion "' + $Value + '" - would remove')
        return 0
    }

    [void] (Write-ManifestChange -Change @{
        type          = 'defenderexclusion'
        exclusionType = $Kind
        parameterName = $entry.Parameter
        value         = $Value
        action        = 'removed'
        description   = ('removed the ' + $Kind + ' exclusion "' + $Value + '"')
    })

    $arguments = @{ $entry.Parameter = @($Value) }
    [void] (Remove-MpPreference @arguments)

    $after = Get-DefenderExclusion
    if (Test-ExclusionContain -Collection @($after[$Kind]) -Value $Value) {
        Write-Failure ($Kind + ' exclusion "' + $Value +
                       '" is still present after Remove-MpPreference returned without an error. ' +
                       'Tamper protection blocks exclusion changes and reports success; check its state above.')
        throw ('Exclusion removal could not be confirmed: ' + $Kind + ' "' + $Value + '"')
    }

    Write-Ok ($Kind + ' exclusion "' + $Value + '" removed and confirmed gone')
    return 1
}

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

function Restore-TrackedBaseline {
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    # The root is derived from $script:ManifestPath rather than read from a local
    # in Invoke-Main. PowerShell's scoping is dynamic, so a local WOULD be visible
    # here - and relying on that is the same trap docs/AUTHORING.md records for $mode.
    $rootPath = [System.IO.Path]::GetDirectoryName($script:ManifestPath)
    $path   = Assert-ManifestPathUnderRoot -Path ([string] $change.path) -RootPath $rootPath
    if ($null -eq $path) { return 'declined' }
    $exists = Test-Path -LiteralPath $path

    if ($exists) {
        $now = [System.IO.File]::ReadAllText($path)
        # Case 2 (docs/DESIGN.md section 4.1) before case 3: the file already holds
        # the content recorded BEFORE this run - either the write never landed or
        # this has already been rolled back. Nothing to do, counted 'restored' so
        # the run converges. Without it the case-3 test below declined as
        # RETRYABLE and every future -Rollback re-selected the run (A-2).
        if ([bool] $change.fileExisted -and
            [string]::Equals($now, [string] $change.previousContent, [System.StringComparison]::Ordinal)) {
            Write-Ok ($path + ' already holds its recorded previous content; nothing to undo.')
            return 'restored'
        }
        # Case 3: neither what this run wrote nor what was there before it.
        if (-not [string]::Equals($now, [string] $change.newContent, [System.StringComparison]::Ordinal)) {
            Write-Finding ($path + ' is not the baseline this run wrote; leaving it alone.')
            return 'declined'
        }
    }
    elseif ($change.fileExisted) {
        Write-Finding ($path + ' is gone, so the baseline this run replaced cannot be put back safely.')
        return 'declined'
    }

    if (-not $change.fileExisted) {
        if ($exists) {
            Remove-Item -LiteralPath $path -Force
            Write-Ok ('Removed ' + $path + ' (there was no baseline before this run)')
        }
        else {
            # Reachable on a SECOND -Rollback of the run that created the first
            # baseline: the first one deleted the file, so there is nothing left
            # to delete. Still 'restored' - case 2 of the doctrine, the host
            # already holds what was there before the run - but the message must
            # not report a deletion that did not happen.
            Write-Ok ($path + ' is already absent (there was no baseline before this run)')
        }
        return 'restored'
    }

    [System.IO.File]::WriteAllText($path, [string] $change.previousContent,
        (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok ('Restored the previous baseline at ' + $path)
    return 'restored'
}

function Restore-TrackedExclusion {
    <#
        Adds back an exclusion this toolkit removed. This is the rollback that
        matters most in this script: an exclusion removed here and not restored
        is a line-of-business application being scanned again, which is a real
        outage on somebody's file server.

        Add-MpPreference is the documented inverse of Remove-MpPreference and
        takes the same four exclusion parameters.
        https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $kind   = [string] $change.exclusionType
    $value  = [string] $change.value
    $entry  = $script:ExclusionKind | Where-Object { $_.Name -eq $kind } | Select-Object -First 1
    if ($null -eq $entry) {
        Write-Finding ('Unknown exclusion kind "' + $kind + '" in the manifest; leaving it alone.')
        return 'declined'
    }

    if (-not (Test-DefenderCommandAvailable -Name 'Add-MpPreference')) {
        Write-Finding ('Add-MpPreference is not available, so the ' + $kind + ' exclusion "' + $value +
                       '" cannot be restored. Add it by hand: Add-MpPreference -' + $entry.Parameter +
                       ' "' + $value + '"')
        return 'declined'
    }

    $current = Get-DefenderExclusion
    if (Test-ExclusionContain -Collection @($current[$kind]) -Value $value) {
        # Case 2 (docs/DESIGN.md section 4.1). This is the clearest instance of
        # A-2 in the toolkit, and the reasoning it replaces was explicitly wrong:
        # "declining keeps the run retryable, rather than claiming a restore it
        # did not perform". The exclusion being present IS the pre-apply state -
        # this script had removed it, and rollback exists to put it back - so
        # there is nothing left to do and a retry can never change anything. The
        # doctrine counts that 'restored' so the run converges; declining left it
        # eligible forever and Test-VisibilityDrift kept reporting it.
        # The honest half of the old comment is kept in the MESSAGE: it says what
        # is true (already present, nothing added), not "Restored".
        Write-Ok ('The ' + $kind + ' exclusion "' + $value + '" is already present - the pre-apply ' +
                  'state - so there is nothing to add back. This run did not add it.')
        return 'restored'
    }

    $arguments = @{ $entry.Parameter = @($value) }
    [void] (Add-MpPreference @arguments)

    $after = Get-DefenderExclusion
    if (-not (Test-ExclusionContain -Collection @($after[$kind]) -Value $value)) {
        throw ('Add-MpPreference returned without an error but the ' + $kind + ' exclusion "' + $value +
               '" is not back. Tamper protection blocks exclusion changes silently; check its state.')
    }
    Write-Ok ('Restored the ' + $kind + ' exclusion "' + $value + '"')
    return 'restored'
}

#endregion

#region Defender report -------------------------------------------------------

function Write-ExclusionInventory {
    param([Parameter(Mandatory = $true)][hashtable] $Exclusion)

    Write-Section 'Current exclusions'
    Write-Info ('source: ' + $script:ExclusionSource)

    $total = 0
    $high  = 0
    foreach ($kind in $script:ExclusionKind) {
        $values = @($Exclusion[$kind.Name])
        $total += $values.Count
        if ($values.Count -eq 0) {
            Write-Info ($kind.Name + ': none')
            continue
        }
        Write-Info ($kind.Name + ': ' + [string] $values.Count)
        foreach ($value in ($values | Sort-Object)) {
            $verdict = Get-ExclusionSeverity -Kind $kind.Name -Value $value
            if ($verdict.Severity -eq 'high') {
                $high++
                Write-Finding ('[high] ' + $kind.Name + ' "' + $value + '" - ' + $verdict.Reason)
            }
            else {
                Write-Info ('  ' + $value)
            }
        }
    }

    if ($total -eq 0) {
        Write-Ok 'no exclusions are configured'
    }
    # Stated every run, whatever the count. Microsoft documents that with
    # HideExclusionsFromLocalAdmins set, "Exclusions aren't visible in
    # Get-MpPreference or Registry Editor" - which are both of this script's
    # sources.
    # https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure
    Write-Info ''
    Write-Info 'A short list is not proof. Microsoft documents HideExclusionsFromLocalAdmins,'
    Write-Info 'whose effect is that exclusions are not visible in Get-MpPreference OR in the'
    Write-Info 'registry - so both sources this script can read are blindable by policy.'
    return $high
}

function Invoke-HostCheck {
    param([Parameter(Mandatory = $true)][string] $ResolvedRoot)

    # POSTURE MOVED OUT on 2026-09-07 to anti-tampering/Test-DefenderPosture.ps1.
    # This script keeps the exclusion baseline, the manifest records and the
    # alerting; reporting what Defender is CONFIGURED to do is a separate job and a
    # read-only one, which is why it is a separate script with no -Apply at all.
    #
    # Get-DefenderStatus went with it. This comment first claimed the exclusion
    # half needed it too; PSScriptAnalyzer said the variable was assigned and never
    # used, which was the truth - its only caller was the posture report.
    Write-Section 'Defender posture'
    Write-Info 'Not reported here. Run Test-DefenderPosture, which owns it: real-time'
    Write-Info 'protection, tamper protection, engine and signature state, and whether'
    Write-Info 'Defender is even the antivirus on this host.'

    $current = Get-DefenderExclusion
    [void] (Write-ExclusionInventory -Exclusion $current)

    $baselinePath = Get-BaselinePath -ResolvedRoot $ResolvedRoot
    $baseline = Read-ExclusionBaseline -Path $baselinePath

    Write-Section 'Change since the baseline'
    $added = @()
    $script:ExclusionBaselineFound = ($null -ne $baseline)
    if ($null -eq $baseline) {
        # "The toolkit was never run here" is exit 0, not 1 - docs/AUTHORING.md.
        # There is nothing to compare against and that is not drift.
        Write-Info ('no baseline at ' + $baselinePath + ' yet, so nothing can be compared.')
        Write-Info 'Run -Apply once to record one; from then on a new exclusion is a finding.'
    }
    else {
        [void] (Compare-ExclusionBaseline -Current $current -Baseline $baseline -BaselinePath $baselinePath)
        $added = @(Get-AddedExclusion -Current $current -Baseline $baseline)
    }

    $changeCount = 0

    # Removals first, so the baseline recorded below reflects the host AFTER
    # this run rather than a state that no longer exists.
    if ($null -ne $RemoveExclusion -and $RemoveExclusion.Count -gt 0) {
        Write-Section 'Requested exclusion removals'
        foreach ($value in $RemoveExclusion) {
            $changeCount += Remove-TrackedExclusion -Kind $RemoveExclusionType -Value $value -Current $current
        }
        if ($changeCount -gt 0) {
            # Re-read so the baseline records what the host actually holds now.
            $current = Get-DefenderExclusion
            # And re-ask what is still unexplained: a removal may have taken away
            # exactly the exclusion that was flagged, in which case the baseline
            # below has nothing to absorb and no reason to refuse.
            if ($null -ne $baseline) {
                $added = @(Get-AddedExclusion -Current $current -Baseline $baseline)
            }
        }
    }

    Write-Section 'Baseline'
    $changeCount += Set-TrackedBaseline -Path $baselinePath -Current $current -Baseline $baseline `
        -Added $added
    return $changeCount
}

#endregion

#region Main -----------------------------------------------------------------

function Restore-DefenderChange {
    <#
        Routes a change record to the right restorer.

        This script does not carry the template's Registry region, so it does
        not have Restore-TrackedChange either - and it does not need it: both of
        the change types it can write are its own. An unknown type is DECLINED
        rather than ignored, because silently "succeeding" on a change it cannot
        undo is how a run gets marked rolled back while the host stays changed.

        Returns 'restored' or 'declined'; throws on a failed write.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    switch ([string] $change.type) {
        'defenderbaseline'  { return (Restore-TrackedBaseline -ChangeRecord $ChangeRecord) }
        'defenderexclusion' { return (Restore-TrackedExclusion -ChangeRecord $ChangeRecord) }
        default {
            Write-Finding ('Cannot roll back change type "' + [string] $change.type +
                           '" - not implemented in this script.')
            return 'declined'
        }
    }
}

function Assert-RemovalArgument {
    <#
        -RemoveExclusion and -RemoveExclusionType are useless apart and
        dangerous half-given: a value with no type is ambiguous, and a type with
        no value is an operator who thought they had asked for something.
        Refused with exit 2 rather than guessed at.
    #>
    $haveValue = ($null -ne $RemoveExclusion -and $RemoveExclusion.Count -gt 0)
    $haveType  = -not [string]::IsNullOrWhiteSpace($RemoveExclusionType)

    if ($haveValue -and -not $haveType) {
        Write-Failure ('-RemoveExclusion needs -RemoveExclusionType as well: "C:\app\svc.exe" is a ' +
                       'valid Path exclusion AND a valid Process exclusion, and this script will not ' +
                       'guess which one you meant. Nothing was changed.')
        return $false
    }
    if ($haveType -and -not $haveValue) {
        Write-Failure '-RemoveExclusionType was given with no -RemoveExclusion value. Nothing was changed.'
        return $false
    }
    return $true
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
    Assert-ParameterNotEmpty -Name 'RemoveExclusion' -Value $RemoveExclusion
    Assert-ParameterSet     -Name 'RemoveExclusionType' -Value $RemoveExclusionType -Allowed @('Path', 'Extension', 'Process', 'IpAddress')

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
    if (-not (Assert-RemovalArgument)) { return 2 }
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        [void] (Invoke-HostCheck -ResolvedRoot $resolvedRoot)
        Write-Section 'Result'
        if ($script:Findings.Count -gt 0) {
            Write-Info ([string] $script:Findings.Count +
                        ' finding(s). A NEW exclusion is the one this script exists to catch.')
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
        # SCOPED, deliberately, and scoped TWICE.
        #
        # It used to end '...and the posture checks passed.' After the 2026-09-07
        # split it ran no posture check at all, so it asserted a control it no
        # longer performs, on every clean run. The first rewrite fixed that and
        # introduced the same fault one clause over: it claimed 'no exclusion has
        # appeared since the baseline' unconditionally, including on a host where
        # Read-ExclusionBaseline returned $null and NOTHING was compared - the
        # no-baseline branch raises neither a finding nor a limit, so a first run
        # on a clean host reached this line and vouched for a comparison that had
        # not happened. A verdict may only claim what the run measured.
        if ($script:ExclusionBaselineFound) {
            Write-Ok ('No findings: no exclusion has appeared since the recorded baseline. This ' +
                      'run did NOT check whether Defender is running or protecting - see the ' +
                      'posture section above for the script that does.')
        }
        else {
            Write-Ok ('No findings: no [high] exclusion on this host. Nothing was compared - ' +
                      'there is no baseline at this toolkit root yet, so this run cannot say ' +
                      'whether an exclusion was ADDED; run -Apply once to record one. It also ' +
                      'did NOT check whether Defender is running or protecting - see the posture ' +
                      'section above for the script that does.')
        }
        return 0
    }

    Enter-ToolkitLock -ToolkitRootPath $resolvedRoot
    try {
        $allowMissingStamp = ($mode -eq 'Rollback')
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -AllowMissingStamp:$allowMissingStamp)
        Assert-ManifestUsable

        if ($mode -eq 'Apply') {
            $parameters = @{ toolkitRoot = $resolvedRoot }
            if ($null -ne $RemoveExclusion -and $RemoveExclusion.Count -gt 0) {
                $parameters['removeExclusionType'] = $RemoveExclusionType
                $parameters['removeExclusion']     = @($RemoveExclusion)
            }
            [void] (Start-ManifestRun -Mode 'Apply' -Parameters $parameters)
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
                $verified = Invoke-HostCheck -ResolvedRoot $resolvedRoot
            }
            catch {
                Write-Failure $_.Exception.Message
                $status = 'completed-with-failures'
            }
            # A run that changed nothing still records itself: otherwise there is
            # no evidence the toolkit ran here and nothing to compare against.
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
                Write-Info ([string] $script:Findings.Count +
                            ' finding(s) remain. Recording a baseline does not fix a bad exclusion; ' +
                            'it only makes the NEXT one visible.')
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

        # One resolution, not two. Resolving -RunId first and then overwriting
        # the result meant the -RunId lookup still ran - and threw - on the
        # abandon path, where its answer was never used.
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun)) {
            $target = Get-RollbackTargetRun -ExplicitRunId $AbandonRun
        }
        else {
            $target = Get-RollbackTargetRun -ExplicitRunId $RunId
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
                $outcome = Restore-DefenderChange -ChangeRecord $target.Changes[$i]
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
