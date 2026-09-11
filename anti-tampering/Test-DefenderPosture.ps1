<#
.SYNOPSIS
Reports Microsoft Defender's posture. Read-only, always.

.DESCRIPTION
Split out of Protect-DefenderConfig on 2026-09-07. That script did two jobs -
report what Defender's configuration IS, and track its exclusion list against a
recorded baseline - and docs/AUTHORING.md's test, more than 700 lines of script-specific
logic means the script is doing two jobs, was met literally.

This half answers "what is Defender doing on this host". Protect-DefenderConfig
still owns the exclusion baseline, the manifest records and the alerting.

READ-ONLY BY CONSTRUCTION, not by a switch. There is no -Apply and no -Rollback:
this script has no write path to disable, so there is nothing here for an
operator to pass by accident and nothing for the manifest to record. That is also
why it carries no Manifest region - a script that records no change needs no
record writer, and 502 lines of one would be 502 lines nobody reads.

WHAT IT DELIBERATELY DOES NOT DO. It does not enable, disable or repair anything.
Several of the conditions it reports cannot be fixed from a script at all -
tamper protection needs Intune or Defender for Endpoint - so they are host limits
and stay out of the exit code. docs/DESIGN.md section 3.1 is the contract.

.PARAMETER Audit
Default, and the only mode. Present so the invocation matches every other script
in this toolkit and an RMM component can pass it without a special case.

.PARAMETER SignatureAgeThresholdDays
    Report a finding when the antivirus signatures are older than this many
    days. Default 7. THIS NUMBER IS THIS TOOLKIT'S CHOICE, not a documented
    Microsoft threshold, which is why it is a parameter and why the report
    prints the age as well as the verdict.

.PARAMETER ToolkitRoot
Base directory this toolkit owns. Default C:\ProgramData\IronBlackBox. Nothing
is written to it; it is validated and its DACL is checked, because a toolkit root
an unprivileged user can write to is a finding wherever it is noticed.

.EXAMPLE
.\Test-DefenderPosture.ps1
Reports the posture. Exit 1 if anything needs an operator.

.NOTES
Author  : Secur01
Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
Version : 1.1.0
License : MIT

Windows PowerShell 5.1, in-box modules only. Requires local administrator;
enforced in code by Assert-Elevated. Get-MpComputerStatus and Get-MpPreference
are not present on a host with no Defender platform, which is reported rather
than assumed away.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [switch] $Audit,
    [Parameter()]
    [int] $SignatureAgeThresholdDays = 7,

    [Parameter()]
    [string] $ToolkitRoot = 'C:\ProgramData\IronBlackBox'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1.0
$script:SuppliedParameter = $PSBoundParameters
$script:ScriptName    = 'Test-DefenderPosture'
$script:ScriptVersion = '1.1.0'
$script:ManifestPath = $null
$script:CurrentRunId        = $null
$script:ChangeIndex  = 0
$script:Findings     = New-Object System.Collections.ArrayList
$script:HostLimits   = New-Object System.Collections.ArrayList
$script:LockHandle   = $null

# No registry restorer, because there is no registry writer. Declared empty so
# the shape matches every sibling and tools/check.ps1's ownership gate can read it.
$script:OwnedRegistryKey = @()


# Copied with their comments from Protect-DefenderConfig: the moved functions read
# them, and five of them were missing on the first assembly - which the lab found
# as "The variable '$script:RunningModeEnabled' cannot be retrieved because it has
# not been set", a clean exit 2 that made the whole script unrunnable.
# ForceDefenderPassiveMode: "Path: HKLM\SOFTWARE\Policies\Microsoft\Windows
# Advanced Threat Protection, Name: ForceDefenderPassiveMode, Type: REG_DWORD,
# Value: 1", documented at
# https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility
$script:PassiveModeKey   = 'SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
$script:PassiveModeValue = 'ForceDefenderPassiveMode'

$script:PassiveModeValue = 'ForceDefenderPassiveMode'

# "Microsoft-Windows-Windows Defender/Operational" is the channel Microsoft's
# own custom-view XML queries name, and event 5007 there is "Event when
# settings are changed" - which is what an exclusion being added looks like in
# the log.
# https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events
$script:DefenderChannel      = 'Microsoft-Windows-Windows Defender/Operational'
$script:SettingsChangeEventId = 5007

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

#region Defender posture ----------------------------------------------------

function Get-DefenderStatus {
    <#
        The posture that decides whether an exclusion list matters. Every
        property read here is documented:

          RealTimeProtectionEnabled, AMServiceEnabled, AntivirusSignatureAge
          (uint32, days, "if signatures have never been updated you will see an
          age of 65535 days") and AntivirusSignatureLastUpdated on
          MSFT_MpComputerStatus:
          https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpcomputerstatus

          IsTamperProtected, read via Get-MpComputerStatus, where "A value of
          true means tamper protection is enabled":
          https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection

          AMRunningMode, read via 'Get-MpComputerStatus | select AMRunningMode':
          https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility

        IsTamperProtected and AMRunningMode are NOT on the MSFT_MpComputerStatus
        class page, which documents an older platform version, so on an old
        build they can simply be absent. Set-StrictMode is at version 1.0 here
        (see the top of the file): under 2.0 reading an absent property throws,
        and this function must report "the host did not tell me" rather than die.
    #>
    $result = [PSCustomObject] @{
        Available                 = $false
        Error                     = ''
        RealTimeProtectionEnabled = $null
        IsTamperProtected         = $null
        AMRunningMode             = $null
        AMServiceEnabled          = $null
        AntivirusSignatureAge     = $null
        AntivirusSignatureUpdated = $null
    }

    if (-not (Test-DefenderCommandAvailable -Name 'Get-MpComputerStatus')) {
        $result.Error = 'Get-MpComputerStatus is not available on this host'
        return $result
    }
    try {
        $status = Get-MpComputerStatus
    }
    catch {
        # Present but unusable: the cmdlet exists while the Defender WMI
        # provider does not answer, which happens on a host where the feature
        # was removed. Reported, not swallowed.
        $result.Error = ('Get-MpComputerStatus failed: ' + $_.Exception.Message)
        return $result
    }

    $result.Available                 = $true
    $result.RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
    $result.IsTamperProtected         = $status.IsTamperProtected
    $result.AMRunningMode             = $status.AMRunningMode
    $result.AMServiceEnabled          = $status.AMServiceEnabled
    $result.AntivirusSignatureAge     = $status.AntivirusSignatureAge
    $result.AntivirusSignatureUpdated = $status.AntivirusSignatureLastUpdated
    return $result
}

function Get-HklmValue {
    # One HKLM value, or $null when the key or the value is absent. Same
    # explicit 64-bit view, for the same reason as Get-HklmValueName.
    param(
        [Parameter(Mandatory = $true)][string] $SubKey,
        [Parameter(Mandatory = $true)][string] $Name
    )

    $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $hive.OpenSubKey($SubKey, $false)
        if ($null -eq $key) { return $null }
        return $key.GetValue($Name, $null)
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        $hive.Dispose()
    }
}

function Get-ThirdPartyAntivirusName {
    <#
        Supplementary only, and marked as such wherever it is used.

        UNVERIFIED: the root\SecurityCenter2 namespace and its AntiVirusProduct
        class. They are what every "which AV is installed" script uses and they
        are present on every Windows client and server this project targets,
        but no learn.microsoft.com documentation page for them was found. So no
        decision is ever taken on this result alone: the documented signals
        (AMRunningMode, AMServiceEnabled, and MsMpEng.exe in the process list)
        decide, and this only adds a name to the report.

        Returns an array of product names, empty when none is reported or when
        the namespace cannot be queried.
    #>
    try {
        $products = @(Get-CimInstance -Namespace 'root\SecurityCenter2' `
            -ClassName 'AntiVirusProduct' -ErrorAction Stop)
    }
    catch {
        Write-Verbose ('root\SecurityCenter2 could not be queried: ' + $_.Exception.Message)
        return @()
    }
    # Defender registers itself here too, so its own entry is not a third party.
    return @($products |
        Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' } |
        ForEach-Object { [string] $_.displayName })
}

function Test-DefenderPresence {
    <#
        Whether Defender is the antivirus actually doing the work. Run FIRST and
        reported loudly, because if it is not, the exclusion list below is close
        to irrelevant and printing it as a clean result would mislead whoever
        reads the RMM alert.

        The individual signals are reported as INFORMATION and exactly ONE
        finding is raised for the combined verdict. Three findings for one
        condition (mode, service flag, process) is three RMM alerts for one
        fact, and an operator who gets that once stops reading them.

        Returns $true when the documented signals say antivirus protection is
        enabled.
    #>
    param([Parameter(Mandatory = $true)] $Status)

    Write-Section 'Is Microsoft Defender the active antivirus'

    $thirdParty = Get-ThirdPartyAntivirusName
    $thirdPartyNote = ''
    if ($thirdParty.Count -gt 0) {
        $thirdPartyNote = (' A non-Microsoft antivirus is registered: ' + ($thirdParty -join ', ') +
                           ' (supplementary signal - see the UNVERIFIED note on Get-ThirdPartyAntivirusName).')
    }

    if (-not $Status.Available) {
        Write-Finding ('Defender status could not be read (' + $Status.Error +
                       '), so this host''s antivirus state is UNKNOWN, not good.' + $thirdPartyNote)
        return $false
    }

    $mode = [string] $Status.AMRunningMode
    if ([string]::IsNullOrWhiteSpace($mode)) {
        Write-Info 'AMRunningMode: not reported by this build'
    }
    elseif ($script:RunningModeEnabled -contains $mode) {
        Write-Ok ('AMRunningMode = ' + $mode +
                  ' (one of the three values Microsoft documents as "antivirus protection is enabled")')
    }
    else {
        Write-Info ('AMRunningMode = ' + $mode +
                    ' - not one of the three values Microsoft documents (Normal, Passive, EDR Block Mode)')
    }

    if ($null -eq $Status.AMServiceEnabled) {
        Write-Info 'AMServiceEnabled: not reported by this build'
    }
    elseif ([bool] $Status.AMServiceEnabled) {
        Write-Ok 'AMServiceEnabled = True'
    }
    else {
        Write-Info 'AMServiceEnabled = False - the antimalware engine is not enabled'
    }

    # "Run the following PowerShell cmdlet: Get-Process. Review the results. You
    # should see MsMpEng.exe if Microsoft Defender Antivirus is enabled."
    # https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility
    $engine = @(Get-Process -Name 'MsMpEng' -ErrorAction SilentlyContinue)
    if ($engine.Count -gt 0) { Write-Ok 'MsMpEng.exe is running' }
    else { Write-Info 'MsMpEng.exe is not running' }

    $passive = Get-HklmValue -SubKey $script:PassiveModeKey -Name $script:PassiveModeValue
    if ($null -ne $passive -and ([int] $passive) -ne 0) {
        Write-Info ('HKLM\' + $script:PassiveModeKey + '\' + $script:PassiveModeValue + ' = ' +
                    [string] ([int] $passive) + ' - this host is configured to keep Defender in passive mode')
    }
    if ($thirdParty.Count -gt 0) { Write-Info ($thirdPartyNote.Trim()) }

    # The verdict is taken from the two DOCUMENTED signals only. The third-party
    # name above never changes it: that source is unverified, so it may add a
    # name to the report but it may not decide anything.
    $active = ($engine.Count -gt 0)
    if ($null -ne $Status.AMServiceEnabled) { $active = ($active -and [bool] $Status.AMServiceEnabled) }

    if ($active) {
        # DF-2: AMRunningMode is part of the verdict, not just reported above.
        # MsMpEng running and the service enabled says Defender is PRESENT; it does
        # NOT say it is the primary real-time antivirus. Passive and EDR Block Mode
        # both mean something else is (or should be) doing real-time protection, so
        # an unqualified "Defender is running" clean bill on such a host hides that
        # its real-time protection is not Defender's. Only Normal mode earns the
        # plain OK; any other reported mode is a finding, told once per run - the
        # same rule the Defender-off finding below already uses for a deliberate
        # third-party estate.
        $mode = [string] $Status.AMRunningMode
        if ([string]::IsNullOrWhiteSpace($mode)) {
            Write-Ok 'Microsoft Defender Antivirus is running (AMRunningMode not reported by this build)'
            return $true
        }
        if ($mode -eq 'Normal') {
            Write-Ok 'Microsoft Defender Antivirus is running on this host in Normal mode'
            return $true
        }
        Write-Finding ('Microsoft Defender is running but in ' + $mode + ' mode, NOT Normal - it is ' +
                       'not the primary real-time antivirus on this host. Real-time protection is ' +
                       'something else''s job here (or nothing''s); confirm what is providing it before ' +
                       'trusting this host''s antivirus posture.' + $thirdPartyNote)
        return $false
    }

    # One finding, and it stays a finding even when a third-party product is
    # named: a host where Defender is off is a host where everything below
    # describes configuration nothing is enforcing, and an estate that runs
    # another AV deliberately should be told once per run rather than never.
    Write-Finding ('MICROSOFT DEFENDER IS NOT PROTECTING THIS HOST. Everything below describes ' +
                   'configuration that nothing is currently enforcing, so a short or clean exclusion ' +
                   'list here says nothing about this host''s real exposure.' + $thirdPartyNote)
    return $false
}

function Test-DefenderPosture {
    <#
        Real-time protection, tamper protection, signature age, and whether the
        channel that records Defender's own settings changes exists. Reported
        only: this script does not write antivirus policy.
    #>
    param([Parameter(Mandatory = $true)] $Status)

    Write-Section 'Protection posture'

    if ($Status.Available) {
        if ($null -eq $Status.RealTimeProtectionEnabled) {
            Write-Finding 'RealTimeProtectionEnabled was not reported by this host'
        }
        elseif ([bool] $Status.RealTimeProtectionEnabled) {
            Write-Ok 'RealTimeProtectionEnabled = True'
        }
        else {
            Write-Finding 'RealTimeProtectionEnabled = False - nothing is scanning files as they are opened'
        }

        if ($null -eq $Status.IsTamperProtected) {
            Write-Finding ('IsTamperProtected was not reported by this host, so tamper protection state ' +
                           'is unknown. Older builds do not expose it.')
        }
        elseif ([bool] $Status.IsTamperProtected) {
            Write-Ok 'IsTamperProtected = True'
        }
        else {
            # Serious, and NOT a finding - a host limit. The distinction is the
            # lever: tamper protection is turned on through Intune or Microsoft
            # Defender for Endpoint, and nothing this toolkit can do will change
            # it. Most SMB fleets an MSP runs do not have either, so as a finding
            # this raised exit 1 on every one of those hosts on every run,
            # forever. A monitor that is always red gets muted, and then the NEW
            # exclusion this script exists to catch is muted with it.
            #
            # It is still printed, still counted, and still queryable - it just
            # is not an alarm, because there is no action for the alarm to
            # prompt.
            Write-HostLimit ('IsTamperProtected = False - with tamper protection ON, Microsoft ' +
                             'documents that exclusions cannot be modified or added. With it OFF, adding ' +
                             'an exclusion for an attacker''s working directory is one command. Turning it ' +
                             'on needs Intune or Defender for Endpoint; this toolkit cannot, so this is ' +
                             'reported rather than alerted.')
        }

        if ($null -eq $Status.AntivirusSignatureAge) {
            Write-Finding 'AntivirusSignatureAge was not reported by this host'
        }
        else {
            $age = [int64] $Status.AntivirusSignatureAge
            $updated = 'never'
            if ($null -ne $Status.AntivirusSignatureUpdated) {
                $updated = ([datetime] $Status.AntivirusSignatureUpdated).ToUniversalTime().ToString(
                    'yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
            }
            # Microsoft documents the sentinel: "if signatures have never been
            # updated you will see an age of 65535 days".
            # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpcomputerstatus
            if ($age -eq 65535) {
                Write-Finding 'the antivirus signatures have NEVER been updated (age 65535, the documented sentinel)'
            }
            elseif ($age -gt $SignatureAgeThresholdDays) {
                Write-Finding ('the antivirus signatures are ' + [string] $age + ' day(s) old (last updated ' +
                               $updated + '). The threshold is ' + [string] $SignatureAgeThresholdDays +
                               ' day(s), which is this toolkit''s choice and not a Microsoft recommendation.')
            }
            else {
                Write-Ok ('the antivirus signatures are ' + [string] $age + ' day(s) old (last updated ' +
                          $updated + '), within the ' + [string] $SignatureAgeThresholdDays + '-day threshold')
            }
        }
    }

    # The channel is where event 5007, "Event when settings are changed", lands.
    # Without it there is no local record of an exclusion being added.
    $log = $null
    try { $log = Get-WinEvent -ListLog $script:DefenderChannel -ErrorAction Stop }
    catch { $log = $null }

    if ($null -eq $log) {
        Write-Finding ('the ' + $script:DefenderChannel + ' channel is not present, so event ' +
                       [string] $script:SettingsChangeEventId +
                       ' ("settings were changed") is not being recorded anywhere on this host')
    }
    elseif (-not $log.IsEnabled) {
        Write-Finding ('the ' + $script:DefenderChannel + ' channel exists but is DISABLED')
    }
    else {
        Write-Ok ('the ' + $script:DefenderChannel + ' channel is enabled with ' +
                  [string] $log.RecordCount + ' record(s) - event ' +
                  [string] $script:SettingsChangeEventId + ' there is what logs a settings change')
    }
}

function Invoke-HostCheck {
    # Both halves of the report, in the order an operator reads them: is Defender
    # the antivirus on this host at all, and then what is it configured to do.
    # READ ONCE, passed to both. Get-MpComputerStatus and Get-MpPreference are two
    # WMI round trips each; calling them twice would also let the two halves of one
    # report describe two different instants.
    $status = Get-DefenderStatus
    [void] (Test-DefenderPresence -Status $status)
    [void] (Test-DefenderPosture -Status $status)

    Write-Section 'What this script does not check'
    Write-Info 'The exclusion list is not diffed here. Protect-DefenderConfig owns the recorded'
    Write-Info 'baseline and the alert on a newly added exclusion; this script reports posture'
    Write-Info 'only. An exclusion added since the last baseline is invisible to this run.'
}

#endregion

#region Main -----------------------------------------------------------------

function Invoke-Main {
    Write-Host ('IronBlackBox - ' + $script:ScriptName + ' v' + $script:ScriptVersion +
                ' [Audit]') -ForegroundColor White

    # -Audit is accepted and ignored: it is the only mode. Rejecting it would make
    # this the one script in the toolkit an RMM component cannot invoke uniformly,
    # and silently accepting a mode that did NOT match would be worse - there is
    # no -Apply here to confuse it with.
    # P-1: the value check BEFORE anything is read. A [Validate*] attribute fails at
    # binding time and exits 1, which collides with "findings" - docs/DESIGN.md
    # section 3. A throw here reaches the bottom catch and exits 2.
    Assert-ParameterRange -Name 'SignatureAgeThresholdDays' -Value $SignatureAgeThresholdDays `
        -Minimum 1 -Maximum 365

    Assert-Elevated

    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    # -ReadOnly: reports an ACL problem on the toolkit root as a finding and
    # changes nothing. This script writes nothing, so adopting or hardening the
    # root here would be a write nobody asked for.
    [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)

    Invoke-HostCheck

    Write-Section 'Result'
    if ($script:Findings.Count -gt 0) {
        Write-Info ([string] $script:Findings.Count +
                    ' finding(s). Read them before deciding this host is protected.')
        if ($script:HostLimits.Count -gt 0) {
            Write-Info ([string] $script:HostLimits.Count + ' host limit(s) as well - see ' +
                        '[limit] above. Those are NOT part of the exit code.')
        }
        return 1
    }
    if ($script:HostLimits.Count -gt 0) {
        # Exit 0, deliberately. They are real and printed above, and nothing this
        # toolkit runs will clear them on this host, so alerting would leave an RMM
        # monitor permanently red - and one that is always red gets muted.
        Write-Ok ('No findings. ' + [string] $script:HostLimits.Count + ' host limit(s) reported ' +
                  'above: true on this host and not clearable by any script here, so they do not ' +
                  'raise the exit code.')
        return 0
    }
    Write-Ok 'No findings: Defender is configured as this toolkit expects.'
    return 0
}

try {
    exit (Invoke-Main)
}
catch {
    Write-Failure $_.Exception.Message
    if ($null -ne $_.ScriptStackTrace) {
        foreach ($frame in ($_.ScriptStackTrace -split "`n")) {
            if (-not [string]::IsNullOrWhiteSpace($frame)) { Write-Host ('  ' + $frame.Trim()) }
        }
    }
    exit 2
}

#endregion
