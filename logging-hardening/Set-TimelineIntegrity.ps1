<#
.SYNOPSIS
    Forces reliable time synchronisation and records the timezone and clock skew,
    because a forensic timeline built on a wrong clock is worse than no timeline.

.DESCRIPTION
    A responder correlating a firewall log, a domain controller's 4624 and an
    endpoint's 4688 needs to know each host's offset from real time and its
    timezone. Windows records neither anywhere durable. This script audits both,
    fixes the time configuration where it is safe to, and writes what it observed
    to a JSON record under the toolkit root so a later collection captures what
    the clock looked like at hardening time. That record is the point of the name.

    Every registry path, value and w32tm parameter is cited to
    learn.microsoft.com; the value KINDS are not documented and are handled as
    described at Resolve-W32TimeValueKind.

    DOMAIN MEMBERS: the time source is NOT changed without -Force.
    Microsoft: "By default, a computer that's joined to a domain synchronizes
    time through a domain hierarchy of time sources ... Most domain-joined
    computers have a time client type of Net Time 5 Directory Service (NT5DS),
    which means that they synchronize time from the domain hierarchy." Forcing
    NTP peers onto such a host is a misconfiguration, not hardening: it takes the
    machine out of the hierarchy its Kerberos tickets are timed against. So on
    any domain-joined host this script reports the situation and refuses to touch
    Type, NtpServer or SpecialPollInterval unless -Force is passed. The one case
    where -Force is legitimate is the forest root PDC emulator, which Microsoft
    documents as the exception that does sync from an external source - detecting
    that role reliably needs directory queries this script does not make, so the
    decision is left to the operator.

    What it still does on a domain member without -Force: makes sure W32Time is
    Automatic and running. A stopped time service is a fault on any host and
    fixing it does not fight the hierarchy.

    What this script deliberately does NOT do:
      - It does not set the clock. Nothing here calls w32tm /resync until the
        configuration is in place, and it never writes a time directly. A
        hardening script that steps a production server's clock breaks Kerberos,
        database replication and TLS in one move.
      - It does not change the timezone. The timezone is RECORDED, never set: an
        operator's regional choice is not drift, and a script that "corrects" it
        shifts every local timestamp on the host.
      - It does not configure the host as an NTP server (W32Time\TimeProviders\
        NtpServer\Enabled), which is a DC decision, not a hardening default.
      - It does not enable the W32Time private log (w32tm /debug). High volume,
        and not an artifact a responder reads.
      - It does not roll back the JSON clock record. -Rollback restores the
        configuration and deliberately leaves the observation on disk: deleting a
        forensic record to satisfy a rollback is the same mistake as deleting a
        USN journal to satisfy one.

    What needs a reboot:
      NOTHING. Microsoft's own example applies a W32Time configuration change
      with `w32tm /config ... /update` followed by a service restart, which is
      what -Apply does. The effect is then PROVEN by re-reading
      `w32tm /query /source`; if the source has not changed, that is a finding
      and the exit code is 1, not 0.

.PARAMETER Audit
    Default. Strictly read-only. Reports the time source, configuration, status,
    timezone, measured offset and service state, plus the exact registry paths
    and values -Apply would write. Writes nothing anywhere.

.PARAMETER Apply
    Writes the NTP configuration (subject to the domain rule above), ensures
    W32Time is Automatic and running, resyncs, and writes the clock record.

.PARAMETER Rollback
    Restores the recorded previous registry values and service state.

.PARAMETER ToolkitRoot
    Base directory for the manifest and the clock record.
    Default C:\ProgramData\IronBlackBox. Validated before use.

.PARAMETER NtpServer
    Peer list. Default 'time.windows.com', which is Microsoft's own documented
    default for a stand-alone Windows host ("The default value on stand-alone
    clients and servers is time.windows.com,0x1"). No third-party pool is
    hard-coded here: a hardening tool should not silently repoint an MSP's whole
    fleet at somebody else's infrastructure. Each entry is written with the
    documented 0x1 SpecialInterval flag so -SpecialPollIntervalSeconds applies.

.PARAMETER SpecialPollIntervalSeconds
    W32Time\TimeProviders\NtpClient\SpecialPollInterval, in seconds. Default
    1024, which is Microsoft's documented Group Policy default for the NTP
    client. Note the out-of-box registry defaults differ (3,600 on a domain
    member, 604,800 on a stand-alone host) - a week between polls is why an
    unmanaged host drifts.

.PARAMETER SkewWarningSeconds
    Report a finding when the measured offset exceeds this many seconds. Default
    5. This is a forensic-correlation threshold chosen by this toolkit, not a
    Windows or Kerberos limit.

.PARAMETER StripchartSamples
    Samples for `w32tm /stripchart`. Default 3.

.PARAMETER Force
    Change the time source even on a domain-joined host. Read the domain rule
    above before using it.

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
    .\Set-TimelineIntegrity.ps1
    Reports the clock, the timezone, the measured offset and what -Apply would set.

.EXAMPLE
    .\Set-TimelineIntegrity.ps1 -Apply
    Configures NTP on a stand-alone host, starts W32Time, resyncs, records the clock.

.EXAMPLE
    .\Set-TimelineIntegrity.ps1 -Apply -Force -NtpServer 'ntp1.example.net','ntp2.example.net'
    Same, on a domain-joined host, with the operator taking responsibility.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.1.1
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
    [string[]] $NtpServer = @('time.windows.com'),

    [Parameter()]
    [int] $SpecialPollIntervalSeconds = 1024,

    [Parameter()]
    [double] $SkewWarningSeconds = 5,

    [Parameter()]
    [int] $StripchartSamples = 3,

    [Parameter()]
    [switch] $Force,

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

$script:ScriptName    = 'Set-TimelineIntegrity'
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
#   Parameters and TimeProviders\NtpClient, both under the W32Time service.
$script:OwnedRegistryKey = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time'
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

#region Native tool paths ----------------------------------------------------

# Anchored once, here, rather than at each call site: the only native tool this
# script launches has to be the in-box one. A bare file name is resolved through
# the machine PATH, and this script runs as SYSTEM - so a PATH entry an
# unprivileged user can write to would choose the binary. The same argument
# Assert-SafeToolkitPath makes about operator input applies with more force to an
# environment variable, which no operator has to touch. Get-NativeToolPath falls
# back to the bare name, so an unusual layout still runs; it just stops being
# anchored.
$script:W32tmPath = Get-NativeToolPath -FileName 'w32tm.exe'

#endregion

#region Windows Time ----------------------------------------------------------

<#
    Registry locations and w32tm parameters, all from Microsoft's Windows Time
    Service reference:
    https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings

    Quoted verbatim, the facts this script depends on:
      "W32Time stores information under the following registry paths:
        HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters
        HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient"
      Parameters\Type - "NoSync ... NTP: The time service synchronizes with the
        servers specified in the NtpServer registry entry. NT5DS: The time
        service synchronizes with the domain hierarchy. AllSync ... The default
        value on domain members is NT5DS. The default value on stand-alone
        clients and servers is NTP."
      Parameters\NtpServer - "a space-delimited list of peers ... 0x1:
        SpecialInterval. 0x2: UseAsFallbackOnly. 0x4: SymmetricActive. 0x8:
        Client ... The default value on stand-alone clients and servers is
        time.windows.com,0x1."
      NtpClient\SpecialPollInterval - "the special poll interval in seconds for
        manual peers. When the SpecialInterval 0x1 flag is enabled, W32Time uses
        this poll interval instead of a poll interval determined by the operating
        system." GPO default 1024.
      NtpClient\Enabled - "Indicates whether the NtpClient provider is enabled in
        the current time service. 1: Yes. 0: No."
      w32tm /query {/source | /configuration | /status} [/verbose]
      w32tm /config [/manualpeerlist:<peers>] [/syncfromflags:<source>] [/update]
        - "/update: Notifies W32Time that the configuration is changing, causing
          the changes to take effect."
      w32tm /resync, w32tm /stripchart /computer:<target> [/dataonly]
        [/samples:<count>] - "NTPOffset: The time offset in seconds between the
        local computer and the NTP server."
#>

$script:W32TimeParametersKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
$script:W32TimeNtpClientKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'
$script:W32TimeServiceName   = 'W32Time'

# 0x8 Client | 0x1 SpecialInterval. Microsoft documents both '0x1' (the
# stand-alone Parameters\NtpServer default) and '0x9' (the Configure Windows NTP
# Client policy default); 0x9 is the superset and is what a client that should
# poll on SpecialPollInterval needs, so that is what gets written.
$script:NtpServerFlags = '0x9'

# Win32_ComputerSystem.DomainRole. 0 Standalone Workstation, 1 Member
# Workstation, 2 Standalone Server, 3 Member Server, 4 Backup Domain Controller,
# 5 Primary Domain Controller.
# https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
$script:DomainRoleNames = @{
    0 = 'Standalone Workstation'; 1 = 'Member Workstation'; 2 = 'Standalone Server'
    3 = 'Member Server'; 4 = 'Backup Domain Controller'; 5 = 'Primary Domain Controller'
}

function Get-LabelledLineValue {
    <#
        Finds a "Label: value" line by matching the LABEL and returns the rest.

        # UNVERIFIED: w32tm's output layout is not a documented API and its
        # labels are localised, so none of the patterns used here will match on a
        # non-English Windows. Every caller therefore treats a missing field as
        # UNKNOWN and reports it as such - the raw output is always printed too,
        # so an operator on a localised host still sees the real answer even when
        # the parser cannot.
    #>
    param(
        # AllowEmptyString as well as AllowEmptyCollection, and not Mandatory:
        # a Mandatory [string[]] rejects an array containing an empty string,
        # which is exactly what a failed 'w32tm /stripchart' produces. Measured
        # on the lab, where the host has no outbound NTP route: w32tm exits 0,
        # prints three 0x800705B4 timeouts and no data lines, and this parameter
        # then threw a binding exception - taking the whole script to exit 2 on
        # a host whose only problem was a blocked firewall port. That is common
        # in the SMB estates this toolkit targets.
        [Parameter()][AllowEmptyCollection()][AllowEmptyString()][string[]] $Lines = @(),
        [Parameter(Mandatory = $true)][string] $LabelPattern
    )
    foreach ($line in $Lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $colon = $line.IndexOf(':')
        if ($colon -lt 1) { continue }
        if ($line.Substring(0, $colon) -match $LabelPattern) {
            return $line.Substring($colon + 1).Trim()
        }
    }
    return $null
}

function ConvertFrom-OffsetToken {
    <#
        Reads the OFFSET from a 'w32tm /stripchart /dataonly' line, and refuses
        the line if it cannot find one.

        This used to take the FIRST [+-]dd.dddddddS token on the line, which is
        the wrong column. w32tm emits delay before offset:

            14:52:18, d:+00.0072893s o:-09.9998877s

        so a host whose clock was ten seconds out reported an offset of 0.0073s,
        -SkewWarningSeconds could essentially never fire, and the number written
        into the forensic clock record was the round-trip delay presented as the
        clock offset. A wrong number in a forensic record is worse than a
        missing one.

        UNVERIFIED: the exact layout. Anchored on the 'o:' label, with a
        deliberate refusal rather than a fallback to the first token - if the
        label is absent the honest answer is "could not measure", not the delay.
    #>
    param([Parameter()][AllowEmptyString()][string] $Line = '')

    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }

    # Labelled form, which is what /dataonly is understood to emit.
    $labelled = [regex]::Match($Line, '(?i)\bo:\s*([+-]?\d+(?:\.\d+)?)\s*s')
    if ($labelled.Success) {
        $parsed = 0.0
        if ([double]::TryParse($labelled.Groups[1].Value,
                [System.Globalization.NumberStyles]::Float,
                [System.Globalization.CultureInfo]::InvariantCulture, [ref] $parsed)) {
            return $parsed
        }
        return $null
    }

    # Unlabelled form: exactly one signed seconds token on the line is
    # unambiguous. More than one is not, and guessing which is the offset is
    # how the original defect happened.
    $all = [regex]::Matches($Line, '([+-]\d+(?:\.\d+)?)\s*s')
    if ($all.Count -eq 1) {
        $parsed = 0.0
        if ([double]::TryParse($all[0].Groups[1].Value,
                [System.Globalization.NumberStyles]::Float,
                [System.Globalization.CultureInfo]::InvariantCulture, [ref] $parsed)) {
            return $parsed
        }
    }
    return $null
}

function Get-DomainMembership {
    $system = Get-CimInstance -ClassName Win32_ComputerSystem
    $role = -1
    if ($null -ne $system.DomainRole) { $role = [int] $system.DomainRole }
    $roleName = 'unknown'
    if ($script:DomainRoleNames.ContainsKey($role)) { $roleName = $script:DomainRoleNames[$role] }
    # PartOfDomain is documented as NULL when "the computer is not in a domain or
    # the status is unknown", so it is read as a tri-state and the ROLE decides.
    return [PSCustomObject] @{
        PartOfDomain = ($true -eq $system.PartOfDomain)
        DomainRole   = $role
        RoleName     = $roleName
        Domain       = [string] $system.Domain
        IsJoined     = ($role -in @(1, 3, 4, 5))
        IsDc         = ($role -in @(4, 5))
    }
}

function Get-W32TimeServiceState {
    $service = Get-Service -Name $script:W32TimeServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return [PSCustomObject] @{ Present = $false; Status = 'absent'; StartType = 'absent' }
    }
    return [PSCustomObject] @{
        Present   = $true
        Status    = [string] $service.Status
        StartType = [string] $service.StartType
    }
}

function Get-W32TimeQuery {
    # w32tm /query <what>. Returns the raw lines plus the exit code; callers
    # decide what a failure means rather than this treating one as empty state.
    param([Parameter(Mandatory = $true)][ValidateSet('source', 'configuration', 'status')][string] $QueryType)
    return (Invoke-NativeCommand -FilePath $script:W32tmPath -Arguments @('/query', ('/' + $QueryType)))
}

function Measure-ClockOffset {
    <#
        Measures the real offset against a peer with `w32tm /stripchart
        /computer:<peer> /samples:<n> /dataonly`, and returns the LAST parseable
        offset in seconds together with every sample.

        A peer that cannot be reached returns Reachable = $false. That is a
        FINDING, not an assumption that the clock is fine: "we could not measure
        it" and "it is correct" are different answers and only one of them is
        honest.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Peer,
        [Parameter(Mandatory = $true)][int] $Samples
    )

    $result = Invoke-NativeCommand -FilePath $script:W32tmPath -Arguments @(
        '/stripchart', ('/computer:' + $Peer), ('/samples:' + [string] $Samples), '/dataonly')

    $offsets = New-Object System.Collections.ArrayList
    foreach ($line in $result.Output) {
        # -Line, not -Text. The parameter was renamed when this parser was
        # rewritten to anchor on the 'o:' label and the caller was not, so every
        # call threw "A parameter cannot be found that matches parameter name
        # 'Text'" the moment w32tm produced any output at all. It went unseen
        # because the lab had no outbound NTP route and the output was empty.
        # PSScriptAnalyzer cannot catch this: it validates parameters against
        # known CMDLETS, and an unknown name is assumed to be a local function.
        $offset = ConvertFrom-OffsetToken -Line $line
        if ($null -ne $offset) { [void] $offsets.Add($offset) }
    }

    $last = $null
    if ($offsets.Count -gt 0) { $last = [double] $offsets[$offsets.Count - 1] }
    return [PSCustomObject] @{
        Peer          = $Peer
        Reachable     = ($result.ExitCode -eq 0 -and $offsets.Count -gt 0)
        OffsetSeconds = $last
        SampleCount   = $offsets.Count
        ExitCode      = $result.ExitCode
        Raw           = ($result.Output -join ' / ')
    }
}

function Resolve-W32TimeValueKind {
    <#
        # UNVERIFIED: the Windows Time reference page documents every value name
        # and its meaning but NOT its registry data type. Restoring a
        # REG_EXPAND_SZ as REG_SZ, or a REG_QWORD as REG_DWORD, is precisely the
        # loss docs/DESIGN.md section 4 makes previousKind mandatory to prevent -
        # so rather than assert a kind from memory, this prefers the kind the
        # HOST already holds and falls back to $ExpectedKind only when the value
        # does not exist yet. A host where W32Time has ever been registered has
        # these values, so the fallback is the rare path.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $ExpectedKind
    )
    $current = Get-RegistryValueState -Path $Path -Name $Name
    if (-not $current.Exists) { return $ExpectedKind }
    if ($script:SupportedKinds -notcontains $current.Kind) { return $ExpectedKind }
    if ($current.Kind -ne $ExpectedKind) {
        Write-Info ($Path + '\' + $Name + ' is ' + $current.Kind + ' on this host, not the expected ' +
                    $ExpectedKind + '; keeping the host''s kind so a rollback restores it faithfully')
    }
    return $current.Kind
}

function Set-TrackedW32TimeService {
    <#
        Ensures W32Time is Automatic and Running, recording the previous start
        type and status to the manifest first. Introduces the 'service' change
        type: a service start type is not registry state this script can reach
        through Set-TrackedRegistryValue without asserting the undocumented
        meaning of Services\<name>\Start, and an unrecorded change is a lost
        previous value.

        Returns $true when it changed something.
        Set-Service is documented to accept -StartupType Automatic and -Status
        Running:
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service
    #>
    $state = Get-W32TimeServiceState
    if (-not $state.Present) {
        Write-Finding ('the ' + $script:W32TimeServiceName + ' service is not present on this host,' +
                       ' so nothing will synchronise the clock')
        return $false
    }

    $needStartType = ($state.StartType -ne 'Automatic')
    $needRunning   = ($state.Status -ne 'Running')
    if (-not $needStartType -and -not $needRunning) {
        Write-Ok ($script:W32TimeServiceName + ' is Running and Automatic')
        return $false
    }
    $reason = ('is ' + $state.Status + '/' + $state.StartType + ', not Running/Automatic')

    # Finding in -Audit, information in -Apply. Emitting it in both would leave
    # every successful -Apply with a non-zero finding count, so a fixed host
    # would report exit 1 - "findings remain" - to an RMM. The template's
    # Set-TrackedRegistryValue splits it the same way and this has to match.
    if (-not $Apply) {
        Write-Finding ($script:W32TimeServiceName + ' ' + $reason + '; would run: Set-Service -Name ' +
                       $script:W32TimeServiceName + ' -StartupType Automatic; Start-Service -Name ' +
                       $script:W32TimeServiceName)
        return $false
    }
    Write-Info ($script:W32TimeServiceName + ' ' + $reason)

    [void] (Write-ManifestChange -Change @{
        type              = 'service'
        serviceName       = $script:W32TimeServiceName
        previousStartType = $state.StartType
        previousStatus    = $state.Status
        newStartType      = 'Automatic'
        newStatus         = 'Running'
        description       = ($script:W32TimeServiceName + ' -> Automatic, Running')
    })

    if ($needStartType) { Set-Service -Name $script:W32TimeServiceName -StartupType Automatic }
    if ($needRunning)   { Start-Service -Name $script:W32TimeServiceName }

    $after = Get-W32TimeServiceState
    if ($after.Status -ne 'Running' -or $after.StartType -ne 'Automatic') {
        Write-Finding ($script:W32TimeServiceName + ' is ' + $after.Status + '/' + $after.StartType +
                       ' after the change, not Running/Automatic')
    }
    else {
        Write-Ok ($script:W32TimeServiceName + ' is now Running and Automatic')
    }
    return $true
}

function Restore-ServiceChange {
    # Rolls back one 'service' record. Only Running and Stopped are restored;
    # any other recorded status (a pending transition) is declined rather than
    # guessed at, because there is no correct action for "was StartPending".
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    # BILINGUAL BY NECESSITY. The manifest is append-only, so a record written
    # before the field names were aligned keeps its original spelling. Renaming
    # the writer above does not rename what is already on disk.
    $name = [string] $change.serviceName
    if ([string]::IsNullOrWhiteSpace($name)) { $name = [string] $change.service }
    # The manifest is operator-writable input: a planted record must not turn
    # -Rollback into "stop any service on this host".
    if ($name -ne $script:W32TimeServiceName) {
        throw ('Refusing to roll back a service change for ' + $name + '; this script only owns ' +
               $script:W32TimeServiceName)
    }

    $current = Get-W32TimeServiceState
    if (-not $current.Present) {
        Write-Finding ($name + ' is no longer present, so its previous state cannot be restored')
        return 'declined'
    }
    $previousStartType = [string] $change.previousStartType
    $previousStatus    = [string] $change.previousStatus
    $newStartType      = [string] $change.newStartType
    if ($previousStartType -notin @('Automatic', 'Manual', 'Disabled')) {
        Write-Finding ($name + ': recorded previous StartType "' + $previousStartType +
                       '" is not one this script can restore; declining')
        return 'declined'
    }

    # T-3: three-way host resolution (docs/DESIGN.md section 4), not a blind
    # overwrite. The old code always Set-Service'd back to the previous value and
    # reported "Restored", even when the host now holds something an operator set
    # deliberately AFTER the -Apply - clobbering their change and calling it a
    # rollback.
    $currentStartType = [string] $current.StartType
    if ($currentStartType -eq $previousStartType) {
        # Case 2 (docs/DESIGN.md section 4.1): the host already holds the recorded
        # previous state. Either -Apply never actually landed, or this has already
        # been restored - the doctrine treats both as "nothing to do and nothing
        # wrong" and counts them RESTORED, which is what makes the run leave the
        # eligible set instead of being re-selected by every future -Rollback.
        # NOT 'declined-permanent': that is case 4, for a change no rollback can
        # EVER undo, and claiming it here would tell an MSP a change is
        # unrecoverable when in fact there is simply nothing to undo.
        Write-Info ($name + ' StartType is already ' + $previousStartType +
                    ' (the pre-apply value); nothing to undo.')
        return 'restored'
    }
    if (-not [string]::IsNullOrEmpty($newStartType) -and $currentStartType -ne $newStartType) {
        # Case 3: the host holds neither the applied value nor the previous one,
        # so something changed it after -Apply. Restoring would overwrite a
        # deliberate change; decline (retryable) and leave it alone.
        Write-Finding ($name + ' StartType is ' + $currentStartType + ', neither what -Apply set (' +
                       $newStartType + ') nor the pre-apply value (' + $previousStartType +
                       '); something changed it after this run, so it is left untouched.')
        return 'declined'
    }

    # Case 1: the host holds what -Apply set. Restore it to the previous value.
    Set-Service -Name $name -StartupType $previousStartType
    if ($previousStatus -eq 'Stopped' -and $current.Status -eq 'Running') {
        Stop-Service -Name $name
        Write-Info ($name + ' stopped, which is the state recorded before the -Apply.')
    }
    elseif ($previousStatus -eq 'Running' -and $current.Status -ne 'Running') {
        Start-Service -Name $name
    }
    elseif ($previousStatus -notin @('Running', 'Stopped')) {
        Write-Info ($name + ': previous status was "' + $previousStatus +
                    '" (a pending transition); StartType restored, run state left as found.')
    }
    Write-Ok ('Restored ' + $name + ' to StartType ' + $previousStartType)
    return 'restored'
}

# The clock as it was found, before -Apply changed anything. Set by
# Invoke-HostCheck, read by the record writer. See the comment where it is
# assigned for why losing it mattered.
$script:PreChangeSnapshot = $null

function Get-ClockSnapshot {
    <#
        Everything a responder needs to interpret this host's timestamps, in one
        object: timezone, local and UTC time, the W32Time source and status, the
        measured offset, and the service state. Also the payload of the JSON
        record -Apply writes.

        Get-TimeZone returns a System.TimeZoneInfo:
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-timezone
        https://learn.microsoft.com/en-us/dotnet/api/system.timezoneinfo
    #>
    param([Parameter(Mandatory = $true)] $Offset)

    $now = Get-Date
    $timeZone = Get-TimeZone
    $status = Get-W32TimeQuery -QueryType 'status'
    $source = Get-W32TimeQuery -QueryType 'source'
    $service = Get-W32TimeServiceState
    $domain = Get-DomainMembership

    $sourceText = 'unknown'
    if ($source.ExitCode -eq 0 -and $source.Output.Count -gt 0) {
        $sourceText = (($source.Output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; ')
    }

    return [PSCustomObject] @{
        recordedUtc            = (Get-UtcStamp)
        hostname               = [System.Net.Dns]::GetHostName()
        script                 = $script:ScriptName
        scriptVersion          = $script:ScriptVersion
        localTime              = $now.ToString('yyyy-MM-ddTHH:mm:ss.fff', [System.Globalization.CultureInfo]::InvariantCulture)
        utcOffsetOfLocalTime   = $timeZone.BaseUtcOffset.ToString()
        timeZoneId             = [string] $timeZone.Id
        timeZoneDisplayName    = [string] $timeZone.DisplayName
        supportsDaylightSaving = [bool] $timeZone.SupportsDaylightSavingTime
        daylightSavingInEffect = [bool] ([System.TimeZoneInfo]::Local.IsDaylightSavingTime($now))
        timeSource             = $sourceText
        lastSuccessfulSync     = (Get-LabelledLineValue -Lines $status.Output -LabelPattern 'last\s+successful\s+sync')
        phaseOffsetText        = (Get-LabelledLineValue -Lines $status.Output -LabelPattern 'phase\s+offset')
        stratumText            = (Get-LabelledLineValue -Lines $status.Output -LabelPattern '^\s*stratum\s*$')
        measuredPeer           = $Offset.Peer
        measuredOffsetSeconds  = $Offset.OffsetSeconds
        measuredPeerReachable  = [bool] $Offset.Reachable
        serviceStatus          = $service.Status
        serviceStartType       = $service.StartType
        domainRole             = $domain.DomainRole
        domainRoleName         = $domain.RoleName
        domain                 = $domain.Domain
    }
}

function Write-ClockRecord {
    # The named deliverable. Written on -Apply only: -Audit is strictly
    # read-only and must not create files under the toolkit root. Deliberately
    # NOT removed by -Rollback - see the header.
    param(
        [Parameter(Mandatory = $true)][string] $DirectoryPath,
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter()] $Before = $null,
        [Parameter()][bool] $ResyncRan = $false
    )
    if (-not (Test-Path -LiteralPath $DirectoryPath)) {
        [void] (New-Item -Path $DirectoryPath -ItemType Directory -Force)
    }

    # Both halves, explicitly labelled. 'asFound' is the clock BEFORE this run
    # touched it and is the half a responder needs to re-base timestamps written
    # while it was wrong; the top level describes the clock the host was left
    # with. On a run that changed nothing the two measurements are simply taken
    # a few seconds apart, and the record says which is which either way rather
    # than leaving a reader to guess.
    if ($null -ne $Before) {
        # clockWasStepped USED TO BE the inequality of the two offsets, and that
        # is true on essentially every run where both measurements succeed: they
        # are two separate '/stripchart' measurements taken seconds apart, and
        # two full-precision doubles of the same host are never bit-identical -
        # docs/VALIDATION.md's own lab values (-11.9857s, then -3.34E-05s) show
        # the precision. So an idempotent second -Apply, which never restarts
        # W32Time and never resyncs, recorded clockWasStepped:true. It was wrong
        # in the other direction too: with either offset unmeasurable the flag
        # read false even on a run that genuinely stepped the clock.
        #
        # Two things this script actually knows, combined:
        #   - whether it ran '/resync' at all. Nothing else here sets the clock
        #     (see the header), so no resync means nothing was stepped, and that
        #     half is certain.
        #   - whether the offset MOVED by more than the toolkit's own
        #     correlation threshold, -SkewWarningSeconds. A resync that shifted
        #     the clock by less than that changes no reader's conclusion about
        #     the host's timestamps, which is the question the flag answers.
        # $null - not $false - when the run resynced and an offset could not be
        # measured: "not determined" is the honest answer there, for the reason
        # ConvertFrom-OffsetToken states about the offset itself.
        $correctionApplied = $false
        if ($ResyncRan) {
            $correctionApplied = $null
            if ($null -ne $Before.measuredOffsetSeconds -and $null -ne $Snapshot.measuredOffsetSeconds) {
                $moved = [Math]::Abs([double] $Before.measuredOffsetSeconds -
                                     [double] $Snapshot.measuredOffsetSeconds)
                $correctionApplied = ($moved -gt $SkewWarningSeconds)
            }
        }
        Add-Member -InputObject $Snapshot -MemberType NoteProperty -Name 'asFound' `
            -Value $Before -Force
        Add-Member -InputObject $Snapshot -MemberType NoteProperty -Name 'clockWasStepped' `
            -Value $correctionApplied -Force
        # What the flag is derived from, so a reader is never left inferring it:
        # a run that did not resync cannot have stepped the clock, and the
        # threshold the comparison used is this toolkit's choice, not a Windows
        # or Kerberos limit.
        Add-Member -InputObject $Snapshot -MemberType NoteProperty -Name 'clockResyncRan' `
            -Value $ResyncRan -Force
        Add-Member -InputObject $Snapshot -MemberType NoteProperty -Name 'clockStepThresholdSeconds' `
            -Value $SkewWarningSeconds -Force
    }

    $fileName = 'clock-' + (Get-UtcStamp).Replace(':', '').Replace('.', '') + '.json'
    $path = [System.IO.Path]::Combine($DirectoryPath, $fileName)
    # UTF-8 with no BOM, written through .NET: Set-Content -Encoding UTF8 emits a
    # BOM under 5.1, which makes the file awkward for any JSON reader downstream.
    [System.IO.File]::WriteAllText($path, ($Snapshot | ConvertTo-Json -Depth 5),
        (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok ('clock record written to ' + $path)
    return $path
}

#endregion

#region Checks ----------------------------------------------------------------

function Set-NtpConfiguration {
    <#
        The four registry values that decide where this host gets its time.
        Returns the number of values changed.

        Note the accumulation idiom, and copy it exactly. Never write
        '$changed = $changed -or (...)': -or short-circuits, so once $changed is
        $true every later call is NEVER MADE and the script silently stops
        applying settings after the first one that worked.
    #>
    $peerList = (($NtpServer | ForEach-Object { $_ + ',' + $script:NtpServerFlags }) -join ' ')
    $changes = 0

    $kind = Resolve-W32TimeValueKind -Path $script:W32TimeParametersKey -Name 'Type' -ExpectedKind 'String'
    if (Set-TrackedRegistryValue -Path $script:W32TimeParametersKey -Name 'Type' `
        -Kind $kind -Value 'NTP' -Description 'time source Type = NTP') { $changes++ }

    $kind = Resolve-W32TimeValueKind -Path $script:W32TimeParametersKey -Name 'NtpServer' -ExpectedKind 'String'
    if (Set-TrackedRegistryValue -Path $script:W32TimeParametersKey -Name 'NtpServer' `
        -Kind $kind -Value $peerList -Description ('peer list = ' + $peerList)) { $changes++ }

    $kind = Resolve-W32TimeValueKind -Path $script:W32TimeNtpClientKey -Name 'SpecialPollInterval' -ExpectedKind 'DWord'
    if (Set-TrackedRegistryValue -Path $script:W32TimeNtpClientKey -Name 'SpecialPollInterval' `
        -Kind $kind -Value $SpecialPollIntervalSeconds `
        -Description ('SpecialPollInterval = ' + [string] $SpecialPollIntervalSeconds + 's')) { $changes++ }

    $kind = Resolve-W32TimeValueKind -Path $script:W32TimeNtpClientKey -Name 'Enabled' -ExpectedKind 'DWord'
    if (Set-TrackedRegistryValue -Path $script:W32TimeNtpClientKey -Name 'Enabled' `
        -Kind $kind -Value 1 -Description 'NtpClient provider enabled') { $changes++ }

    return $changes
}

function Get-ClockMeasurementPeer {
    # T-6: measure the clock offset against the host's ACTUAL time source, not a
    # hard-coded time.windows.com. A firewalled or domain-joined host cannot
    # reach time.windows.com (EC2 blocks external NTP; a domain member takes time
    # from the hierarchy), so measuring against it produced "could not measure"
    # and a finding on every run, forever, while the real source was fine.
    # w32tm /query /source names what the host really syncs from; the ',0xN' flag
    # suffix is stripped. A host on the Local CMOS / free-running clock has no
    # upstream source at all - reported as such, and falling back to the
    # configured peer only so an offset can still be attempted.
    #
    # THE EXIT CODE IS TESTED FIRST. Invoke-NativeCommand merges stderr into
    # Output, so a failed '/query /source' puts its error text in $raw - and that
    # text is neither whitespace nor a CMOS match, so it used to come back as the
    # measured peer. Three things followed: the free-running finding below was
    # skipped, '/stripchart /computer:<error text>' was run and reported as a
    # failed measurement against a sentence, and the error text was written into
    # the forensic record as measuredPeer. The trigger is not exotic - a stopped
    # W32Time is a condition this script exists to fix, and this runs BEFORE
    # Set-TrackedW32TimeService starts it. Get-ClockSnapshot already guards the
    # same query this way. docs/AUTHORING.md: a native tool's exit code is not a claim
    # about its output, and discarding it is the same defect in reverse.
    #
    # "Could not read the source" is its own answer, kept separate from "the
    # source is the CMOS clock": one is a measurement this run could not take,
    # the other is a fact about the host.
    $q = Get-W32TimeQuery -QueryType 'source'
    $raw = ($q.Output -join ' ').Trim()
    if ($q.ExitCode -ne 0) {
        return [PSCustomObject] @{
            Peer = $NtpServer[0]; IsRealSource = $false; SourceReadable = $false
            RawSource = ('exit ' + [string] $q.ExitCode + ': ' + $raw)
        }
    }
    $candidate = ($raw -replace ',.*$', '').Trim()
    if ([string]::IsNullOrWhiteSpace($candidate) -or $raw -match '(?i)Local CMOS Clock|Free-running') {
        return [PSCustomObject] @{
            Peer = $NtpServer[0]; IsRealSource = $false; SourceReadable = $true; RawSource = $raw
        }
    }
    return [PSCustomObject] @{
        Peer = $candidate; IsRealSource = $true; SourceReadable = $true; RawSource = $raw
    }
}

function Invoke-HostCheck {
    $domain = Get-DomainMembership
    $measurePeer = Get-ClockMeasurementPeer
    $peer = $measurePeer.Peer
    if (-not $measurePeer.SourceReadable) {
        # Not "free-running": the query failed, so what this host syncs from is
        # unknown rather than known to be nothing. A finding either way - the
        # same treatment '/query /status' failing gets below - and W32Time being
        # stopped is a lever -Apply pulls a few sections down.
        Write-Finding ('w32tm /query /source failed (' + $measurePeer.RawSource + '), so this run ' +
                       'cannot tell what this host synchronises from. The offset below is measured ' +
                       'against ' + $peer + ' only as a reference.')
    }
    elseif (-not $measurePeer.IsRealSource) {
        Write-Finding ('this host has no upstream time source (w32tm /query /source: ' +
                       $measurePeer.RawSource + '), so its clock is free-running and its timestamps ' +
                       'cannot be trusted to line up with anything. The offset below is measured ' +
                       'against ' + $peer + ' only as a reference.')
    }
    $changeCount = 0

    Write-Section 'Host and clock'
    Write-Info ('domain role: ' + $domain.RoleName + ' (' + [string] $domain.DomainRole +
                '), domain/workgroup: ' + $domain.Domain)

    $offset = Measure-ClockOffset -Peer $peer -Samples $StripchartSamples
    if (-not $offset.Reachable) {
        Write-Finding ('the clock offset could NOT be measured against ' + $peer +
                       ' (w32tm /stripchart exit ' + [string] $offset.ExitCode +
                       '); this is not evidence that the clock is correct')
        Write-Info ('w32tm said: ' + $offset.Raw)
    }
    else {
        $text = $offset.OffsetSeconds.ToString('N4', [System.Globalization.CultureInfo]::InvariantCulture)
        if ([Math]::Abs($offset.OffsetSeconds) -gt $SkewWarningSeconds) {
            $message = ('clock offset against ' + $peer + ' is ' + $text + 's, beyond the ' +
                        [string] $SkewWarningSeconds + 's threshold - timestamps on this host will' +
                        ' not line up with other machines')
            # In -Apply this is the offset BEFORE the resync, so it is reported
            # as information here and re-measured afterwards. The post-resync
            # measurement is the one allowed to raise a finding: raising it here
            # too would make a run that successfully corrected the clock exit 1.
            if ($Apply) { Write-Info $message } else { Write-Finding $message }
        }
        else {
            Write-Ok ('clock offset against ' + $peer + ' is ' + $text + 's')
        }
    }

    $snapshot = Get-ClockSnapshot -Offset $offset

    # THE NUMBER THIS SCRIPT IS NAMED FOR (the review log kept in the development repository, T-1).
    #
    # This snapshot is taken BEFORE anything is changed, and on an -Apply run
    # the '/resync' that follows STEPS THE CLOCK. It used to be computed, shown
    # on the console, and then thrown away: the record written at the end of the
    # run was built from a fresh post-resync measurement, so the offset the host
    # had when it was found - the one that lets a responder re-base months of
    # timestamps that were written while the clock was wrong - survived only in
    # console scrollback. For a script called Set-TimelineIntegrity that was the
    # one number it could not afford to lose.
    #
    # NOT $script:Snapshot or anything that could collide with a parameter name:
    # in a .ps1 a parameter lives in the script scope, which is how -RunId was
    # destroyed by '$script:RunId = $null'. See docs/AUTHORING.md.
    $script:PreChangeSnapshot = $snapshot

    Write-Info ('timezone: ' + $snapshot.timeZoneId + ' (' + $snapshot.timeZoneDisplayName +
                '), DST in effect: ' + [string] $snapshot.daylightSavingInEffect)
    Write-Info ('time source: ' + $snapshot.timeSource)
    if ($null -ne $snapshot.lastSuccessfulSync) {
        Write-Info ('last successful sync: ' + $snapshot.lastSuccessfulSync)
    }
    else {
        # A finding only when w32tm ITSELF failed. An unparseable label is this
        # parser's limitation on a localised host, not a fault of the host, and
        # raising a permanent finding for it would make every French or German
        # endpoint alert an RMM forever with nothing an operator could fix.
        $statusQuery = Get-W32TimeQuery -QueryType 'status'
        if ($statusQuery.ExitCode -ne 0) {
            Write-Finding ('w32tm /query /status failed (exit ' + [string] $statusQuery.ExitCode +
                           '), so this host cannot confirm it has ever synchronised its clock')
        }
        else {
            Write-Info 'last successful sync: w32tm reported it under a label this parser did not'
            Write-Info 'recognise (a localised Windows); the raw status output is the authority here.'
        }
    }

    Write-Section 'W32Time service'
    if (Set-TrackedW32TimeService) { $changeCount++ }

    Write-Section 'Time source configuration'
    Write-Info ('paths -Apply writes: ' + $script:W32TimeParametersKey + ' (Type, NtpServer) and ' +
                $script:W32TimeNtpClientKey + ' (SpecialPollInterval, Enabled)')

    if ($domain.IsJoined -and -not $Force) {
        # The domain rule. Report, do not touch. A member that syncs from the
        # hierarchy is CORRECT, and the finding here is informational drift for
        # an operator to judge, not a defect to fix by force.
        $currentType = Get-RegistryValueState -Path $script:W32TimeParametersKey -Name 'Type'
        $typeText = 'not set'
        if ($currentType.Exists) { $typeText = [string] $currentType.Value }
        # T-4: a member correctly syncing from the domain hierarchy (Type NT5DS)
        # is the RIGHT configuration - reporting it as a finding made every
        # domain-joined host exit 1 forever on its correct state. Only a member
        # that is NOT on NT5DS (it takes time from somewhere else) is worth a
        # finding here; the correct NT5DS case is an OK, not a defect.
        if ($typeText -eq 'NT5DS') {
            Write-Ok ('this host is domain-joined (' + $domain.RoleName + ') and Type is NT5DS: it ' +
                      'correctly synchronises from the domain hierarchy. Not changed, and not a problem.')
        }
        else {
            Write-Finding ('this host is domain-joined (' + $domain.RoleName + ') but Type is ' +
                           $typeText + ', not NT5DS - it is not taking time purely from the domain ' +
                           'hierarchy. Not changed without -Force; confirm this is intended.')
        }
        Write-Info 'Pass -Force only if this host is genuinely the forest root PDC emulator, or is'
        Write-Info 'otherwise meant to take its time from an external peer.'
    }
    else {
        if ($domain.IsJoined) {
            Write-Info ('-Force was passed on a domain-joined host (' + $domain.RoleName +
                        '): overriding the domain time hierarchy on the operator''s authority.')
        }
        $changeCount += Set-NtpConfiguration
    }

    return [PSCustomObject] @{
        ChangeCount     = $changeCount
        Snapshot        = $snapshot
        SourceConfigured = (-not $domain.IsJoined -or [bool] $Force)
    }
}

function Invoke-TimeServiceRefresh {
    <#
        Applies the configuration and PROVES it, rather than assuming a registry
        write reached the running service. /update is Microsoft's documented
        notification mechanism; the service restart follows Microsoft's own
        worked example, and /resync is what actually pulls time from the peers.

        Returns $true when the new source could be demonstrated. A false here is
        a finding, which makes -Apply exit 1: the settings are recorded and real,
        but the effect is unproven and saying otherwise would be a lie.
    #>
    $update = Invoke-NativeCommand -FilePath $script:W32tmPath -Arguments @('/config', '/update')
    if ($update.ExitCode -ne 0) {
        Write-Finding ('w32tm /config /update exited ' + [string] $update.ExitCode + ': ' +
                       ($update.Output -join ' '))
    }

    $service = Get-W32TimeServiceState
    if ($service.Present -and $service.Status -eq 'Running') {
        Restart-Service -Name $script:W32TimeServiceName
    }

    $resync = Invoke-NativeCommand -FilePath $script:W32tmPath -Arguments @('/resync')
    if ($resync.ExitCode -ne 0) {
        Write-Finding ('w32tm /resync exited ' + [string] $resync.ExitCode +
                       ' - the peers may be unreachable from this host: ' + ($resync.Output -join ' '))
    }

    return (Test-ConfiguredPeerInUse)
}

function Test-ConfiguredPeerInUse {
    # Read-only proof that the host is actually taking its time from a configured
    # peer. Kept separate from Invoke-TimeServiceRefresh so that an -Apply which
    # changed nothing can prove the effect WITHOUT restarting W32Time: a second
    # idempotent run must not disrupt the running time service.
    $source = Get-W32TimeQuery -QueryType 'source'
    $sourceText = ($source.Output -join ' ')
    Write-Info ('time source now: ' + $sourceText.Trim())
    foreach ($peer in $NtpServer) {
        if ($sourceText -match [regex]::Escape($peer)) { return $true }
    }
    Write-Finding ('the configured peer(s) do not appear in w32tm /query /source, so the new time' +
                   ' source could not be demonstrated on this run')
    return $false
}

#endregion

#region Main -----------------------------------------------------------------

function Restore-TimelineChange {
    <#
        Routes a change record to the right restorer. The template's
        Restore-TrackedChange only knows 'registry' and declines anything else -
        correctly, since silently "succeeding" on a change type it cannot undo is
        how a run gets marked rolled back while the host stays modified. This
        script introduces 'service', so it handles that one here and delegates
        the rest.

        Returns 'restored' or 'declined'; throws on failure.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    if ($ChangeRecord.change.type -ne 'service') {
        return (Restore-TrackedChange -ChangeRecord $ChangeRecord)
    }
    return (Restore-ServiceChange -ChangeRecord $ChangeRecord)
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
    Assert-ParameterCount   -Name 'NtpServer' -Value $NtpServer -Minimum 1 -Maximum 10
    Assert-ParameterPattern -Name 'NtpServer' -Value $NtpServer -Pattern '^[A-Za-z0-9][A-Za-z0-9\.\-]*$' `
        -Describe 'a host name starting with a letter or digit and containing only letters, digits, dots and hyphens'
    Assert-ParameterRange   -Name 'SpecialPollIntervalSeconds' -Value $SpecialPollIntervalSeconds -Minimum 64 -Maximum 604800
    Assert-ParameterRange   -Name 'SkewWarningSeconds' -Value $SkewWarningSeconds -Minimum 0.1 -Maximum 3600
    Assert-ParameterRange   -Name 'StripchartSamples' -Value $StripchartSamples -Minimum 1 -Maximum 20

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')
    $recordDirectory = [System.IO.Path]::Combine($resolvedRoot, 'TimelineIntegrity')

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        [void] (Invoke-HostCheck)
        Write-Section 'Result'
        # The reported path is the one -Apply would really use, derived from the
        # same root. An audit that names a different path than apply writes is a
        # defect this repo has paid for once already.
        Write-Info ('-Apply would write the clock record under ' + $recordDirectory)
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
        Write-Ok 'No findings: the clock is synchronised, measured and within threshold.'
        return 0
    }

    Enter-ToolkitLock -ToolkitRootPath $resolvedRoot
    try {
        $allowMissingStamp = ($mode -eq 'Rollback')
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -AllowMissingStamp:$allowMissingStamp)
        Assert-ManifestUsable

        if ($mode -eq 'Apply') {
            [void] (Start-ManifestRun -Mode 'Apply' -Parameters @{
                toolkitRoot                = $resolvedRoot
                ntpServer                  = @($NtpServer)
                specialPollIntervalSeconds = $SpecialPollIntervalSeconds
                skewWarningSeconds         = $SkewWarningSeconds
                stripchartSamples          = $StripchartSamples
                force                      = [bool] $Force
            })

            $status = 'completed'
            $proven = $false
            # Invoke-TimeServiceRefresh is the only thing here that resyncs, so
            # this is the whole truth about whether this run could have moved the
            # clock. The record's clockWasStepped is derived from it rather than
            # from two noisy offset measurements disagreeing.
            $resyncRan = $false
            try {
                $outcome = Invoke-HostCheck
                if (-not $outcome.SourceConfigured) {
                    # The domain rule refused to touch the time source, so there
                    # is nothing to prove and no reason to restart W32Time on a
                    # member that was already correct.
                    $proven = $true
                }
                elseif ($outcome.ChangeCount -gt 0) {
                    Write-Section 'Applying and proving the configuration'
                    $proven = Invoke-TimeServiceRefresh
                    $resyncRan = $true
                }
                else {
                    # Idempotent re-run: nothing changed, so the service is NOT
                    # restarted and nothing is resynced. The effect is still
                    # proven, read-only.
                    Write-Section 'Proving the configuration'
                    $proven = Test-ConfiguredPeerInUse
                }

                # Re-measure AFTER the resync so the record - and the skew
                # finding - describe the clock the host was left with, not the
                # one it started the run with.
                Write-Section 'Clock record'
                $postPeer = Get-ClockMeasurementPeer
                $offset = Measure-ClockOffset -Peer $postPeer.Peer -Samples $StripchartSamples
                if (-not $offset.Reachable) {
                    # T-5: the post-resync measurement is the one allowed to raise a
                    # skew finding, so if it could not be taken at all the run must
                    # NOT quietly exit 0 - a clock that was skewed before and cannot
                    # be re-measured is not a clock proven correct.
                    Write-Finding ('after synchronising, the clock offset could NOT be re-measured ' +
                        'against ' + $offset.Peer + ' (w32tm /stripchart exit ' + [string] $offset.ExitCode +
                        '), so this run cannot confirm the clock is now correct')
                }
                elseif ([Math]::Abs($offset.OffsetSeconds) -gt $SkewWarningSeconds) {
                    Write-Finding ('after synchronising, the clock is still off by ' +
                        $offset.OffsetSeconds.ToString('N4', [System.Globalization.CultureInfo]::InvariantCulture) +
                        's against ' + $offset.Peer)
                }
                [void] (Write-ClockRecord -DirectoryPath $recordDirectory `
                            -Snapshot (Get-ClockSnapshot -Offset $offset) `
                            -Before $script:PreChangeSnapshot -ResyncRan $resyncRan)
                if ($null -ne $script:PreChangeSnapshot -and
                    $null -ne $script:PreChangeSnapshot.measuredOffsetSeconds) {
                    Write-Info ('the record carries the offset as FOUND (' +
                        ([double] $script:PreChangeSnapshot.measuredOffsetSeconds).ToString('N4',
                            [System.Globalization.CultureInfo]::InvariantCulture) +
                        's) as well as the offset after this run, under "asFound" - that is what lets ' +
                        'a responder re-base timestamps written while the clock was wrong.')
                }
            }
            catch {
                Write-Failure $_.Exception.Message
                $status = 'completed-with-failures'
            }
            Stop-ManifestRun -Status $status
            Write-Section 'Result'
            if ($status -ne 'completed') { return 2 }
            # The VERIFIED change count, NOT the number of records written.
            # This script's Invoke-HostCheck returns an object rather than a bare
            # count, so the number comes off ChangeCount. docs/DESIGN.md section 4
            # flushes a change record BEFORE its change, so $script:ChangeIndex
            # counts INTENTS - reporting it as "applied" was defect U-3.
            $verified = 0
            if ($null -ne $outcome) { $verified = [int] $outcome.ChangeCount }
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
            Write-Info 'No reboot is needed: w32tm /config /update plus a service restart is what'
            Write-Info 'Microsoft''s own worked example uses, and that is what ran.'
            if (-not $proven) {
                Write-Info 'The configuration is recorded but its effect could not be demonstrated.'
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
                $outcome = Restore-TimelineChange -ChangeRecord $target.Changes[$i]
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


        # The restored values only reach the running service through /update.
        $update = Invoke-NativeCommand -FilePath $script:W32tmPath -Arguments @('/config', '/update')
        if ($update.ExitCode -ne 0) {
            Write-Info ('w32tm /config /update exited ' + [string] $update.ExitCode +
                        ' after the rollback; the registry values are restored either way.')
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
        Write-Info 'The clock records written under TimelineIntegrity are deliberately left in place.'
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
