<#
.SYNOPSIS
    Configures this host as a Windows Event Forwarding SOURCE: registers a
    collector in the SubscriptionManager policy, makes sure WinRM is running,
    and lets the forwarder account read the Security log.

.DESCRIPTION
    WEF is the one thing here that cannot be judged from a single host: it
    needs a collector, at least one source, and in practice a domain for the
    authentication. docs/VALIDATION.md is the only file allowed to say where
    this script has run, and its row is the one to read before deploying.

    Registry paths, value formats, service names and commands are cited to
    learn.microsoft.com inline; what could not be cited is marked
    '# UNVERIFIED:' in the code with what needs checking - those markers are
    per-fact and do not clear just because the script as a whole has been
    exercised.

    WEF is the poor man's SIEM: the events Enable-IRVisibility turns on are
    only useful while the host still has them, and a host that gets
    ransomwared, reimaged or simply rolls its Security log over takes them
    with it. Forwarding puts a copy somewhere else while it still exists.

    WinRM is the sharp edge here. WEF rides on WinRM, many RMM agents ride on
    WinRM too, and docs/AUTHORING.md forbids touching anything that can break RMM
    connectivity. So this script starts the WinRM service if it is stopped and
    does nothing else to it: no 'winrm quickconfig', no listener, no firewall
    rule, no restart of a running service. What it observes about WinRM it
    reports, and what it changes it records so -Rollback can put it back.

    What this script deliberately does NOT do:
      - Run 'winrm quickconfig' (or 'winrm qc -q'). It creates listeners and
        opens firewall ports and can disrupt an existing WinRM configuration.
        Microsoft's source-initiated walkthrough does tell you to run it on the
        source; this script refuses to, reports the listener state instead, and
        leaves that decision to the operator.
      - Create, delete or modify a WinRM listener, or touch the firewall.
      - Restart the WinRM service. Starting a stopped service is additive;
        restarting a running one drops every session on it, including an RMM's.
      - Add NETWORK SERVICE to the built-in Event Log Readers group, which is
        Microsoft's documented way to make the Security log readable. This
        script detects that route and, if it is already in place, changes
        nothing; when it has to act it grants the narrower right instead. See
        the 'Security channel readability' region for the full argument.
      - Enable or resize any event channel. A forwarder is passive: it cannot
        create events that were never generated, and the local channel size is
        the only buffer it has while the collector is unreachable. Sizing the
        Security, Application and System logs is Enable-IRVisibility's job and
        retention is Protect-EventLogs'.
      - Configure certificate-based (HTTPS) forwarding for sources outside the
        collector's domain. That needs a client authentication certificate, a
        certificate mapping on the collector and an IssuerCA thumbprint in the
        policy value; -CollectorUri accepts such a string verbatim, but this
        script does not provision certificates.
      - Verify that events arrive. It cannot: the collector is another host.
        It reports what the local forwarding channel says and returns 1 when
        it cannot demonstrate a connection.

.PARAMETER Audit
    Default. Strictly read-only. Reports the WinRM state, the collector URIs
    already registered, whether the forwarder can read the Security log, and
    what the forwarding channel says about connections.

.PARAMETER Apply
    Registers -CollectorUri, starts WinRM if needed, and grants the forwarder
    read access to the Security log, recording every previous value first.

.PARAMETER Rollback
    Restores the previous values recorded by a prior -Apply.

.PARAMETER ToolkitRoot
    Base directory for the manifest. Default C:\ProgramData\IronBlackBox.
    Validated before use - see Assert-SafeToolkitPath.

.PARAMETER CollectorUri
    The subscription manager to register. Required by -Apply, and checked in
    code rather than declared Mandatory: a missing mandatory parameter fails
    binding before the script's own code runs and returns host exit code 1,
    which collides with "findings" (docs/DESIGN.md section 3).

    Two forms are accepted:
      - a complete policy string, used verbatim, e.g.
        'Server=http://wec01.contoso.com:5985/wsman/SubscriptionManager/WEC,Refresh=900'
      - a URI, wrapped as 'Server=<uri>,Refresh=<RefreshSeconds>', e.g.
        'http://wec01.contoso.com:5985/wsman/SubscriptionManager/WEC'
    A bare hostname is refused: the scheme and port decide how the fleet
    authenticates to the collector and this script will not guess them.

.PARAMETER RefreshSeconds
    Refresh interval, in seconds, used only when -CollectorUri is a bare URI
    with no Refresh= of its own. Default 900. This is how often the source asks
    the collector which subscriptions it should be running.

.PARAMETER SubscriptionManagerValueName
    Overrides the registry value name written under the SubscriptionManager
    key. By default the script writes the lowest unused positive integer. The
    naming convention of that key is the one fact here that could not be cited
    to Microsoft - see the 'Subscription manager policy' region.

.PARAMETER SkipSecurityChannelGrant
    Do not touch the Security channel's descriptor. The audit still reports
    whether the forwarder can read it, so the finding stays visible.

.PARAMETER StopWinRmOnRollback
    -Rollback only. Also stop the WinRM service if this run started it.
    Off by default: a service that has been running for weeks may be carrying
    the RMM session that is executing the rollback.

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
    .\Enable-WefClient.ps1
    Reports the forwarding configuration of this host. Changes nothing.

.EXAMPLE
    .\Enable-WefClient.ps1 -Apply -CollectorUri 'http://wec01.contoso.com:5985/wsman/SubscriptionManager/WEC'
    Registers that collector, starts WinRM if it is stopped, and grants the
    forwarder read access to the Security log.

.EXAMPLE
    .\Enable-WefClient.ps1 -Rollback
    Restores the host to its pre-Apply forwarding state.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.1.1
    License : MIT

    Windows PowerShell 5.1. No module dependencies. Requires local
    administrator; enforced in code by Assert-Elevated, deliberately not by
    #Requires -RunAsAdministrator (see docs/DESIGN.md section 3).

    Change types introduced by this script: 'winrmconfig',
    'wefsubscriptionmanager'. It also writes 'channelaccess' records, reusing
    the shape anti-tampering/Protect-EventLogs.ps1 already defines and
    anti-tampering/Test-VisibilityDrift.ps1 already verifies.
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
    [string] $CollectorUri = '',

    [Parameter()]
    [int] $RefreshSeconds = 900,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SubscriptionManagerValueName = '',

    [Parameter()]
    [switch] $SkipSecurityChannelGrant,

    [Parameter(ParameterSetName = 'Rollback')]
    [switch] $StopWinRmOnRollback,

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

$script:ScriptName    = 'Enable-WefClient'
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

# Set by Invoke-ForwarderDiagnostic. $false means "could not demonstrate that
# this host has reached a collector", which is what makes an otherwise
# successful -Apply exit 1 instead of 0.
$script:ForwarderConnected = $false

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

#region Native tool paths ----------------------------------------------------

# Anchored once, here, rather than at each call site: every native tool this
# script launches has to be the in-box one. A bare file name is resolved through
# the machine PATH, and this script runs as SYSTEM - so a PATH entry an
# unprivileged user can write to would choose the binary. The same argument
# Assert-SafeToolkitPath makes about operator input applies with more force to an
# environment variable, which no operator has to touch. Get-NativeToolPath falls
# back to the bare name, so an unusual layout still runs; it just stops being
# anchored.
$script:WevtutilPath = Get-NativeToolPath -FileName 'wevtutil.exe'
# winrm.cmd, not winrm.exe: the WinRM command-line tool is a script, and `&`
# hands a .cmd to the command processor. Anchoring it matters the same way.
$script:CscriptPath  = Get-NativeToolPath -FileName 'cscript.exe'
$script:WinrmScript  = [System.IO.Path]::Combine(
    [System.IO.Path]::Combine($env:SystemRoot, 'System32'), 'winrm.vbs')

#endregion

#region WinRM -----------------------------------------------------------------

<#
    Microsoft's minimum WEF client configuration is three steps: "Configure the
    collector URI(s). Start the WinRM service. Add the Network Service account
    to the built-in Event Log Readers security group." (Appendix D)
    https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection
    The other Microsoft page says to run 'winrm qc -q' on the source, which
    creates a listener and opens a firewall port:
    https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription
    This script starts the service and stops there - see the header for why.

    # UNVERIFIED: whether a source-initiated forwarder works with the service
    # running but NO listener configured. Forwarding is outbound and Appendix D
    # asks only for the service, but the two pages disagree in scope and nothing
    # here has been measured. The audit prints the listener state instead.
#>

$script:WinRmServiceName = 'WinRM'

function Get-ServiceState {
    # Get-Service, not sc.exe: Status and StartType are typed, not localised
    # display text. Enable-ServerPrefetch reads SysMain the same way.
    # # UNVERIFIED: StartType under PS 5.1 has no distinct value for "Automatic
    # (Delayed Start)" - delayed autostart is understood to report plain
    # 'Automatic'. This script only restores the value it read, so the worst
    # case is a rollback that drops a delay flag it could not see.
    param([Parameter(Mandatory = $true)][string] $Name)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return [PSCustomObject] @{ Present = $false; Status = ''; StartType = '' }
    }
    return [PSCustomObject] @{
        Present = $true; Status = [string] $service.Status; StartType = [string] $service.StartType
    }
}

function Get-WinRmListenerState {
    # 'winrm e winrm/config/listener' is Microsoft's own way to look at the
    # listeners (certificate section of the walkthrough cited above). The parsed
    # summary is used for REPORTING and the manifest record only, never to
    # decide a change - so localised field names could not cause a wrong write.
    # A non-zero exit means "unknown", never "none": usually a stopped service.
    # NOT winrm.cmd. Measured on the lab, 2026-09-03: that wrapper's entire body is
    # '@cscript //nologo "%~dpn0.vbs" %*' - cscript UNQUALIFIED, resolved by
    # cmd.exe, which searches the CURRENT DIRECTORY before PATH. So anchoring
    # winrm.cmd bought nothing for this tool, and it added a vector the others do
    # not have: the working directory of a SYSTEM process, chosen by the RMM.
    # Calling an anchored cscript.exe with the .vbs path spelled out removes both.
    # Also measured: byte-identical output and exit code to winrm.cmd, so the
    # parser below is untouched.
    $result = Invoke-NativeCommand -FilePath $script:CscriptPath `
        -Arguments @('//nologo', $script:WinrmScript, 'enumerate', 'winrm/config/listener')
    if ($result.ExitCode -ne 0) {
        return [PSCustomObject] @{
            Readable = $false; Summaries = @()
            Detail = ('winrm.vbs exited ' + [string] $result.ExitCode + ': ' +
                      (($result.Output | Select-Object -First 2) -join ' '))
        }
    }
    $summaries = New-Object System.Collections.ArrayList
    $current = $null
    foreach ($line in $result.Output) {
        if ($line -match '^\s*Listener\s*$') {
            if ($null -ne $current) { [void] $summaries.Add(($current -join ' ')) }
            $current = New-Object System.Collections.ArrayList
            continue
        }
        if ($null -eq $current) { continue }
        if ($line -match '^\s*(Transport|Address|Port|Enabled)\s*=\s*(.*)$') {
            [void] $current.Add($Matches[1] + '=' + $Matches[2].Trim())
        }
    }
    if ($null -ne $current) { [void] $summaries.Add(($current -join ' ')) }
    return [PSCustomObject] @{ Readable = $true; Summaries = @($summaries.ToArray()); Detail = '' }
}

function Invoke-WinRmCheck {
    # Reports WinRM; under -Apply starts it. Returns the number of changes.
    Write-Section 'WinRM (the transport WEF rides on)'

    $state = Get-ServiceState -Name $script:WinRmServiceName
    if (-not $state.Present) {
        Write-Finding ($script:WinRmServiceName + ' is not present: this host cannot forward events')
        return 0
    }
    Write-Info ($script:WinRmServiceName + ' is ' + $state.Status + '/' + $state.StartType)

    $listeners = Get-WinRmListenerState
    if (-not $listeners.Readable) { Write-Info ('listeners unknown: ' + $listeners.Detail) }
    elseif ($listeners.Summaries.Count -eq 0) { Write-Info 'no WinRM listener is configured' }
    else { foreach ($summary in $listeners.Summaries) { Write-Info ('listener: ' + $summary) } }
    Write-Info 'this script never runs winrm quickconfig and never creates a listener'

    $needsStartType = ($state.StartType -ne 'Automatic')
    $needsStart     = ($state.Status -ne 'Running')
    if (-not $needsStartType -and -not $needsStart) {
        Write-Ok ($script:WinRmServiceName + ' is Running and Automatic')
        return 0
    }
    if (-not $Apply) {
        Write-Finding ($script:WinRmServiceName + ' is ' + $state.Status + '/' + $state.StartType +
                       ' - would set Automatic and start it (no restart, no quickconfig)')
        return 0
    }

    # Record before changing. The listener snapshot rides along as evidence:
    # this script never changes listeners, so if the set has moved by the time
    # -Rollback runs, something else moved it and the rollback says so instead
    # of "restoring" a listener configuration it never touched.
    [void] (Write-ManifestChange -Change @{
        type               = 'winrmconfig'
        serviceName        = $script:WinRmServiceName
        previousStartType  = $state.StartType
        previousStatus     = $state.Status
        newStartType       = 'Automatic'
        newStatus          = 'Running'
        previousListeners  = @($listeners.Summaries)
        listenerChangeMade = $false
        description        = ($script:WinRmServiceName + ': Automatic and Running for event forwarding')
    })

    # Start type first: Start-Service on a Disabled service fails.
    if ($needsStartType) { Set-Service -Name $script:WinRmServiceName -StartupType 'Automatic' }
    if ($needsStart)     { Start-Service -Name $script:WinRmServiceName }

    $confirmed = Get-ServiceState -Name $script:WinRmServiceName
    if ($confirmed.StartType -ne 'Automatic' -or $confirmed.Status -ne 'Running') {
        throw ($script:WinRmServiceName + ' did not read back as Automatic/Running: it is ' +
               $confirmed.Status + '/' + $confirmed.StartType)
    }
    Write-Ok ($script:WinRmServiceName + ' is now Running and Automatic')
    return 1
}

function Restore-WinRmConfig {
    # Restores the start type; stops the service only when explicitly asked.
    # Stopping WinRM is the likeliest way for this toolkit to lock an MSP out of
    # the host it hardened - the rollback may be arriving over an RMM agent that
    # uses WinRM. So the default restores the start type, reports the rest and
    # DECLINES, which keeps the run retryable and puts a human in the loop,
    # rather than claiming a state was restored when it was not.
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $name   = [string] $change.serviceName
    $state  = Get-ServiceState -Name $name
    if (-not $state.Present) {
        Write-Finding ('service ' + $name + ' is no longer present; leaving it alone.')
        return 'declined'
    }

    $expected = [string] $change.newStartType
    $previous = [string] $change.previousStartType

    # Three-way host resolution (docs/DESIGN.md section 4, A-2). Case 2 FIRST: the
    # host already holds the pre-apply StartType and needs no status change, so
    # there is nothing to undo - counted RESTORED per the doctrine. It fell through
    # to the restore path before, so the message claimed work that never happened.
    # NOTE: the 'declined' at the END of this
    # function is deliberate and is NOT this defect: it leaves the run retryable
    # so an operator can re-run with -StopWinRmOnRollback, which is a documented
    # way to converge. Case 2 has no such follow-up, so it is permanent.
    $statusSettled = ([string] $change.previousStatus -eq 'Running') -or ($state.Status -ne 'Running')
    if ($state.StartType -eq $previous -and $statusSettled) {
        Write-Ok ($name + ' already holds its recorded previous state (' + $previous + '/' + $state.Status +
                    '); nothing to undo.')
        return 'restored'
    }

    # Case 3: neither what this run set nor what it found.
    if ($state.StartType -ne $expected -and $state.StartType -ne $previous) {
        Write-Finding ($name + ' StartType is ' + $state.StartType + ', neither what this run set (' +
                       $expected + ') nor what it found (' + $previous + '); leaving it alone.')
        return 'declined'
    }
    # Case 1 falls through: the host holds what -Apply set - restore it.
    if ($state.StartType -ne $previous) {
        Set-Service -Name $name -StartupType $previous
        $afterType = (Get-ServiceState -Name $name).StartType
        if ($afterType -ne $previous) {
            throw ($name + ' StartType did not read back as ' + $previous + '; it is ' + $afterType)
        }
        Write-Ok ('Restored ' + $name + ' StartType to ' + $previous)
    }

    # Listener evidence: reported, never acted on.
    $listeners = Get-WinRmListenerState
    if ($listeners.Readable) {
        $recorded = @()
        if ($null -ne $change.previousListeners) { $recorded = @($change.previousListeners) }
        if (-not [string]::Equals(($recorded -join '|'), ($listeners.Summaries -join '|'),
                                  [System.StringComparison]::Ordinal)) {
            Write-Info ('the WinRM listener set has changed since -Apply; this script does not remove ' +
                        'listeners. Recorded: ' + ($recorded -join '; ') + ' | now: ' +
                        ($listeners.Summaries -join '; '))
        }
    }

    if ([string] $change.previousStatus -eq 'Running' -or $state.Status -ne 'Running') {
        return 'restored'
    }
    if ($StopWinRmOnRollback) {
        Stop-Service -Name $name
        if ((Get-ServiceState -Name $name).Status -eq 'Running') { throw ($name + ' did not stop') }
        Write-Ok ('Stopped ' + $name)
        return 'restored'
    }
    Write-Finding ($name + ' was ' + [string] $change.previousStatus + ' before -Apply and is Running ' +
                   'now; left running deliberately. Re-run -Rollback -StopWinRmOnRollback to stop it.')
    return 'declined'
}

#endregion

#region Subscription manager policy -------------------------------------------

<#
    Key, cited verbatim - "Alternatively, you can make registry settings in the
    following subkey: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\
    EventLog\EventForwarding\SubscriptionManager":
    https://learn.microsoft.com/en-us/troubleshoot/windows-server/admin-development/configure-eventlog-forwarding-performance
    Policy behind it: EventForwarding.admx, policy SubscriptionManager, key
    Software\Policies\Microsoft\Windows\EventLog\EventForwarding:
    https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-eventforwarding
    Value format, cited from that page: "Server=https://<FQDN of the collector>
    :5986/wsman/SubscriptionManager/WEC,Refresh=<Refresh interval in seconds>,
    IssuerCA=<Thumb print...>. When using the HTTP protocol, use port 5985."
    Refresh is in seconds (troubleshoot page above).

    # UNVERIFIED: the NAME of each value under the SubscriptionManager subkey.
    # Field practice says they are numbered ("1", "2", ...) and the ADMX <list>
    # element supports that through valuePrefix
    # (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/81a89003-5121-4216-b788-fde8daa71c78),
    # but no learn.microsoft.com page states it for this policy - and the
    # sibling case in this toolkit goes the OTHER way: PowerShell's ModuleNames
    # list has no valuePrefix and stores name/value PAIRS ('*' = '*',
    # verification/facts.json fact ps-module-names). Guessing wrong writes a
    # value the forwarder never reads and then confirms it.
    # To settle it: on a host where the GPO "Configure target Subscription
    # Manager" is enabled, read the subkey and look at the value names. Until
    # then -Audit PRINTS every value name found, so the first managed host this
    # runs on answers it, and -SubscriptionManagerValueName overrides.

    # UNVERIFIED: whether the forwarder tolerates a GAP in the numbering, which
    # is what -Rollback leaves when it removes its entry from the middle of the
    # list. Renumbering the survivors would be worse: it would rewrite entries
    # this script never created, one of which is likely the customer's GPO.
#>

$script:KeySubscriptionManager =
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'

function Get-SubscriptionManagerState {
    # Every value under the key, through the explicit 64-bit view
    # Split-RegistryPath opens: a 32-bit RMM host would otherwise read the
    # WOW6432Node redirection of a key the forwarder reads unredirected.
    $split = Split-RegistryPath -Path $script:KeySubscriptionManager
    $key = $null
    try {
        $key = $split.Hive.OpenSubKey($split.SubKey, $false)
        if ($null -eq $key) { return [PSCustomObject] @{ KeyExists = $false; Entries = @() } }
        $entries = New-Object System.Collections.ArrayList
        foreach ($name in @($key.GetValueNames())) {
            [void] $entries.Add([PSCustomObject] @{
                Name  = [string] $name
                Kind  = [string] $key.GetValueKind($name).ToString()
                Value = [string] $key.GetValue($name, $null,
                            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            })
        }
        return [PSCustomObject] @{ KeyExists = $true; Entries = @($entries.ToArray()) }
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $split -and $null -ne $split.Hive) { $split.Hive.Dispose() }
    }
}

function Format-SubscriptionManagerValue {
    # A bare hostname is refused rather than completed: choosing http:5985 over
    # https:5986 decides how the whole fleet authenticates to its collector.
    param(
        [Parameter(Mandatory = $true)][string] $Uri,
        [Parameter(Mandatory = $true)][int] $Refresh
    )
    $trimmed = $Uri.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) { throw 'CollectorUri is empty.' }
    if ($trimmed -match '^Server\s*=') { return $trimmed }
    if ($trimmed -match '^https?://')  { return ('Server=' + $trimmed + ',Refresh=' + [string] $Refresh) }
    throw ('CollectorUri must be a full policy string or a URI, not a bare host name - e.g. ' +
           'Server=http://wec01.contoso.com:5985/wsman/SubscriptionManager/WEC,Refresh=900. Got: ' +
           $trimmed)
}

function Get-SubscriptionManagerServerUri {
    # The Server= token, so two entries naming one collector with different
    # Refresh values are recognised as one collector rather than two.
    param([Parameter()][AllowEmptyString()][string] $Value = '')
    foreach ($part in ($Value -split ',')) {
        if ($part.Trim() -match '^Server\s*=\s*(.+)$') { return $Matches[1].Trim() }
    }
    return ''
}

function Invoke-SubscriptionManagerCheck {
    # Reports the collectors this host talks to; under -Apply registers
    # -CollectorUri if absent. Declines rather than guessing when an entry
    # already names this collector with different parameters, or when a named
    # slot is occupied - overwriting either would silently change a value this
    # script did not set, very likely a customer GPO.
    Write-Section 'Subscription manager (which collector this host forwards to)'

    $state = Get-SubscriptionManagerState
    if (-not $state.KeyExists) { Write-Info ('policy key absent: ' + $script:KeySubscriptionManager) }
    elseif ($state.Entries.Count -eq 0) { Write-Info 'policy key present but empty' }
    else {
        foreach ($entry in $state.Entries) {
            Write-Info ('value "' + $entry.Name + '" (' + $entry.Kind + ') = ' + $entry.Value)
        }
        Write-Info 'those value NAMES answer the unverified fact noted in this region'
    }

    if ([string]::IsNullOrWhiteSpace($CollectorUri)) {
        if ($state.Entries.Count -eq 0) { Write-Finding 'no collector registered: this host forwards nothing' }
        else { Write-Ok ([string] $state.Entries.Count + ' collector entr(y/ies) registered') }
        return 0
    }

    $intended       = Format-SubscriptionManagerValue -Uri $CollectorUri -Refresh $RefreshSeconds
    $intendedServer = Get-SubscriptionManagerServerUri -Value $intended
    if ($intendedServer -notmatch '/wsman/SubscriptionManager/WEC\s*$') {
        Write-Finding ('the collector URI does not end in the documented path ' +
                       '/wsman/SubscriptionManager/WEC: ' + $intendedServer)
    }

    $usedNames = @{}
    foreach ($entry in $state.Entries) {
        $usedNames[$entry.Name.ToUpperInvariant()] = $true
        # OrdinalIgnoreCase, unlike the toolkit's usual case-sensitive compare:
        # a URI differing only in host case names the SAME collector, so a
        # case-sensitive compare would add a duplicate entry on every run.
        if ([string]::Equals($entry.Value, $intended, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Ok ('already registered as value "' + $entry.Name + '"')
            return 0
        }
        $existing = Get-SubscriptionManagerServerUri -Value $entry.Value
        if ([string]::Equals($existing, $intendedServer, [System.StringComparison]::OrdinalIgnoreCase) -and
            -not [string]::IsNullOrWhiteSpace($existing)) {
            Write-Finding ('value "' + $entry.Name + '" already points at this collector with different ' +
                           'parameters (' + $entry.Value + '); refusing to duplicate or overwrite it.')
            return 0
        }
    }

    $valueName = $SubscriptionManagerValueName.Trim()
    if ([string]::IsNullOrWhiteSpace($valueName)) {
        for ($i = 1; $i -le 64; $i++) {
            if (-not $usedNames.ContainsKey([string] $i)) { $valueName = [string] $i; break }
        }
        if ([string]::IsNullOrWhiteSpace($valueName)) {
            throw ('64 numbered entries already exist; review ' + $script:KeySubscriptionManager)
        }
    }
    elseif ($usedNames.ContainsKey($valueName.ToUpperInvariant())) {
        Write-Finding ('-SubscriptionManagerValueName "' + $valueName +
                       '" is in use by another collector; leaving it alone.')
        return 0
    }

    if (-not $Apply) {
        Write-Finding ('would register ' + $script:KeySubscriptionManager + '\' + $valueName + ' = ' + $intended)
        return 0
    }

    # Its own change type rather than a plain 'registry' record: the identity of
    # this change is "this host is registered with that collector", not "value
    # name N holds string X", and the rollback needs the collector URI and the
    # slot together to decide whether the entry it is about to delete is still
    # the one this run created. The discipline is a registry change's - record
    # first, write, read back, confirm.
    [void] (Write-ManifestChange -Change @{
        type              = 'wefsubscriptionmanager'
        path              = $script:KeySubscriptionManager
        name              = $valueName
        valueExisted      = $false
        previousValue     = $null
        previousKind      = $null
        newValue          = $intended
        newKind           = 'String'
        collectorUri      = $intendedServer
        siblingValueNames = @($state.Entries | ForEach-Object { [string] $_.Name })
        description       = ('registered subscription manager ' + $intendedServer)
    })

    Set-RegistryValueRaw -Path $script:KeySubscriptionManager -Name $valueName -Kind 'String' -Value $intended

    $confirm = Get-RegistryValueState -Path $script:KeySubscriptionManager -Name $valueName
    if (-not $confirm.Exists -or $confirm.Kind -ne 'String' -or
        -not [string]::Equals([string] $confirm.Value, $intended, [System.StringComparison]::Ordinal)) {
        throw ('The subscription manager value did not read back at ' +
               $script:KeySubscriptionManager + '\' + $valueName)
    }
    Write-Ok ('registered subscription manager as value "' + $valueName + '": ' + $intended)
    return 1
}

function Restore-SubscriptionManagerEntry {
    # Removes the entry this run created, and only while the host still holds
    # exactly that collector: a GPO refresh or an operator edit are both reasons
    # the slot may hold somebody else's collector by now.
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $path   = [string] $change.path
    $name   = [string] $change.name
    if ($path -notmatch '^(HKLM|HKEY_LOCAL_MACHINE):?\\') {
        throw ('Refusing to roll back a change outside HKLM: ' + $path)
    }

    $current = Get-RegistryValueState -Path $path -Name $name
    if (-not $current.Exists) {
        Write-Ok ($path + '\' + $name + ' is already absent')
        return 'restored'
    }
    # Case 2 (docs/DESIGN.md section 4.1), before case 3: the slot already holds
    # the value recorded BEFORE this run. The absent case above covers a value
    # that did not exist; this covers one that did. Either way there is nothing to
    # undo, and the doctrine counts it 'restored' so the run converges - declining
    # here left it retryable forever (A-2).
    if ([bool] $change.valueExisted -and
        [string]::Equals([string] $current.Value, [string] $change.previousValue,
                         [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Ok ($path + '\' + $name + ' already holds its recorded previous value; nothing to undo.')
        return 'restored'
    }

    # Case 3: the slot holds neither what this run registered nor what was there
    # before it - a GPO refresh or an operator edit has been here since.
    if (-not [string]::Equals([string] $current.Value, [string] $change.newValue,
                              [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Finding ($path + '\' + $name + ' no longer holds the collector this run registered; ' +
                       'leaving it alone.')
        return 'declined'
    }
    if (-not $change.valueExisted) {
        Remove-RegistryValueRaw -Path $path -Name $name
        if ((Get-RegistryValueState -Path $path -Name $name).Exists) {
            throw ('Failed to remove ' + $path + '\' + $name)
        }
        Write-Ok ('Removed ' + $path + '\' + $name + ' (did not exist before)')
        return 'restored'
    }
    Assert-SupportedKind -Kind ([string] $change.previousKind) `
        -Context ($path + '\' + $name + ', recorded previous value')
    Set-RegistryValueRaw -Path $path -Name $name -Kind ([string] $change.previousKind) `
        -Value (ConvertFrom-ManifestValue -Value $change.previousValue -Kind ([string] $change.previousKind))
    Write-Ok ('Restored ' + $path + '\' + $name)
    return 'restored'
}

#endregion

#region Security channel readability ------------------------------------------

<#
    A WEF client that forwards everything except the Security log is the classic
    WEF failure: the forwarder runs as NETWORK SERVICE and the Security channel
    does not let it read. Microsoft documents the fix as a group membership -
    "To be able to forward the Security log you need to add the NETWORK SERVICE
    account to the EventLog Readers group."
    https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription
    "Add the Network Service account to the built-in Event Log Readers security
    group. This addition allows reading from secured event channel, such as the
    security event channel." (Appendix D)
    https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection
    This script grants the narrower right on the channel itself instead, and
    detects the documented route so a host already configured that way is left
    alone. The full argument is in the script header.

    Masks: 0x1 read, 0x2 write, 0x4 CLEAR, 0xF0000 standard rights
    (verification/facts.json, fact eventlog-channelaccess-masks - decoded from
    live descriptors on the lab). 0x1 = read also appears in Microsoft's own
    example granting Event Log Readers read on a channel, in exactly this shape:
    wevtutil sl Microsoft-Windows-CAPI2/Operational
    /ca:"O:BAG:SYD:(A;;0x7;;;BA)(A;;0x2;;;AU)(A;;0x1;;;S-1-5-32-573)"
    (Appendix C of the intrusion-detection article above).

    SIDs by value, never by name - both principals are localised and fr-FR is a
    deployment target: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
#>

$script:RightRead  = 0x1
$script:RightWrite = 0x2
$script:RightClear = 0x4

$script:SecurityChannel    = 'Security'
$script:NetworkServiceSid  = 'S-1-5-20'
$script:EventLogReadersSid = 'S-1-5-32-573'
$script:KeyEventLogPolicy  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog'

function Get-ChannelConfiguration {
    # EventLogConfiguration rather than 'wevtutil gl' plus a regex: descriptor,
    # enabled flag and maximum size come back typed, so there is no output
    # format to parse and nothing to localise.
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogconfiguration
    # Protect-EventLogs parses 'wevtutil gl' for the same descriptor: that is a
    # deliberate difference, not drift. Writes still go through 'wevtutil sl',
    # the path that script proved on the lab.
    param([Parameter(Mandatory = $true)][string] $Channel)

    $config = $null
    try { $config = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($Channel) }
    catch {
        return [PSCustomObject] @{
            Present = $false; Enabled = $false; MaxSizeBytes = [int64] 0
            Sddl = ''; Detail = $_.Exception.Message
        }
    }
    try {
        return [PSCustomObject] @{
            Present = $true; Enabled = [bool] $config.IsEnabled
            MaxSizeBytes = [int64] $config.MaximumSizeInBytes
            Sddl = [string] $config.SecurityDescriptor; Detail = ''
        }
    }
    finally { $config.Dispose() }
}

function Get-ChannelRecordCount {
    # Runtime state, a different object from configuration. Returns -1 for
    # "could not read", never 0: "empty" and "I could not look" differ.
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventloginformation
    param([Parameter(Mandatory = $true)][string] $Channel)
    try {
        $info = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogInformation(
                    $Channel, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
        if ($null -eq $info -or $null -eq $info.RecordCount) { return [int64] (-1) }
        return [int64] $info.RecordCount
    }
    catch { return [int64] (-1) }
}

function Get-EventLogPolicyValueList {
    # Which policy values GPO sets for this channel. Reports the NAMES found
    # rather than testing for a specific one, because the EventLog policy that
    # governs a descriptor could not be cited - and a policy value beats local
    # channel configuration (facts.json, eventlog-policy-overrides-local-config),
    # so these are what to look at when a descriptor write does not stick.
    param([Parameter(Mandatory = $true)][string] $Channel)
    $split = Split-RegistryPath -Path ($script:KeyEventLogPolicy + '\' + $Channel)
    $key = $null
    try {
        $key = $split.Hive.OpenSubKey($split.SubKey, $false)
        if ($null -eq $key) { return @() }
        return @($key.GetValueNames())
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $split -and $null -ne $split.Hive) { $split.Hive.Dispose() }
    }
}

function Get-SddlAceMap {
    <#
        Returns a hashtable of SID string -> combined allow mask.

        Everything that compares descriptors goes through this, never through
        string comparison. Two reasons, both measured on the lab:
          - .NET regenerates a descriptor using rights abbreviations
            (CCDCLC) where Windows printed hex (0x7). Identical meaning,
            completely different text, so a string compare reports a change
            that did not happen and rewrites the descriptor on every run.
          - ACE order is not guaranteed to survive a round trip.
    #>
    param([Parameter(Mandatory = $true)][string] $Sddl)

    $map = @{}
    $sd = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false, $false, $Sddl)
    foreach ($ace in $sd.DiscretionaryAcl) {
        # Deny ACEs are recorded separately so a comparison cannot mistake a
        # deny for an absence of access.
        $key = $ace.SecurityIdentifier.Value
        if ($ace.AceType -ne 'AccessAllowed') { $key = ('DENY:' + $key) }
        if ($map.ContainsKey($key)) { $map[$key] = $map[$key] -bor $ace.AccessMask }
        else { $map[$key] = $ace.AccessMask }
    }
    return $map
}

function Get-SidDisplayName {
    param([Parameter(Mandatory = $true)][string] $Sid)
    try {
        $account = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate(
            [System.Security.Principal.NTAccount])
        return ($Sid + ' (' + $account.Value + ')')
    }
    catch {
        return $Sid
    }
}

function Format-RightMask {
    param([Parameter(Mandatory = $true)][int] $Mask)
    $parts = @()
    if (($Mask -band $script:RightRead)  -ne 0) { $parts += 'read' }
    if (($Mask -band $script:RightWrite) -ne 0) { $parts += 'write' }
    if (($Mask -band $script:RightClear) -ne 0) { $parts += 'CLEAR' }
    if (($Mask -band 0xF0000) -ne 0)            { $parts += 'standard-rights' }
    if ($parts.Count -eq 0) { $parts += 'none' }
    return (('0x' + ('{0:X}' -f $Mask)) + ' [' + ($parts -join ', ') + ']')
}

function Assert-SddlNotMorePermissive {
    <#
        The guard that exists because of a real published defect: an earlier
        incarnation of this project shipped a descriptor whose access masks were
        inverted, so the script GRANTED the very right its name promised to
        remove. On an event log, that hands out the ability to erase evidence.

        Refuses the write if any principal gained a right, if a deny ACE was
        dropped, or if a principal appeared that was not there before. Rights
        may only be removed.

        Copied unchanged from anti-tampering/Protect-EventLogs.ps1. This script
        WIDENS access, so it cannot use this guard on its -Apply path: see
        Assert-SddlWidensOnlyBy. It is used here, unchanged, on -Rollback, where
        the descriptor being restored must be no more permissive than the live
        one - which is the direction it was written for.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Before,
        [Parameter(Mandatory = $true)][string] $After,
        [Parameter(Mandatory = $true)][string] $Channel
    )

    $b = Get-SddlAceMap -Sddl $Before
    $a = Get-SddlAceMap -Sddl $After

    foreach ($sid in $a.Keys) {
        if (-not $b.ContainsKey($sid)) {
            throw ('Refusing to write the descriptor for ' + $Channel +
                   ': it would add a principal that was not there before (' + $sid + ').')
        }
        $gained = $a[$sid] -band (-bnot $b[$sid])
        if ($gained -ne 0) {
            throw ('Refusing to write the descriptor for ' + $Channel + ': ' +
                   (Get-SidDisplayName -Sid ($sid -replace '^DENY:', '')) +
                   ' would GAIN ' + (Format-RightMask -Mask $gained) + '.')
        }
    }
    foreach ($sid in $b.Keys) {
        if ($sid -like 'DENY:*' -and -not $a.ContainsKey($sid)) {
            throw ('Refusing to write the descriptor for ' + $Channel +
                   ': it would drop a deny ACE (' + $sid + ').')
        }
    }
}

function Assert-SddlWidensOnlyBy {
    <#
        THE DELIBERATE EXCEPTION to the guard above, and why it is a separate
        function rather than an edit to it or a try/catch around it.

        Assert-SddlNotMorePermissive refuses ANY widening. Making the Security
        log forwardable REQUIRES granting a read right, so it would refuse every
        write this script needs. The two wrong ways out are editing the guard
        (copied text - a locally loosened copy is how 28 scripts stop agreeing
        on what "not more permissive" means) and catching its exception (which
        keeps the ceremony and throws away the protection).

        So the widening is BOUNDED, not bypassed: this applies the original
        guard's checks to every principal and cuts exactly one hole - the SID in
        -Sid may gain exactly the bits in -AllowedGain and nothing else. Every
        other principal, and every other bit for that SID, still throws. No run
        of this script can hand 0x2 (write) or 0x4 (CLEAR) to anybody, NETWORK
        SERVICE included, and 0x4 is what lets a principal erase the log.

        Stricter than the original in one way: losing an ACE also throws. The
        only intent here is to add a read right, so a principal disappearing
        means the descriptor was built wrong.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Before,
        [Parameter(Mandatory = $true)][string] $After,
        [Parameter(Mandatory = $true)][string] $Channel,
        [Parameter(Mandatory = $true)][string] $Sid,
        [Parameter(Mandatory = $true)][int] $AllowedGain
    )

    $b = Get-SddlAceMap -Sddl $Before
    $a = Get-SddlAceMap -Sddl $After

    foreach ($key in $a.Keys) {
        $isTarget = [string]::Equals($key, $Sid, [System.StringComparison]::OrdinalIgnoreCase)
        if (-not $b.ContainsKey($key)) {
            if ($isTarget -and ($a[$key] -band (-bnot $AllowedGain)) -eq 0) { continue }
            throw ('Refusing to write the descriptor for ' + $Channel +
                   ': it would add a principal that was not there before (' + $key + ').')
        }
        $gained = $a[$key] -band (-bnot $b[$key])
        if ($gained -eq 0) { continue }
        if ($isTarget -and ($gained -band (-bnot $AllowedGain)) -eq 0) { continue }
        throw ('Refusing to write the descriptor for ' + $Channel + ': ' +
               (Get-SidDisplayName -Sid ($key -replace '^DENY:', '')) + ' would GAIN ' +
               (Format-RightMask -Mask $gained) + '; only ' +
               (Format-RightMask -Mask $AllowedGain) + ' for ' + $Sid + ' is allowed here.')
    }
    foreach ($key in $b.Keys) {
        if (-not $a.ContainsKey($key)) {
            throw ('Refusing to write the descriptor for ' + $Channel + ': it would remove ' + $key +
                   ', and this script only adds a read right.')
        }
        $lost = $b[$key] -band (-bnot $a[$key])
        if ($lost -ne 0) {
            throw ('Refusing to write the descriptor for ' + $Channel + ': ' +
                   (Get-SidDisplayName -Sid ($key -replace '^DENY:', '')) + ' would LOSE ' +
                   (Format-RightMask -Mask $lost) + '.')
        }
    }
}

function Test-SidInLocalGroup {
    # Is $MemberSid in the local group $GroupSid? $true / $false / $null for
    # "could not tell", which callers must not read as $false. ADSI over the
    # WinNT provider: no module dependency, and Get-LocalGroupMember does not
    # exist on every SKU this toolkit targets.
    # https://learn.microsoft.com/en-us/windows/win32/adsi/adsi-winnt-provider
    # The group is LOOKED UP by translating its well-known SID to a name (WinNT
    # wants a name); every COMPARISON is on SIDs, because the group name is
    # localised.
    # # UNVERIFIED: the Invoke('Members') idiom has not been run on Windows by
    # this project. It fails closed - any exception returns $null.
    param(
        [Parameter(Mandatory = $true)][string] $MemberSid,
        [Parameter(Mandatory = $true)][string] $GroupSid
    )
    try {
        $account = (New-Object System.Security.Principal.SecurityIdentifier($GroupSid)).Translate(
            [System.Security.Principal.NTAccount]).Value
        $groupName = $account
        $separator = $account.IndexOf('\')
        if ($separator -ge 0) { $groupName = $account.Substring($separator + 1) }

        $group = [ADSI] ('WinNT://./' + $groupName + ',group')
        foreach ($member in @($group.Invoke('Members', $null))) {
            $raw = $member.GetType().InvokeMember('objectSid', 'GetProperty', $null, $member, $null)
            $sid = New-Object System.Security.Principal.SecurityIdentifier([byte[]] $raw, 0)
            if ([string]::Equals($sid.Value, $MemberSid, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        return $false
    }
    catch {
        Write-Verbose ('Could not enumerate members of ' + $GroupSid + ': ' + $_.Exception.Message)
        return $null
    }
}

function Get-ForwarderReadState {
    # Can the forwarder read this channel? Answers both ways it can be true - a
    # direct ACE, or membership of a group the channel grants read to.
    param([Parameter(Mandatory = $true)][string] $Channel)

    $config = Get-ChannelConfiguration -Channel $Channel
    if (-not $config.Present) {
        return [PSCustomObject] @{
            Present = $false; Sddl = ''; DirectMask = 0; GroupMask = 0
            InReadersGroup = $null; CanRead = $null; DeniedRead = $false; Detail = $config.Detail
        }
    }

    $map = Get-SddlAceMap -Sddl $config.Sddl
    $directMask = 0
    if ($map.ContainsKey($script:NetworkServiceSid)) { $directMask = $map[$script:NetworkServiceSid] }
    $groupMask = 0
    if ($map.ContainsKey($script:EventLogReadersSid)) { $groupMask = $map[$script:EventLogReadersSid] }
    $denyKey = 'DENY:' + $script:NetworkServiceSid
    $deniedRead = $false
    if ($map.ContainsKey($denyKey)) { $deniedRead = (($map[$denyKey] -band $script:RightRead) -ne 0) }

    $inGroup = $null
    $canRead = $false
    if (($directMask -band $script:RightRead) -ne 0) { $canRead = $true }
    elseif (($groupMask -band $script:RightRead) -ne 0) {
        $inGroup = Test-SidInLocalGroup -MemberSid $script:NetworkServiceSid `
                        -GroupSid $script:EventLogReadersSid
        $canRead = $inGroup
    }
    if ($deniedRead) { $canRead = $false }

    return [PSCustomObject] @{
        Present = $true; Sddl = $config.Sddl; DirectMask = $directMask; GroupMask = $groupMask
        InReadersGroup = $inGroup; CanRead = $canRead; DeniedRead = $deniedRead; Detail = ''
    }
}

function Invoke-SecurityChannelCheck {
    # Reports whether the forwarder can read the Security log; under -Apply
    # grants the read right if it cannot. Returns changes made.
    Write-Section 'Can the forwarder read the Security log?'

    $channel = $script:SecurityChannel
    $state = Get-ForwarderReadState -Channel $channel
    if (-not $state.Present) {
        Write-Finding ('channel ' + $channel + ' could not be read: ' + $state.Detail)
        return 0
    }
    Write-Info ('NETWORK SERVICE (' + $script:NetworkServiceSid + ') holds ' +
                (Format-RightMask -Mask $state.DirectMask))
    Write-Info ('Event Log Readers (' + $script:EventLogReadersSid + ') holds ' +
                (Format-RightMask -Mask $state.GroupMask))
    if ($state.InReadersGroup -eq $true)  { Write-Info 'NETWORK SERVICE IS in the Event Log Readers group' }
    if ($state.InReadersGroup -eq $false) { Write-Info 'NETWORK SERVICE is NOT in that group' }
    if ($state.DeniedRead) {
        Write-Finding ('a DENY ace blocks NETWORK SERVICE from reading ' + $channel + '; this script ' +
                       'does not remove deny entries, so Security events will not forward.')
        return 0
    }

    $policyValues = @(Get-EventLogPolicyValueList -Channel $channel)
    if ($policyValues.Count -gt 0) {
        Write-Info ('Group Policy sets value(s) for this channel (' + ($policyValues -join ', ') +
                    '); a policy value overrides local configuration, so a write here may not stick')
    }

    if ($state.CanRead -eq $true) {
        Write-Ok ('the forwarder can already read ' + $channel)
        return 0
    }
    if ($null -eq $state.CanRead) {
        Write-Finding ('cannot confirm whether the forwarder can read ' + $channel +
                       ' (group membership unreadable); treating it as NOT readable.')
    }
    if ($SkipSecurityChannelGrant) {
        Write-Finding ('the forwarder cannot read ' + $channel +
                       ' and -SkipSecurityChannelGrant was passed: Security events will not forward.')
        return 0
    }
    if (-not $Apply) {
        Write-Finding ('would grant NETWORK SERVICE read (0x1) on ' + $channel)
        return 0
    }

    # SetAccess with an explicitly computed mask, never an implicit helper:
    # facts.json (sddl-removeaccess-fails-silently) records
    # DiscretionaryAcl.RemoveAccess returning success and changing nothing. The
    # same distrust applies to a write meant to ADD a bit - hence the assert on
    # the built descriptor before the write and the re-read after it.
    $before = $state.Sddl
    $sd = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false, $false, $before)
    $sid = New-Object System.Security.Principal.SecurityIdentifier($script:NetworkServiceSid)
    $sd.DiscretionaryAcl.SetAccess(
        [System.Security.AccessControl.AccessControlType]::Allow,
        $sid, ($state.DirectMask -bor $script:RightRead),
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None)
    $after = $sd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

    Assert-SddlWidensOnlyBy -Before $before -After $after -Channel $channel `
        -Sid $script:NetworkServiceSid -AllowedGain $script:RightRead

    $afterMap = Get-SddlAceMap -Sddl $after
    if (-not $afterMap.ContainsKey($script:NetworkServiceSid) -or
        ($afterMap[$script:NetworkServiceSid] -band $script:RightRead) -eq 0) {
        throw ('Building the descriptor for ' + $channel + ' did not add the read right.')
    }

    # The same change type and field names Protect-EventLogs writes,
    # deliberately: that shape is what Test-VisibilityDrift already verifies,
    # and it verifies the right thing here - drift when a principal gains access
    # relative to what this run wrote.
    [void] (Write-ManifestChange -Change @{
        type         = 'channelaccess'
        channel      = $channel
        previousSddl = $before
        newSddl      = $after
        description  = ($channel + ': granted NETWORK SERVICE read for the WEF forwarder')
    })

    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @('sl', $channel, ('/ca:' + $after))
    if ($result.ExitCode -ne 0) {
        throw ('wevtutil sl failed for ' + $channel + ': ' + ($result.Output -join ' '))
    }

    $confirm = Get-ChannelConfiguration -Channel $channel
    if (-not $confirm.Present) { throw ('Could not re-read the descriptor for ' + $channel) }
    $confirmMap = Get-SddlAceMap -Sddl $confirm.Sddl
    if (-not $confirmMap.ContainsKey($script:NetworkServiceSid) -or
        ($confirmMap[$script:NetworkServiceSid] -band $script:RightRead) -eq 0) {
        $hint = ''
        if ($policyValues.Count -gt 0) {
            $hint = ' Group Policy sets ' + ($policyValues -join ', ') + ' for this channel and a policy ' +
                    'value overrides local configuration - look there.'
        }
        throw ('Descriptor written for ' + $channel + ' but NETWORK SERVICE still cannot read it.' + $hint)
    }
    Write-Ok ($channel + ': NETWORK SERVICE can now read the log')
    return 1
}

function Restore-SecurityChannelAccess {
    # Puts the previous descriptor back, proving it is the narrower of the two
    # first - Assert-SddlNotMorePermissive, unchanged, in its own direction.
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change  = $ChangeRecord.change
    $channel = [string] $change.channel
    $config  = Get-ChannelConfiguration -Channel $channel
    if (-not $config.Present) {
        Write-Finding ('channel ' + $channel + ' could not be read; leaving it alone.')
        return 'declined'
    }

    # By mask, not by text: the descriptor was stored in whatever form .NET
    # generated and Windows may render it differently.
    $currentMap  = Get-SddlAceMap -Sddl $config.Sddl
    $intendedMap = Get-SddlAceMap -Sddl ([string] $change.newSddl)
    $same = ($currentMap.Count -eq $intendedMap.Count)
    if ($same) {
        foreach ($sid in $intendedMap.Keys) {
            if (-not $currentMap.ContainsKey($sid) -or $currentMap[$sid] -ne $intendedMap[$sid]) {
                $same = $false
                break
            }
        }
    }
    if (-not $same) {
        # Case 2 (docs/DESIGN.md section 4.1): does the channel already hold the
        # descriptor recorded BEFORE this run? Either this rollback already ran or
        # the write never landed, and both mean nothing to do - counted 'restored'
        # so the run converges. This is the same fix R-1 made to
        # Protect-EventLogs' Restore-ChannelAccess, which this function mirrors:
        # without it a second -Rollback declined descriptors the toolkit had just
        # restored, the run never left the eligible set, and Test-VisibilityDrift
        # reported every change in it as drifted.
        $previousMap = Get-SddlAceMap -Sddl ([string] $change.previousSddl)
        $alreadyPrevious = ($currentMap.Count -eq $previousMap.Count)
        if ($alreadyPrevious) {
            foreach ($sid in $previousMap.Keys) {
                if (-not $currentMap.ContainsKey($sid) -or $currentMap[$sid] -ne $previousMap[$sid]) {
                    $alreadyPrevious = $false
                    break
                }
            }
        }
        if ($alreadyPrevious) {
            Write-Ok ($channel + ' already holds the descriptor recorded before this run; nothing to restore.')
            return 'restored'
        }

        # Case 3: neither what this run set nor what was recorded before it.
        Write-Finding ($channel + ': the descriptor holds neither what this run set nor what was ' +
                       'recorded before it; leaving it alone.')
        return 'declined'
    }

    Assert-SddlNotMorePermissive -Before $config.Sddl -After ([string] $change.previousSddl) -Channel $channel

    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @(
        'sl', $channel, ('/ca:' + [string] $change.previousSddl))
    if ($result.ExitCode -ne 0) {
        throw ('wevtutil sl failed restoring ' + $channel + ': ' + ($result.Output -join ' '))
    }

    # Re-read and assert, because an ACL write that reports success proves
    # nothing (facts.json, sddl-removeaccess-fails-silently).
    $confirmMap  = Get-SddlAceMap -Sddl (Get-ChannelConfiguration -Channel $channel).Sddl
    $previousMap = Get-SddlAceMap -Sddl ([string] $change.previousSddl)
    foreach ($sid in $confirmMap.Keys) {
        $wanted = 0
        if ($previousMap.ContainsKey($sid)) { $wanted = $previousMap[$sid] }
        if ($confirmMap[$sid] -ne $wanted) {
            throw ('Descriptor restored on ' + $channel + ' but ' + $sid + ' holds ' +
                   (Format-RightMask -Mask $confirmMap[$sid]) + ' instead of ' +
                   (Format-RightMask -Mask $wanted))
        }
    }
    Write-Ok ('Restored the descriptor on ' + $channel)
    return 'restored'
}

#endregion

#region Forwarder diagnostics -------------------------------------------------

<#
    "The registry value is set" and "events are being forwarded" are different
    claims, and only the second is worth anything to a responder.

    Channel: Microsoft says "The Eventlog-forwardingPlugin/Operational event
    channel logs the success, warning, and error events related to WEF
    subscriptions present on the device", and the walkthrough names the path
    "Applications and Services Logs\Microsoft\Windows\Eventlog-ForwardingPlugin\
    Operational". The brief that commissioned this script called it
    Microsoft-Windows-Forwarding/Operational instead, so both are probed.
    Measured 2026-08-27 on Server 2019 build 17763.9121:
    Microsoft-Windows-Eventlog-ForwardingPlugin/Operational does NOT exist and
    Microsoft-Windows-Forwarding/Operational does. Both stay in the list because
    only one build has been measured.

    Event IDs, both cited from step 7 of the walkthrough ("These steps should
    produce event 104 ... 'The forwarder has successfully connected to the
    subscription manager at address <FQDN>' followed by event 100 with the
    message: 'The subscription <sub_name> is created successfully.'"):
    https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription
    No other ID from that channel is hard-coded, because no other one could be
    cited: recent events are printed with their real IDs and levels, and only
    these two are interpreted.
#>

$script:ForwardingChannelCandidates = @(
    'Microsoft-Windows-Eventlog-ForwardingPlugin/Operational',
    'Microsoft-Windows-Forwarding/Operational'
)
$script:EventIdForwarderConnected  = 104
$script:EventIdSubscriptionCreated = 100
# 101 and 102 are the two events that name a subscription this host could not
# fully honour, and reading them is not optional. Defect W-2 lived for two days
# behind a 101 that was sitting in this channel the whole time: over Microsoft's
# 20-expression XPath ceiling the source DROPS the offending channel and keeps
# forwarding the others, so the collector shows Active / LastError 0 / a fresh
# heartbeat while one channel delivers nothing. The 101 even carries a
# QueryStatus document naming the failing channel and its error code. Nothing on
# the collector side can see any of this - only the source can.
$script:EventIdSubscriptionPartial = 101
$script:EventIdSubscriptionFailed  = 102
# 103 is how the forwarder says it dropped a subscription. On every policy
# refresh it unsubscribes everything and then re-subscribes whatever the
# collector still offers, so a subscription whose NEWEST event is 103 is one this
# host no longer carries - and reporting its last verdict would be a finding
# about something that no longer exists. Measured: a first attempt bounded this
# by a time window instead, and leaked a deleted subscription back as a finding
# 46 seconds later. The SubscriptionManager value carries Refresh=60, so rounds
# are a minute apart in production and no window can separate them reliably.
$script:EventIdSubscriptionDropped = 103

function Get-SubscriptionVerdict {
    <#
        Newest 100/101/102 per subscription, from this channel. Locale-independent
        by construction: the subscription name comes from the structured
        EventData field <Data Name='Id'>, never from the rendered message, and
        the per-channel detail comes from the <Data Name='Status'> QueryStatus
        document. Measured field layout on Server 2019 build 17763.9121:
          100 SubscribeSuccess        Id, Query
          101 SubscribePartialSuccess Id, Query, Status
          102 SubscribeFailure        Id, Query, ErrorCode
          103 (unsubscribed)          Id
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Channel,
        [Parameter()][int] $MaxEvents = 400
    )
    $verdicts = @{}
    $newestDrop = ''
    $events = @()
    try {
        $events = @(Get-WinEvent -LogName $Channel -MaxEvents $MaxEvents -ErrorAction Stop |
                    Where-Object { [int] $_.Id -in @($script:EventIdSubscriptionCreated,
                                                     $script:EventIdSubscriptionPartial,
                                                     $script:EventIdSubscriptionFailed,
                                                     $script:EventIdSubscriptionDropped) })
    } catch {
        return @{ Verdicts = $verdicts; NewestDropUtc = $newestDrop }
    }
    # Newest first out of Get-WinEvent, so the first sighting of a name wins.
    foreach ($item in $events) {
        $data = @{}
        try {
            $doc = [xml] $item.ToXml()
            foreach ($field in $doc.Event.EventData.Data) {
                if ($field -is [string]) { continue }
                $fieldName = [string] $field.Name
                if (-not [string]::IsNullOrWhiteSpace($fieldName)) {
                    $data[$fieldName] = [string] $field.'#text'
                }
            }
        } catch { continue }
        $id = ''
        if ($data.ContainsKey('Id')) { $id = [string] $data['Id'] }
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        # Newest first, so the newest 103 in the whole channel is the first one seen.
        if ([int] $item.Id -eq $script:EventIdSubscriptionDropped -and
            [string]::IsNullOrWhiteSpace($newestDrop)) {
            $newestDrop = $item.TimeCreated.ToUniversalTime().ToString(
                              'yyyy-MM-ddTHH:mm:ssZ',
                              [System.Globalization.CultureInfo]::InvariantCulture)
        }
        if ($verdicts.ContainsKey($id)) { continue }

        $badChannels = New-Object System.Collections.ArrayList
        if ($data.ContainsKey('Status')) {
            foreach ($element in [regex]::Matches([string] $data['Status'], '<[^>]*Channel\b[^>]*/>')) {
                $text = $element.Value
                $nameMatch = [regex]::Match($text, 'Name="([^"]*)"')
                $codeMatch = [regex]::Match($text, 'ErrorCode="([^"]*)"')
                if (-not $nameMatch.Success) { continue }
                $code = ''
                if ($codeMatch.Success) { $code = $codeMatch.Groups[1].Value }
                if ($code -ne '0' -and $code -ne '') {
                    [void] $badChannels.Add($nameMatch.Groups[1].Value + ' (error ' + $code + ')')
                }
            }
        }
        $errorCode = ''
        if ($data.ContainsKey('ErrorCode')) { $errorCode = [string] $data['ErrorCode'] }
        $verdicts[$id] = @{
            Id           = $id
            EventId      = [int] $item.Id
            WhenUtc      = $item.TimeCreated.ToUniversalTime().ToString(
                               'yyyy-MM-ddTHH:mm:ssZ',
                               [System.Globalization.CultureInfo]::InvariantCulture)
            BadChannels  = @($badChannels)
            ErrorCode    = $errorCode
        }
    }
    @{ Verdicts = $verdicts; NewestDropUtc = $newestDrop }
}

function Invoke-ForwarderDiagnostic {
    # Read-only in every mode. Returns $true only when it could demonstrate that
    # this host reached a subscription manager; $false is what makes an
    # otherwise successful -Apply exit 1 rather than 0, per docs/AUTHORING.md.
    Write-Section 'What the forwarder itself says'

    $channel = ''
    $config = $null
    foreach ($candidate in $script:ForwardingChannelCandidates) {
        $probe = Get-ChannelConfiguration -Channel $candidate
        if ($probe.Present) { $channel = $candidate; $config = $probe; break }
    }
    if ([string]::IsNullOrWhiteSpace($channel)) {
        Write-Finding ('none of the candidate forwarding channels exists (' +
                       ($script:ForwardingChannelCandidates -join ', ') +
                       '): the forwarder cannot be observed from here')
        return $false
    }
    Write-Info ('forwarding channel: ' + $channel)
    if (-not $config.Enabled) {
        Write-Finding ($channel + ' is DISABLED, so the forwarder logs nothing about itself. This ' +
                       'script does not enable channels; enable it by hand to diagnose forwarding.')
        return $false
    }

    $count = Get-ChannelRecordCount -Channel $channel
    if ($count -lt 0) { Write-Info 'the number of events in that channel could not be read' }
    else { Write-Info ([string] $count + ' event(s) in ' + $channel) }
    if ($count -eq 0) {
        Write-Finding ($channel + ' is empty: this host has never tried to reach a collector')
        return $false
    }

    $events = @()
    try { $events = @(Get-WinEvent -LogName $channel -MaxEvents 10 -ErrorAction Stop) }
    catch {
        Write-Info ('could not read events from ' + $channel + ': ' + $_.Exception.Message)
        return $false
    }

    $connected = $false
    foreach ($item in $events) {
        $when = 'unknown time'
        if ($null -ne $item.TimeCreated) {
            # InvariantCulture: in a custom format string ':' is the culture's
            # time separator - the trap Get-UtcStamp exists for.
            $when = $item.TimeCreated.ToUniversalTime().ToString(
                'yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        }
        $message = ''
        if ($null -ne $item.Message) {
            $message = ([string] $item.Message) -replace '\s+', ' '
            if ($message.Length -gt 130) { $message = $message.Substring(0, 130) + '...' }
        }
        Write-Info ($when + '  id ' + [string] $item.Id + '  ' +
                    [string] $item.LevelDisplayName + '  ' + $message)
        if ([int] $item.Id -eq $script:EventIdForwarderConnected) { $connected = $true }
    }

    # Per-subscription verdict. This is the only place in the toolkit that can
    # see a partially honoured subscription; see the note beside the event IDs.
    # A subscription whose newest event is 103 was dropped and is not reported.
    $probe = Get-SubscriptionVerdict -Channel $channel
    $allVerdicts = $probe.Verdicts
    $newestDrop = [string] $probe.NewestDropUtc
    $verdicts = @{}
    $dropped = 0
    $stale = 0
    foreach ($key in $allVerdicts.Keys) {
        $entry = $allVerdicts[$key]
        if ([int] $entry.EventId -eq $script:EventIdSubscriptionDropped) { $dropped++; continue }
        # A 102 never gets a 103 - you cannot unsubscribe what was never
        # subscribed - so a failed subscription the collector has since removed
        # would otherwise be reported forever. Every round begins by
        # unsubscribing everything, so a verdict older than the channel's newest
        # 103 belongs to a previous round and describes a subscription this
        # collector no longer offers. With no 103 at all this host has never
        # dropped anything, and every verdict stands.
        if (-not [string]::IsNullOrWhiteSpace($newestDrop)) {
            $verdictStamp = [datetime]::MinValue
            $dropStamp = [datetime]::MinValue
            # Both strings were built above with InvariantCulture and a 'Z'
            # suffix, so they must be read back the same way: the no-provider
            # TryParse overload uses the ambient culture, which is the trap
            # Get-UtcStamp exists for. A culture that defeats the parse would
            # silently stop the stale suppression this block argues for.
            # AdjustToUniversal honours the 'Z'; AssumeUniversal keeps a stamp
            # that somehow lost it on the same UTC footing rather than local.
            $stampCulture = [System.Globalization.CultureInfo]::InvariantCulture
            $stampStyles  = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
                            [System.Globalization.DateTimeStyles]::AssumeUniversal
            if ([datetime]::TryParse($entry.WhenUtc, $stampCulture, $stampStyles, [ref] $verdictStamp) -and
                [datetime]::TryParse($newestDrop, $stampCulture, $stampStyles, [ref] $dropStamp) -and
                $verdictStamp -lt $dropStamp) {
                $stale++
                continue
            }
        }
        $verdicts[$key] = $entry
    }
    if ($verdicts.Keys.Count -eq 0) {
        Write-Info 'no per-subscription verdict (event 100, 101 or 102) found in this channel'
    }
    if ($dropped -gt 0) {
        Write-Info ([string] $dropped + ' subscription(s) were unsubscribed (event 103) and are not ' +
                    'reported: this host no longer carries them')
    }
    if ($stale -gt 0) {
        Write-Info ([string] $stale + ' verdict(s) predate the last unsubscribe at ' + $newestDrop +
                    ' and are not reported: they describe subscriptions this collector no longer offers')
    }
    foreach ($name in ($verdicts.Keys | Sort-Object)) {
        $verdict = $verdicts[$name]
        if ([int] $verdict.EventId -eq $script:EventIdSubscriptionCreated) {
            Write-Ok ('subscription ' + $name + ': created successfully (event 100 at ' +
                      $verdict.WhenUtc + ') - every channel in its query was readable')
            continue
        }
        if ([int] $verdict.EventId -eq $script:EventIdSubscriptionPartial) {
            $detail = 'the failing channel was not named in the event'
            if (@($verdict.BadChannels).Count -gt 0) {
                $detail = 'unreadable channel(s): ' + (@($verdict.BadChannels) -join ', ')
            }
            Write-Finding ('subscription ' + $name + ' is only PARTIALLY honoured (event 101 at ' +
                           $verdict.WhenUtc + '): ' + $detail + '. This host forwards the rest of ' +
                           'the query and NOTHING from those channels, and the collector cannot see ' +
                           'it - wecutil reports the subscription Active with LastError 0 and a live ' +
                           'heartbeat while a channel silently delivers nothing. A query that puts ' +
                           'more than 20 EventID terms in one <Select> is one cause; see W-2 in ' +
                           'the review log kept in the development repository.')
            continue
        }
        $codeText = ''
        if (-not [string]::IsNullOrWhiteSpace($verdict.ErrorCode)) {
            $codeText = ', error code ' + $verdict.ErrorCode
        }
        Write-Finding ('subscription ' + $name + ' could NOT be created (event 102 at ' +
                       $verdict.WhenUtc + $codeText + '): this host forwards nothing for it.')
    }

    if ($connected) {
        Write-Ok ('event ' + [string] $script:EventIdForwarderConnected +
                  ' present: this host has connected to a subscription manager')
        return $true
    }
    Write-Finding ('no event ' + [string] $script:EventIdForwarderConnected + ' in the last ' +
                   [string] $events.Count + ' events: no recent evidence that this host reached a ' +
                   'collector. Forwarding cannot be demonstrated from this side.')
    return $false
}

#endregion

#region Client checks ---------------------------------------------------------

function Invoke-HostCheck {
    <#
        Note the accumulation idiom, and copy it exactly. Never write
        '$changed = $changed -or (...)': -or short-circuits, so once $changed is
        $true every later call is NEVER MADE and the script silently stops
        applying settings after the first one that worked.

        Returns the number of changes made, and sets $script:ForwarderConnected.
    #>
    $changeCount = 0
    $changeCount += Invoke-WinRmCheck
    $changeCount += Invoke-SubscriptionManagerCheck
    $changeCount += Invoke-SecurityChannelCheck
    $script:ForwarderConnected = Invoke-ForwarderDiagnostic

    # Reported for context, never changed. Wecsvc is the COLLECTOR service: a
    # source does not need it and its being stopped here is not a fault. Winmgmt
    # hosts other WinRM plugins - # UNVERIFIED: whether source-initiated
    # forwarding needs it at all; it is reported because it gets blamed.
    Write-Section 'Related services (reported, not changed)'
    foreach ($name in @('Wecsvc', 'Winmgmt', 'EventLog')) {
        $state = Get-ServiceState -Name $name
        if (-not $state.Present) { Write-Info ($name + ': not present'); continue }
        Write-Info ($name + ': ' + $state.Status + '/' + $state.StartType)
    }
    return $changeCount
}

#endregion

#region Main -----------------------------------------------------------------

function Restore-WefClientChange {
    <#
        Routes a change record to the right restorer. The template's
        Restore-TrackedChange only knows the 'registry' type and declines
        anything else - correctly, since silently "succeeding" on a change type
        it cannot undo is how a run gets marked rolled back while the host stays
        modified. This script introduces two types and reuses a third, so it
        routes them here and delegates the rest.

        Returns 'restored' or 'declined'; throws on failure.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    switch ([string] $change.type) {
        'winrmconfig'            { return (Restore-WinRmConfig -ChangeRecord $ChangeRecord) }
        'wefsubscriptionmanager' { return (Restore-SubscriptionManagerEntry -ChangeRecord $ChangeRecord) }
        'channelaccess'          { return (Restore-SecurityChannelAccess -ChangeRecord $ChangeRecord) }
        default                  { return (Restore-TrackedChange -ChangeRecord $ChangeRecord) }
    }
}

function Assert-CollectorUriUsable {
    # -CollectorUri is validated here rather than declared Mandatory on the
    # Apply set: a missing or malformed mandatory parameter fails binding
    # before this script's own code runs, and PowerShell then returns host exit
    # code 1 - which an RMM reads as "findings" (docs/DESIGN.md section 3). Bad
    # input is an execution error: exit 2, said out loud.
    if ([string]::IsNullOrWhiteSpace($CollectorUri)) {
        if ($Apply) {
            Write-Failure '-Apply needs -CollectorUri (the subscription manager address). Nothing changed.'
            return $false
        }
        return $true
    }
    try { [void] (Format-SubscriptionManagerValue -Uri $CollectorUri -Refresh $RefreshSeconds) }
    catch {
        Write-Failure $_.Exception.Message
        return $false
    }
    return $true
}

function Write-GroupPolicyOwnershipNote {
    <#
        GP-1. On a domain-joined host the Group Policy engine owns
        HKLM:\SOFTWARE\Policies, and this script reads or writes values that live
        there. A domain GPO setting the same value WINS at the next policy
        refresh, whatever was set locally.

        Measured 2026-09-09 on a Server 2019 member and again on a Windows 11
        client, by counting real 4104 events rather than reading the registry
        back: the value went 1 -> logging worked, gpupdate -> 0 and logging
        STOPPED, -Apply -> 1 and it worked again while printing "[ ok ] ... set"
        at exit 0, next refresh -> 0 and stopped again. So on a domain-joined
        fleet a run of zeroes does not mean the fleet is armed.

        INFORMATIONAL, NEVER A FINDING, NEVER A HOST LIMIT, and both alternatives
        were considered and rejected. A finding would exit 1 on every
        domain-joined host forever - exactly the T-4 defect this project already
        fixed once, and a monitor that is permanently red gets muted. A [limit]
        would claim no lever exists when one does: it belongs to whoever owns the
        GPO, not to this script.

        Silent on a host whose domain role cannot be read. Asserting domain
        membership this run did not observe would be the same class of mistake
        the note exists to warn about.
    #>
    $role = -1
    try { $role = [int] (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole }
    catch { return }
    # 1 member workstation, 3 member server, 4 backup DC, 5 primary DC.
    # 0 and 2 are standalone and have no domain policy to be overridden by.
    if ($role -ne 1 -and $role -ne 3 -and $role -ne 4 -and $role -ne 5) { return }
    Write-Info ('This host is joined to a domain, and the values this script touches live in ' +
                'the Group Policy engine''s own registry hive. A domain GPO that sets them wins ' +
                'at the next policy refresh, whatever is set locally - measured, with the ' +
                'logging stopping when it does.')
    Write-Info ('Schedule Test-VisibilityDrift. It is the only thing in this toolkit that ' +
                'detects that afterwards, and a clean run here does not rule it out.')
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
    Assert-ParameterRange   -Name 'RefreshSeconds' -Value $RefreshSeconds -Minimum 60 -Maximum 86400

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')

    if ($mode -ne 'Rollback') {
        if (-not (Assert-CollectorUriUsable)) { return 2 }
    }

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        [void] (Invoke-HostCheck)
        Write-Section 'Result'
        Write-GroupPolicyOwnershipNote
        if ($script:Findings.Count -gt 0) {
            Write-Info ([string] $script:Findings.Count + ' finding(s). Re-run with -Apply -CollectorUri <uri> to change them.')
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
        Write-Ok 'No findings: this host is configured to forward its events.'
        return 0
    }

    Enter-ToolkitLock -ToolkitRootPath $resolvedRoot
    try {
        $allowMissingStamp = ($mode -eq 'Rollback')
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -AllowMissingStamp:$allowMissingStamp)
        Assert-ManifestUsable

        if ($mode -eq 'Apply') {
            [void] (Start-ManifestRun -Mode 'Apply' -Parameters @{
                toolkitRoot                  = $resolvedRoot
                collectorUri                 = $CollectorUri
                refreshSeconds               = $RefreshSeconds
                subscriptionManagerValueName = $SubscriptionManagerValueName
                skipSecurityChannelGrant     = [bool] $SkipSecurityChannelGrant
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
            Write-GroupPolicyOwnershipNote
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
            Write-Info 'The forwarder reads this policy on its own schedule, and this script does not'
            Write-Info 'restart WinRM to force it: a restart drops every session on it, an RMM included.'
            if (-not $script:ForwarderConnected) {
                Write-Info 'Nothing here proves an event reached a collector - that needs the second host.'
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
            Write-GroupPolicyOwnershipNote
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
                $outcome = Restore-WefClientChange -ChangeRecord $target.Changes[$i]
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
            Write-GroupPolicyOwnershipNote
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
        Write-GroupPolicyOwnershipNote
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
