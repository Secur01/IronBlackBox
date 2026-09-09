<#
.SYNOPSIS
    Configures this host as a Windows Event Forwarding COLLECTOR: starts the
    Windows Event Collector service, sizes the ForwardedEvents channel so it
    does not throw away what it collected, and registers a source-initiated
    subscription for the events Enable-IRVisibility turns on.

.DESCRIPTION
    WEF is the one thing here that cannot be judged from a single host: it
    needs a collector, at least one source, and in practice a domain for the
    authentication. docs/VALIDATION.md is the only file allowed to say where
    this script has run, and its row is the one to read before deploying.

    Commands, service names, registry paths and XML element names are cited to
    learn.microsoft.com inline; what could not be cited is marked
    '# UNVERIFIED:' with what needs checking - those markers are per-fact and
    do not clear just because the script as a whole has been exercised.

    The three things a collector needs, and the two failures this script exists
    to prevent:
      - 'wecutil qc /q' initialises the collector. Microsoft documents exactly
        what it does: enable the ForwardedEvents channel, set the Windows Event
        Collector service to delay start, start it if it is not running.
      - The ForwardedEvents channel ships small. A collector with a
        default-sized channel silently discards what it worked to collect, so
        this script sizes it deliberately - in BYTES, which is the unit
        'wevtutil sl /ms:' takes, and NOT the kilobytes the EventLog policy
        takes. Getting that backwards asks for 1024 times too little. Raising
        the cap is gated on free space on the volume that will HOLD the log:
        a cap is a promise that volume has to be able to keep, and filling the
        system drive of a collector is not an improvement in visibility.
      - A subscription that exists is not a subscription that works. The audit
        reports the runtime status of every subscription and how many events
        the channel actually holds, because "the subscription exists" and
        "events are arriving" are different claims.

    WinRM caution. WEF rides on WinRM and many RMM agents ride on WinRM too,
    so docs/AUTHORING.md forbids touching anything that can break RMM connectivity.
    This script never reconfigures WinRM: no 'winrm quickconfig', no listener,
    no firewall rule. It does run 'wecutil qc /q', whose documented steps do
    not mention WinRM at all - which is exactly why it snapshots the WinRM
    service and listener state into the manifest first. If qc turns out to
    touch WinRM anyway, the evidence is recorded and -Rollback can report it.

    What this script deliberately does NOT do:
      - Reconfigure WinRM, create a listener, or open a firewall port. If the
        collector needs an HTTP or HTTPS listener, that is an operator decision
        made with the network in front of them.
      - Remove a WinRM listener on -Rollback, even one that appeared during
        -Apply. Removing a listener is how an MSP loses the host.
      - Delete a subscription it did not create. -Rollback deletes exactly the
        subscription named in its own manifest record, and only while that
        subscription still carries this toolkit's marker in its description.
      - Modify an existing subscription. If one already exists under the
        requested name without the toolkit's marker, it is reported and left
        alone.
      - Configure certificate-based (HTTPS) collection for sources outside the
        collector's domain, or any certificate mapping.
      - Move the ForwardedEvents .evtx off the system volume, which Microsoft
        recommends for performance on a busy collector.
      - Set the rendering locale. The generated subscription requests en-US
        rendered text, which keeps event descriptions stable for downstream
        detection rules; change it in the generated XML if that is wrong for
        the customer.
      - Prove that events arrive. It reports every signal it can read locally
        and returns 1 when it cannot demonstrate that any event has landed.

.PARAMETER Audit
    Default. Strictly read-only. Reports the collector service, the
    ForwardedEvents channel, the WinRM listener state, every existing
    subscription with its runtime status, and what -Apply would change.

.PARAMETER Apply
    Initialises the collector, sizes ForwardedEvents and registers the
    subscription, recording every previous value first.

.PARAMETER Rollback
    Deletes the subscription this script created and restores the channel and
    the service to what it found.

.PARAMETER ToolkitRoot
    Base directory for the manifest and the generated subscription XML.
    Default C:\ProgramData\IronBlackBox. Validated before use.

.PARAMETER SubscriptionName
    Name (SubscriptionId) of the subscription this script manages, and the base
    name of the XML file written under the toolkit root. Restricted to letters,
    digits, dot, dash and underscore: it becomes part of a file path.
    Default IronBlackBox-Baseline.

.PARAMETER ForwardedEventsSizeMb
    Target size of the ForwardedEvents channel, in MEGABYTES, converted to
    bytes for 'wevtutil sl /ms:'. Default 2048 (2 GB). A channel already larger
    than this is left alone - this script never shrinks an event log.

.PARAMETER MinimumFreeDiskPercent
    Free-space floor, as a percentage of the volume holding the ForwardedEvents
    log, below which this script will NOT raise the channel cap. Default 10.
    The volume is read from the channel's own log file path, which is not
    necessarily the volume the toolkit root is on. A refusal reports itself and
    still switches the channel on; only the resize is skipped.

.PARAMETER DeliveryMaxItems
    Events batched before a source delivers them. Default 20.

.PARAMETER DeliveryMaxLatencyMs
    Maximum time a source holds a partial batch, in milliseconds.
    Default 300000 (5 minutes).

.PARAMETER HeartbeatIntervalMs
    How often a source with nothing to send checks in, in milliseconds.
    Default 900000 (15 minutes). This is what decides when the collector calls
    a source Inactive.

.PARAMETER ContentFormat
    RenderedText (default) ships the event description with the event, which
    roughly doubles or triples its size but is readable without the source's
    provider. Events ships the binary XML only, and more than doubles what one
    collector can take.

.PARAMETER ReadExistingEvents
    Collect the events already in a source's logs when it first connects,
    instead of only new ones. Off by default: on a fleet, turning it on means
    every host uploads its history at once.

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
    .\Enable-WefCollector.ps1
    Reports the collector state, the subscriptions and their runtime status.

.EXAMPLE
    .\Enable-WefCollector.ps1 -Apply
    Initialises the collector, sizes ForwardedEvents to 2 GB and registers the
    baseline subscription.

.EXAMPLE
    .\Enable-WefCollector.ps1 -Rollback
    Deletes the subscription this toolkit created and restores the channel and
    service state.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.0.0
    License : MIT

    Windows PowerShell 5.1. No module dependencies. Requires local
    administrator; enforced in code by Assert-Elevated, deliberately not by
    #Requires -RunAsAdministrator (see docs/DESIGN.md section 3).

    Change types introduced by this script: 'wefsubscription', 'eventchannel',
    'servicestartup'. It also writes a 'winrmconfig' record, in the same shape
    logging-hardening/Enable-WefClient.ps1 defines.

    NOTE FOR RECONCILIATION: 'eventchannel' is introduced here and, in
    parallel, by logging-hardening/Enable-DnsVisibility.ps1 for the same
    purpose. The shape here is deliberately minimal - channel, previous enabled
    state, previous max size in bytes, and the new values - so the two can be
    merged without either one losing information.
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
    [string] $SubscriptionName = 'IronBlackBox-Baseline',

    [Parameter()]
    [int] $ForwardedEventsSizeMb = 2048,

    # Raising the channel cap is gated on free space on the volume that will HOLD
    # the log, the way Enable-LolbinAudit gates its own channel resize. A 2 GiB
    # cap on a system volume that cannot take it turns a logging improvement into
    # an outage on what is usually a domain controller.
    [Parameter()]
    [int] $MinimumFreeDiskPercent = 10,

    [Parameter()]
    [int] $DeliveryMaxItems = 20,

    [Parameter()]
    [int] $DeliveryMaxLatencyMs = 300000,

    [Parameter()]
    [int] $HeartbeatIntervalMs = 900000,

    [Parameter()]
    [string] $ContentFormat = 'RenderedText',

    [Parameter()]
    [switch] $ReadExistingEvents,

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

$script:ScriptName    = 'Enable-WefCollector'
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

# Set by Invoke-SubscriptionCheck: $false means "no event has been observed in
# ForwardedEvents", which is what makes an otherwise successful -Apply exit 1.
$script:EventsObserved = $false

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

# Anchored once, here, rather than at each of the thirteen call sites: every
# native tool this script launches has to be the in-box one. A bare file name is
# resolved through the machine PATH, and this script runs as SYSTEM - so a PATH
# entry an unprivileged user can write to would choose the binary. The same
# argument Assert-SafeToolkitPath makes about operator input applies with more
# force to an environment variable, which no operator has to touch.
# Get-NativeToolPath falls back to the bare name, so an unusual layout still
# runs; it just stops being anchored.
$script:WecutilPath  = Get-NativeToolPath -FileName 'wecutil.exe'
$script:WevtutilPath = Get-NativeToolPath -FileName 'wevtutil.exe'
$script:NetshPath    = Get-NativeToolPath -FileName 'netsh.exe'
# winrm.cmd, not winrm.exe: the WinRM command-line tool is a script, and `&`
# hands a .cmd to the command processor. Anchoring it matters the same way.
$script:CscriptPath  = Get-NativeToolPath -FileName 'cscript.exe'
$script:WinrmScript  = [System.IO.Path]::Combine(
    [System.IO.Path]::Combine($env:SystemRoot, 'System32'), 'winrm.vbs')

#endregion

#region Collector service -----------------------------------------------------

<#
    'wecutil qc /q' is the documented way to initialise a collector, and
    Microsoft documents exactly what it does: "Configures the Windows Event
    Collector service to ensure a subscription can be created and sustained
    through reboots. This includes the following steps: 1. Enable the
    ForwardedEvents channel if it is disabled. 2. Set the Windows Event
    Collector service to delay start. 3. Start the Windows Event Collector
    service if it is not running."
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wecutil
    The service short name is wecsvc, from the same page: "you need to start the
    Windows Event Collector service (wecsvc)".

    Note step 2: qc sets DELAY START, not plain Automatic. Windows PowerShell
    5.1 reports a delayed-autostart service as StartType 'Automatic', so
    "Automatic and Running" is the end state this script checks for and the
    delay is invisible to it - see Get-ServiceState.

    Note also what those three documented steps do NOT include: any change to
    WinRM. The widely repeated claim that 'wecutil qc' also configures WinRM is
    not in the documentation, and this project does not state Windows facts it
    cannot cite. # UNVERIFIED: whether qc touches WinRM in practice. Because it
    might, the WinRM service and listener state are snapshotted into the
    manifest immediately before qc runs, so a surprise is at least recorded.
#>

$script:CollectorServiceName = 'Wecsvc'
$script:WinRmServiceName     = 'WinRM'

function Get-ServiceState {
    # Get-Service, not sc.exe: Status and StartType are typed, not localised
    # display text. Enable-ServerPrefetch reads SysMain the same way.
    # # UNVERIFIED: StartType under PS 5.1 has no distinct value for "Automatic
    # (Delayed Start)", which is what wecutil qc sets. This script only ever
    # restores the value it read, so the worst case is a rollback that puts back
    # plain Automatic where the host had delayed-auto.
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
    # listeners: https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription
    # The parsed summary is used for REPORTING and the manifest record only,
    # never to decide a change, so localised field names cannot cause a wrong
    # write. A non-zero exit means "unknown", never "none".
    #
    # Ports is the same parse, kept as numbers instead of display text. It feeds
    # the W-1 reservation check, which used to hardcode 5985 and so declared a
    # correctly configured collector broken whenever its listener was on any
    # other port. Every port is collected, enabled or not, because the Enabled
    # VALUE is text from a localisable tool: an extra candidate port costs one
    # substring match against netsh output, while filtering on a word this code
    # cannot be sure it recognises would drop the real listener.
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
            Readable = $false; Summaries = @(); Ports = @()
            Detail = ('winrm.vbs exited ' + [string] $result.ExitCode + ': ' +
                      (($result.Output | Select-Object -First 2) -join ' '))
        }
    }
    $summaries = New-Object System.Collections.ArrayList
    $ports = New-Object System.Collections.ArrayList
    $current = $null
    foreach ($line in $result.Output) {
        if ($line -match '^\s*Listener\s*$') {
            if ($null -ne $current) { [void] $summaries.Add(($current -join ' ')) }
            $current = New-Object System.Collections.ArrayList
            continue
        }
        if ($null -eq $current) { continue }
        if ($line -match '^\s*(Transport|Address|Port|Enabled)\s*=\s*(.*)$') {
            $field = $Matches[1]
            $value = $Matches[2].Trim()
            [void] $current.Add($field + '=' + $value)
            if ($field -eq 'Port') {
                # InvariantCulture: a port is not culture-formatted, and the
                # ambient culture must not decide whether this parses.
                $number = 0
                if ([int]::TryParse($value, [System.Globalization.NumberStyles]::Integer,
                                    [System.Globalization.CultureInfo]::InvariantCulture, [ref] $number)) {
                    if ($number -gt 0 -and -not $ports.Contains($number)) { [void] $ports.Add($number) }
                }
            }
        }
    }
    if ($null -ne $current) { [void] $summaries.Add(($current -join ' ')) }
    return [PSCustomObject] @{
        Readable = $true; Summaries = @($summaries.ToArray()); Ports = @($ports.ToArray()); Detail = ''
    }
}

function Write-WinRmSnapshot {
    # Records what WinRM looked like immediately before 'wecutil qc /q'. The new
    # values equal the previous ones on purpose: this script intends NO change
    # to WinRM, and the record exists because qc's full side effects are not
    # documented. Same field shape as Enable-WefClient's winrmconfig record.
    param([Parameter(Mandatory = $true)] $State, [Parameter(Mandatory = $true)] $Listeners)

    [void] (Write-ManifestChange -Change @{
        type               = 'winrmconfig'
        serviceName        = $script:WinRmServiceName
        previousStartType  = $State.StartType
        previousStatus     = $State.Status
        newStartType       = $State.StartType
        newStatus          = $State.Status
        previousListeners  = @($Listeners.Summaries)
        listenerChangeMade = $false
        description        = 'WinRM state captured before wecutil qc /q; this script does not change WinRM'
    })
}

function Get-ServiceHostSharingState {
    <#
        Are Wecsvc and WinRM running in the SAME svchost process?

        This is defect W-1, and it is the whole answer to "forwarding does not
        establish with both sides verified correct". Above roughly 3.5 GB of RAM
        Windows gives each service its own svchost process. WinRM then owns the
        single HTTP URL reservation 'HTTP://+:5985/WSMAN/' and everything beneath
        it, and Wecsvc - in a different process - CANNOT register
        'HTTP://+:5985/WSMAN/SUBSCRIPTIONMANAGER/WEC/'. A source enumerating
        that URL is answered by WinRM, which has no handler for the sub-path, and
        gets "the requested HTTP URL was not available" - WS-Man error
        2150859027, surfaced on the source as event 105.

        Measured on the lab, both directions (verification/facts.json, fact
        wef-svchost-split-breaks-source-initiated):

          split   Wecsvc PID 3200, WinRM PID 3088
                  reservations: HTTP://+:5985/WSMAN/                     (one)
          merged  Wecsvc PID 776,  WinRM PID 776
                  reservations: HTTP://+:5985/WSMAN/
                                HTTP://+:5985/WSMAN/SUBSCRIPTIONS/<guid>/
                                HTTP://+:5985/WSMAN/SUBSCRIPTIONMANAGER/WEC/

        This function only READS. Merging the two services means writing
        SvcHostSplitDisable under both service keys and rebooting, which changes
        how WinRM itself is hosted - and docs/AUTHORING.md forbids this toolkit from
        touching RMM connectivity. So the condition is named and left to the
        operator, the same stance the AppLocker, NTLM and LDAP scripts take.
    #>
    $state = [PSCustomObject] @{
        WecPid           = 0
        WinRmPid         = 0
        Shared           = $false
        WecSplitDisable  = $null
        WinRmSplitDisable = $null
        Readable         = $false
    }
    try {
        $wec = Get-CimInstance -ClassName Win32_Service -Filter "Name='Wecsvc'" -ErrorAction Stop
        $rm  = Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
        $state.WecPid   = [int] $wec.ProcessId
        $state.WinRmPid = [int] $rm.ProcessId
        $state.Readable = $true
    }
    catch {
        return $state
    }
    # A stopped service reports PID 0. Two stopped services are not "shared".
    $state.Shared = ($state.WecPid -ne 0 -and $state.WecPid -eq $state.WinRmPid)
    foreach ($pair in @(@{ Name = 'Wecsvc'; Field = 'WecSplitDisable' },
                        @{ Name = 'WinRM';  Field = 'WinRmSplitDisable' })) {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $pair.Name
        $v = Get-ItemProperty -Path $key -Name 'SvcHostSplitDisable' -ErrorAction SilentlyContinue
        if ($null -ne $v) { $state.($pair.Field) = [int] $v.SvcHostSplitDisable }
    }
    return $state
}

function Get-SubscriptionManagerReservation {
    <#
        Does anything hold the URL a source-initiated forwarder actually asks
        for? This is the language-independent half of the W-1 check: an HTTP URL
        reservation is structural, where 'wecutil gr' output is localisable text.

        'netsh http show servicestate view=requestq' lists the registered URL
        prefixes. Returns Present=$false when nothing holds a
        .../WSMAN/SUBSCRIPTIONMANAGER path on any of the WinRM listener ports.

        -Port takes a LIST, because the caller reads the ports off the live
        listeners rather than assuming one. A host with an HTTPS listener on a
        non-default port is configured correctly and must not be diagnosed as
        defect W-1.
    #>
    param([Parameter(Mandatory = $true)][int[]] $Port)

    $result = Invoke-NativeCommand -FilePath $script:NetshPath `
                -Arguments @('http', 'show', 'servicestate', 'view=requestq')
    if ($result.ExitCode -ne 0) {
        return [PSCustomObject] @{ Readable = $false; Present = $false; Reservations = @() }
    }
    $wanted = @($Port | ForEach-Object { (':' + [string] $_ + '/WSMAN').ToUpperInvariant() })
    $found = New-Object System.Collections.ArrayList
    foreach ($line in $result.Output) {
        $text = ([string] $line).Trim()
        $upper = $text.ToUpperInvariant()
        foreach ($candidate in $wanted) {
            if ($upper.Contains($candidate)) { [void] $found.Add($text); break }
        }
    }
    $present = $false
    foreach ($r in $found) {
        if ($r.ToUpperInvariant().Contains('SUBSCRIPTIONMANAGER')) { $present = $true }
    }
    return [PSCustomObject] @{ Readable = $true; Present = $present; Reservations = @($found) }
}

function Invoke-SubscriptionManagerEndpointCheck {
    <#
        Reports W-1. Read-only in EVERY mode, including -Apply: see
        Get-ServiceHostSharingState for why this script will not merge the
        service hosts itself. Always returns 0 changes.
    #>
    Write-Section 'Subscription manager endpoint (W-1)'

    # The port comes from the LIVE listener, never from a constant. This used to
    # be `$listenerPort = 5985` while Get-WinRmListenerState was already parsing
    # the real port and throwing it away, so a collector listening on 5986 or on
    # any other port matched no reservation and got told it had defect W-1 - a
    # diagnosis that sends the operator to investigate svchost hosting on a
    # correctly configured host. Read again here rather than plumbed through
    # Invoke-HostCheck: one extra read-only winrm.cmd enumeration is cheaper than
    # threading state across two call sites for a diagnostic.
    $listeners = Get-WinRmListenerState
    $listenerPorts = @()
    if ($listeners.Readable) { $listenerPorts = @($listeners.Ports) }
    $portReason = ''
    if ($listenerPorts.Count -eq 0) {
        # No listener port could be read: the enumeration failed, no listener
        # exists, or the tool's field names are localised. 5985 is not asserted
        # as a Windows default here - it is the port measured on the lab
        # (verification/facts.json, wef-svchost-split-breaks-source-initiated),
        # and the output says it was assumed so no reader mistakes it for a
        # reading of this host.
        $portReason = 'no listener was returned'
        if (-not $listeners.Readable) { $portReason = $listeners.Detail }
        $listenerPorts = @(5985)
    }
    $portText = ($listenerPorts | ForEach-Object { [string] $_ }) -join ', '

    $res = Get-SubscriptionManagerReservation -Port $listenerPorts
    $svc = Get-ServiceHostSharingState

    if ($svc.Readable) {
        Write-Info ('Wecsvc PID ' + [string] $svc.WecPid + ', WinRM PID ' + [string] $svc.WinRmPid)
    }
    else {
        Write-Finding 'could not read the Wecsvc and WinRM process ids, so the svchost split is unknown'
    }

    if (-not [string]::IsNullOrWhiteSpace($portReason)) {
        Write-Info ('no WinRM listener port could be read (' + $portReason +
                    '), so the reservation check below ASSUMES port ' + $portText)
    }
    else {
        Write-Info ('WinRM listener port(s): ' + $portText)
    }

    if ($res.Readable) {
        foreach ($r in $res.Reservations) { Write-Info ('  reservation: ' + $r) }
    }
    else {
        Write-Finding 'netsh http show servicestate failed, so the URL reservations are unknown'
    }

    if ($res.Readable -and $res.Present) {
        Write-Ok ('a SUBSCRIPTIONMANAGER URL is reserved on port ' + $portText +
                  ', so a source-initiated forwarder has something to talk to')
        return 0
    }
    if (-not $res.Readable) { return 0 }

    # No SubscriptionManager reservation. Name the cause if the evidence is here.
    # A STOPPED Wecsvc reports PID 0. That is a different and much simpler
    # problem than a split svchost, and conflating the two would send an
    # operator chasing service hosting when the service is merely off.
    if ($svc.Readable -and $svc.WecPid -eq 0) {
        Write-Finding ('NO SUBSCRIPTIONMANAGER URL is reserved because Wecsvc is NOT RUNNING (PID 0). ' +
                       'It registers that URL when it starts, so nothing can forward until it does. ' +
                       'This is not the svchost split - start the collector service first, then ' +
                       're-run this check to see whether the split (W-1) is also present.')
        return 0
    }
    if ($svc.Readable -and -not $svc.Shared) {
        Write-Finding ('NO SUBSCRIPTIONMANAGER URL is reserved, and Wecsvc (PID ' + [string] $svc.WecPid +
                       ') and WinRM (PID ' + [string] $svc.WinRmPid + ') are in DIFFERENT svchost ' +
                       'processes. WinRM owns HTTP://+:' + $portText + '/WSMAN/ and Wecsvc ' +
                       'cannot register the SubscriptionManager sub-path, so every source gets ' +
                       '"the requested HTTP URL was not available" - WS-Man 2150859027, event 105 on ' +
                       'the source. This is defect W-1, measured on the lab in both directions.')
        Write-Info ('  This script will NOT fix it: merging the hosts means setting ' +
                    'SvcHostSplitDisable=1 under BOTH HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc ' +
                    'and ...\WinRM and REBOOTING, which changes how WinRM itself is hosted. This ' +
                    'toolkit does not alter WinRM hosting - see docs/AUTHORING.md on RMM connectivity.')
        Write-Info ('  Wecsvc SvcHostSplitDisable = ' +
                    $(if ($null -eq $svc.WecSplitDisable) { 'not set' } else { [string] $svc.WecSplitDisable }) +
                    ', WinRM SvcHostSplitDisable = ' +
                    $(if ($null -eq $svc.WinRmSplitDisable) { 'not set' } else { [string] $svc.WinRmSplitDisable }))
        Write-Info '  Setting it on Wecsvc alone is NOT enough - measured. Both, then a reboot.'
        return 0
    }
    Write-Finding ('NO SUBSCRIPTIONMANAGER URL is reserved on port ' + $portText +
                   ', so a source-initiated forwarder has nothing to enumerate. The services share a ' +
                   'process (or their state could not be read), so the svchost split is not the cause ' +
                   'here - check that wecutil qc has run and that a source-initiated subscription exists.')
    return 0
}

function Invoke-CollectorServiceCheck {
    # Reports the collector service and, under -Apply, initialises it with
    # 'wecutil qc /q'. Returns the number of changes made.
    Write-Section 'Windows Event Collector service'

    $state = Get-ServiceState -Name $script:CollectorServiceName
    if (-not $state.Present) {
        Write-Finding ($script:CollectorServiceName + ' is not present: this host cannot be a collector')
        return 0
    }
    Write-Info ($script:CollectorServiceName + ' is ' + $state.Status + '/' + $state.StartType)

    $winRm = Get-ServiceState -Name $script:WinRmServiceName
    if ($winRm.Present) { Write-Info ($script:WinRmServiceName + ' is ' + $winRm.Status + '/' + $winRm.StartType) }
    else { Write-Finding ($script:WinRmServiceName + ' is not present: sources cannot reach this collector') }
    $listeners = Get-WinRmListenerState
    if (-not $listeners.Readable) { Write-Info ('listeners unknown: ' + $listeners.Detail) }
    elseif ($listeners.Summaries.Count -eq 0) {
        Write-Finding ('no WinRM listener is configured: sources have nothing to connect to. This ' +
                       'script does not create one - see the header.')
    }
    else { foreach ($summary in $listeners.Summaries) { Write-Info ('listener: ' + $summary) } }

    if ($state.StartType -eq 'Automatic' -and $state.Status -eq 'Running') {
        Write-Ok ($script:CollectorServiceName + ' is Running and Automatic')
        return 0
    }
    if (-not $Apply) {
        Write-Finding ($script:CollectorServiceName + ' is ' + $state.Status + '/' + $state.StartType +
                       ' - would run wecutil qc /q to initialise the collector')
        return 0
    }

    # Both records go down before either change: qc performs the service change
    # and may perform the channel change in one call, and docs/DESIGN.md section
    # 4 requires the record on disk BEFORE the change it describes.
    if ($winRm.Present) { Write-WinRmSnapshot -State $winRm -Listeners $listeners }
    [void] (Write-ManifestChange -Change @{
        type              = 'servicestartup'
        serviceName       = $script:CollectorServiceName
        previousStartType = $state.StartType
        previousStatus    = $state.Status
        newStartType      = 'Automatic'
        newStatus         = 'Running'
        description       = ($script:CollectorServiceName + ': initialised by wecutil qc /q')
    })

    $result = Invoke-NativeCommand -FilePath $script:WecutilPath -Arguments @('qc', '/q')
    if ($result.ExitCode -ne 0) {
        throw ('wecutil qc /q failed with exit code ' + [string] $result.ExitCode + ': ' +
               ($result.Output -join ' '))
    }

    # qc is documented to set delay start and to start the service. Confirm it
    # rather than believing it, and fall back to the service APIs if the
    # documented behaviour did not land - a collector whose service is not
    # Automatic loses every event after the next reboot.
    $after = Get-ServiceState -Name $script:CollectorServiceName
    if ($after.StartType -ne 'Automatic') { Set-Service -Name $script:CollectorServiceName -StartupType 'Automatic' }
    if ($after.Status -ne 'Running')      { Start-Service -Name $script:CollectorServiceName }

    $confirmed = Get-ServiceState -Name $script:CollectorServiceName
    if ($confirmed.StartType -ne 'Automatic' -or $confirmed.Status -ne 'Running') {
        throw ($script:CollectorServiceName + ' did not read back as Automatic/Running: it is ' +
               $confirmed.Status + '/' + $confirmed.StartType)
    }
    Write-Ok ($script:CollectorServiceName + ' is now Running and Automatic')
    return 1
}

function Restore-ServiceStartup {
    # Restores the collector service. Unlike WinRM, stopping Wecsvc cannot cut
    # an RMM's transport - it only stops collecting - so a full restore is safe
    # here and is what -Rollback does.
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $name   = [string] $change.serviceName

    # The service name is constrained by the SCRIPT, never by the record - the
    # same boundary Restore-TrackedChange defends with $script:OwnedRegistryKey.
    # The manifest is operator-writable input, and this is the one code path in
    # the script that can disable and stop a service on instruction from a file:
    # a planted 'servicestartup' record naming the RMM agent's service, with
    # previousStartType 'Disabled' and previousStatus 'Stopped', would have made
    # -Rollback do exactly what docs/AUTHORING.md forbids absolutely. This script writes
    # only one 'servicestartup' record and it always names the collector
    # service, so anything else did not come from here.
    if (-not [string]::Equals($name, $script:CollectorServiceName,
                              [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('Refusing to roll back a servicestartup change for "' + $name + '"; this script only ' +
               'ever records ' + $script:CollectorServiceName + '. A record naming any other service ' +
               'did not come from this script.')
    }

    $state  = Get-ServiceState -Name $name
    if (-not $state.Present) {
        Write-Finding ('service ' + $name + ' is no longer present; leaving it alone.')
        return 'declined'
    }

    $expected = [string] $change.newStartType
    $previous = [string] $change.previousStartType

    # Three-way host resolution (docs/DESIGN.md section 4, A-2). Case 2 FIRST:
    # the host already holds the pre-apply StartType AND needs no status change,
    # so there is nothing to undo. This returned 'restored' before - claiming a
    # restore that did no work, which is how a rollback report stops being
    # evidence - and 'declined' would have left the run retryable forever.
    # Only a stop is ever issued below, never a start, so a recorded previous
    # status of Running needs no action either way.
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
    }
    if ([string] $change.previousStatus -ne 'Running' -and $state.Status -eq 'Running') {
        Stop-Service -Name $name
        if ((Get-ServiceState -Name $name).Status -eq 'Running') { throw ($name + ' did not stop') }
    }
    Write-Ok ('Restored ' + $name + ' to ' + $previous + '/' + [string] $change.previousStatus)
    return 'restored'
}

function Restore-WinRmSnapshot {
    # This script never changes WinRM, so there is normally nothing to restore.
    # If the live state differs from the snapshot, something else changed it -
    # possibly 'wecutil qc /q', whose side effects are not documented - and the
    # honest answer is to report it and decline. Stopping WinRM or removing a
    # listener to "restore" it is exactly the action docs/AUTHORING.md forbids.
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $name   = [string] $change.serviceName

    # Constrained by the SCRIPT for the same reason Restore-ServiceStartup is,
    # even though this restorer only reads: a planted record naming another
    # service would otherwise put that service's name into a finding that reads
    # as a WinRM verdict, and the next reader of this function should not have to
    # re-derive that the record cannot steer a write.
    if (-not [string]::Equals($name, $script:WinRmServiceName,
                              [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('Refusing to process a winrmconfig change for "' + $name + '"; this script only ever ' +
               'records ' + $script:WinRmServiceName + '. A record naming any other service did not ' +
               'come from this script.')
    }

    $state  = Get-ServiceState -Name $name
    if (-not $state.Present) {
        Write-Info ('service ' + $name + ' is not present; nothing to compare.')
        return 'restored'
    }

    $drift = @()
    if ($state.StartType -ne [string] $change.previousStartType) {
        $drift += ('StartType ' + [string] $change.previousStartType + ' -> ' + $state.StartType)
    }
    if ($state.Status -ne [string] $change.previousStatus) {
        $drift += ('Status ' + [string] $change.previousStatus + ' -> ' + $state.Status)
    }
    $listeners = Get-WinRmListenerState
    if ($listeners.Readable) {
        $recorded = @()
        if ($null -ne $change.previousListeners) { $recorded = @($change.previousListeners) }
        if (-not [string]::Equals(($recorded -join '|'), ($listeners.Summaries -join '|'),
                                  [System.StringComparison]::Ordinal)) {
            $drift += ('listeners "' + ($recorded -join '; ') + '" -> "' +
                       ($listeners.Summaries -join '; ') + '"')
        }
    }

    if ($drift.Count -eq 0) {
        Write-Ok ($name + ' is unchanged since -Apply, as expected')
        return 'restored'
    }
    Write-Finding ($name + ' has changed since -Apply (' + ($drift -join '; ') + '). This script does ' +
                   'not reconfigure WinRM and will not stop it or remove a listener to undo it: that ' +
                   'is how an MSP loses the host. Review it by hand.')
    return 'declined'
}

#endregion

#region ForwardedEvents channel -----------------------------------------------

<#
    THE UNIT TRAP, and the reason this region exists at all.

    'wevtutil sl <log> /ms:<MaxSize>' takes BYTES: "Sets the maximum size of the
    log in bytes. The minimum log size is 1048576 bytes (1024KB) and log files
    are always multiples of 64KB, so the value you enter will be rounded off
    accordingly."
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
    The EventLog policy value MaxSize takes KILOBYTES instead - proven by
    measurement on the lab, where a policy value of 1048576 produced a channel
    maxSize of 1073741824 bytes (verification/facts.json, fact
    eventlog-maxsize). Using one unit where the other belongs asks for 1024
    times too much or too little.

    ForwardedEvents is sized here through wevtutil and NOT through the policy,
    because EventLog.admx declares channel policies only for Application,
    Security, Setup and System (same fact) - there is no ForwardedEvents policy
    to write, and so also nothing to override the local configuration.

    Microsoft's own documented use of the same command sizes a channel this way:
    "%SystemRoot%\System32\wevtutil.exe  sl Microsoft-Windows-CAPI2/Operational
    /ms:102432768" (Appendix C)
    https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection

    This script never SHRINKS the channel: a collector already sized larger by
    the customer keeps its size, and the comparison is ">= target" so a second
    -Apply reports no change.
#>

$script:ForwardedEventsChannel = 'ForwardedEvents'

# The channels a manifest 'eventchannel' record from THIS script may name. Read
# by Restore-EventChannel, which passes the recorded name to 'wevtutil sl
# <channel> /e:false' as SYSTEM - the one code path here that can switch a
# channel off on instruction from a file. Same boundary as
# $script:OwnedRegistryKey, and Enable-LolbinAudit constrains its own resize
# restorer the identical way.
$script:OwnedChannel = @($script:ForwardedEventsChannel)

function Get-ChannelConfiguration {
    # EventLogConfiguration rather than parsing 'wevtutil gl': enabled flag and
    # maximum size come back as typed properties, so there is no output format
    # to parse and nothing to localise. Writes still go through 'wevtutil sl'.
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogconfiguration
    param([Parameter(Mandatory = $true)][string] $Channel)

    $config = $null
    try { $config = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($Channel) }
    catch {
        return [PSCustomObject] @{
            Present = $false; Enabled = $false; MaxSizeBytes = [int64] 0
            LogMode = ''; LogFilePath = ''; Detail = $_.Exception.Message
        }
    }
    try {
        return [PSCustomObject] @{
            Present = $true; Enabled = [bool] $config.IsEnabled
            MaxSizeBytes = [int64] $config.MaximumSizeInBytes
            LogMode = [string] $config.LogMode; LogFilePath = [string] $config.LogFilePath; Detail = ''
        }
    }
    finally { $config.Dispose() }
}

function Get-ChannelRuntime {
    # RecordCount and FileSize are runtime state, a different object from
    # configuration. RecordCount -1 means "could not read", never "empty".
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventloginformation
    param([Parameter(Mandatory = $true)][string] $Channel)
    try {
        $info = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogInformation(
                    $Channel, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
        $count = [int64] (-1)
        if ($null -ne $info -and $null -ne $info.RecordCount) { $count = [int64] $info.RecordCount }
        $size = [int64] 0
        if ($null -ne $info -and $null -ne $info.FileSize) { $size = [int64] $info.FileSize }
        $written = ''
        if ($null -ne $info -and $null -ne $info.LastWriteTime) {
            $written = $info.LastWriteTime.ToUniversalTime().ToString(
                'yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        }
        return [PSCustomObject] @{ RecordCount = $count; FileSizeBytes = $size; LastWriteUtc = $written }
    }
    catch {
        return [PSCustomObject] @{ RecordCount = [int64] (-1); FileSizeBytes = [int64] 0; LastWriteUtc = '' }
    }
}

function Get-ChannelSizingHeadroom {
    <#
        Can the volume that will HOLD the enlarged log take it?

        docs/AUTHORING.md requires this check on the volume that will hold the data,
        which is not necessarily the one being protected - and the only DriveInfo
        read elsewhere in this script looks at the toolkit root, a different
        volume. Raising the cap to 2 GiB by default and never asking is how a
        logging improvement fills the system drive of a production host, which on
        a WEF collector is typically a domain controller. The header says this
        script does not move the .evtx off the system volume, so the system
        volume is exactly where the growth lands.

        Growth is the worst case, and it is the one that matters: the file may
        fill to its new maximum, so the space this run commits is the new cap
        minus what the file holds today. FileSizeBytes reads 0 when the runtime
        information cannot be read (a disabled channel, measured on the lab),
        which overstates the growth rather than understating it.

        Fails CLOSED. An unreadable log path or unreadable free space means the
        question was not answered, and this returns Allowed=$false for the same
        reason Initialize-ToolkitRoot refuses a directory it cannot enumerate:
        two neighbouring guards must not have opposite failure policies.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Channel,
        [Parameter(Mandatory = $true)] $ChannelState,
        [Parameter(Mandatory = $true)][int64] $TargetBytes,
        [Parameter(Mandatory = $true)][int] $MinimumFreePercent
    )

    # LogFilePath comes back UNEXPANDED - on the lab it reads
    # '%SystemRoot%\System32\Winevt\Logs\ForwardedEvents.evtx'
    # (lab/runs/20260825T121312Z-Enable-WefCollector/stdout.txt), and
    # GetPathRoot of that string yields nothing usable. Expand first.
    $logPath = ''
    if (-not [string]::IsNullOrWhiteSpace([string] $ChannelState.LogFilePath)) {
        $logPath = [System.Environment]::ExpandEnvironmentVariables([string] $ChannelState.LogFilePath)
    }
    $volumeRoot = ''
    if (-not [string]::IsNullOrWhiteSpace($logPath)) {
        try { $volumeRoot = [string] [System.IO.Path]::GetPathRoot($logPath) }
        catch { $volumeRoot = '' }
    }
    if ([string]::IsNullOrWhiteSpace($volumeRoot)) {
        return [PSCustomObject] @{
            Allowed = $false; VolumeRoot = ''
            Detail  = ('the channel log path ("' + [string] $ChannelState.LogFilePath + '") does not ' +
                       'resolve to a volume, so the free space where the log would grow is unknown')
        }
    }

    $free  = [int64] 0
    $total = [int64] 0
    try {
        $drive = New-Object System.IO.DriveInfo($volumeRoot)
        $free  = [int64] $drive.AvailableFreeSpace
        $total = [int64] $drive.TotalSize
    }
    catch {
        return [PSCustomObject] @{
            Allowed = $false; VolumeRoot = $volumeRoot
            Detail  = ('free space on ' + $volumeRoot + ' could not be read (' +
                       $_.Exception.Message + ')')
        }
    }

    $onDisk = [int64] (Get-ChannelRuntime -Channel $Channel).FileSizeBytes
    $growth = $TargetBytes - $onDisk
    if ($growth -lt 0) { $growth = [int64] 0 }
    $projectedFree = $free - $growth
    $floorBytes = [int64] ([math]::Floor(($total * $MinimumFreePercent) / 100))
    if ($projectedFree -lt $floorBytes) {
        return [PSCustomObject] @{
            Allowed = $false; VolumeRoot = $volumeRoot
            Detail  = ($volumeRoot + ' has ' + [string] $free + ' bytes free of ' + [string] $total +
                       ', the new cap commits up to ' + [string] $growth + ' more, and that would ' +
                       'leave ' + [string] $projectedFree + ' below the ' +
                       [string] $MinimumFreePercent + '% floor of ' + [string] $floorBytes + ' bytes')
        }
    }
    return [PSCustomObject] @{
        Allowed = $true; VolumeRoot = $volumeRoot
        Detail  = ($volumeRoot + ' has ' + [string] $free + ' bytes free; the new cap commits up to ' +
                   [string] $growth + ' more and stays above the ' + [string] $MinimumFreePercent +
                   '% floor of ' + [string] $floorBytes + ' bytes')
    }
}

function Set-ForwardedEventsChannel {
    <#
        Enables and sizes the channel. Takes the state read BEFORE
        'wecutil qc /q' ran, because qc is documented to enable the channel
        itself: the previous value recorded in the manifest has to be the one
        from before this run touched anything, not the one qc left behind.

        Returns the number of changes made.
    #>
    param(
        [Parameter(Mandatory = $true)] $PreRunState,
        [Parameter(Mandatory = $true)][int64] $TargetBytes,
        [switch] $RecordOnly
    )

    if (-not $PreRunState.Present) { return 0 }
    $needsEnable = (-not $PreRunState.Enabled)
    $needsSize   = ($PreRunState.MaxSizeBytes -lt $TargetBytes)
    if (-not $needsEnable -and -not $needsSize) { return 0 }

    if ($RecordOnly) {
        # RECORD THE SIZE THE RUN WILL ACTUALLY LEAVE, not the target.
        #
        # This function is reached when EITHER the enable or the resize is
        # needed, but the resize below is conditional on 'live < target' because
        # the script never shrinks a channel. So on a host that is DISABLED and
        # already sized ABOVE the target, the run enables the channel and leaves
        # the size alone - and a record claiming newMaxSizeBytes = target named
        # a size the host would never hold. Restore-EventChannel then read the
        # live size as "at or above newSize + 65536", concluded the host no
        # longer held what this run set, and returned a retryable 'declined':
        # the enable was never undone, the rollback record stayed 'failed', and
        # -Rollback could not converge without -AbandonRun.
        #
        # The maximum of the two is what wevtutil will be asked for, or left
        # holding, in every case: below the target the resize runs and the value
        # is the target; at or above it, nothing is written and the value is what
        # the channel already had.
        $recordedSize = [int64] $PreRunState.MaxSizeBytes
        if ($recordedSize -lt $TargetBytes) { $recordedSize = $TargetBytes }
        # Record before changing. This is called before wecutil qc /q, which may
        # perform the enable itself.
        [void] (Write-ManifestChange -Change @{
            type                 = 'eventchannel'
            channel              = $script:ForwardedEventsChannel
            previousEnabled      = [bool] $PreRunState.Enabled
            previousMaxSizeBytes = [int64] $PreRunState.MaxSizeBytes
            newEnabled           = $true
            newMaxSizeBytes      = $recordedSize
            description          = ($script:ForwardedEventsChannel + ': enabled and sized to ' +
                                    [string] $recordedSize + ' bytes')
        })
        return 0
    }

    $live = Get-ChannelConfiguration -Channel $script:ForwardedEventsChannel
    if (-not $live.Enabled) {
        $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @(
            'sl', $script:ForwardedEventsChannel, '/e:true')
        if ($result.ExitCode -ne 0) {
            throw ('wevtutil sl /e:true failed for ' + $script:ForwardedEventsChannel + ': ' +
                   ($result.Output -join ' '))
        }
    }
    if ($live.MaxSizeBytes -lt $TargetBytes) {
        # BYTES. See the region comment: the policy takes kilobytes, this does
        # not, and wevtutil rounds to a multiple of 64KB.
        $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @(
            'sl', $script:ForwardedEventsChannel, ('/ms:' + [string] $TargetBytes))
        if ($result.ExitCode -ne 0) {
            throw ('wevtutil sl /ms: failed for ' + $script:ForwardedEventsChannel + ': ' +
                   ($result.Output -join ' '))
        }
    }

    $confirm = Get-ChannelConfiguration -Channel $script:ForwardedEventsChannel
    if (-not $confirm.Enabled -or $confirm.MaxSizeBytes -lt $TargetBytes) {
        throw ($script:ForwardedEventsChannel + ' did not read back as enabled and at least ' +
               [string] $TargetBytes + ' bytes: it is enabled=' + [string] $confirm.Enabled +
               ', maxSize=' + [string] $confirm.MaxSizeBytes)
    }
    Write-Ok ($script:ForwardedEventsChannel + ' is enabled and sized to ' +
              [string] $confirm.MaxSizeBytes + ' bytes')
    return 1
}

function Restore-EventChannel {
    # Restores the channel only while it still holds what this run set: a
    # customer who has since grown the log keeps their size.
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change  = $ChangeRecord.change
    $channel = [string] $change.channel

    # The channel name is constrained by the SCRIPT, through $script:OwnedChannel,
    # never by the record - the same boundary Restore-TrackedChange defends with
    # $script:OwnedRegistryKey. The manifest is operator-writable input, and the
    # restore path below runs 'wevtutil sl <channel> /e:false' as SYSTEM: one
    # planted line would otherwise switch off any channel on this host, which is
    # the exact inverse of what this toolkit exists to do.
    $owned = $false
    foreach ($candidate in $script:OwnedChannel) {
        if ([string]::Equals([string] $candidate, $channel, [System.StringComparison]::OrdinalIgnoreCase)) {
            $owned = $true
            break
        }
    }
    if (-not $owned) {
        throw ('Refusing to roll back an eventchannel change for "' + $channel + '"; this script only ' +
               'owns ' + (($script:OwnedChannel | ForEach-Object { [string] $_ }) -join ', ') + '. A ' +
               'manifest record naming any other channel did not come from this script.')
    }

    $live = Get-ChannelConfiguration -Channel $channel
    if (-not $live.Present) {
        Write-Finding ('channel ' + $channel + ' could not be read; leaving it alone.')
        return 'declined'
    }
    $newSize = [int64] $change.newMaxSizeBytes
    $previousSize = [int64] $change.previousMaxSizeBytes

    # Three-way host resolution (docs/DESIGN.md section 4, A-2). Case 2 FIRST: the
    # host already holds the PRE-APPLY state, so there is nothing to undo -
    # either the write never landed (an EventLog policy value can override
    # 'wevtutil sl /ms:' so the size never sticks - verification/facts.json) or it
    # has already been restored. The doctrine counts both as RESTORED - nothing
    # to do and nothing wrong - which is what makes the run leave the eligible
    # set. NOT 'declined-permanent': that is case 4, for a change no rollback
    # can ever undo. Returning plain 'declined' was the A-2 defect: it left the
    # run retryable, so every future -Rollback re-selected it and it never
    # converged. Proven on the lab.
    # The same 64KB rounding tolerance is applied to the PREVIOUS size: wevtutil
    # rounded it on the way in too, so an exact compare would miss case 2.
    $atPreviousSize = ($previousSize -le 0) -or
                      ((([int64] $live.MaxSizeBytes) -ge $previousSize) -and
                       (([int64] $live.MaxSizeBytes) -lt ($previousSize + 65536)))
    if (([bool] $live.Enabled -eq [bool] $change.previousEnabled) -and $atPreviousSize) {
        Write-Ok ($channel + ' already holds its recorded previous state (enabled=' +
                    [string] $change.previousEnabled + ', maxSize=' + [string] $live.MaxSizeBytes +
                    ' bytes); nothing to undo.')
        return 'restored'
    }

    # Case 3: the host holds neither the applied value nor the previous one.
    # Rounding-tolerant, because wevtutil rounds /ms: to a multiple of 64KB:
    # "log files are always multiples of 64KB, so the value you enter will be
    # rounded off accordingly". An exact -ne compare would decline a legitimate
    # rollback whenever the OS rounded the requested size up.
    $sizeMoved = ([int64] $live.MaxSizeBytes -lt $newSize) -or
                 ([int64] $live.MaxSizeBytes -ge ($newSize + 65536))
    if ([bool] $live.Enabled -ne [bool] $change.newEnabled -or $sizeMoved) {
        Write-Finding ($channel + ' no longer holds what this run set (enabled=' +
                       [string] $live.Enabled + ', maxSize=' + [string] $live.MaxSizeBytes +
                       '); leaving it alone.')
        return 'declined'
    }

    # Case 1 fell through: the host holds what -Apply set - restore it.
    if ($previousSize -gt 0 -and $previousSize -ne [int64] $live.MaxSizeBytes) {
        $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @(
            'sl', $channel, ('/ms:' + [string] $previousSize))
        if ($result.ExitCode -ne 0) {
            throw ('wevtutil sl /ms: failed restoring ' + $channel + ': ' + ($result.Output -join ' '))
        }
    }
    if (-not [bool] $change.previousEnabled) {
        $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @('sl', $channel, '/e:false')
        if ($result.ExitCode -ne 0) {
            throw ('wevtutil sl /e:false failed restoring ' + $channel + ': ' + ($result.Output -join ' '))
        }
    }

    # Re-read and assert: a native command that exits 0 is not proof.
    $confirm = Get-ChannelConfiguration -Channel $channel
    if ([bool] $confirm.Enabled -ne [bool] $change.previousEnabled) {
        throw ($channel + ' enabled state did not read back as ' + [string] $change.previousEnabled)
    }
    if ($previousSize -gt 0 -and [int64] $confirm.MaxSizeBytes -ne $previousSize) {
        throw ($channel + ' maxSize did not read back as ' + [string] $previousSize + ' bytes; it is ' +
               [string] $confirm.MaxSizeBytes)
    }
    Write-Ok ('Restored ' + $channel + ' to enabled=' + [string] $change.previousEnabled + ', maxSize=' +
              [string] $previousSize + ' bytes')
    return 'restored'
}

#endregion

#region Subscriptions ---------------------------------------------------------

<#
    Commands, all from
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wecutil :
      wecutil es              - "Displays the names of all remote event
                                subscriptions that exist."
      wecutil gs <Subid>      - subscription configuration
      wecutil gr <Subid>      - "Displays the runtime status of a subscription."
      wecutil cs <Configfile> - "Creates a remote subscription."
      wecutil ds <Subid>      - "Deletes a subscription and unsubscribes from
                                all event sources..."
    All of them need the collector service: "If you receive the message, 'The
    RPC server is unavailable' when you try to run wecutil, you need to start
    the Windows Event Collector service (wecsvc)." So a non-zero exit from
    'wecutil es' means UNKNOWN, never "no subscriptions".

    The subscription XML is generated from the table below rather than embedded
    as a literal. Element names and the source-initiated shape are copied from
    Microsoft's sample:
    https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription
    including the default security descriptor for AllowedSourceDomainComputers,
    quoted verbatim from that page: "if AllowedSourceDomainComputers,
    AllowedSourceNonDomainComputers/IssuerCAList, AllowedSubjectList, and
    DeniedSubjectList are all empty, then 'O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)'
    will be used as the default security descriptor ... The default descriptor
    grants members of the Domain Computers domain group, as well as the local
    Network Service group (for the local forwarder), the ability to raise events
    for this subscription."

    <Expires> is deliberately OMITTED even though the sample carries it: the
    sample's value is a date in the past, and a subscription created with an
    expiry that has already passed collects nothing while looking configured.

    TransportName is http. In a domain that is not cleartext: "In a domain
    setting, the connection used to transmit WEF events is encrypted using
    Kerberos, by default", from
    https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection

    THE EVENT IDS. Every ID below is cited to Appendix E or F of that same
    article, which publishes Microsoft's own baseline WEF queries. IDs that
    Enable-IRVisibility's audit policy produces but which could NOT be cited
    there are deliberately absent, and named in the script header's list of
    things this does not do, rather than written from memory:
    # UNVERIFIED: 4740 (account lockout), 4719 (audit policy change), 5145
    # (detailed file share), 4663 and 6416 (removable storage), 4673 and 4674
    # (sensitive privilege use), and the MPSSVC rule-level policy change IDs.
    # Add them to the generated XML once their numbers are confirmed against a
    # Microsoft source or observed on a host.

    The channel set is deliberately narrow: there is no point collecting events
    the fleet does not generate. Security, System and the PowerShell operational
    channel are exactly what logging-hardening/Enable-IRVisibility.ps1 turns on.
#>

$script:SubscriptionMarker = 'IronBlackBox'

# Event IDs per <Select> element. Microsoft documents the ceiling as "more than
# 20 expressions" in one XPath expression; measured on Server 2019 build
# 17763.9121, the forwarding plugin takes 23 terms and refuses 24. 20 is the
# documented number, so 20 is what this uses - see New-SubscriptionXml.
$script:MaxSelectTerms = 20

# Reconciliation ledger (AT-11). The audit target set (Enable-IRVisibility) and
# this forwarding list are two independent standalone scripts with no shared
# module, so nothing enforces that everything the toolkit AUDITS is also
# FORWARDED. This ledger is the manual reconciliation, kept here so drift between
# the two lists is visible to a reviewer. Every Security-channel event id
# Enable-IRVisibility's subcategories can produce is either forwarded below or
# listed here with the reason it stays on the host:
#
#   4627 Group Membership     - one event per logon, so forwarding it roughly
#                               doubles logon volume fleet-wide; 4624 forwards and
#                               the token groups are on the host at triage time.
#   4656/4658/4663 Removable  - file-access, SACL-gated and high volume; 6416
#     Storage                   (device attach) forwards instead as the signal.
#   4673/4674 Sensitive Priv  - measured 5 562 in nine minutes vs 669 4688 in the
#     Use                       Atomic exercise, zero reconstruction value (AT-7).
#   4768/4769 Kerberos        - workload-dependent, very high on a DC; 4771
#                               (pre-auth failure) forwards at failure-only volume.
#   5145 Detailed File Share  - high volume at Success; 5140 (share access) forwards.
#   6145 Other Policy Change  - GPO-processing errors, operational noise.
#
# When a subcategory is added to Enable-IRVisibility, decide here whether its
# events forward, and record the reason either way.

$script:SubscriptionQueries = @(
    @{
        Channel = 'Security'
        <#
            Every ID below is named from Microsoft's own table, "Appendix L -
            Events to Monitor", not from memory:
            https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
            To check an ID against the host itself rather than a web page:
            wevtutil gp Microsoft-Windows-Security-Auditing /ge /gm:true

            4688/4689 process create and terminate; 4624/4625/4634/4647 logon,
            failure, logoff, user-initiated logoff; 4672 special privileges;
            4720/4722/4725/4726 account lifecycle; 4728/4732/4733/4756 group
            membership added; 4697 service installed; 5140/5142/5144 share
            access, create, delete; 4776 credential validation; 4648 explicit
            credentials; 4778/4779 RDP session reconnect and disconnect; 4616
            system time change; 1100/1102 event log service stopped and Security
            log cleared.

            Added 2026-08-27 after the Atomic Red Team exercise measured what
            this subscription was leaving on the host (defect AT-1):

            4698 A scheduled task was created - the single richest artifact the
                 exercise produced: measured 1 603 bytes of task XML in one
                 event, carrying the action, the trigger, the principal and the
                 run level, so the persistence stays reconstructable after the
                 task itself is deleted.
            4699 A scheduled task was deleted - the anti-forensic half of 4698.
            4702 A scheduled task was updated - Microsoft's own note on this
                 event says to alert when the updated Task Content XML contains
                 <LogonType>Password</LogonType>. Editing an existing task is
                 quieter than creating one.
            4719 System audit policy was changed - one of the few events
                 Microsoft rates "High" criticality, meaning one occurrence
                 should be investigated. anti-tampering/Deploy-TamperAlerts.ps1
                 treats it as a primary signal, and the exercise measured 13 of
                 them for a single auditpol tamper. It was not being forwarded.
            4724 An attempt was made to reset an account's password - observed in
                 the exercise alongside 4720; the pair distinguishes an account
                 creation from a password reset on an existing account.
            4738 A user account was changed - observed in the exercise.
            4729 A member was removed from a security-enabled global group, and
            4757 the same for a universal group. 4728 and 4756 (added) were
                 already here without their removals. Removal is not symmetry
                 for its own sake: add-self, act, remove-self is how the
                 privilege escalation gets cleaned up.
            4771 Kerberos pre-authentication failed - low volume by construction
                 (failures only) and high value: in the exercise this was the
                 ONLY event naming the account behind an otherwise anonymous
                 NTLM logon on the target.

            Deliberately NOT forwarded, with the reason, because a WEF
            subscription's cost is multiplied by every source and lands in one
            shared channel on the collector:

            4768/4769 Kerberos TGT and service ticket requests. Workload
                 dependent and very high volume on a domain controller. 4771
                 carries the investigative signal at failure-only volume.
            5145 Detailed file share. High volume wherever that subcategory runs
                 at Success. 5140 is already here.
            4673/4674 Privileged service called / privileged object operation.
                 Measured in the exercise: 5 562 events in nine minutes against
                 669 process creations, and not one of them contributed to any
                 of the eleven activity reconstructions.
            4657/4663 Registry value modified / object access attempted. Both
                 need SACLs this toolkit does not place broadly.
        #>
        Ids = @(4688, 4689, 4624, 4625, 4634, 4647, 4720, 4722, 4725, 4726,
                4728, 4729, 4732, 4733, 4756, 4757, 4697, 5142, 5144, 4776,
                4648, 4778, 4779, 4616, 1100, 1102,
                4698, 4699, 4702, 4719, 4724, 4738, 4771,
                # Added 2026-08-28 (AT-11). A reconciliation of every subcategory
                # Enable-IRVisibility turns on against what this subscription
                # carried found these enabled-but-never-forwarded. All are
                # discrete, incident-shaped, near-zero-baseline events; each ID
                # was confirmed on the host itself with its message text via
                # "wevtutil gp Microsoft-Windows-Security-Auditing /ge /gm:true",
                # not from memory.
                4740,              # A user account was locked out - password spraying
                4741, 4742,        # Computer account created / changed - rogue machine, RBCD (DC)
                4782,              # The password hash of an account was accessed - credential theft (DC)
                4704, 4705,        # A user right was assigned / removed - e.g. SeDebugPrivilege granted
                5025,              # The Windows Firewall service was stopped
                5038, 6410,        # Code integrity: image hash invalid / file failed to load - tampered binary
                4612,              # Audit message queue exhausted - the log is dropping events under flood
                6416,              # A new external device was recognized - USB attach, exfil/HID
                4886, 4887, 4888)  # AD CS certificate requested / issued / denied - ADCS abuse (CA only)
        # 4672 and 5140 are carried below in Filters, not here, because each
        # needs a per-event predicate. They MUST stay out of this plain list:
        # a filter belongs to a single <Select>, and if 4672 shared a <Select>
        # (or a query-scoped <Suppress>) with 4688, the S-1-5-18 exclusion would
        # also delete every process SYSTEM ever created. Measured on the lab:
        # that is 1 227 of 3 032 process-create events on the member (40%) and
        # 565 of 1 124 on the DC (50%) - the services and SYSTEM-run tasks that
        # matter most. So each filter gets its own <Select> for its own one ID.
        Filters = @(
            @{
                Id = 4672
                # 4672 fires whenever a logon is granted special privileges.
                # SYSTEM holds them at essentially every service operation, so
                # S-1-5-18 is pure noise here - measured 3 952 of 4 758 on the DC
                # (83%). The escalation signal is a NON-system SID suddenly
                # getting a privileged token, and that is exactly what survives
                # this filter. Microsoft's own baseline suppresses the same SID.
                Predicate = '*[EventData[Data[@Name="SubjectUserSid"] != "S-1-5-18"]]'
                Why = '4672 special privileges, excluding SYSTEM (S-1-5-18) which always holds them'
            },
            @{
                Id = 5140
                # IPC$ and NetLogon are accessed by every domain member on every
                # Group Policy refresh - measured 115 of 341 on the DC, and the
                # rest was SYSVOL, which is deliberately KEPT because writing a
                # malicious logon script there is a real signal. This predicate
                # is Microsoft's, verbatim.
                Predicate = '*[EventData[Data[@Name="ShareName"] != "\\*\IPC$"]] and *[EventData[Data[@Name="ShareName"] != "\\*\NetLogon"]]'
                Why = '5140 network share access, excluding the always-noisy IPC$ and NetLogon shares'
            }
        )
    },
    @{
        Channel = 'System'
        # 104 a log other than Security was cleared; 7000/7045 Service Control
        # Manager service start failure and new service; 12/13 Kernel-General
        # startup and shutdown; 1074 who asked for the restart.
        # 7009 added 2026-08-27: the Atomic exercise measured it firing beside
        # 7000 - "A timeout was reached (30000 milliseconds) while waiting for
        # the <name> service to connect" - which is what a service pointed at a
        # binary that is not a service host looks like.
        Ids = @(104, 7000, 7009, 7045, 12, 13, 1074)
    },
    @{
        Channel = 'Microsoft-Windows-PowerShell/Operational'
        # 4103 module logging, 4104 script block logging, 4105/4106 command
        # start and stop - the channel Enable-IRVisibility fills.
        Ids = @(4103, 4104, 4105, 4106)
    }
)

function New-SubscriptionXml {
    <#
        Builds the source-initiated subscription document. The query uses the
        '*[System[(EventID=N or EventID=M)]]' form from Microsoft's published
        baseline queries, and the whole QueryList sits in a CDATA section as in
        Microsoft's sample.

        Each channel's event IDs are emitted across SEVERAL <Select> elements,
        never one. Microsoft's own limit, verbatim: "If the XPath expression is a
        compound expression that contains more than 20 expressions or you are
        querying for events from multiple sources, then you must use a
        structured XML query."
        https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events

        Using a structured query does NOT lift that limit - it is what lets you
        stay under it, by spreading the terms over multiple selectors. This
        script put all 26 Security IDs in a single <Select> until 2026-08-27,
        and that is the whole of defect W-2. Measured on Server 2019 build
        17763.9121: 23 EventID terms in one <Select> is accepted, 24 is not.
        See the review log kept in the development repository for the measurement and the failure mode.
    #>
    param([Parameter(Mandatory = $true)][string] $Name)

    $queryLines = New-Object System.Collections.ArrayList
    [void] $queryLines.Add('<QueryList>')
    $queryId = 0
    foreach ($query in $script:SubscriptionQueries) {
        $path = [System.Security.SecurityElement]::Escape([string] $query.Channel)
        [void] $queryLines.Add('  <Query Id="' + [string] $queryId + '" Path="' + $path + '">')
        $ids = @($query.Ids)
        if ($ids.Count -eq 0) {
            # A <Query> with no <Select> is not a query that collects nothing -
            # it is a document wecutil may accept and a channel that silently
            # forwards nothing, which is the same failure class as W-2.
            throw ('The event query table lists channel "' + [string] $query.Channel +
                   '" with no event IDs.')
        }
        $start = 0
        while ($start -lt $ids.Count) {
            $take = $script:MaxSelectTerms
            if (($start + $take) -gt $ids.Count) { $take = $ids.Count - $start }
            $chunk = @($ids[$start..($start + $take - 1)])
            $terms = @($chunk | ForEach-Object { 'EventID=' + [string] $_ })
            [void] $queryLines.Add('    <Select Path="' + $path + '">*[System[(' +
                                   ($terms -join ' or ') + ')]]</Select>')
            # Advance by what was actually taken, not by the ceiling: the two are
            # equal except on the final partial chunk, and coupling them means a
            # later change to one has to remember the other.
            $start += $take
        }
        # Filtered event IDs: one <Select> each, with the per-event predicate
        # appended. Per-Select and never a query-scoped <Suppress>, so the filter
        # can only ever touch its own event ID - see the Filters comment in the
        # query table for why that distinction is not optional.
        foreach ($filter in @($query.Filters)) {
            if ($null -eq $filter) { continue }
            [void] $queryLines.Add('    <Select Path="' + $path + '">*[System[(EventID=' +
                                   [string] $filter.Id + ')]] and ' + [string] $filter.Predicate +
                                   '</Select>')
        }
        [void] $queryLines.Add('  </Query>')
        $queryId++
    }
    [void] $queryLines.Add('</QueryList>')

    # A ']]>' anywhere in the query would terminate the CDATA section early and
    # produce a document that is still well-formed but means something else.
    # Nothing in the table above can produce it; assert rather than assume,
    # because a later edit to the table could.
    $queryText = ($queryLines -join "`r`n")
    if ($queryText.Contains(']]>')) {
        throw 'The generated event query contains "]]>", which would break the CDATA section.'
    }

    # Guard against re-introducing W-2. Over the documented ceiling the source's
    # forwarding plugin drops the offending channel and keeps delivering the
    # others, so the subscription looks healthy on the collector while one
    # channel silently forwards nothing. A wrong number here is invisible
    # without reading the source's own Microsoft-Windows-Forwarding/Operational
    # log, which is why this asserts instead of trusting the chunk loop.
    foreach ($line in $queryLines) {
        if ($line -notmatch '<Select ') { continue }
        $termCount = ([regex]::Matches($line, 'EventID=')).Count
        if ($termCount -gt $script:MaxSelectTerms) {
            throw ('A generated <Select> holds ' + [string] $termCount +
                   ' EventID terms, over the ' + [string] $script:MaxSelectTerms +
                   '-term ceiling. That is defect W-2: the source drops the channel ' +
                   'and forwards the rest, so nothing on the collector reports a problem.')
        }
    }

    $readExisting = 'false'
    if ($ReadExistingEvents) { $readExisting = 'true' }
    $escapedName = [System.Security.SecurityElement]::Escape($Name)
    $description = [System.Security.SecurityElement]::Escape(
        $script:SubscriptionMarker + ' baseline forwarding subscription - do not rename this description, ' +
        '-Rollback uses it to prove the subscription is the one it created')

    $lines = @(
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">',
        ('  <SubscriptionId>' + $escapedName + '</SubscriptionId>'),
        '  <SubscriptionType>SourceInitiated</SubscriptionType>',
        ('  <Description>' + $description + '</Description>'),
        '  <Enabled>true</Enabled>',
        '  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>',
        '  <ConfigurationMode>Custom</ConfigurationMode>',
        '  <Delivery Mode="Push">',
        '    <Batching>',
        ('      <MaxItems>' + [string] $DeliveryMaxItems + '</MaxItems>'),
        ('      <MaxLatencyTime>' + [string] $DeliveryMaxLatencyMs + '</MaxLatencyTime>'),
        '    </Batching>',
        '    <PushSettings>',
        ('      <Heartbeat Interval="' + [string] $HeartbeatIntervalMs + '"/>'),
        '    </PushSettings>',
        '  </Delivery>',
        '  <Query><![CDATA[',
        $queryText,
        '  ]]></Query>',
        ('  <ReadExistingEvents>' + $readExisting + '</ReadExistingEvents>'),
        '  <TransportName>http</TransportName>',
        ('  <ContentFormat>' + $ContentFormat + '</ContentFormat>'),
        '  <Locale Language="en-US"/>',
        ('  <LogFile>' + $script:ForwardedEventsChannel + '</LogFile>'),
        '  <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>',
        '  <AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)</AllowedSourceDomainComputers>',
        '</Subscription>'
    )
    return (($lines -join "`r`n") + "`r`n")
}

function Get-SubscriptionNameList {
    # 'wecutil es'. Readable=$false means unknown - typically a stopped Wecsvc,
    # which the wecutil documentation calls out explicitly.
    $result = Invoke-NativeCommand -FilePath $script:WecutilPath -Arguments @('es')
    if ($result.ExitCode -ne 0) {
        return [PSCustomObject] @{
            Readable = $false; Names = @()
            Detail = ('wecutil es exited ' + [string] $result.ExitCode + ': ' +
                      (($result.Output | Select-Object -First 2) -join ' '))
        }
    }
    $names = @($result.Output | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
    return [PSCustomObject] @{ Readable = $true; Names = $names; Detail = '' }
}

function Test-SubscriptionMarker {
    # Does the live subscription carry this toolkit's marker in its description?
    # The whole 'never delete a subscription this script did not create' rule
    # rests on this: the manifest says which name was created, and this says the
    # thing under that name is still that subscription.
    # $null means "could not tell", which callers must not treat as yes.
    param([Parameter(Mandatory = $true)][string] $Name)

    $result = Invoke-NativeCommand -FilePath $script:WecutilPath -Arguments @('gs', $Name)
    if ($result.ExitCode -ne 0) { return $null }
    foreach ($line in $result.Output) {
        if ($line -like ('*' + $script:SubscriptionMarker + '*')) { return $true }
    }
    return $false
}

function Write-SubscriptionRuntimeStatus {
    <#
        'wecutil gr <name>' per subscription: the only local answer to "are
        events arriving from anybody", because it lists each source and its
        status. The output is printed VERBATIM rather than parsed - its labels
        are wecutil's own text and this project does not build a verdict on
        text it has not proven is stable. The machine-readable verdict comes
        from the ForwardedEvents record count instead.
    #>
    param([Parameter(Mandatory = $true)][string] $Name)

    $result = Invoke-NativeCommand -FilePath $script:WecutilPath -Arguments @('gr', $Name)
    if ($result.ExitCode -ne 0) {
        Write-Finding ('wecutil gr ' + $Name + ' exited ' + [string] $result.ExitCode +
                       ': runtime status unknown')
        return
    }
    $shown = 0
    foreach ($line in $result.Output) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($shown -ge 30) {
            Write-Info '    ... (runtime status truncated)'
            break
        }
        Write-Info ('    ' + $line.Trim())
        $shown++
    }
    # 'EventSources' is the label wecutil prints ONLY once a source has actually
    # connected. Measured on the lab: while W-1 was unfixed the whole output was
    #     Subscription: <name> / RunTimeStatus: Active / LastError: 0
    # - three non-blank lines, no EventSources section, and a subscription that
    # had never been reached by anything. The old threshold was '$shown -le 1',
    # so on that exact output the check could not fire: it reported a healthy
    # collector throughout the entire failure. RunTimeStatus Active and
    # LastError 0 describe the SUBSCRIPTION, not whether any source uses it.
    # UNVERIFIED: whether the 'EventSources' label is localised. If it is, this
    # over-reports; the language-independent signal is the SUBSCRIPTIONMANAGER
    # URL reservation, checked in Invoke-SubscriptionManagerEndpointCheck.
    $hasSources = $false
    foreach ($line in $result.Output) {
        if (([string] $line) -match '(?i)EventSources') { $hasSources = $true; break }
    }
    if (-not $hasSources) {
        Write-Finding ($Name + ': runtime status has no EventSources section, so NO source has ever ' +
                       'connected to this subscription. RunTimeStatus and LastError above describe the ' +
                       'subscription itself and stay green while nothing forwards at all.')
    }
}

function Invoke-SubscriptionCheck {
    <#
        Reports every subscription and its runtime status, then makes sure the
        one this script owns exists. Returns the number of changes made and
        sets $script:EventsObserved.
    #>
    param([Parameter(Mandatory = $true)][string] $ConfigDirectory)

    Write-Section ($script:ForwardedEventsChannel + ' contents (is anything arriving?)')
    $channel = Get-ChannelConfiguration -Channel $script:ForwardedEventsChannel
    if (-not $channel.Present) {
        Write-Finding ($script:ForwardedEventsChannel + ' could not be read: ' + $channel.Detail)
    }
    else {
        $runtime = Get-ChannelRuntime -Channel $script:ForwardedEventsChannel
        Write-Info ('enabled=' + [string] $channel.Enabled + ', maxSize=' +
                    [string] $channel.MaxSizeBytes + ' bytes, mode=' + $channel.LogMode)
        Write-Info ('file=' + $channel.LogFilePath + ', ' + [string] $runtime.FileSizeBytes + ' bytes on disk')
        if ($runtime.RecordCount -lt 0) { Write-Info 'record count could not be read' }
        else { Write-Info ([string] $runtime.RecordCount + ' event(s) collected, last write ' +
                           $runtime.LastWriteUtc) }
        $script:EventsObserved = ($runtime.RecordCount -gt 0)
        if ($runtime.RecordCount -eq 0) {
            Write-Finding ($script:ForwardedEventsChannel + ' is empty: nothing has ever been ' +
                           'collected on this host')
        }
        elseif ($runtime.RecordCount -lt 0) {
            # -1 is "could not be read", never "empty" - and it leaves
            # $script:EventsObserved false just as an empty channel does. The
            # finding used to be gated on '-eq 0' alone, so this path printed
            # "exit 1, not 0" in the Result section and then exited 0, and -Audit
            # could print "No findings: this host is collecting forwarded events"
            # having read no count at all. The header promises 1 whenever the run
            # cannot demonstrate that an event landed, so this has to count.
            # Not a host limit: enabling the channel is a lever, and a disabled
            # channel is what produced this on the lab
            # (lab/runs/20260825T121312Z-Enable-WefCollector/stdout.txt).
            Write-Finding ('the number of events in ' + $script:ForwardedEventsChannel + ' could not ' +
                           'be read, so this run cannot demonstrate that anything has been collected. ' +
                           'A disabled channel reads this way; check the capacity section above.')
        }
    }

    Write-Section 'Subscriptions'
    $subscriptions = Get-SubscriptionNameList
    if (-not $subscriptions.Readable) {
        Write-Finding ('subscriptions could not be listed: ' + $subscriptions.Detail)
        return 0
    }
    if ($subscriptions.Names.Count -eq 0) {
        Write-Info 'no subscriptions exist on this collector'
    }
    foreach ($name in $subscriptions.Names) {
        Write-Info ('subscription: ' + $name)
        Write-SubscriptionRuntimeStatus -Name $name
    }

    $exists = $false
    foreach ($name in $subscriptions.Names) {
        if ([string]::Equals($name, $SubscriptionName, [System.StringComparison]::OrdinalIgnoreCase)) {
            $exists = $true
            break
        }
    }

    $configPath = [System.IO.Path]::Combine($ConfigDirectory, ($SubscriptionName + '.xml'))
    if ($exists) {
        $ours = Test-SubscriptionMarker -Name $SubscriptionName
        if ($ours -eq $true) {
            Write-Ok ($SubscriptionName + ' already exists and carries this toolkit''s marker')
            return 0
        }
        if ($null -eq $ours) {
            Write-Finding ($SubscriptionName + ' exists but its configuration could not be read; ' +
                           'leaving it alone.')
            return 0
        }
        Write-Finding ($SubscriptionName + ' exists but was not created by this toolkit (no marker in ' +
                       'its description). Refusing to modify or replace it - choose another ' +
                       '-SubscriptionName.')
        return 0
    }

    if (-not $Apply) {
        Write-Finding ('would create source-initiated subscription "' + $SubscriptionName + '" from ' +
                       $configPath + ' covering ' + [string] $script:SubscriptionQueries.Count +
                       ' channel(s)')
        foreach ($query in $script:SubscriptionQueries) {
            $idCount = @($query.Ids).Count
            Write-Info ('  ' + [string] $query.Channel + ': ' + [string] $idCount + ' event ID(s)')
        }
        return 0
    }

    $xml = New-SubscriptionXml -Name $SubscriptionName

    # Record before creating, carrying the name and the marker: -Rollback needs
    # both to prove that what it is about to delete is what this run created.
    [void] (Write-ManifestChange -Change @{
        type             = 'wefsubscription'
        subscriptionId   = $SubscriptionName
        configPath       = $configPath
        marker           = $script:SubscriptionMarker
        createdByThisRun = $true
        description      = ('created source-initiated subscription ' + $SubscriptionName)
    })

    # UTF8Encoding($false): no BOM, because the document declares its own
    # encoding and wecutil parses the file rather than a PowerShell stream.
    [System.IO.File]::WriteAllText($configPath, $xml, (New-Object System.Text.UTF8Encoding($false)))

    $result = Invoke-NativeCommand -FilePath $script:WecutilPath -Arguments @('cs', $configPath)
    if ($result.ExitCode -ne 0) {
        throw ('wecutil cs failed with exit code ' + [string] $result.ExitCode + ': ' +
               ($result.Output -join ' '))
    }

    $after = Get-SubscriptionNameList
    $confirmed = $false
    if ($after.Readable) {
        foreach ($name in $after.Names) {
            if ([string]::Equals($name, $SubscriptionName, [System.StringComparison]::OrdinalIgnoreCase)) {
                $confirmed = $true
                break
            }
        }
    }
    if (-not $confirmed) {
        throw ('wecutil cs reported success but ' + $SubscriptionName + ' does not appear in wecutil es')
    }

    Write-Ok ('created subscription ' + $SubscriptionName + ' from ' + $configPath)
    Write-SubscriptionRuntimeStatus -Name $SubscriptionName
    return 1
}

function Remove-TrackedSubscription {
    # Deletes exactly what this run created, and only while the live
    # subscription still carries the marker. Anything else - a missing
    # subscription, an unreadable one, one that has lost the marker - is
    # declined, because deleting somebody else's subscription silently stops
    # their collection.
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $name   = [string] $change.subscriptionId
    if (-not $change.createdByThisRun) {
        Write-Finding ($name + ' was not created by this run; leaving it alone.')
        return 'declined'
    }

    $subscriptions = Get-SubscriptionNameList
    if (-not $subscriptions.Readable) {
        Write-Finding ('subscriptions could not be listed (' + $subscriptions.Detail +
                       '); leaving ' + $name + ' alone.')
        return 'declined'
    }
    $exists = $false
    foreach ($existing in $subscriptions.Names) {
        if ([string]::Equals($existing, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
            $exists = $true
            break
        }
    }
    if (-not $exists) {
        Write-Ok ('subscription ' + $name + ' is already absent')
        return 'restored'
    }

    $ours = Test-SubscriptionMarker -Name $name
    if ($ours -ne $true) {
        Write-Finding ($name + ' no longer carries this toolkit''s marker; refusing to delete it.')
        return 'declined'
    }

    $result = Invoke-NativeCommand -FilePath $script:WecutilPath -Arguments @('ds', $name)
    if ($result.ExitCode -ne 0) {
        throw ('wecutil ds failed for ' + $name + ' with exit code ' + [string] $result.ExitCode + ': ' +
               ($result.Output -join ' '))
    }

    $after = Get-SubscriptionNameList
    if ($after.Readable) {
        foreach ($existing in $after.Names) {
            if ([string]::Equals($existing, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw ('wecutil ds reported success but ' + $name + ' still appears in wecutil es')
            }
        }
    }
    Write-Ok ('Deleted subscription ' + $name)
    Write-Info 'events already collected into ForwardedEvents are not deleted, by design'
    return 'restored'
}

#endregion

#region Collector checks ------------------------------------------------------

function Invoke-HostCheck {
    <#
        Note the accumulation idiom, and copy it exactly. Never write
        '$changed = $changed -or (...)': -or short-circuits, so once $changed is
        $true every later call is NEVER MADE and the script silently stops
        applying settings after the first one that worked.

        The ordering is not cosmetic. The channel's pre-run state is captured
        FIRST and its manifest record is written BEFORE 'wecutil qc /q' runs,
        because qc is documented to enable that channel itself - so the previous
        value has to be recorded before anything, including qc, can change it.
    #>
    param([Parameter(Mandatory = $true)][string] $ConfigDirectory)

    $targetBytes = [int64] $ForwardedEventsSizeMb * [int64] 1048576
    $preRunChannel = Get-ChannelConfiguration -Channel $script:ForwardedEventsChannel

    # The disk gate is DECIDED here and REPORTED further down, in the capacity
    # section. It cannot wait: the manifest record is written before 'wecutil qc
    # /q' runs, and it has to carry the size this run will really leave.
    $effectiveBytes = $targetBytes
    $headroom = $null
    if ($preRunChannel.Present -and ([int64] $preRunChannel.MaxSizeBytes) -lt $targetBytes) {
        $headroom = Get-ChannelSizingHeadroom -Channel $script:ForwardedEventsChannel `
                        -ChannelState $preRunChannel -TargetBytes $targetBytes `
                        -MinimumFreePercent $MinimumFreeDiskPercent
        if (-not $headroom.Allowed) {
            # Clamp to the cap already in place, which means the resize is not
            # attempted and nothing is shrunk. The ENABLE still proceeds: raising
            # a ceiling is what consumes the volume, switching the channel on is
            # not, and a collector with the channel off records nothing at all.
            $effectiveBytes = [int64] $preRunChannel.MaxSizeBytes
        }
    }

    if ($Apply) {
        [void] (Set-ForwardedEventsChannel -PreRunState $preRunChannel `
                    -TargetBytes $effectiveBytes -RecordOnly)
    }

    $changeCount = 0
    $changeCount += Invoke-CollectorServiceCheck
    $changeCount += Invoke-SubscriptionManagerEndpointCheck

    Write-Section ($script:ForwardedEventsChannel + ' capacity')
    if ($null -ne $headroom) {
        if ($headroom.Allowed) {
            Write-Info ('disk headroom: ' + $headroom.Detail)
        }
        else {
            Write-Finding ('REFUSED raising ' + $script:ForwardedEventsChannel + ' to ' +
                           [string] $targetBytes + ' bytes: ' + $headroom.Detail +
                           '. Lower -ForwardedEventsSizeMb, add disk, or move the channel to a volume ' +
                           'that can hold it. The channel is still switched on if it was off.')
        }
    }
    if (-not $preRunChannel.Present) {
        Write-Finding ($script:ForwardedEventsChannel + ' does not exist on this host')
    }
    elseif ($preRunChannel.Enabled -and $preRunChannel.MaxSizeBytes -ge $targetBytes) {
        Write-Ok ($script:ForwardedEventsChannel + ' is enabled and at least ' + [string] $targetBytes +
                  ' bytes already')
    }
    elseif (-not $Apply) {
        # The size clause names $effectiveBytes, not the target: after a refusal
        # above, -Apply would enable the channel and leave the cap alone, and
        # this line has to say what -Apply would really do.
        $sizeClause = 'and maxSize=' + [string] $effectiveBytes + ' bytes (BYTES, not KB)'
        if ($effectiveBytes -le [int64] $preRunChannel.MaxSizeBytes) {
            $sizeClause = 'and leave maxSize at ' + [string] $preRunChannel.MaxSizeBytes + ' bytes'
        }
        Write-Finding ($script:ForwardedEventsChannel + ' is enabled=' + [string] $preRunChannel.Enabled +
                       ', maxSize=' + [string] $preRunChannel.MaxSizeBytes + ' bytes - would set ' +
                       'enabled=true ' + $sizeClause)
    }
    else {
        $changeCount += Set-ForwardedEventsChannel -PreRunState $preRunChannel -TargetBytes $effectiveBytes
    }

    $changeCount += Invoke-SubscriptionCheck -ConfigDirectory $ConfigDirectory
    return $changeCount
}

#endregion

#region Main -----------------------------------------------------------------

function Restore-WefCollectorChange {
    <#
        Routes a change record to the right restorer. The template's
        Restore-TrackedChange only knows the 'registry' type and declines
        anything else - correctly, since silently "succeeding" on a change type
        it cannot undo is how a run gets marked rolled back while the host stays
        modified. This script introduces three types and shares a fourth with
        Enable-WefClient, so it routes them here and delegates the rest.

        That delegation is the only reason this script carries the template's
        Registry region: it changes no registry value of its own, but a rollback
        must never meet a change type it silently mishandles, and re-deriving
        Restore-TrackedChange locally is how two scripts stop agreeing on what
        the manifest means (docs/DESIGN.md section 6).

        Returns 'restored' or 'declined'; throws on failure.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    switch ([string] $change.type) {
        'wefsubscription' { return (Remove-TrackedSubscription -ChangeRecord $ChangeRecord) }
        'eventchannel'    { return (Restore-EventChannel -ChangeRecord $ChangeRecord) }
        'servicestartup'  { return (Restore-ServiceStartup -ChangeRecord $ChangeRecord) }
        'winrmconfig'     { return (Restore-WinRmSnapshot -ChangeRecord $ChangeRecord) }
        default           { return (Restore-TrackedChange -ChangeRecord $ChangeRecord) }
    }
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
    Assert-ParameterPattern -Name 'SubscriptionName' -Value $SubscriptionName -Pattern '^[A-Za-z0-9._-]{1,64}$' `
        -Describe '1 to 64 characters made up of letters, digits, dot, underscore or hyphen'
    Assert-ParameterRange   -Name 'ForwardedEventsSizeMb' -Value $ForwardedEventsSizeMb -Minimum 64 -Maximum 16384
    Assert-ParameterRange   -Name 'MinimumFreeDiskPercent' -Value $MinimumFreeDiskPercent -Minimum 0 -Maximum 90
    Assert-ParameterRange   -Name 'DeliveryMaxItems' -Value $DeliveryMaxItems -Minimum 1 -Maximum 1000
    Assert-ParameterRange   -Name 'DeliveryMaxLatencyMs' -Value $DeliveryMaxLatencyMs -Minimum 1000 -Maximum 21600000
    Assert-ParameterRange   -Name 'HeartbeatIntervalMs' -Value $HeartbeatIntervalMs -Minimum 1000 -Maximum 21600000
    Assert-ParameterSet     -Name 'ContentFormat' -Value $ContentFormat -Allowed @('RenderedText', 'Events')

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')
    # The subscription XML lives under the toolkit root, in a subdirectory that
    # inherits the root's DACL (SYSTEM and Administrators only). -SubscriptionName
    # is operator input that becomes part of this path, which is why the
    # parameter is pattern-validated to letters, digits, dot, dash, underscore.
    $configDirectory = [System.IO.Path]::Combine($resolvedRoot, 'Wef')

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        # The reported path is the one -Apply would really use; the directory is
        # NOT created here, because -Audit writes nothing.
        [void] (Invoke-HostCheck -ConfigDirectory $configDirectory)
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
        Write-Ok 'No findings: this host is collecting forwarded events.'
        return 0
    }

    Enter-ToolkitLock -ToolkitRootPath $resolvedRoot
    try {
        $allowMissingStamp = ($mode -eq 'Rollback')
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -AllowMissingStamp:$allowMissingStamp)
        Assert-ManifestUsable

        if ($mode -eq 'Apply') {
            [void] (Start-ManifestRun -Mode 'Apply' -Parameters @{
                toolkitRoot           = $resolvedRoot
                subscriptionName      = $SubscriptionName
                forwardedEventsSizeMb = $ForwardedEventsSizeMb
                minimumFreeDiskPercent = $MinimumFreeDiskPercent
                deliveryMaxItems      = $DeliveryMaxItems
                deliveryMaxLatencyMs  = $DeliveryMaxLatencyMs
                heartbeatIntervalMs   = $HeartbeatIntervalMs
                contentFormat         = $ContentFormat
                readExistingEvents    = [bool] $ReadExistingEvents
            })

            if (-not (Test-Path -LiteralPath $configDirectory)) {
                [void] (New-Item -Path $configDirectory -ItemType Directory -Force)
            }

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
                $verified = Invoke-HostCheck -ConfigDirectory $configDirectory
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
            Write-Info 'A subscription is not a working subscription. Sources appear only after their own'
            Write-Info 'policy refresh, and only if a source is allowed by the subscription descriptor.'
            if (-not $script:EventsObserved) {
                Write-Info ('Nothing has arrived in ' + $script:ForwardedEventsChannel + ' yet, so this ' +
                            'run cannot demonstrate collection: exit 1, not 0.')
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
                $outcome = Restore-WefCollectorChange -ChangeRecord $target.Changes[$i]
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
