<#
.SYNOPSIS
    Enables and sizes the DNS Client query log channel, and optionally DNS Server
    debug logging on a domain controller.

.DESCRIPTION
    DNS is where an intrusion announces itself: the beacon domain, the exfil
    endpoint, the newly registered C2 name. Windows ships the client-side channel
    that records it - Microsoft-Windows-DNS-Client/Operational - turned off, so
    on a default host the lookups that mattered were never written down.

    This script turns that channel on, sizes it so it holds more than an
    afternoon, and records the previous state so -Rollback can put it back. On a
    host that also runs the DNS Server role it can additionally enable DNS
    server debug logging, but only when explicitly asked - see below.

    THE UNIT TRAP, stated once and loudly.
      `wevtutil sl <channel> /ms:<MaxSize>` takes BYTES. Microsoft: "Sets the
      maximum size of the log in bytes. The minimum log size is 1048576 bytes
      (1024KB) and log files are always multiples of 64KB, so the value you enter
      will be rounded off accordingly."
      The EventLog *policy* value MaxSize under
      HKLM\Software\Policies\Microsoft\Windows\EventLog\<Channel> takes
      KILOBYTES - measured on the lab and recorded in verification/facts.json as
      fact eventlog-maxsize ("a policy value of 1048576 produced a channel
      maxSize of 1073741824 bytes"). Enable-IRVisibility writes kilobytes there;
      this script writes bytes here. Getting the two the wrong way round asks for
      a channel 1024x too small or 1024x too big, and in the small direction the
      channel silently wraps before anyone reads it.

    SIZE POLICY: -Apply never shrinks a channel. -ChannelSizeBytes is a FLOOR.
    A channel already larger is left alone: shrinking an event log discards the
    events that no longer fit, and "at least this big" is also what keeps -Apply
    idempotent when wevtutil rounds a value up to a 64KB multiple.

    DISK POLICY: the enlargement is gated on free space on the volume that will
    hold the channel - the path `wevtutil gl` reports, not an assumed C: - and
    the gate runs BEFORE the write. If the growth would take the volume below a
    10% floor it is refused as a finding and the channel is still ENABLED at the
    size it already has, which costs no new disk. Not recording DNS lookups at
    all is the wrong way to protect a volume from a cap this script chose.

    THE DC PATH IS OPT-IN.
      The DNS-server half does nothing at all unless -IncludeDnsServerDebugLog is
      passed. docs/VALIDATION.md is the only file allowed to say where this
      script has run, and it carries a separate line for the server half. The
      switch is deliberate rather than automatic for two reasons:
        - Volume. Microsoft: "Debug logging can be resource intensive, affecting
          overall server performance, and consuming disk space. Therefore, it
          should only be used temporarily." On a busy DC, Dns.log grows fast; the
          size cap here exists so that "fills the system volume" is not a
          possible outcome, but it is still not something to switch on across a
          fleet without deciding to.
        - Blast radius. A DNS server's debug log is a per-role decision an
          operator makes for a named host, not a fleet default. Switching it on
          across every domain controller because a hardening script offered to
          is how a toolkit loses the right to be run unattended.
      The DC path also refuses to change a setting whose PREVIOUS value it could
      not read, because a change with no recorded previous value is an
      unrecoverable change on a client's domain controller.

    What this script deliberately does NOT do:
      - It does not shrink a channel or a debug log, even when asked.
      - It does not clear DNS server debug-logging bits. -DnsServerLogLevel is
        OR'd into the server's current mask, so a bit an administrator turned on
        is never turned off here.
      - It does not set the DNS server log file PATH. The default is
        %windir%\system32\dns\Dns.log and it is left there on purpose: the lab
        already proved (verification/facts.json, fact firewall-logging) that
        pointing a Windows service's log at a toolkit directory ACLed to SYSTEM
        and Administrators produces no log at all, silently. Moving Dns.log to
        somewhere the DNS service may not be able to write would repeat that
        defect on a domain controller.
      - It does not enable the DNS Server Analytical channel. That is a second,
        different mechanism with its own performance profile and its own rollback
        story; it belongs in its own increment.
      - It does not enable per-IP debug filtering (dnscmd /logipfilterlist).
      - It does not touch the EventLog *policy* keys. Channel sizing through
        policy is Enable-IRVisibility's job, and the lab proved the policy
        OVERRIDES the local channel configuration this script writes
        (verification/facts.json, fact eventlog-policy-overrides-local-config) -
        so if a policy ever names this channel, the value set here will not stick
        and the audit will report the drift rather than fighting it.

    What needs a reboot:
      NOTHING for the client channel: `wevtutil sl` changes the channel's local
      configuration and the script proves the result by re-reading it with
      `wevtutil gl`. The DNS server settings are applied through dnscmd, which
      Microsoft documents as configuring the running server - # UNVERIFIED: not
      demonstrated here, and the script re-reads them rather than assuming.

.PARAMETER Audit
    Default. Strictly read-only. Reports the channel's enabled state and size,
    the DNS Server role, and the exact wevtutil and dnscmd command lines -Apply
    would run. Writes nothing anywhere.

.PARAMETER Apply
    Enables and sizes the channel, recording the previous state to the manifest
    first.

.PARAMETER Rollback
    Restores the recorded previous enabled state and maximum size.

.PARAMETER ToolkitRoot
    Base directory for the manifest. Default C:\ProgramData\IronBlackBox.
    Validated before use.

.PARAMETER ChannelSizeBytes
    Channel maximum size floor, in BYTES. Default 67108864 (64 MiB) - a multiple
    of 64KB, so wevtutil's documented rounding is a no-op. DNS client events are
    small and frequent; a channel at the documented 1 MiB minimum holds minutes
    of a busy host.

    A value that is NOT a multiple of 64KB is rounded UP to one before it is
    written or recorded. That is not cosmetic: wevtutil rounds the value itself,
    and a manifest that recorded the un-rounded request would describe a size
    the host does not hold, which makes every later -Rollback of that run
    decline as retryable and blocks -Rollback from reaching an older run.

    Subject to the DISK POLICY above: an enlargement that would take the
    channel's volume below a 10% free-space floor is refused, and the channel is
    enabled at its existing size instead.

.PARAMETER IncludeDnsServerDebugLog
    Also configure DNS Server debug logging, if and only if the DNS Server role
    is present. Read THE DC PATH IS UNVERIFIED above first.

.PARAMETER DnsServerLogLevel
    dnscmd /config /loglevel bitmask. Default 62224 (0xF310) = 0x10 queries and
    notifications, 0x100 question transactions, 0x200 answers, 0x1000 send
    packets, 0x2000 receive packets, 0x4000 UDP, 0x8000 TCP - every bit cited
    below at $script:DnsLogLevelBits. Deliberately excludes 0x1000000 (full
    packets) and 0xFFFF (all packets), which multiply the volume for data a
    responder rarely needs.

    ADDED to the mask the server already holds, never written over it. The bits
    an administrator deliberately enabled on their DNS server stay enabled: this
    is a bitmask, and writing a target value over it would switch some of them
    off. -Rollback still restores the exact previous mask.

.PARAMETER DnsServerLogMaxSizeBytes
    dnscmd /config /logfilemaxsize, in BYTES. Default 268435456 (256 MiB).
    Microsoft's own default is 0x400000 (4 MiB), which wraps almost immediately
    on a real DC; the cap here is the compromise between usable history and not
    filling a system volume.

.PARAMETER RunId
    -Rollback only. The run to roll back. Defaults to the most recent
    rollback-eligible run for this script. Cannot be combined with -AbandonRun,
    which names its own run.
.PARAMETER AbandonRun
    -Rollback only, and it names a run id rather than being a switch. Stops
    trying to roll back that run, on the record. Cannot be combined with -RunId.

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
    .\Enable-DnsVisibility.ps1
    Reports whether DNS client queries are being logged, and what -Apply would set.

.EXAMPLE
    .\Enable-DnsVisibility.ps1 -Apply
    Enables and sizes the DNS Client channel, recording the previous state.

.EXAMPLE
    .\Enable-DnsVisibility.ps1 -Apply -IncludeDnsServerDebugLog
    Same, plus DNS server debug logging if the role is present. UNVERIFIED path.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.1.0
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

    # Lower bound is wevtutil's own documented minimum of 1048576 BYTES.
    [Parameter()]
    [long] $ChannelSizeBytes = 67108864,

    [Parameter()]
    [switch] $IncludeDnsServerDebugLog,

    # dnscmd documents the loglevel bits up to 0x80000000; 0 means no log.
    [Parameter()]
    [long] $DnsServerLogLevel = 62224,

    # dnscmd documents /logfilemaxsize as 0x10000-0xFFFFFFFF bytes.
    [Parameter()]
    [long] $DnsServerLogMaxSizeBytes = 268435456,

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

$script:ScriptName    = 'Enable-DnsVisibility'
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

#region Event channel ---------------------------------------------------------

<#
    wevtutil, from
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil

      wevtutil {gl | get-log} <Logname> [/f:<Format>]
        "Displays configuration information for the specified log, which includes
         whether the log is enabled or not, the current maximum size limit of the
         log, and the path to the file where the log is stored."
      wevtutil {sl | set-log} <Logname> [/e:<Enabled>] [/ms:<MaxSize>] ...
      /e:<Enabled> "Enables or disables a log. <Enabled> can be true or false."
      /ms:<MaxSize> "Sets the maximum size of the log in BYTES. The minimum log
         size is 1048576 bytes (1024KB) and log files are always multiples of
         64KB, so the value you enter will be rounded off accordingly."

    State is read through /f:xml rather than by scraping the text output, because
    the XML shape IS documented: "The configuration file is an XML file with the
    same format as the output of wevtutil gl <Logname> /f:xml", and the worked
    example on that page shows <channel name=... enabled=...><logging>
    <retention/><autoBackup/><maxSize/></logging></channel>. Element and
    attribute names are not localised; the text-mode labels would be.
#>

# The channel name, and the fact that `wevtutil sl` is how it is turned on, are
# cited to Microsoft's own troubleshooting instruction: "To enable the DNS Client
# log provider, run `wevtutil sl Microsoft-Windows-DNS-Client/Operational
# /enabled:true`."
# https://learn.microsoft.com/en-us/entra/global-secure-access/troubleshoot-app-access
$script:DnsClientChannel = 'Microsoft-Windows-DNS-Client/Operational'

# "Disabled by default" is NOT asserted from memory anywhere in this script: the
# state is read from the host every run, and the claim in the header is only that
# Microsoft's own guidance is to enable it before troubleshooting and disable it
# afterwards. What the script reports is what wevtutil said.

# A channel smaller than this is reported as too small to be useful. This is a
# toolkit judgement, not a Windows limit: DNS client events are small and
# frequent, and 16 MiB is roughly where a busy host stops holding a full day.
$script:MinimumUsefulChannelSize = 16777216

function Format-Mib {
    param([Parameter()] $Bytes)
    if ($null -eq $Bytes) { return 'unknown' }
    return (([double] $Bytes / 1048576.0).ToString('N1', [System.Globalization.CultureInfo]::InvariantCulture) +
            ' MiB (' + ([long] $Bytes).ToString([System.Globalization.CultureInfo]::InvariantCulture) + ' bytes)')
}

function Get-EventChannelState {
    <#
        Reads a channel's configuration with `wevtutil gl <channel> /f:xml`.

        Present = $false covers both "no such channel on this SKU" and "wevtutil
        could not read it"; the exit code and raw output are carried so the
        caller can say which. Readable = $false means the XML came back but the
        two fields this script needs were not in it, which is treated as UNKNOWN
        and blocks any write.
    #>
    param([Parameter(Mandatory = $true)][string] $Channel)

    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @('gl', $Channel, '/f:xml')
    $state = [PSCustomObject] @{
        Channel   = $Channel
        Present   = $false
        Readable  = $false
        Enabled   = $null
        MaxSize   = $null
        LogPath   = $null
        ExitCode  = $result.ExitCode
        Raw       = ($result.Output -join ' / ')
    }
    if ($result.ExitCode -ne 0) { return $state }
    $state.Present = $true

    $document = $null
    try { $document = [xml] ($result.Output -join "`n") }
    catch {
        # Not a failure of the host - a failure of this parser's assumption. Say
        # so rather than reporting the channel as disabled.
        Write-Verbose ('wevtutil gl /f:xml output did not parse as XML: ' + $_.Exception.Message)
        return $state
    }
    if ($null -eq $document -or $null -eq $document.channel) { return $state }

    $enabledText = [string] $document.channel.enabled
    if ($enabledText -match '^(?i:true|false)$') { $state.Enabled = ($enabledText -match '^(?i:true)$') }
    $state.MaxSize = ConvertFrom-NativeInteger -Text ([string] $document.channel.logging.maxSize)
    $state.LogPath = [string] $document.channel.logging.logFileName
    if ($null -ne $state.Enabled -and $null -ne $state.MaxSize) { $state.Readable = $true }
    return $state
}

# wevtutil's own documented granularity: "log files are always multiples of
# 64KB, so the value you enter will be rounded off accordingly" (see THE UNIT
# TRAP in the header). A requested floor is rounded UP to this before it is
# written OR recorded - see Get-RoundedChannelSize for why recording the
# un-rounded value is a rollback defect rather than a cosmetic one.
$script:ChannelSizeBlock = 65536

function Get-RoundedChannelSize {
    <#
        Rounds a requested channel size UP to wevtutil's 64KB granularity.

        This is not cosmetic. The manifest has to record the size the HOST will
        hold, because -Rollback resolves the change against the host: recording
        an un-rounded 20000000 while the channel holds 20054016 makes case 3 of
        the doctrine fire on every -Rollback, decline as RETRYABLE, and keep the
        run eligible forever - which blocks -Rollback from ever reaching an older
        run. That is the R-1 class this file spends sixty lines explaining,
        reachable from a documented parameter with no warning.

        UP rather than nearest, so -ChannelSizeBytes stays a floor: rounding down
        would size the channel below what the operator asked for. Any exact
        multiple is returned unchanged, so the 64 MiB default is a no-op and
        -Apply stays idempotent.
    #>
    param([Parameter(Mandatory = $true)][long] $Bytes)

    $remainder = $Bytes % $script:ChannelSizeBlock
    if ($remainder -eq 0) { return $Bytes }
    return ($Bytes + ($script:ChannelSizeBlock - $remainder))
}

function Get-VolumeHeadroom {
    <#
        Free space, capacity and this toolkit's 10% floor for the volume that
        will hold a given file.

        THE VOLUME MATTERS, which is why this takes a path instead of assuming
        $env:SystemDrive. A channel's log file lives wherever `wevtutil gl`
        reports logFileName, which this script already reads into $state.LogPath;
        that is not required to be the system volume, and checking the wrong
        volume is a free-space guard that guards nothing.

        -Path may be unexpanded - wevtutil reports logFileName with %SystemRoot%
        in it - so it is expanded before the root is taken. Readable = $false
        means DriveInfo refused; every caller treats that as "do not grow the
        file", never as permission to guess.

        Same source as Protect-EventLogs' headroom check and
        Enable-VssPreservation's Get-VolumeCapacity: System.IO.DriveInfo, no CIM
        session and no localised property.
    #>
    param([Parameter()][AllowEmptyString()][string] $Path)

    $root = ''
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $expanded = [System.Environment]::ExpandEnvironmentVariables($Path)
        $root = [string] [System.IO.Path]::GetPathRoot($expanded)
    }
    $derived = $true
    if ([string]::IsNullOrWhiteSpace($root)) {
        # Nothing to derive from, so say which volume was measured instead of
        # silently measuring the wrong one. The volume holding %SystemRoot% is
        # the same fallback Enable-VssPreservation's Resolve-VolumeRoot uses.
        $derived = $false
        $root = [string] [System.IO.Path]::GetPathRoot($env:SystemRoot)
    }
    if ([string]::IsNullOrWhiteSpace($root)) { $root = 'C:\' }

    $headroom = [PSCustomObject] @{
        Root       = $root
        Derived    = $derived
        Readable   = $false
        FreeBytes  = 0
        TotalBytes = 0
        FloorBytes = 0
        Error      = ''
    }
    try {
        $drive = New-Object System.IO.DriveInfo($root)
        $headroom.FreeBytes  = [long] $drive.AvailableFreeSpace
        $headroom.TotalBytes = [long] $drive.TotalSize
        $headroom.FloorBytes = [long] ([math]::Floor([double] $headroom.TotalBytes * 0.10))
        $headroom.Readable   = $true
    }
    catch {
        $headroom.Error = $_.Exception.Message
    }
    return $headroom
}

function Set-TrackedEventChannel {
    <#
        The one entry point that changes a channel. Records the previous enabled
        state and maximum size to the manifest first, then writes, then re-reads
        with `wevtutil gl` to confirm. Returns $true when it changed something -
        and only when the read-back CONFIRMED it; see the read-back below.

        -ChannelSizeBytes is a FLOOR: a channel already larger keeps its size, so
        a second -Apply reports no change, and no events are ever discarded by
        shrinking. The floor is rounded to wevtutil's 64KB granularity here
        rather than left for wevtutil to round, so the size written, the size
        recorded and the size the host holds are the same number.

        The enlargement is gated on free space on the CHANNEL'S OWN volume, and
        gated BEFORE the write rather than after it. When it does not fit, the
        channel is still ENABLED - at the size it already has, which costs no new
        disk - because refusing to record DNS lookups at all is the wrong way to
        protect a volume from a cap this script chose.
    #>
    param(
        [Parameter(Mandatory = $true)] $State,
        [Parameter(Mandatory = $true)][long] $TargetMaxSize
    )

    $channel = $State.Channel
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture

    if (-not $State.Present) {
        Write-Finding ('the ' + $channel + ' channel is not present on this host: nothing here can' +
                       ' record DNS client queries, which is unexpected on a supported Windows SKU')
        Write-Info ('wevtutil gl exited ' + [string] $State.ExitCode + ': ' + $State.Raw)
        return $false
    }
    if (-not $State.Readable) {
        Write-Finding ($channel + ' configuration could not be parsed, so it is left alone rather than' +
                       ' written blind with no recoverable previous value')
        Write-Info ('wevtutil said: ' + $State.Raw)
        return $false
    }

    # Rounded BEFORE the max() and before anything is recorded, so the manifest
    # holds the value the host will hold. The current size is deliberately NOT
    # rounded: it is whatever the host already reports, and rounding it up would
    # turn a no-op re-run into a write every time.
    $newMaxSize = Get-RoundedChannelSize -Bytes $TargetMaxSize
    if ([long] $State.MaxSize -gt $newMaxSize) { $newMaxSize = [long] $State.MaxSize }

    # FREE SPACE, before the write. -ChannelSizeBytes accepts up to 4 GiB and
    # this is the only change on the default (non-DC) path, so without this the
    # one change the script always makes was the one change nothing gated.
    # Measured against the channel's own volume: $State.LogPath is what wevtutil
    # reported, and the system volume is only a fallback.
    if ($newMaxSize -gt [long] $State.MaxSize) {
        $growth = $newMaxSize - [long] $State.MaxSize
        $headroom = Get-VolumeHeadroom -Path $State.LogPath
        $fits = $false
        if ($headroom.Readable) {
            $fits = (($headroom.FreeBytes - $growth) -ge $headroom.FloorBytes)
        }
        # Named so the console says WHICH volume was measured. A guard that
        # reports a number without saying where it came from is unfalsifiable.
        $where = [string] $headroom.Root
        if (-not $headroom.Derived) {
            $where = $where + ' (system volume; wevtutil reported no log file path)'
        }
        if (-not $fits) {
            if (-not $headroom.Readable) {
                Write-Finding ($channel + ' is NOT being enlarged: free space on ' + $where +
                               ' could not be read (' + $headroom.Error + '), and growing an event log' +
                               ' blind is how a hardening script fills a volume')
            }
            else {
                Write-Finding ('REFUSING to enlarge ' + $channel + ' to ' + (Format-Mib -Bytes $newMaxSize) +
                               ': the ' + (Format-Mib -Bytes $growth) + ' of growth against ' +
                               (Format-Mib -Bytes $headroom.FreeBytes) + ' free on ' + $where +
                               ' would leave less than the 10% floor of ' +
                               (Format-Mib -Bytes $headroom.FloorBytes) +
                               '. Lower -ChannelSizeBytes or free space first.')
            }
            # Clamped, not aborted. The channel is still turned on below at the
            # size it already has, which needs no new disk.
            $newMaxSize = [long] $State.MaxSize
        }
        else {
            Write-Ok ('free space: ' + (Format-Mib -Bytes $headroom.FreeBytes) + ' on ' + $where +
                      ', growth ' + (Format-Mib -Bytes $growth) + ', 10% floor ' +
                      (Format-Mib -Bytes $headroom.FloorBytes))
        }
    }

    if ($State.Enabled -and $newMaxSize -eq [long] $State.MaxSize) {
        Write-Ok ($channel + ' already enabled at ' + (Format-Mib -Bytes $State.MaxSize))
        return $false
    }

    $reasons = New-Object System.Collections.ArrayList
    if (-not $State.Enabled) {
        # AT-5: narrowed. This channel records lookups that go THROUGH the Windows
        # DNS Client service. Measured in the Atomic exercise: nslookup.exe (and dig,
        # and malware with its own resolver) builds and sends its own queries and
        # never touches the service, so 255 nslookups produced one relevant record
        # here - the command line in 4688 is what caught the sweep. So this is not
        # 'no DNS lookups are recorded', only the service-mediated ones.
        [void] $reasons.Add('is DISABLED, so service-mediated DNS lookups from this host are not recorded (tools with their own resolver - nslookup, dig - never appear here regardless; 4688 command lines catch those)')
    }
    if ([long] $State.MaxSize -lt $script:MinimumUsefulChannelSize) {
        [void] $reasons.Add('is only ' + (Format-Mib -Bytes $State.MaxSize) +
                            ', too small to hold a useful window of query history')
    }
    if ($reasons.Count -eq 0) {
        [void] $reasons.Add('is smaller than the ' + (Format-Mib -Bytes $newMaxSize) + ' floor')
    }
    $reason = ($reasons.ToArray() -join '; and ')

    # /ms: is BYTES. See THE UNIT TRAP in the header - the EventLog policy value
    # of the same name is kilobytes, and this repo writes both.
    #
    # /ms: is omitted when the size is not changing - the free-space guard above
    # clamped it, or the channel is merely being enabled. `wevtutil sl /e:true`
    # alone leaves the size untouched, which keeps the recorded newMaxSizeBytes
    # equal to what the host holds even if the host's current size is not a 64KB
    # multiple this script could reproduce.
    $arguments = @('sl', $channel, '/e:true')
    if ($newMaxSize -ne [long] $State.MaxSize) {
        $arguments += ('/ms:' + $newMaxSize.ToString($invariant))
    }

    # The reason is a FINDING only in -Audit and information in -Apply. Emitting
    # it in both would leave every successful -Apply with a non-zero finding
    # count, so a fixed host would report exit 1 - "findings remain" - to an RMM.
    # Set-TrackedRegistryValue in the template splits it the same way.
    if (-not $Apply) {
        Write-Finding ($channel + ' ' + $reason + '; would run: wevtutil.exe ' + ($arguments -join ' '))
        return $false
    }
    Write-Info ($channel + ' ' + $reason)

    # Record before changing. Not after. Sizes are INVARIANT DECIMAL STRINGS, not
    # JSON numbers: PS 5.1 deserializes a JSON integer as Int32 where PS 7 uses
    # Int64, the trap docs/DESIGN.md section 4 records for REG_QWORD, and a
    # channel size can legitimately exceed Int32.
    [void] (Write-ManifestChange -Change @{
        type            = 'eventchannel'
        channel         = $channel
        previousEnabled = [bool] $State.Enabled
        previousMaxSizeBytes = ([long] $State.MaxSize).ToString($invariant)
        newEnabled      = $true
        newMaxSizeBytes      = $newMaxSize.ToString($invariant)
        description     = ($channel + ' enabled at ' + $newMaxSize.ToString($invariant) + ' bytes')
    })

    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments $arguments
    if ($result.ExitCode -ne 0) {
        Write-Failure ('wevtutil sl ' + $channel + ' exited ' + [string] $result.ExitCode)
        throw ('wevtutil sl failed for ' + $channel + ': ' + ($result.Output -join ' '))
    }

    # Confirm by re-reading. A confirmation that cannot be made is a FINDING
    # (exit 1), not an execution error (exit 2): the write was accepted, so the
    # change is real and recorded, and what is missing is the proof.
    # A read-back that did not confirm returns $false, and that is the whole
    # point of the return value. Invoke-Main documents $verified as the VERIFIED
    # count and compares it against $script:ChangeIndex to report records that
    # never landed; returning $true here regardless made that comparison
    # structurally unable to fire, so -Apply printed "1 change(s) applied" two
    # lines under its own finding saying the channel reads back as something
    # else - defect U-3 rebuilt inside the function the comment names it in.
    #
    # The manifest record STAYS: -Rollback resolves each change against the
    # host, and case 2 of the doctrine already means "recorded but never landed
    # needs nothing undone".
    $after = Get-EventChannelState -Channel $channel
    if (-not $after.Readable) {
        Write-Finding ($channel + ' was set but its configuration could not be read back')
        return $false
    }
    if (-not $after.Enabled -or [long] $after.MaxSize -lt $newMaxSize) {
        Write-Finding ($channel + ' reads back as enabled=' + [string] $after.Enabled + ', size ' +
                       (Format-Mib -Bytes $after.MaxSize) + ' - not what was requested. If an EventLog' +
                       ' policy names this channel it overrides local configuration; see' +
                       ' verification/facts.json, fact eventlog-policy-overrides-local-config')
        return $false
    }
    Write-Ok ($channel + ' enabled at ' + (Format-Mib -Bytes $after.MaxSize))
    return $true
}

function Restore-EventChannelChange {
    # Rolls back one 'eventchannel' record, restoring BOTH the enabled state and
    # the maximum size in a single wevtutil sl call. Returns 'restored' or
    # 'declined'; throws on a failed write.
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $channel = [string] $change.channel
    # The manifest is operator-writable input: a planted record must not turn
    # -Rollback into "reconfigure any channel on this host".
    if ($channel -ne $script:DnsClientChannel) {
        throw ('Refusing to roll back an eventchannel change for ' + $channel +
               '; this script only owns ' + $script:DnsClientChannel)
    }

    # BILINGUAL BY NECESSITY. The manifest is append-only, so a record written
    # before the field names were aligned keeps its original spelling. Renaming
    # the writer above does not rename what is already on disk.
    $recordedPrevious = [string] $change.previousMaxSizeBytes
    if ([string]::IsNullOrWhiteSpace($recordedPrevious)) { $recordedPrevious = [string] $change.previousMaxSize }
    $previousMaxSize = ConvertFrom-NativeInteger -Text $recordedPrevious
    if ($null -eq $previousMaxSize) {
        Write-Finding ($channel + ': the recorded previous maximum size is missing or unreadable, so' +
                       ' there is nothing to restore it to; declining rather than guessing')
        return 'declined'
    }
    $previousEnabled = [bool] $change.previousEnabled

    $current = Get-EventChannelState -Channel $channel
    if (-not $current.Readable) {
        Write-Finding ($channel + ' configuration cannot be read, so a restore cannot be verified and' +
                       ' is not attempted')
        return 'declined'
    }

    # Three-way host resolution (docs/DESIGN.md section 4, A-2), the same three
    # cases the template's registry restorer uses.
    $recordedNew = [string] $change.newMaxSizeBytes
    if ([string]::IsNullOrWhiteSpace($recordedNew)) { $recordedNew = [string] $change.newMaxSize }
    $intendedMaxSize = ConvertFrom-NativeInteger -Text $recordedNew

    # Case 2 FIRST: the host already holds the PRE-APPLY state. The write may
    # never have landed - an EventLog policy value can override 'wevtutil sl /ms:'
    # so the channel size never sticks (verification/facts.json) - or it has been
    # restored already. Either way there is nothing to undo, and this must be
    # PERMANENT: returning 'declined' (retryable) left the run eligible, so every
    # future -Rollback re-selected it and it never converged (A-2 / the R-1 class).
    if (($current.Enabled -eq $previousEnabled) -and ([long] $current.MaxSize -eq [long] $previousMaxSize)) {
        Write-Ok ($channel + ' already holds its recorded previous state (enabled=' + [string] $previousEnabled +
                    ', ' + (Format-Mib -Bytes $previousMaxSize) + '); nothing to undo.')
        return 'restored'
    }

    # Case 3: the host holds neither the applied value nor the previous one, so
    # something changed it since; this rollback does not own it.
    if (-not $current.Enabled -or ($null -ne $intendedMaxSize -and [long] $current.MaxSize -ne $intendedMaxSize)) {
        Write-Finding ($channel + ' is enabled=' + [string] $current.Enabled + ' at ' +
                       (Format-Mib -Bytes $current.MaxSize) + ', not what this run set; leaving it alone')
        return 'declined'
    }
    # Case 1 falls through: the host holds what -Apply set - restore it.

    $enabledText = 'false'
    if ($previousEnabled) { $enabledText = 'true' }
    if ($previousMaxSize -lt [long] $current.MaxSize) {
        Write-Info ($channel + ': restoring the smaller previous size DISCARDS the events that no' +
                    ' longer fit. That is what the recorded previous value was.')
    }
    $result = Invoke-NativeCommand -FilePath $script:WevtutilPath -Arguments @(
        'sl', $channel, ('/e:' + $enabledText),
        ('/ms:' + $previousMaxSize.ToString([System.Globalization.CultureInfo]::InvariantCulture)))
    if ($result.ExitCode -ne 0) {
        throw ('wevtutil sl failed restoring ' + $channel + ': ' + ($result.Output -join ' '))
    }

    $after = Get-EventChannelState -Channel $channel
    if ($after.Readable -and ($after.Enabled -ne $previousEnabled -or [long] $after.MaxSize -ne $previousMaxSize)) {
        Write-Finding ($channel + ' reads back as enabled=' + [string] $after.Enabled + ', ' +
                       (Format-Mib -Bytes $after.MaxSize) + ' after the restore')
    }
    Write-Ok ('Restored ' + $channel + ' to enabled=' + $enabledText + ', ' +
              (Format-Mib -Bytes $previousMaxSize))
    return 'restored'
}

#endregion

#region DNS server ------------------------------------------------------------

<#
    # UNVERIFIED: EVERYTHING IN THIS REGION.
    # This host is not a domain controller and does not carry the DNS Server
    # role, so none of the code below has ever executed. The command lines and
    # value semantics are cited to
    # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd
    # and
    # https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics
    # but the OUTPUT FORMAT of `dnscmd /info <setting>` is documented nowhere,
    # and the parser here is a best effort that refuses to act when it cannot
    # read a previous value. Add a row to docs/VALIDATION.md only after this has
    # run on a real DNS server.
    #
    # Cited, verbatim:
    #   dnscmd [<servername>] /config <parameter>
    #   dnscmd [<servername>] /info [<settings>]
    #   /loglevel [<eventtype>] - "Determines which types of events are recorded
    #     in the Dns.log file ... 0x0 - The DNS server doesn't create a log. This
    #     is the default entry."
    #   /logfilemaxsize [<size>] - "Specifies the maximum size in bytes
    #     (0x10000-0xFFFFFFFF) of the Dns.log file. When the file reaches its
    #     maximum size, DNS overwrites the oldest events. The default size is
    #     0x400000, which is 4 megabytes (MB)."
    #   "By default, all debug logging options are disabled."
    #   "Debug logging can be resource intensive, affecting overall server
    #     performance, and consuming disk space."
    #   "Dns.log contains debug logging activity. By default, the DNS debug log
    #     is located in the %windir%\system32\dns directory."
#>

# Every bit of the default -DnsServerLogLevel, each quoted from the dnscmd page.
$script:DnsLogLevelBits = @(
    @{ Bit = 0x0010; Why = 'logs queries and notifications' },
    @{ Bit = 0x0100; Why = 'logs question transactions' },
    @{ Bit = 0x0200; Why = 'logs answers' },
    @{ Bit = 0x1000; Why = 'logs send packets' },
    @{ Bit = 0x2000; Why = 'logs receive packets' },
    @{ Bit = 0x4000; Why = 'logs UDP packets' },
    @{ Bit = 0x8000; Why = 'logs TCP packets' }
)

function Get-DnsServerPresence {
    <#
        # UNVERIFIED: role detection. The primary test is behavioural rather than
        # a claim about Windows - if `dnscmd . /info` returns success then a DNS
        # server answered on this host, which is the only thing that matters
        # before configuring one. The service-name check is secondary and
        # reported, not relied on: that the DNS Server service is named 'DNS' is
        # itself an unverified Windows fact.
    #>
    # NOT Get-Command: that enumerates $env:PATH in order, and .Source was then
    # executed as SYSTEM - including in -Audit, which is where role detection
    # runs. On a host WITHOUT the DNS role there is no System32 copy to shadow, so
    # any user-writable PATH directory won outright: a planted dnscmd.exe exiting
    # 0 from '. /info' made this script conclude a DNS server was present, and
    # -Apply then fed it /config writes. -RequireAnchored is what makes absence
    # mean "the role is not installed" instead of "ask PATH".
    $dnscmdPath = Get-NativeToolPath -FileName 'dnscmd.exe' -RequireAnchored
    $service = Get-Service -Name 'DNS' -ErrorAction SilentlyContinue

    $presence = [PSCustomObject] @{
        DnscmdPath     = $null
        ServicePresent = ($null -ne $service)
        ServiceStatus  = 'absent'
        Answers        = $false
        Raw            = ''
    }
    if ($null -ne $service) { $presence.ServiceStatus = [string] $service.Status }
    if ([string]::IsNullOrWhiteSpace($dnscmdPath)) { return $presence }

    $presence.DnscmdPath = $dnscmdPath
    $result = Invoke-NativeCommand -FilePath $presence.DnscmdPath -Arguments @('.', '/info')
    $presence.Answers = ($result.ExitCode -eq 0)
    $presence.Raw = ($result.Output -join ' / ')
    return $presence
}

function Get-DnsServerSettingValue {
    <#
        # UNVERIFIED: reads one server setting with `dnscmd . /info <setting>`.
        # The output layout is undocumented, so three patterns are tried in
        # order of specificity and $null is returned when none matches. $null
        # means the caller must NOT write, because a change with no recorded
        # previous value is unrecoverable.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $DnscmdPath,
        [Parameter(Mandatory = $true)][string] $Setting
    )

    $result = Invoke-NativeCommand -FilePath $DnscmdPath -Arguments @('.', '/info', ('/' + $Setting))
    if ($result.ExitCode -ne 0) {
        return [PSCustomObject] @{ Value = $null; Raw = ($result.Output -join ' / ') }
    }

    # D-1 (the review log kept in the development repository), now fixed against the MEASURED format
    # rather than a guessed one.
    #
    # What 'dnscmd . /info /<setting>' actually prints on Server 2019, measured
    # on a live domain controller:
    #
    #     (blank)
    #     Query result:
    #     Dword:  500000000 (1DCD6500)
    #     (blank)
    #     Command completed successfully.
    #
    # Three things follow, and the first two killed earlier versions of this
    # function.
    #
    # 1. The output does NOT name the setting. An intermediate fix required a
    #    candidate line to mention it, which would have refused EVERY read on a
    #    real DC - a fail-closed so total the script could never write anything.
    #    That is the over-correction to watch for: turning a fail-open into a
    #    refusal that never fires correctly is not a fix.
    #
    # 2. The original defect grabbed the first parenthesised eight-hex-digit
    #    token anywhere in the output. The per-setting query has no banner, so
    #    that was survivable here - but 'dnscmd . /info' with NO setting prints
    #    'version = 4563000A (10.0 build 17763)', and 4563000A is exactly such a
    #    token. One argument's difference between harmless and writing 1163886602
    #    into the manifest as a previous value.
    #
    # 3. A setting with no numeric value answers 'Null RPC data ptr of type 3.'
    #    - measured for /LogFilePath. There is no Dword line at all, and the
    #    honest answer is $null.
    #
    # So: anchor on the 'Dword:' label, which is what dnscmd emits and what a
    # banner never contains, and require exactly ONE such value. Ambiguity is
    # refused rather than ranked. $null makes the caller decline to write, which
    # on a client's domain controller is the right way to be wrong.
    $candidates = New-Object System.Collections.ArrayList
    foreach ($line in $result.Output) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $match = [regex]::Match($line, '(?i)^\s*dword\s*:\s*([0-9]+)\b')
        if (-not $match.Success) { continue }
        $parsed = ConvertFrom-NativeInteger -Text $match.Groups[1].Value
        if ($null -ne $parsed) { [void] $candidates.Add([long] $parsed) }
    }

    $value = $null
    $distinct = @($candidates.ToArray() | Sort-Object -Unique)
    if ($distinct.Count -eq 1) {
        $value = [long] $distinct[0]
    }
    elseif ($distinct.Count -gt 1) {
        Write-Info ('dnscmd /info /' + $Setting + ' printed ' + [string] $distinct.Count +
                    ' different Dword values (' + (($distinct | ForEach-Object { [string] $_ }) -join ', ') +
                    '); refusing to guess which one is the setting.')
    }
    return [PSCustomObject] @{ Value = $value; Raw = ($result.Output -join ' / ') }
}

function Set-TrackedDnsServerSetting {
    <#
        # UNVERIFIED: writes one server setting through
        # `dnscmd . /config /<setting> <value>`, recording the previous value
        # first. Returns $true when it changed something.
        #
        # Refuses when the previous value could not be read. On a client's domain
        # controller an unrecorded change is unrecoverable, and "we could not
        # read it so we wrote anyway" is how that happens.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $DnscmdPath,
        [Parameter(Mandatory = $true)][string] $Setting,
        [Parameter(Mandatory = $true)][long] $Value,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $current = Get-DnsServerSettingValue -DnscmdPath $DnscmdPath -Setting $Setting
    if ($null -eq $current.Value) {
        Write-Finding ('DNS server setting ' + $Setting + ' could not be read, so it is not being' +
                       ' changed: without a recorded previous value the change is unrecoverable')
        Write-Info ('dnscmd said: ' + $current.Raw)
        return $false
    }
    if ([long] $current.Value -eq $Value) {
        Write-Ok ($Description + ' - already set')
        return $false
    }

    $arguments = @('.', '/config', ('/' + $Setting), $Value.ToString($invariant))
    $reason = ($Description + ' - currently ' + ([long] $current.Value).ToString($invariant))
    # Finding in -Audit, information in -Apply; see Set-TrackedEventChannel.
    if (-not $Apply) {
        Write-Finding ($reason + '; would run: dnscmd.exe ' + ($arguments -join ' '))
        return $false
    }
    Write-Info $reason

    [void] (Write-ManifestChange -Change @{
        type          = 'dnsserversetting'
        setting       = $Setting
        previousValue = ([long] $current.Value).ToString($invariant)
        newValue      = $Value.ToString($invariant)
        description   = $Description
    })

    $result = Invoke-NativeCommand -FilePath $DnscmdPath -Arguments $arguments
    if ($result.ExitCode -ne 0) {
        Write-Failure ('dnscmd /config /' + $Setting + ' exited ' + [string] $result.ExitCode)
        throw ('dnscmd /config /' + $Setting + ' failed: ' + ($result.Output -join ' '))
    }

    # $false when the read-back did not confirm, for the reason spelled out in
    # Set-TrackedEventChannel: Invoke-Main's $verified is the VERIFIED count, and
    # a setter that returns $true after its own finding says the host did not
    # take the value makes the reconciliation that count feeds unable to fire.
    # The manifest record stays; -Rollback resolves it against the host.
    $after = Get-DnsServerSettingValue -DnscmdPath $DnscmdPath -Setting $Setting
    if ($null -eq $after.Value -or [long] $after.Value -ne $Value) {
        Write-Finding ($Description + ' - was set but did not read back as ' + $Value.ToString($invariant))
        return $false
    }
    Write-Ok ($Description + ' - set')
    return $true
}

function Restore-DnsServerSettingChange {
    # UNVERIFIED: restores one 'dnsserversetting' record.
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $setting = [string] $change.setting
    # Constrain what a manifest record may ask for: this script only ever sets
    # these two, and a planted record must not become an arbitrary dnscmd call.
    if ($setting -notin @('loglevel', 'logfilemaxsize')) {
        throw ('Refusing to roll back an unexpected DNS server setting: ' + $setting)
    }

    $presence = Get-DnsServerPresence
    if (-not $presence.Answers) {
        Write-Finding ('the DNS Server role does not answer on this host now, so ' + $setting +
                       ' cannot be restored')
        return 'declined'
    }
    $previous = ConvertFrom-NativeInteger -Text ([string] $change.previousValue)
    if ($null -eq $previous) {
        Write-Finding ($setting + ': recorded previous value is missing or unreadable; declining')
        return 'declined'
    }

    $current = Get-DnsServerSettingValue -DnscmdPath $presence.DnscmdPath -Setting $setting
    $intended = ConvertFrom-NativeInteger -Text ([string] $change.newValue)
    if ($null -eq $current.Value) {
        Write-Finding ($setting + ' cannot be read now, so a restore cannot be verified; declining')
        return 'declined'
    }
    # Case 2 (docs/DESIGN.md section 4.1), before case 3: the setting already holds
    # the value recorded BEFORE this run - either dnscmd never landed it or it has
    # already been put back. Nothing to do, counted 'restored' so the run
    # converges. Without this the case-3 test below declined it as RETRYABLE and
    # every future -Rollback re-selected the run (A-2).
    if ([long] $current.Value -eq [long] $previous) {
        Write-Ok ($setting + ' already holds its recorded previous value (' + [string] $previous +
                  '); nothing to undo.')
        return 'restored'
    }

    # Case 3: neither the applied value nor the previous one.
    if ($null -ne $intended -and [long] $current.Value -ne $intended) {
        Write-Finding ($setting + ' is ' + [string] $current.Value + ', not the ' + [string] $intended +
                       ' this run set; leaving it alone')
        return 'declined'
    }
    # Case 1 falls through: the host holds what -Apply set - restore it.

    $result = Invoke-NativeCommand -FilePath $presence.DnscmdPath -Arguments @(
        '.', '/config', ('/' + $setting),
        $previous.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    if ($result.ExitCode -ne 0) {
        throw ('dnscmd /config /' + $setting + ' failed restoring: ' + ($result.Output -join ' '))
    }
    Write-Ok ('Restored DNS server ' + $setting + ' to ' + [string] $previous)
    return 'restored'
}

#endregion

#region Checks ----------------------------------------------------------------

function Invoke-DnsServerCheck {
    # UNVERIFIED path, opt-in. Returns the number of changes made.
    $presence = Get-DnsServerPresence
    if ($null -eq $presence.DnscmdPath) {
        Write-Info 'dnscmd.exe is not on this host, so the DNS Server role is not installed; skipping.'
        return 0
    }
    Write-Info ('DNS service present: ' + [string] $presence.ServicePresent + ' (' + $presence.ServiceStatus +
                '), dnscmd at ' + $presence.DnscmdPath)
    if (-not $presence.Answers) {
        Write-Info ('dnscmd . /info did not succeed, so no DNS server is answering here; skipping.')
        Write-Info ('dnscmd said: ' + $presence.Raw)
        return 0
    }

    Write-Info 'WARNING: DNS server debug logging is HIGH VOLUME. Microsoft: "Debug logging can be'
    Write-Info 'resource intensive, affecting overall server performance, and consuming disk space."'
    Write-Info ('The log cap is treated as a MINIMUM of ' + (Format-Mib -Bytes $DnsServerLogMaxSizeBytes) +
                ' - a host already above it keeps what it has - and the log stays at its default ' +
                'path (%windir%\system32\dns\Dns.log) on purpose.')
    foreach ($bit in $script:DnsLogLevelBits) {
        if (($DnsServerLogLevel -band $bit.Bit) -ne 0) {
            Write-Info ('  0x' + ([int] $bit.Bit).ToString('X4') + ' ' + $bit.Why)
        }
    }

    # A FLOOR, NOT A TARGET, and this was measured the hard way. On a real
    # Server 2019 DC the shipped logfilemaxsize is 500000000 bytes (~476 MiB),
    # which is MORE than this script's 256 MiB default - so applying the default
    # LOWERED the cap and reduced how much DNS history the DC could keep. A
    # visibility toolkit does not shrink a log. Enable-UsnJournalTracking already
    # treats its size as a floor; this now agrees with it.
    $currentCap = (Get-DnsServerSettingValue -DnscmdPath $presence.DnscmdPath `
                       -Setting 'logfilemaxsize').Value
    $targetCap = [long] $DnsServerLogMaxSizeBytes
    if ($null -ne $currentCap -and [long] $currentCap -gt $targetCap) {
        Write-Ok ('DNS debug log cap is already ' + (Format-Mib -Bytes ([long] $currentCap)) +
                  ', above the ' + (Format-Mib -Bytes $targetCap) + ' floor - left alone. ' +
                  'Lowering it would discard DNS history, which is the opposite of the job.')
        $targetCap = [long] $currentCap
    }

    # FREE SPACE, because this is a domain controller (the review log kept in the development repository,
    # D-2). Both size parameters accept up to 0xFFFFFFFF, and a full system
    # volume on a DC stops Active Directory, DNS and the DC's own logging - the
    # outage this script was deployed to help investigate. docs/DESIGN.md
    # section 7 requires the check.
    # Measured on the volume that will hold Dns.log, derived from its path
    # rather than from $env:SystemDrive: Microsoft, quoted at the top of this
    # region, puts the debug log in "%windir%\system32\dns". Get-VolumeHeadroom
    # expands it and reports whether DriveInfo could read the volume at all -
    # which the previous inline DriveInfo call would have thrown on, turning an
    # unreadable volume into exit 2 instead of a finding.
    $headroom = Get-VolumeHeadroom -Path ([System.IO.Path]::Combine($env:SystemRoot, 'System32\dns'))
    if (-not $headroom.Readable) {
        Write-Finding ('REFUSING the DNS server settings: free space on ' + $headroom.Root +
                       ' could not be read (' + $headroom.Error + '). On a domain controller a full' +
                       ' system volume stops AD, DNS and the logging itself, so this is not done blind.')
        return 0
    }
    $volumeRoot = [string] $headroom.Root
    $free = [long] $headroom.FreeBytes
    # Dns.log lives under %windir%\system32\dns, so it lands on the volume
    # measured above. The channel is gated separately, on the volume wevtutil
    # reports for IT - which is not required to be this one - and is counted here
    # as well: double-counting it errs toward refusing, which on a domain
    # controller is the right direction to be wrong.
    $budget = $targetCap + [long] $ChannelSizeBytes
    $floor = [long] $headroom.FloorBytes
    if (($free - $budget) -lt $floor) {
        Write-Finding ('REFUSING the DNS server settings: a ' + (Format-Mib -Bytes $budget) +
                       ' logging budget against ' + (Format-Mib -Bytes $free) + ' free on ' +
                       $volumeRoot + ' would leave less than the 10% floor of ' +
                       (Format-Mib -Bytes $floor) + '. On a domain controller a full system volume ' +
                       'stops AD, DNS and the logging itself. Lower -DnsServerLogMaxSizeBytes or ' +
                       'free space first.')
        return 0
    }
    Write-Ok ('free space: ' + (Format-Mib -Bytes $free) + ' on ' + $volumeRoot +
              ', budget ' + (Format-Mib -Bytes $budget) + ', 10% floor ' + (Format-Mib -Bytes $floor))

    # A UNION, NOT A TARGET, for the same reason the cap above is a floor. The
    # loglevel is a BITMASK, so writing this script's default over a DC whose
    # administrator had already set extra bits CLEARS them - a visibility toolkit
    # turning DNS debug logging DOWN on the one host class where it matters most.
    # The requested bits are OR'd into whatever the server already logs; nothing
    # is ever switched off here. -Rollback still restores the exact previous mask,
    # because the previous mask is what Set-TrackedDnsServerSetting records.
    $currentLevel = (Get-DnsServerSettingValue -DnscmdPath $presence.DnscmdPath `
                         -Setting 'loglevel').Value
    $targetLevel = [long] $DnsServerLogLevel
    if ($null -ne $currentLevel) {
        $targetLevel = ([long] $currentLevel -bor [long] $DnsServerLogLevel)
        if ($targetLevel -ne [long] $DnsServerLogLevel) {
            Write-Ok ('DNS debug log level 0x' + ([long] $currentLevel).ToString('X') +
                      ' is already set here; the requested 0x' +
                      ([long] $DnsServerLogLevel).ToString('X') + ' is ADDED to it, giving 0x' +
                      $targetLevel.ToString('X') + '. Bits an administrator set are not cleared.')
        }
    }

    $changes = 0
    # Size FIRST, then level. If the order were reversed there would be a window
    # in which logging is on at the old 4 MiB default - harmless - but also a
    # window in which a bigger cap is set while nothing logs, which is the
    # ordering that cannot surprise anyone. Same reasoning as writing
    # AutoBackupLogFiles before Retention in Protect-EventLogs.
    if (Set-TrackedDnsServerSetting -DnscmdPath $presence.DnscmdPath -Setting 'logfilemaxsize' `
        -Value $targetCap `
        -Description ('DNS debug log cap ' + (Format-Mib -Bytes $targetCap))) { $changes++ }
    if (Set-TrackedDnsServerSetting -DnscmdPath $presence.DnscmdPath -Setting 'loglevel' `
        -Value $targetLevel `
        -Description ('DNS debug log level 0x' + $targetLevel.ToString('X'))) { $changes++ }
    return $changes
}

function Invoke-HostCheck {
    <#
        Note the accumulation idiom, and copy it exactly. Never write
        '$changed = $changed -or (...)': -or short-circuits, so once $changed is
        $true every later call is NEVER MADE and the script silently stops
        applying settings after the first one that worked.
    #>
    Write-Section 'DNS client query logging'
    Write-Info ('channel: ' + $script:DnsClientChannel)
    $state = Get-EventChannelState -Channel $script:DnsClientChannel
    if ($state.Readable) {
        Write-Info ('current: enabled=' + [string] $state.Enabled + ', max size ' +
                    (Format-Mib -Bytes $state.MaxSize))
        if (-not [string]::IsNullOrWhiteSpace($state.LogPath)) {
            Write-Info ('log file: ' + $state.LogPath)
        }
    }
    $changeCount = 0
    if (Set-TrackedEventChannel -State $state -TargetMaxSize $ChannelSizeBytes) { $changeCount++ }

    Write-Section 'DNS server debug logging'
    if (-not $IncludeDnsServerDebugLog) {
        Write-Info 'not requested: pass -IncludeDnsServerDebugLog to configure it on a DNS server.'
        Write-Info 'It is opt-in because a DNS debug log is high volume and is a per-host'
        Write-Info 'decision - see the header.'
        return $changeCount
    }
    $changeCount += Invoke-DnsServerCheck
    return $changeCount
}

#endregion

#region Main -----------------------------------------------------------------

function Restore-DnsVisibilityChange {
    <#
        Routes a change record to the right restorer. The template's
        Restore-TrackedChange only knows 'registry' and declines anything else -
        correctly, since silently "succeeding" on a change type it cannot undo is
        how a run gets marked rolled back while the host stays modified. This
        script introduces 'eventchannel' and 'dnsserversetting', so it handles
        both here and delegates the rest.

        Returns 'restored' or 'declined'; throws on failure.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    switch ([string] $ChangeRecord.change.type) {
        'eventchannel'     { return (Restore-EventChannelChange -ChangeRecord $ChangeRecord) }
        'dnsserversetting' { return (Restore-DnsServerSettingChange -ChangeRecord $ChangeRecord) }
        default            { return (Restore-TrackedChange -ChangeRecord $ChangeRecord) }
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
    Assert-ParameterRange   -Name 'ChannelSizeBytes' -Value $ChannelSizeBytes -Minimum 1048576 -Maximum 4294967296
    Assert-ParameterRange   -Name 'DnsServerLogLevel' -Value $DnsServerLogLevel -Minimum 1 -Maximum 4294967295
    Assert-ParameterRange   -Name 'DnsServerLogMaxSizeBytes' -Value $DnsServerLogMaxSizeBytes -Minimum 65536 -Maximum 4294967295

    # -AbandonRun already names the run to act on, so a second -RunId can only
    # disagree with it. Resolving -RunId FIRST and discarding it afterwards meant
    # a stale -RunId - one already rolled back, or absent - threw before the
    # abandon ever ran: exit 2 on the one command line that exists to unblock a
    # run which declines forever. Refused here, where nothing has been read,
    # locked or changed yet.
    if (-not [string]::IsNullOrWhiteSpace($AbandonRun) -and -not [string]::IsNullOrWhiteSpace($RunId)) {
        throw ('-AbandonRun and -RunId cannot be combined: -AbandonRun already names the run to ' +
               'act on. Nothing was read or changed.')
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
        Write-Ok 'No findings: DNS client queries are being recorded to a usefully sized channel.'
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
                channelSizeBytes         = $ChannelSizeBytes.ToString([System.Globalization.CultureInfo]::InvariantCulture)
                includeDnsServerDebugLog = [bool] $IncludeDnsServerDebugLog
                dnsServerLogLevel        = $DnsServerLogLevel.ToString([System.Globalization.CultureInfo]::InvariantCulture)
                dnsServerLogMaxSizeBytes = $DnsServerLogMaxSizeBytes.ToString([System.Globalization.CultureInfo]::InvariantCulture)
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
            # Gated on $verified, not printed unconditionally. This sentence
            # CLAIMS an observation, and it used to print even when the read-back
            # had just reported the channel as something other than what was
            # requested - or when nothing was applied at all. docs/AUTHORING.md: never
            # claim an effect you have not observed.
            if ($verified -gt 0) {
                Write-Info 'No reboot is needed for the channel: wevtutil sl takes effect on the running'
                Write-Info 'Event Log service, and the result above was read back to prove it.'
            }
            Write-Info 'The channel records from now on - it does NOT contain earlier lookups.'
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

        # Resolved ONCE, from -AbandonRun when it was given. The two cannot both
        # be supplied - refused above - so this is the only run id in play.
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
                $outcome = Restore-DnsVisibilityChange -ChangeRecord $target.Changes[$i]
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
