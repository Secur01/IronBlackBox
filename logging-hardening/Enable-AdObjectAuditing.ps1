<#
.SYNOPSIS
    Puts audit ACEs (SACLs) on the three Active Directory objects an attacker
    has to touch to keep domain control: AdminSDHolder, the GPO container, and
    the Domain Controllers OU.

.DESCRIPTION
    docs/VALIDATION.md is the only file allowed to say where this script has
    run; read its row before deploying. Directory facts that could not be cited
    to learn.microsoft.com are still marked "# UNVERIFIED:" with what needs
    checking - those markers are per-fact and do not clear just because the
    script as a whole has been exercised.

    THIS SCRIPT MODIFIES THE SECURITY DESCRIPTOR OF AdminSDHolder, the object
    whose ACL SDProp stamps onto every protected group in the domain. If it ever
    widened a DACL there, that would be a domain compromise delivered by a
    hardening tool. So it does not touch the DACL, and it proves that it did not:

      - it adds an AUDIT ace (a SACL entry), which grants nobody anything - a
        SACL says what gets logged, not who may do it;
      - it reads the object with Owner, Group, Dacl and Sacl visible, and
        REFUSES to proceed if the DACL is not visible, because a guard that
        cannot see the DACL is not a guard;
      - before committing, it asserts in memory that the DACL is byte-identical
        to what it read, that owner and primary group are unchanged, and -
        independently, by decoding per-principal masks the way
        anti-tampering/Protect-EventLogs.ps1's Assert-SddlNotMorePermissive does
        - that nobody gained a right and no deny ACE was dropped;
      - after committing, it re-reads the object and asserts all of that again
        against a fresh read.

    The previous SACL of each object is recorded to the manifest before the
    change, so -Rollback restores exactly it, and the whole previous descriptor
    is recorded with it as evidence.

    A SACL produces nothing on its own: DS Access auditing has to be on. So the
    "Directory Service Changes" and "Directory Service Access" subcategories are
    checked first and reported first, and set by -Apply. That is done the way
    logging-hardening/Enable-IRVisibility.ps1 does it - one full
    'auditpol /backup' captured before the first change and restored with
    'auditpol /restore', with the numeric setting value read by column index so
    nothing depends on localised text.

    What this script deliberately does NOT do:
      - touch a DACL, anywhere, for any reason (see above);
      - SACL the domain root or the Configuration container. Both are legitimate
        targets - Microsoft's Defender for Identity asks for exactly that - but
        an inherited audit ACE at the domain root audits every object in the
        domain, which is a volume decision an MSP makes deliberately and not a
        side effect of running a script called Enable-AdObjectAuditing;
      - use the ActiveDirectory PowerShell module. It is banned by docs/AUTHORING.md and
        is not present on a server without RSAT anyway. Everything here is
        [adsisearcher] and System.DirectoryServices;
      - enable Failure auditing by default (-IncludeFailureAuditing does, and
        it is off because success is what Microsoft's own configuration asks
        for; a failed attempt on AdminSDHolder is arguably the more interesting
        event, which is why the switch exists);
      - reach into another domain or the forest root. It works on the domain
        this DC belongs to;
      - catch SAMR enumeration of the user container (AT-6). 'net user /domain'
        and 'net group "Domain Admins" /domain' read CN=Users over SAMR, not
        LDAP, and CN=Users carries no SACL - so they produce 4662: 0 and 5145: 0
        on the DC, measured in the Atomic exercise. This script SACLs the three
        persistence-CHANGE targets (AdminSDHolder, GPOs, the DC OU), where an
        attacker MODIFYING an object is the high-value signal; broad read-
        enumeration of the user container is not caught here because SACLing it
        audits every logon's user reads, which is prohibitive volume. That an
        account enumerated Domain Admins is recoverable from the enumerating
        host's 4688 command line, not from the DC's DS-Access auditing;
      - collect the resulting 4662/5136 events. That is Invoke-TriageCollection.

.PARAMETER Audit
    Default. Strictly read-only. Reports the audit policy state, whether each
    SACL is already present, what audit entries are already there, and exactly
    what -Apply would add.

.PARAMETER Apply
    Sets the DS Access audit policy and adds the missing audit ACEs, recording
    each previous state to the manifest first.

.PARAMETER Rollback
    Removes exactly the audit ACEs a prior -Apply added, verifies the result
    equals the recorded previous SACL, and restores the audit policy from the
    backup taken at that time. Declines rather than guessing.

.PARAMETER ToolkitRoot
    Base directory for the manifest and the auditpol backup. Default
    C:\ProgramData\IronBlackBox. Validated before use.

.PARAMETER IncludeFailureAuditing
    Also audit failed attempts (AuditFlags Success and Failure instead of
    Success alone).

.PARAMETER LdapPageSize
    Page size for the read-only LDAP queries. Default 200.

.PARAMETER LdapResultCap
    Hard cap on how many objects any LDAP query in this script returns, enforced
    by the enumeration itself. Default 1000.

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
    .\Enable-AdObjectAuditing.ps1
    Reports whether DS Access auditing is on, whether the three SACLs are
    present, and what audit entries are already on those objects.

.EXAMPLE
    .\Enable-AdObjectAuditing.ps1 -Apply
    Sets the audit policy and adds the audit ACEs, recording every previous
    state first.

.EXAMPLE
    .\Enable-AdObjectAuditing.ps1 -Rollback
    Removes the ACEs this toolkit added and restores the audit policy.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.1.1
    License : MIT

    Windows PowerShell 5.1. No module dependencies. Requires local
    administrator; enforced in code by Assert-Elevated, deliberately not by
    #Requires -RunAsAdministrator (see docs/DESIGN.md section 3).

    Writing a SACL additionally needs the "Manage auditing and security log"
    right (SeSecurityPrivilege) and write access to the object's SACL, which on
    these three objects means Domain Admins in practice. Local administrator on
    a DC is not automatically enough. # UNVERIFIED: which of the reads below
    silently return an EMPTY SACL rather than failing when that right is
    missing - so an empty SACL is reported as ambiguous, never as "clean".

    Exit codes: 0 clean or not applicable here, 1 findings, 2 execution error.
    A host that is not a domain controller is 0 with a clear message - not a
    finding, not an error.
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
    [switch] $IncludeFailureAuditing,

    [Parameter()]
    [int] $LdapPageSize = 200,

    [Parameter()]
    [int] $LdapResultCap = 1000,

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

$script:ScriptName    = 'Enable-AdObjectAuditing'
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

#region Host role -------------------------------------------------------------

function Get-HostRoleState {
    <#
        Win32_ComputerSystem.DomainRole: 0 Standalone Workstation, 1 Member
        Workstation, 2 Standalone Server, 3 Member Server, 4 Backup Domain
        Controller, 5 Primary Domain Controller.
        https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem

        The test is "4 or 5", never "= 5": "Backup" is the pre-Windows 2000 name
        and every writable DC that does not hold the PDC emulator role reports 4.
    #>
    $roleName = @{
        0 = 'Standalone Workstation'; 1 = 'Member Workstation'
        2 = 'Standalone Server';      3 = 'Member Server'
        4 = 'Backup Domain Controller'; 5 = 'Primary Domain Controller'
    }
    $system = Get-CimInstance -ClassName Win32_ComputerSystem
    $role = [int] $system.DomainRole
    $name = 'unrecognised role ' + [string] $role
    if ($roleName.ContainsKey($role)) { $name = $roleName[$role] }

    return [PSCustomObject] @{
        DomainRole         = $role
        RoleName           = $name
        Domain             = [string] $system.Domain
        IsDomainController = ($role -eq 4 -or $role -eq 5)
    }
}

#endregion

#region Audit policy ----------------------------------------------------------

<#
    The prerequisite, and the reason it comes first: a SACL on AdminSDHolder
    produces nothing at all unless DS Access auditing is on. An MSP that ran
    only the SACL half would have a hardening report saying "auditing enabled"
    and an empty Security log.

    Two subcategories, addressed by their well-known GUID because the display
    names are localised. Both GUIDs were read from 'auditpol /list
    /subcategory:* /r' on the lab and are recorded in verification/facts.json
    (fact auditpol-subcategory-guids):

      {0CCE923C-69AE-11D9-BED3-505054503030}  Directory Service Changes  -> 5136
      {0CCE923B-69AE-11D9-BED3-505054503030}  Directory Service Access   -> 4662

    Both are set to 3 (success and failure). That is the configuration
    Microsoft's Defender for Identity asks for - its table lists DS Access
    "Audit Directory Service Changes" (event 5136) and "Audit Directory Service
    Access" (event 4662, "for this event, you must also configure domain object
    auditing") with Success AND Failure:
    https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection

    Rollback restores a full 'auditpol /backup' captured before the first
    change, exactly as logging-hardening/Enable-IRVisibility.ps1 does it: the
    backup CSV carries a NUMERIC setting value in its LAST column, read by index
    so nothing depends on the localised text, and 'auditpol /restore' puts the
    whole policy back including subcategories this script never touched. Both
    behaviours were proven on the lab.
#>

$script:AuditTarget = @(
    @{ Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; Name = 'Directory Service Changes'
       Setting = 3; Why = '5136 - the object was modified, with the old and new value' },
    @{ Guid = '{0CCE923B-69AE-11D9-BED3-505054503030}'; Name = 'Directory Service Access'
       Setting = 3; Why = '4662 - an operation was performed on an object (needs the SACLs below)' }
)

# Resolved once, at script scope. Every auditpol invocation in this file goes
# through it, so none of them can be diverted by a writable directory sitting
# ahead of System32 in the machine PATH - this script both reads and WRITES the
# audit policy with it, as SYSTEM, on a domain controller.
$script:AuditpolPath = Get-NativeToolPath -FileName 'auditpol.exe'

function Get-AuditPolicyState {
    <#
        Returns a hashtable of upper-case GUID -> integer setting value, read
        from 'auditpol /backup'. Empty hashtable if the policy cannot be read,
        which callers must treat as "unknown", never as "nothing is enabled".
    #>
    param([Parameter(Mandatory = $true)][string] $BackupPath)

    $state = @{}
    $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @('/backup', ('/file:' + $BackupPath))
    if ($result.ExitCode -ne 0) {
        throw ('auditpol /backup failed with exit code ' + $result.ExitCode + ': ' + ($result.Output -join ' '))
    }
    if (-not (Test-Path -LiteralPath $BackupPath)) {
        throw ('auditpol /backup reported success but wrote no file: ' + $BackupPath)
    }

    $lines = @(Get-Content -LiteralPath $BackupPath)
    if ($lines.Count -lt 2) { return $state }

    # By index, not by header name: the headers may be localised. The backup
    # format is
    #   Machine Name,Policy Target,Subcategory,Subcategory GUID,
    #   Inclusion Setting,Exclusion Setting,Setting Value
    # so the GUID is field 3 and the numeric value is the LAST field.
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $fields = $lines[$i] -split ','
        if ($fields.Count -lt 7) { continue }
        $guid = $fields[3].Trim()
        $raw  = $fields[$fields.Count - 1].Trim()
        $parsed = 0
        # WITH A PROVIDER. The no-provider overload uses the AMBIENT culture, the trap
        # Enable-WefClient's forwarder diagnostic already names. auditpol's setting value
        # is a small integer today so this parsed everywhere, but a value read from a
        # native tool is invariant text and never locale text.
        if ([int]::TryParse($raw, [System.Globalization.NumberStyles]::Integer,
                    [System.Globalization.CultureInfo]::InvariantCulture, [ref] $parsed)) {
            $state[$guid.ToUpperInvariant()] = $parsed
        }
    }
    return $state
}

function Set-AuditSubcategory {
    param(
        [Parameter(Mandatory = $true)][string] $Guid,
        [Parameter(Mandatory = $true)][int] $Setting
    )
    # 1 = Success, 2 = Failure, 3 = both. Anything else disables.
    $success = 'disable'
    $failure = 'disable'
    if (($Setting -band 1) -ne 0) { $success = 'enable' }
    if (($Setting -band 2) -ne 0) { $failure = 'enable' }

    $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @(
        '/set', ('/subcategory:' + $Guid), ('/success:' + $success), ('/failure:' + $failure))
    if ($result.ExitCode -ne 0) {
        throw ('auditpol /set failed for ' + $Guid + ' with exit code ' +
               $result.ExitCode + ': ' + ($result.Output -join ' '))
    }
}

function Test-AuditPolicyMatchesBackup {
    <#
        Does the EFFECTIVE audit policy already equal the policy in a recorded
        backup file? Used for case 2 of the rollback doctrine
        (docs/DESIGN.md section 4.1).

        Measured on the lab 2026-08-28, because this comparison is only sound if
        'auditpol /backup' reflects the live policy:
          - two backups of an unchanged policy are byte-identical;
          - after 'auditpol /set /subcategory:<guid> /success:disable
            /failure:disable' the backup DID change (Setting Value 3 -> 0).
        So a fresh backup compared against the recorded one is a real test of
        state, not of file age.

        Returns $true only on a confirmed match. Any failure to produce or read a
        fresh backup returns $false, so an unreadable comparison falls through to
        the normal restore rather than silently skipping it.
    #>
    param([Parameter(Mandatory = $true)][string] $BackupPath)

    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) { return $false }
    $probe = [System.IO.Path]::Combine($env:TEMP,
        ('ibb-auditpol-probe-' + [System.Guid]::NewGuid().ToString('N') + '.csv'))
    try {
        # NOT /file:(Join-Path ...) - PowerShell does not expand a subexpression
        # glued to a literal prefix in argument mode, and piped to Out-Null the
        # failure is invisible. Build the whole switch as one string.
        $fileArg = '/file:' + $probe
        $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @('/backup', $fileArg)
        if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $probe -PathType Leaf)) {
            return $false
        }
        $liveHash = (Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash
        $recordedHash = (Get-FileHash -LiteralPath $BackupPath -Algorithm SHA256).Hash
        return [string]::Equals($liveHash, $recordedHash, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
    finally { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
}

function Restore-AuditPolicyFromBackup {
    param([Parameter(Mandatory = $true)][string] $BackupPath)

    if (-not (Test-Path -LiteralPath $BackupPath)) {
        throw ('Audit policy backup is missing, cannot restore: ' + $BackupPath)
    }
    $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @('/restore', ('/file:' + $BackupPath))
    if ($result.ExitCode -ne 0) {
        throw ('auditpol /restore failed with exit code ' + $result.ExitCode + ': ' + ($result.Output -join ' '))
    }
}

function Set-DsAccessAuditPolicy {
    <#
        Reads the current policy, reports or applies the difference, and in
        -Apply records ONE change record carrying the path of a full
        'auditpol /backup' taken before anything is altered. That backup is the
        rollback.

        Only ever ADDS auditing: '-bor' means "at least these bits", so a host
        already auditing more than this asks for keeps it.

        Every -Apply also writes an 'expectation' record naming both target
        subcategories, whether or not either needed changing - see AT-2 below.
        Without it, the prerequisite this whole script rests on has no watchdog
        on a host that was already compliant.
    #>
    param([Parameter(Mandatory = $true)][string] $WorkDirectory)
    Write-Section 'DS Access audit policy (the prerequisite for every SACL below)'

    # A FRESH NAME PER CALL, and the directory is why. In -Audit mode
    # $WorkDirectory is the OS temp directory (see Invoke-Main), where a constant
    # file name is guessable by anyone on the box - and auditpol.exe writes it
    # with this script's token, SYSTEM under an RMM. The file is then parsed to
    # decide what the operator is told and, below, what gets set. Same pattern as
    # Test-AuditPolicyMatchesBackup, which was already doing it correctly in the
    # same directory; the two constant names here were the outliers.
    $probePath = [System.IO.Path]::Combine($WorkDirectory,
                    ('ibb-auditpol-dsaccess-probe-' + [System.Guid]::NewGuid().ToString('N') + '.csv'))
    try { $current = Get-AuditPolicyState -BackupPath $probePath }
    finally {
        # In a finally: Get-AuditPolicyState THROWS on an auditpol failure, so the
        # plain cleanup that used to follow it left the probe on disk on exactly
        # the runs where something went wrong.
        Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
    }

    if ($current.Count -eq 0) {
        Write-Finding 'the audit policy could not be read; not changing it'
        return 0
    }

    $needed = @()
    foreach ($target in $script:AuditTarget) {
        $guid = $target.Guid.ToUpperInvariant()
        if (-not $current.ContainsKey($guid)) {
            Write-Finding ($target.Name + ' - subcategory not present on this host')
            continue
        }
        $have = $current[$guid]
        if (($have -bor $target.Setting) -ne $have) { $needed += $target }
        else { Write-Ok ($target.Name + ' - already auditing (' + $target.Why + ')') }
    }

    # AT-2, and this script needed it more than the one it was fixed in. Record
    # the FULL intended subcategory set on every -Apply, not only what had to
    # change. Test-VisibilityDrift verifies recorded CHANGES, so a subcategory
    # already enabled at apply time produced no change record and was invisible
    # to it - and on a managed domain BOTH DS Access subcategories being already
    # on is the common case, which meant the whole audit policy went unwatched on
    # exactly the hosts that were already compliant.
    #
    # What that cost: this script's own premise is that a SACL produces nothing
    # unless DS Access auditing is on, its 'adobjectsacl' changes are on
    # Test-VisibilityDrift's declared-unverifiable list (they need a DC and an
    # LDAP bind), so with no record of any kind an attacker switching DS Access
    # off left three SACLs logging nothing while the drift detector reported the
    # host clean.
    #
    # This is NOT a change record: it has no previous value, is never rolled
    # back, and does not count toward changeCount, so idempotence and the
    # recorded-versus-verified arithmetic in Invoke-Main are unaffected. Field
    # names match Enable-IRVisibility's expectation record so one reader serves
    # both.
    if ($Apply) {
        $present = @()
        foreach ($expTarget in $script:AuditTarget) {
            if ($current.ContainsKey($expTarget.Guid.ToUpperInvariant())) { $present += $expTarget.Guid }
        }
        if ($present.Count -gt 0) {
            Write-ManifestRecord -Record @{
                recordType   = 'expectation'
                runId        = $script:CurrentRunId
                recordedUtc  = (Get-UtcStamp)
                change       = @{ type = 'auditpol'; subcategories = $present
                                  description = 'intended DS Access subcategory coverage' }
            }
        }
    }

    if ($needed.Count -eq 0) { return 0 }

    if (-not $Apply) {
        foreach ($target in $needed) {
            Write-Finding ($target.Name + ' - would enable; without it the SACLs below log NOTHING (' +
                           $target.Why + ')')
        }
        return 0
    }

    $backupPath = [System.IO.Path]::Combine($WorkDirectory,
                    ('auditpol-backup-' + $script:CurrentRunId + '.csv'))
    $result = Invoke-NativeCommand -FilePath $script:AuditpolPath -Arguments @('/backup', ('/file:' + $backupPath))
    if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $backupPath)) {
        throw ('Could not back up the audit policy; refusing to change it. auditpol exit ' +
               [string] $result.ExitCode)
    }

    [void] (Write-ManifestChange -Change @{
        type          = 'auditpol'
        backupPath    = $backupPath
        subcategories = @($needed | ForEach-Object { $_.Guid })
        description   = ('audit policy: ' + [string] $needed.Count + ' DS Access subcategor(y/ies) enabled')
    })

    foreach ($target in $needed) {
        $wanted = $target.Setting
        $guid = $target.Guid.ToUpperInvariant()
        if ($current.ContainsKey($guid)) { $wanted = $current[$guid] -bor $target.Setting }
        Set-AuditSubcategory -Guid $target.Guid -Setting $wanted
        Write-Ok ($target.Name + ' - enabled')
    }

    $confirmPath = [System.IO.Path]::Combine($WorkDirectory,
                    ('ibb-auditpol-dsaccess-confirm-' + [System.Guid]::NewGuid().ToString('N') + '.csv'))
    try { $after = Get-AuditPolicyState -BackupPath $confirmPath }
    finally { Remove-Item -LiteralPath $confirmPath -Force -ErrorAction SilentlyContinue }
    foreach ($target in $needed) {
        $guid = $target.Guid.ToUpperInvariant()
        if (-not $after.ContainsKey($guid) -or (($after[$guid] -bor $target.Setting) -ne $after[$guid])) {
            throw ('Audit subcategory did not read back as set: ' + $target.Name + ' ' + $target.Guid)
        }
    }
    return 1
}

#endregion

#region Directory context -----------------------------------------------------

# CreateChild 1, DeleteChild 2, Self 8, WriteProperty 32, DeleteTree 64,
# ExtendedRight 256, Delete 65536, WriteDacl 262144, WriteOwner 524288 - names
# and values from
# https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights
# The literals are summed here rather than OR-ing enum members, so this file
# does not depend on System.DirectoryServices being loaded at parse time; the
# invariant below asserts the total at run time.
#
# That total, 852331, is not invented. It is the access mask Microsoft's own
# Defender for Identity tooling reports for its domain object auditing
# configuration - "AccessMask=852331" in the Get-MDIConfiguration sample output:
# https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/get-mdiconfiguration
# and it is what the manual instruction produces ("select Full Control, then
# clear List contents, Read all properties and Read permissions"):
# https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection
# Read rights are deliberately NOT audited: every logon reads these objects,
# and auditing reads is how a Security log fills in an hour.
#
# Verified on this dev box: [System.DirectoryServices.ActiveDirectoryRights]
# 852331 decodes to exactly "CreateChild, DeleteChild, Self, WriteProperty,
# DeleteTree, ExtendedRight, Delete, WriteDacl, WriteOwner" - so the literals
# below and the documented mask agree on what they mean, on the .NET side at
# least. What the directory does with it is no longer a .NET-side inference:
# see this script's row in docs/VALIDATION.md for the events a SACL carrying
# this mask actually produced.
$script:AuditRightMask = 1 -bor 2 -bor 8 -bor 32 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288

# Everyone. A well-known SID, never the name: "Everyone" is "Tout le monde" on
# fr-FR Windows, a real deployment target for this toolkit.
# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
$script:EveryoneSid = 'S-1-1-0'

$script:AllSecurityMask = $null

function Assert-DirectoryServiceType {
    <#
        System.DirectoryServices ships with Windows but is not necessarily
        loaded in a fresh 5.1 session, and the ActiveDirectory module is banned
        (docs/AUTHORING.md) - so the assembly is loaded from the GAC, which installs
        nothing. '-as [type]' probes for the type without throwing.

        Also asserts the rights invariant: if someone edits the literals above,
        the run stops here instead of writing an ACE nobody intended.
    #>
    # # UNVERIFIED: that Add-Type -AssemblyName 'System.DirectoryServices'
    # resolves on Windows PowerShell 5.1 without RSAT. It is a GAC assembly that
    # ships with the OS and the [adsisearcher] accelerator implies it is
    # loadable, but this was only exercised under pwsh 7 on the dev box.
    if ($null -eq ('System.DirectoryServices.ActiveDirectoryRights' -as [type])) {
        Add-Type -AssemblyName 'System.DirectoryServices'
    }
    if ($null -eq ('System.DirectoryServices.ActiveDirectoryRights' -as [type])) {
        throw 'System.DirectoryServices is not available; cannot read or write a directory SACL.'
    }
    if ($script:AuditRightMask -ne 852331) {
        throw ('The audited rights mask is ' + [string] $script:AuditRightMask +
               ' but the documented value is 852331. Refusing to write an ACE nobody reviewed.')
    }

    # Owner, Group, Dacl and Sacl - all four, deliberately. The SACL alone would
    # be enough to WRITE, but then the DACL would be invisible, and a guard that
    # cannot see the DACL is not a guard.
    # https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.securitymasks
    $script:AllSecurityMask = (
        [System.DirectoryServices.SecurityMasks]::Owner -bor
        [System.DirectoryServices.SecurityMasks]::Group -bor
        [System.DirectoryServices.SecurityMasks]::Dacl  -bor
        [System.DirectoryServices.SecurityMasks]::Sacl)
}

function Get-DomainNamingContext {
    <#
        The domain DN, read from RootDSE rather than derived from the DNS domain
        name: on a renamed domain the two disagree, and every DN below is built
        from this one.
        https://learn.microsoft.com/en-us/windows/win32/adschema/rootdse

        InvokeGet, not .Get(). The snippet everyone writes is
        ([adsi]'LDAP://RootDSE').Get('defaultNamingContext'), and DirectoryEntry
        has NO public Get method - verified by reflection on this dev box. That
        idiom only works through a PowerShell adapter, which is not something to
        depend on inside a script that runs as SYSTEM on a client's DC.
        InvokeGet is the documented ADSI passthrough; the property cache is the
        fallback.
        https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry.invokeget
    #>
    $rootDse = $null
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $value = ''
        try { $value = [string] $rootDse.InvokeGet('defaultNamingContext') }
        catch {
            Write-Verbose ('InvokeGet on RootDSE failed, falling back to the property cache: ' +
                           $_.Exception.Message)
        }
        if ([string]::IsNullOrWhiteSpace($value)) {
            $rootDse.RefreshCache(@('defaultNamingContext'))
            if ($rootDse.Properties.Contains('defaultNamingContext')) {
                $value = [string] $rootDse.Properties['defaultNamingContext'].Value
            }
        }
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw 'RootDSE returned an empty defaultNamingContext.'
        }
        return $value
    }
    finally {
        # AD-1: an ADSI object that never bound throws from MEMBER LOOKUP, not
        # from the call, so `if ($null -ne $x)` does not protect this line.
        # Measured on the lab: resolving .Dispose on a DirectoryEntry whose bind
        # failed raises "The specified domain either does not exist or could not
        # be contacted", and because it is raised in `finally` it REPLACES the
        # real error - turning a reportable gap into exit 2. Swallowed here on
        # purpose: a failed cleanup of an object that never bound has nothing to
        # release, and the caller's own error is the one worth reporting.
        if ($null -ne $rootDse) {
            try { $rootDse.Dispose() }
            catch { Write-Verbose ('disposing RootDSE failed: ' + $_.Exception.Message) }
        }
    }
}

function Get-DomainControllerObjectDn {
    <#
        Every domain controller COMPUTER object, found by the
        SERVER_TRUST_ACCOUNT bit rather than by looking in a container, so that
        DCs living outside the default OU are seen rather than assumed away.

        userAccountControl SERVER_TRUST_ACCOUNT = 0x2000 = 8192, "a computer
        account for a domain controller that is a member of this domain":
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
        The bitwise filter uses matching rule OID 1.2.840.113556.1.4.803
        (LDAP_MATCHING_RULE_BIT_AND), and the value must be decimal:
        https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax

        Bounded three ways. PageSize makes it a paged search so a large result
        set does not arrive in one lump; SizeLimit is the server-side cap;
        # UNVERIFIED: which of those two the server honours once paging is on -
        so the enumeration counts and stops as well, and that third bound is the
        one this function actually relies on.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $DomainDn,
        [Parameter(Mandatory = $true)][int] $PageSize,
        [Parameter(Mandatory = $true)][int] $ResultCap
    )

    $root = $null
    $searcher = $null
    $results = $null
    $found = New-Object System.Collections.ArrayList
    $capped = $false
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry(('LDAP://' + $DomainDn))
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        $searcher.Filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.PageSize = $PageSize
        $searcher.SizeLimit = $ResultCap
        $searcher.ClientTimeout = [System.TimeSpan]::FromSeconds(60)
        [void] $searcher.PropertiesToLoad.Add('distinguishedname')

        $results = $searcher.FindAll()
        foreach ($result in $results) {
            if ($found.Count -ge $ResultCap) { $capped = $true; break }
            $dn = ''
            if ($result.Properties.Contains('distinguishedname')) {
                $dn = [string] $result.Properties['distinguishedname'][0]
            }
            if (-not [string]::IsNullOrWhiteSpace($dn)) { [void] $found.Add($dn) }
        }
    }
    finally {
        # AD-1: an ADSI object that never bound throws from MEMBER LOOKUP, not
        # from the call, so `if ($null -ne $x)` does not protect this line.
        # Measured on the lab: resolving .Dispose on a DirectoryEntry whose bind
        # failed raises "The specified domain either does not exist or could not
        # be contacted", and because it is raised in `finally` it REPLACES the
        # real error - turning a reportable gap into exit 2. Swallowed here on
        # purpose: a failed cleanup of an object that never bound has nothing to
        # release, and the caller's own error is the one worth reporting.
        foreach ($disposable in @($results, $searcher, $root)) {
            if ($null -eq $disposable) { continue }
            try { $disposable.Dispose() }
            catch { Write-Verbose ('disposing a directory object failed: ' + $_.Exception.Message) }
        }
    }
    return [PSCustomObject] @{ Dn = $found.ToArray(); Capped = $capped }
}

function Write-DomainControllerPlacementReport {
    <#
        Read-only, and useful: a DC object moved out of the default OU is outside
        the SACL this script sets, and outside whatever GPO the MSP links there.
        Reported, never "fixed" - moving a DC object is not a hardening script's
        decision.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $DomainDn,
        [Parameter(Mandatory = $true)][string] $DefaultOu
    )

    Write-Section 'Domain controller placement (read-only)'
    $discovered = $null
    try {
        $discovered = Get-DomainControllerObjectDn -DomainDn $DomainDn `
            -PageSize $LdapPageSize -ResultCap $LdapResultCap
    }
    catch {
        Write-Finding ('could not enumerate domain controller objects: ' + $_.Exception.Message)
        return
    }

    if ($discovered.Dn.Count -eq 0) {
        Write-Finding 'no computer object carries the SERVER_TRUST_ACCOUNT bit, which cannot be right on a DC'
        return
    }
    Write-Info ([string] $discovered.Dn.Count + ' domain controller object(s) found')
    if ($discovered.Capped) {
        Write-Info ('the enumeration stopped at the -LdapResultCap of ' + [string] $LdapResultCap)
    }

    $suffix = ',' + $DefaultOu
    foreach ($dn in $discovered.Dn) {
        if (-not $dn.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Finding ('domain controller object outside the default OU, so outside the SACL set ' +
                           'below: ' + $dn)
        }
    }
}

#endregion

#region Object SACL -----------------------------------------------------------

<#
    The three objects, why each one, and where its DN comes from.

    CN=AdminSDHolder,CN=System,<domain DN> - "The purpose of the AdminSDHolder
    object is to provide template permissions for the protected accounts and
    groups in the domain", it "is automatically created as an object in the
    System container of every Active Directory domain", and SDProp stamps its
    ACL onto every protected account and group about every 60 minutes from the
    PDC emulator:
    https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
    Which is exactly why it is a persistence target: an ACE added here comes
    back on Domain Admins an hour after anyone removes it from Domain Admins.

    CN=Policies,CN=System,<domain DN> - the Group Policy container. Every GPO's
    directory half lives there, as "LDAP://<gpo guid>,CN=policies,CN=system,
    <rootdse>":
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/2f362c13-9a2d-469b-8c4b-7b4045258995
    https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-storage
    A modified GPO is code execution on every host it applies to.

    OU=Domain Controllers,<domain DN> - # UNVERIFIED: that this is the DN on the
    target domain. It is the default location created when a domain is built,
    but it can be renamed, and no learn.microsoft.com page is cited here for the
    name itself. Two things make that safe rather than silent: the bind fails
    loudly and becomes a finding if the OU is not there, and
    Write-DomainControllerPlacementReport finds the DC objects by their
    userAccountControl bit and reports any that live outside this OU.

    Inheritance: None on AdminSDHolder, which has no children worth auditing,
    and All on the two containers ("the object to which the ACE is applied, the
    object's immediate children, and the descendents of the object's children"):
    https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance
#>

$script:SaclTarget = @(
    @{ Title = 'AdminSDHolder'; RelativeDn = 'CN=AdminSDHolder,CN=System'; Inheritance = 'None'
       Why = 'its ACL is stamped onto every protected group by SDProp - the classic persistence target' },
    @{ Title = 'GPO container'; RelativeDn = 'CN=Policies,CN=System'; Inheritance = 'All'
       Why = 'a modified GPO is code execution on every host it applies to' },
    @{ Title = 'Domain Controllers OU'; RelativeDn = 'OU=Domain Controllers'; Inheritance = 'All'
       Why = 'changes to the DC objects themselves' }
)

function Get-SidDisplayName {
    param([Parameter(Mandatory = $true)][string] $Sid)
    try {
        $account = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate(
            [System.Security.Principal.NTAccount])
        return ($Sid + ' (' + $account.Value + ')')
    }
    catch {
        # An unresolvable SID is normal (a deleted principal, or a SID from
        # another domain) and is not worth failing a read-only report over.
        return $Sid
    }
}

function Get-AclFingerprint {
    <#
        Base64 of the DACL's raw binary form - the "byte-identical" in this
        script's promise. Returns $null when the descriptor carries no DACL,
        which callers treat as "refuse to proceed", never as "empty".

        Bytes, not SDDL text: verification/facts.json records
        (sddl-text-is-not-comparable) that .NET regenerates a descriptor with
        rights abbreviations where Windows prints hex - identical meaning,
        different string.
    #>
    param([Parameter(Mandatory = $true)][string] $Sddl)

    $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    if ($null -eq $raw.DiscretionaryAcl) { return $null }
    $bytes = New-Object byte[] $raw.DiscretionaryAcl.BinaryLength
    $raw.DiscretionaryAcl.GetBinaryForm($bytes, 0)
    return [System.Convert]::ToBase64String($bytes)
}

function Get-DaclAceMap {
    <#
        Per-principal DACL masks, the same decode
        anti-tampering/Protect-EventLogs.ps1's Get-SddlAceMap does, extended for
        the object ACEs an AD descriptor carries: the key includes the object
        and inherited-object GUIDs, so a per-property ACE is never folded
        together with a whole-object one - folding them would hide exactly the
        widening this is looking for.

        Deny ACEs are keyed separately so an absence of allow cannot be
        mistaken for a deny.
    #>
    param([Parameter(Mandatory = $true)][string] $Sddl)

    $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    if ($null -eq $raw.DiscretionaryAcl) { return $null }

    $map = @{}
    foreach ($ace in $raw.DiscretionaryAcl) {
        if (-not ($ace -is [System.Security.AccessControl.KnownAce])) { continue }
        $type = [string] $ace.AceType
        $objectGuid = '-'
        $inheritedGuid = '-'
        if ($ace -is [System.Security.AccessControl.ObjectAce]) {
            $objectGuid = [string] $ace.ObjectAceType
            $inheritedGuid = [string] $ace.InheritedObjectAceType
        }
        $prefix = 'ALLOW'
        if ($type.StartsWith('AccessDenied', [System.StringComparison]::Ordinal)) { $prefix = 'DENY' }
        $key = ($prefix + '|' + $ace.SecurityIdentifier.Value + '|' + $objectGuid + '|' + $inheritedGuid)
        if ($map.ContainsKey($key)) { $map[$key] = $map[$key] -bor [int] $ace.AccessMask }
        else { $map[$key] = [int] $ace.AccessMask }
    }
    return $map
}

function Get-SaclAceMap {
    <#
        The SACL, keyed for exact comparison and carrying enough to rebuild each
        ACE as an ActiveDirectoryAuditRule during -Rollback. The mask is part of
        the KEY here, unlike Get-DaclAceMap: this comparison wants "identical",
        not "no wider".

        An empty or absent SACL is an empty map, not an error - and the caller
        is responsible for remembering that an empty SACL can also mean "this
        account may not see the SACL".
    #>
    param([Parameter()][AllowEmptyString()][string] $Sddl = '')

    $map = @{}
    if ([string]::IsNullOrWhiteSpace($Sddl)) { return $map }

    $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    if ($null -eq $raw.SystemAcl) { return $map }

    foreach ($ace in $raw.SystemAcl) {
        if (-not ($ace -is [System.Security.AccessControl.QualifiedAce])) { continue }
        $type = [string] $ace.AceType
        if (-not $type.StartsWith('SystemAudit', [System.StringComparison]::Ordinal)) { continue }

        $objectGuid = [System.Guid]::Empty
        $inheritedGuid = [System.Guid]::Empty
        if ($ace -is [System.Security.AccessControl.ObjectAce]) {
            $flags = $ace.ObjectAceFlags
            if (($flags -band [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) -ne 0) {
                $objectGuid = $ace.ObjectAceType
            }
            if (($flags -band [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent) -ne 0) {
                $inheritedGuid = $ace.InheritedObjectAceType
            }
        }

        $entry = [PSCustomObject] @{
            Sid                 = [string] $ace.SecurityIdentifier.Value
            Mask                = [int] $ace.AccessMask
            AuditFlags          = [int] $ace.AuditFlags
            InheritanceFlags    = [string] $ace.InheritanceFlags
            PropagationFlags    = [string] $ace.PropagationFlags
            IsInherited         = [bool] $ace.IsInherited
            ObjectType          = $objectGuid
            InheritedObjectType = $inheritedGuid
        }
        $key = ($entry.Sid + '|' + [string] $entry.Mask + '|' + [string] $entry.AuditFlags + '|' +
                $entry.InheritanceFlags + '|' + $entry.PropagationFlags + '|' +
                [string] $entry.IsInherited + '|' + $objectGuid.ToString() + '|' +
                $inheritedGuid.ToString())
        $map[$key] = $entry
    }
    return $map
}

function Test-AceMapEqual {
    param([Parameter(Mandatory = $true)] $Left, [Parameter(Mandatory = $true)] $Right)
    if ($Left.Count -ne $Right.Count) { return $false }
    foreach ($key in $Left.Keys) {
        if (-not $Right.ContainsKey($key)) { return $false }
    }
    return $true
}

function New-AdSecuritySnapshot {
    <#
        Everything this script needs about one object's descriptor, captured as
        plain strings so it survives the DirectoryEntry being disposed.
    #>
    param(
        [Parameter(Mandatory = $true)] $Security,
        [Parameter(Mandatory = $true)][string] $DistinguishedName
    )

    $fullSddl = [string] $Security.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::All)

    $saclSddl = ''
    try {
        $saclSddl = [string] $Security.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Audit)
    }
    catch {
        # An object with no SACL, or a SACL this account cannot see. Both come
        # back as "no audit section"; the difference is reported, not guessed.
        # # UNVERIFIED: whether GetSecurityDescriptorSddlForm(Audit) returns an
        # empty string or throws when there is no SACL - hence the catch.
        Write-Verbose ('No audit section readable on ' + $DistinguishedName + ': ' + $_.Exception.Message)
    }

    $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($fullSddl)
    $owner = ''
    $group = ''
    if ($null -ne $raw.Owner) { $owner = [string] $raw.Owner.Value }
    if ($null -ne $raw.Group) { $group = [string] $raw.Group.Value }

    $auditRule = New-Object System.Collections.ArrayList
    try {
        foreach ($rule in $Security.GetAuditRules($true, $true,
                    [System.Security.Principal.SecurityIdentifier])) {
            [void] $auditRule.Add([PSCustomObject] @{
                Sid                 = [string] $rule.IdentityReference.Value
                Rights              = [int] $rule.ActiveDirectoryRights
                AuditFlags          = [int] $rule.AuditFlags
                InheritanceType     = [string] $rule.InheritanceType
                ObjectType          = [string] $rule.ObjectType
                InheritedObjectType = [string] $rule.InheritedObjectType
                IsInherited         = [bool] $rule.IsInherited
            })
        }
    }
    catch {
        Write-Verbose ('Audit rules unreadable on ' + $DistinguishedName + ': ' + $_.Exception.Message)
    }

    return [PSCustomObject] @{
        DistinguishedName = $DistinguishedName
        FullSddl          = $fullSddl
        SaclSddl          = $saclSddl
        DaclFingerprint   = (Get-AclFingerprint -Sddl $fullSddl)
        Owner             = $owner
        Group             = $group
        AuditRule         = $auditRule.ToArray()
    }
}

function Get-AdObjectSecurityObject {
    <#
        The ActiveDirectorySecurity of one object, WITH its SACL, read through a
        DirectorySearcher.

        THIS IS THE ONLY WAY IT WORKS, and the first version of this script had
        it wrong in a way that only a domain controller could reveal. It set
        DirectoryEntry.Options.SecurityMasks - and measured on Server 2019,
        DirectoryEntryConfiguration has no SecurityMasks property at all. Every
        read failed with "The property 'SecurityMasks' cannot be found on this
        object", on all three targets, so the script could read nothing and
        write nothing. SecurityMasks exists on DirectorySearcher, not on a
        DirectoryEntry's configuration.
        https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher.securitymasks

        And DirectoryEntry.ObjectSecurity is not a workaround: measured, it
        reports zero audit rules on an object that has two, and AddAuditRule on
        it throws "The system acl cannot be modified as it was not retrieved
        from the backend store."

        So: ask the searcher for ntSecurityDescriptor under a mask that includes
        Sacl, and rehydrate it. Proven on the lab against AdminSDHolder - a
        1,356-byte descriptor carrying the 3 audit rules AD ships by default.

        Returns $null when the object is not found, so the caller can tell
        "absent" from "unreadable".
    #>
    param([Parameter(Mandatory = $true)][string] $DistinguishedName)

    $root = $null
    $searcher = $null
    try {
        # Search from the object itself rather than the domain root: an exact
        # base-scope bind cannot accidentally match a different object, and it
        # does not depend on knowing the naming context.
        $root = New-Object System.DirectoryServices.DirectoryEntry(('LDAP://' + $DistinguishedName))
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        $searcher.Filter = '(objectClass=*)'
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
        $searcher.SecurityMasks = $script:AllSecurityMask
        [void] $searcher.PropertiesToLoad.Add('ntSecurityDescriptor')

        $result = $searcher.FindOne()
        if ($null -eq $result) { return $null }
        if (-not $result.Properties.Contains('ntsecuritydescriptor')) { return $null }

        # A caller without SeSecurityPrivilege gets a descriptor with NO SACL
        # rather than an error, which is why nothing downstream treats an empty
        # SACL as proof of anything.
        $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $security.SetSecurityDescriptorBinaryForm(
            [byte[]] $result.Properties['ntsecuritydescriptor'][0])
        return $security
    }
    finally {
        if ($null -ne $searcher) { $searcher.Dispose() }
        if ($null -ne $root) { $root.Dispose() }
    }
}

function Save-AdObjectSecurity {
    <#
        Writes a modified descriptor back by setting ntSecurityDescriptor to its
        binary form.

        CommitChanges on a DirectoryEntry whose ObjectSecurity was modified is
        not available here - see Get-AdObjectSecurityObject for why the SACL
        cannot be modified through that path at all. Writing the attribute
        directly is what works, proven on the lab: one audit rule added, the
        DACL byte-identical afterwards, and a second identical add left the
        count unchanged rather than duplicating the ACE.

        The caller must have already asserted the DACL is unchanged. This is a
        read-modify-write of the WHOLE descriptor, so that assertion is what
        keeps the promise that no DACL is ever modified - and it is asserted
        again after the write, against the pre-change snapshot.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $DistinguishedName,
        [Parameter(Mandatory = $true)] $Security
    )

    $entry = $null
    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry(('LDAP://' + $DistinguishedName))
        $entry.Properties['ntSecurityDescriptor'].Value = $Security.GetSecurityDescriptorBinaryForm()
        $entry.CommitChanges()
    }
    finally {
        if ($null -ne $entry) { $entry.Dispose() }
    }
}

function Get-AdObjectSecurityState {
    param([Parameter(Mandatory = $true)][string] $DistinguishedName)

    $security = Get-AdObjectSecurityObject -DistinguishedName $DistinguishedName
    if ($null -eq $security) {
        throw ('Could not read the security descriptor of ' + $DistinguishedName +
               ': the object was not found, or ntSecurityDescriptor was not returned.')
    }
    return (New-AdSecuritySnapshot -Security $security -DistinguishedName $DistinguishedName)
}

function Assert-DaclUnchanged {
    <#
        The guard this whole script is built around. Three independent checks,
        because this runs against the object that controls the ACLs of every
        protected group in the domain and one bug must not be able to disable
        the proof:

          1. the DACL's raw bytes are identical;
          2. owner and group are identical;
          3. decoded per-principal masks show nobody gained a right and no deny
             ACE was dropped - the same discipline as
             Protect-EventLogs' Assert-SddlNotMorePermissive.

        Check 3 is redundant given check 1, and that is the point: they fail
        independently. A missing DACL on either side is a refusal, never a pass.
    #>
    param(
        [Parameter(Mandatory = $true)] $Before,
        [Parameter(Mandatory = $true)] $After,
        [Parameter(Mandatory = $true)][string] $DistinguishedName
    )

    if ($null -eq $Before.DaclFingerprint -or $null -eq $After.DaclFingerprint) {
        throw ('Refusing to proceed on ' + $DistinguishedName +
               ': the DACL is not visible on one side of the comparison, so it cannot be proven unchanged.')
    }
    if (-not [string]::Equals($Before.DaclFingerprint, $After.DaclFingerprint,
                              [System.StringComparison]::Ordinal)) {
        throw ('DACL CHANGED on ' + $DistinguishedName +
               '. This script must never do that. Refusing to continue; the previous descriptor is in ' +
               'the manifest for this run.')
    }
    if (-not [string]::Equals($Before.Owner, $After.Owner, [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($Before.Group, $After.Group, [System.StringComparison]::Ordinal)) {
        throw ('Owner or primary group changed on ' + $DistinguishedName + '. Refusing to continue.')
    }

    $beforeMap = Get-DaclAceMap -Sddl $Before.FullSddl
    $afterMap  = Get-DaclAceMap -Sddl $After.FullSddl
    if ($null -eq $beforeMap -or $null -eq $afterMap) {
        throw ('Refusing to proceed on ' + $DistinguishedName + ': the DACL could not be decoded.')
    }
    foreach ($key in $afterMap.Keys) {
        if (-not $beforeMap.ContainsKey($key)) {
            throw ('Refusing to write ' + $DistinguishedName + ': the DACL would gain an entry (' +
                   $key + ').')
        }
        $gained = $afterMap[$key] -band (-bnot $beforeMap[$key])
        if ($gained -ne 0) {
            throw ('Refusing to write ' + $DistinguishedName + ': ' + $key + ' would GAIN access mask 0x' +
                   ('{0:X}' -f $gained) + '.')
        }
    }
    foreach ($key in $beforeMap.Keys) {
        if ($key.StartsWith('DENY|', [System.StringComparison]::Ordinal) -and
            -not $afterMap.ContainsKey($key)) {
            throw ('Refusing to write ' + $DistinguishedName + ': it would drop a deny ACE (' + $key + ').')
        }
    }
}

#endregion

#region SACL changes ----------------------------------------------------------

function Get-IntendedAuditFlag {
    <#
        Success alone by default, which is the configuration Microsoft's own
        Defender for Identity instructions ask for. -IncludeFailureAuditing adds
        Failure; a failed attempt on AdminSDHolder is arguably the more
        interesting event, which is why the switch exists and why it is not the
        default (volume, and an unproven script should not pick the noisier
        option on a client's DC).
        https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.auditflags
    #>
    $flags = [System.Security.AccessControl.AuditFlags]::Success
    if ($IncludeFailureAuditing) {
        $flags = ([System.Security.AccessControl.AuditFlags]::Success -bor
                  [System.Security.AccessControl.AuditFlags]::Failure)
    }
    return [System.Security.AccessControl.AuditFlags] $flags
}

function Test-AuditRuleCovered {
    <#
        True when the object already carries an explicit audit rule for Everyone
        that covers at least what this script would add, with the same
        inheritance and no per-attribute restriction.

        "Covers at least" and not "equals", so an administrator who already
        audits MORE than this asks for does not get a second, narrower ACE
        stacked on top - that is what makes -Apply idempotent here.
    #>
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)][int] $Rights,
        [Parameter(Mandatory = $true)][int] $AuditFlag,
        [Parameter(Mandatory = $true)][string] $Inheritance
    )

    $emptyGuid = [System.Guid]::Empty.ToString()
    foreach ($rule in $Snapshot.AuditRule) {
        if ($rule.IsInherited) { continue }
        if (-not [string]::Equals($rule.Sid, $script:EveryoneSid, [System.StringComparison]::Ordinal)) { continue }
        if (($rule.AuditFlags -band $AuditFlag) -ne $AuditFlag) { continue }
        if (-not [string]::Equals($rule.InheritanceType, $Inheritance,
                                  [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if (-not [string]::Equals($rule.ObjectType, $emptyGuid, [System.StringComparison]::Ordinal)) { continue }
        if (($rule.Rights -band $Rights) -ne $Rights) { continue }
        return $true
    }
    return $false
}

function Write-ExistingAuditReport {
    <#
        Read-only: what is already audited on this object that this toolkit did
        not put there. An MSP inheriting an environment wants to know that
        somebody else has been here - and an empty SACL is reported as
        AMBIGUOUS, because a SACL this account may not read comes back looking
        exactly like a SACL that is not there.
    #>
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)][int] $Rights,
        [Parameter(Mandatory = $true)][int] $AuditFlag,
        [Parameter(Mandatory = $true)][string] $Inheritance
    )

    if ($Snapshot.AuditRule.Count -eq 0) {
        Write-Info 'no audit entries visible on this object - which means either none are set, or this'
        Write-Info 'account cannot read the SACL. Those two are indistinguishable from here.'
        return
    }

    $reported = 0
    foreach ($rule in $Snapshot.AuditRule) {
        $isOurs = ([string]::Equals($rule.Sid, $script:EveryoneSid, [System.StringComparison]::Ordinal) -and
                   -not $rule.IsInherited -and
                   ($rule.Rights -band $Rights) -eq $Rights -and
                   ($rule.AuditFlags -band $AuditFlag) -eq $AuditFlag -and
                   [string]::Equals($rule.InheritanceType, $Inheritance,
                                    [System.StringComparison]::OrdinalIgnoreCase))
        if ($isOurs) { continue }
        $source = 'explicit'
        if ($rule.IsInherited) { $source = 'inherited' }
        Write-Info ('  existing audit entry (' + $source + '): ' + (Get-SidDisplayName -Sid $rule.Sid) +
                    ' rights 0x' + ('{0:X}' -f $rule.Rights) + ' flags ' + [string] $rule.AuditFlags +
                    ' scope ' + $rule.InheritanceType)
        $reported++
    }
    if ($reported -eq 0) { Write-Info '  no audit entries beyond the one this script manages' }
}

function Set-TrackedObjectSacl {
    <#
        Adds one audit ACE to one object. Records the previous SACL first, proves
        the DACL is untouched twice - once in memory before the commit, once
        against a fresh read afterwards - and returns 1 if it changed something.

        The write path deliberately re-reads the object rather than reusing the
        snapshot taken for the report: between the two reads somebody could have
        changed the descriptor, and adding an ACE onto a stale copy would write
        back whatever it held. If the two reads disagree, this refuses.
    #>
    param(
        [Parameter(Mandatory = $true)] $Target,
        [Parameter(Mandatory = $true)][string] $DomainDn
    )

    $dn = ($Target.RelativeDn + ',' + $DomainDn)
    $auditFlag = Get-IntendedAuditFlag
    $auditFlagInt = [int] $auditFlag

    Write-Section ($Target.Title + ' - ' + $dn)
    Write-Info $Target.Why

    $before = $null
    try { $before = Get-AdObjectSecurityState -DistinguishedName $dn }
    catch {
        Write-Finding ('cannot read the security descriptor of ' + $dn + ': ' + $_.Exception.Message)
        return 0
    }

    if ($null -eq $before.DaclFingerprint) {
        Write-Finding ('the DACL of ' + $dn + ' is not visible, so the guard that proves this script did ' +
                       'not touch it cannot run. Refusing to write a SACL here.')
        return 0
    }

    Write-ExistingAuditReport -Snapshot $before -Rights $script:AuditRightMask `
        -AuditFlag $auditFlagInt -Inheritance $Target.Inheritance

    if (Test-AuditRuleCovered -Snapshot $before -Rights $script:AuditRightMask `
            -AuditFlag $auditFlagInt -Inheritance $Target.Inheritance) {
        Write-Ok 'the audit ACE is already present'
        return 0
    }

    $description = ('audit ACE for Everyone (rights 0x' + ('{0:X}' -f $script:AuditRightMask) +
                    ', ' + [string] $auditFlag + ', scope ' + $Target.Inheritance + ') on ' + $dn)

    if (-not $Apply) {
        Write-Finding ('would add an ' + $description)
        return 0
    }

    try {
        $security = Get-AdObjectSecurityObject -DistinguishedName $dn
        if ($null -eq $security) { throw ('Could not re-read the descriptor of ' + $dn + '. Refusing.') }

        $reread = New-AdSecuritySnapshot -Security $security -DistinguishedName $dn
        # Text comparison is legitimate HERE and nowhere else in this script:
        # both strings were produced by the same .NET generator in the same
        # process seconds apart, so any difference means the object really
        # changed between the two reads. Refusing is the safe direction.
        if (-not [string]::Equals($reread.FullSddl, $before.FullSddl, [System.StringComparison]::Ordinal)) {
            throw ('The descriptor of ' + $dn + ' changed between the read and the write. Refusing.')
        }

        $identity = New-Object System.Security.Principal.SecurityIdentifier($script:EveryoneSid)
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
            $identity,
            ([System.DirectoryServices.ActiveDirectoryRights] $script:AuditRightMask),
            $auditFlag,
            ([System.DirectoryServices.ActiveDirectorySecurityInheritance] $Target.Inheritance))
        [void] $security.AddAuditRule($rule)

        $pending = New-AdSecuritySnapshot -Security $security -DistinguishedName $dn
        Assert-DaclUnchanged -Before $reread -After $pending -DistinguishedName $dn

        # ObjectSecurity.AccessRulesModified / OwnerModified / GroupModified look
        # like the obvious third guard here, and they are NOT USABLE: verified by
        # reflection on this dev box, all three are non-public, so
        # '$security.AccessRulesModified' from PowerShell silently evaluates to
        # $null and 'if ($security.AccessRulesModified) { throw }' would be a
        # guard that can never fire. Exactly the trap docs/AUTHORING.md warns
        # about under "never trust an ACL helper's return value", one level up.
        # The byte comparison and the independent mask decode inside
        # Assert-DaclUnchanged are the checks that actually run.

        # Recorded and flushed BEFORE the commit. previousFullSddl is the whole
        # descriptor, DACL included: it is not used by -Rollback, which only ever
        # touches the SACL, but if this script ever did damage a DACL that record
        # is what an operator would rebuild from.
        [void] (Write-ManifestChange -Change @{
            type              = 'adobjectsacl'
            distinguishedName = $dn
            previousSacl      = $reread.SaclSddl
            newSacl           = $pending.SaclSddl
            previousFullSddl  = $reread.FullSddl
            description       = $description
        })

        # The whole descriptor goes back, Owner, Group, DACL and SACL together,
        # with a DACL that Assert-DaclUnchanged has just proven byte-identical to
        # what was read seconds earlier. The post-write check below is what turns
        # that into evidence rather than an argument.
        Save-AdObjectSecurity -DistinguishedName $dn -Security $security
    }
    catch {
        throw
    }

    $after = Get-AdObjectSecurityState -DistinguishedName $dn
    Assert-DaclUnchanged -Before $before -After $after -DistinguishedName $dn
    if (-not (Test-AuditRuleCovered -Snapshot $after -Rights $script:AuditRightMask `
                -AuditFlag $auditFlagInt -Inheritance $Target.Inheritance)) {
        throw ('The audit ACE did not read back on ' + $dn + '.')
    }
    Write-Ok ('added the ' + $description + ' - DACL proven unchanged')
    return 1
}

function New-AuditRuleFromAce {
    <#
        One ActiveDirectoryAuditRule from a recorded SACL ACE. Shared by the
        removal and the re-add paths in Restore-ObjectSacl so the two can never
        disagree about how an ACE maps to a rule - if they did, the rollback
        would remove one thing and put back a subtly different one, and the
        equality check would fail for a reason nobody could read.
    #>
    param(
        [Parameter(Mandatory = $true)] $Security,
        [Parameter(Mandatory = $true)] $Ace
    )

    $identity = New-Object System.Security.Principal.SecurityIdentifier($Ace.Sid)
    return $Security.AuditRuleFactory(
        $identity,
        $Ace.Mask,
        $Ace.IsInherited,
        ([System.Security.AccessControl.InheritanceFlags] $Ace.InheritanceFlags),
        ([System.Security.AccessControl.PropagationFlags] $Ace.PropagationFlags),
        ([System.Security.AccessControl.AuditFlags] $Ace.AuditFlags),
        $Ace.ObjectType,
        $Ace.InheritedObjectType)
}

function Restore-ObjectSacl {
    <#
        Returns 'restored' or 'declined'; throws on a failed write.

        Removes exactly the ACEs the recorded change added - the difference
        between the recorded new SACL and the recorded previous one - and then
        checks, before committing, that what is left equals the recorded previous
        SACL. It never writes a recorded SDDL blob back onto the object: on
        AdminSDHolder, "remove what I added and prove the result matches what was
        there" is a much smaller promise than "overwrite the SACL with this
        string".

        # UNVERIFIED: whether RemoveAuditRuleSpecific followed by CommitChanges
        reproduces the recorded previous SACL byte for byte, or whether .NET
        canonicalisation reorders or merges what is left. If it does not match,
        this declines rather than guessing, and the recorded previousSacl and
        previousFullSddl are in the manifest for an operator to work from.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $dn = [string] $change.distinguishedName

    $current = Get-AdObjectSecurityState -DistinguishedName $dn
    if ($null -eq $current.DaclFingerprint) {
        Write-Finding ($dn + ': the DACL is not visible, so nothing can be proven here. Leaving it alone.')
        return 'declined'
    }

    $recordedNew = Get-SaclAceMap -Sddl ([string] $change.newSacl)
    $recordedOld = Get-SaclAceMap -Sddl ([string] $change.previousSacl)
    $live = Get-SaclAceMap -Sddl $current.SaclSddl

    if (-not (Test-AceMapEqual -Left $live -Right $recordedNew)) {
        # CASE 2 of the rollback doctrine (docs/DESIGN.md 4.1). A SACL that
        # equals the recorded PREVIOUS state means the write never landed, or
        # this rollback already ran. Both mean there is nothing to do and nothing
        # wrong - so this is 'restored', not a decline.
        #
        # It used to decline here while its own message said "nothing to undo",
        # which is the contradiction the doctrine exists to remove: the run then
        # never finished, and Test-VisibilityDrift went on expecting the change.
        if (Test-AceMapEqual -Left $live -Right $recordedOld) {
            Write-Ok ($dn + ': the SACL already equals the recorded previous state - either the change ' +
                      'never landed or it has already been undone. Nothing to restore.')
            return $script:RollbackRestored
        }

        # Case 3: neither state. Something else has written this SACL since.
        Write-Finding ($dn + ': the SACL matches neither what this run wrote nor what was recorded ' +
                       'before it; leaving it alone. If a LATER run of this script wrote it, this one ' +
                       'can never resolve - close it with -Rollback -AbandonRun ' +
                       [string] $ChangeRecord.runId + '.')
        return $script:RollbackDeclined
    }

    $toRemove = New-Object System.Collections.ArrayList
    foreach ($key in $recordedNew.Keys) {
        if (-not $recordedOld.ContainsKey($key)) { [void] $toRemove.Add($recordedNew[$key]) }
    }
    if ($toRemove.Count -eq 0) {
        Write-Finding ($dn + ': the recorded change added no audit ACE, so there is nothing to remove.')
        return $script:RollbackDeclined
    }

    try {
        $security = Get-AdObjectSecurityObject -DistinguishedName $dn
        if ($null -eq $security) { throw ('Could not read the descriptor of ' + $dn + '. Refusing.') }

        foreach ($ace in $toRemove) {
            [void] $security.RemoveAuditRuleSpecific((New-AuditRuleFromAce -Security $security -Ace $ace))
        }

        # PUT BACK WHAT THE ADD SWALLOWED (the review log kept in the development repository, AD-1).
        #
        # AddAuditRule MERGES rather than appends: for the same SID, audit flags
        # and inheritance scope it ORs the rights masks into the EXISTING ACE
        # instead of adding a second one. Measured on AdminSDHolder, which ships
        # an explicit 0xC0020 Success/None audit ACE - adding 0xD016B Success/None
        # produced ONE ACE at 0xD016B, because 0xC0020 -bor 0xD016B = 0xD016B.
        #
        # So "remove the ACE we added" removes the pre-existing one with it: the
        # two are the same ACE. On the object whose ACL is stamped onto every
        # protected group in the domain, that is the silent loss of an audit
        # setting somebody else put there, and on the lab it had to be restored
        # by hand.
        #
        # Removing then re-adding keeps the promise this script makes - it never
        # writes a recorded SDDL blob wholesale over a live descriptor - while
        # repairing the merge. The equality check below is what proves it worked;
        # it is not decoration.
        $afterRemoval = Get-SaclAceMap -Sddl (
            (New-AdSecuritySnapshot -Security $security -DistinguishedName $dn).SaclSddl)
        $toRestore = New-Object System.Collections.ArrayList
        foreach ($key in $recordedOld.Keys) {
            if ($afterRemoval.ContainsKey($key)) { continue }
            # Inherited ACEs are not ours to write: they come from the parent and
            # reappear on their own. Only an explicit ACE can have been swallowed.
            if ($recordedOld[$key].IsInherited) { continue }
            [void] $toRestore.Add($recordedOld[$key])
        }
        foreach ($ace in $toRestore) {
            Write-Info ($dn + ': re-adding the pre-existing audit ACE that AddAuditRule merged into ' +
                        'this run''s - rights 0x' + ('{0:X}' -f [int] $ace.Mask) + ', ' +
                        [string] $ace.AuditFlags + ', scope ' + [string] $ace.InheritanceFlags)
            [void] $security.AddAuditRule((New-AuditRuleFromAce -Security $security -Ace $ace))
        }

        $pending = New-AdSecuritySnapshot -Security $security -DistinguishedName $dn
        $pendingMap = Get-SaclAceMap -Sddl $pending.SaclSddl
        if (-not (Test-AceMapEqual -Left $pendingMap -Right $recordedOld)) {
            Write-Finding ($dn + ': removing the recorded ACEs would not reproduce the recorded previous ' +
                           'SACL, so this leaves the object alone. The previous SACL is in the manifest.')
            return $script:RollbackDeclined
        }
        Assert-DaclUnchanged -Before $current -After $pending -DistinguishedName $dn

        Save-AdObjectSecurity -DistinguishedName $dn -Security $security
    }
    catch {
        throw
    }

    $after = Get-AdObjectSecurityState -DistinguishedName $dn
    Assert-DaclUnchanged -Before $current -After $after -DistinguishedName $dn
    if (-not (Test-AceMapEqual -Left (Get-SaclAceMap -Sddl $after.SaclSddl) -Right $recordedOld)) {
        throw ('The SACL of ' + $dn + ' did not read back as the recorded previous SACL.')
    }
    Write-Ok ('Restored the SACL on ' + $dn + ' - DACL proven unchanged')
    return 'restored'
}

#endregion

#region Checks ----------------------------------------------------------------

function Invoke-HostCheck {
    <#
        Prerequisite first, then the three objects, then the read-only placement
        report. The order is the reading order an operator needs: a SACL is
        worthless without the audit policy above it.
    #>
    param(
        [Parameter(Mandatory = $true)] $Role,
        [Parameter(Mandatory = $true)][string] $WorkDirectory
    )

    Write-Info ($Role.RoleName + ' in domain "' + $Role.Domain + '"')
    $domainDn = Get-DomainNamingContext
    Write-Info ('domain naming context: ' + $domainDn)

    $changeCount = 0
    $changeCount += Set-DsAccessAuditPolicy -WorkDirectory $WorkDirectory
    foreach ($target in $script:SaclTarget) {
        $changeCount += Set-TrackedObjectSacl -Target $target -DomainDn $domainDn
    }
    Write-DomainControllerPlacementReport -DomainDn $domainDn `
        -DefaultOu ('OU=Domain Controllers,' + $domainDn)
    return $changeCount
}

#endregion

#region Main -----------------------------------------------------------------

function Restore-AdAuditingChange {
    <#
        Routes a change record to the right restorer. This script does not carry
        the template's Registry region - it changes no registry value - so there
        is no Restore-TrackedChange to delegate to, and an unknown change type is
        DECLINED rather than reported as restored. Silently "succeeding" on a
        change type it cannot undo is how a run gets marked rolled back while the
        host stays modified.

        Returns 'restored' or 'declined'; throws on failure.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    switch ([string] $change.type) {
        'adobjectsacl' { return (Restore-ObjectSacl -ChangeRecord $ChangeRecord) }
        'auditpol' {
            # Case 2 (docs/DESIGN.md section 4.1): the effective policy may already BE
            # the recorded pre-apply policy - either -Apply never landed or this has
            # already been rolled back. Nothing to do, counted 'restored' so the run
            # converges. Before this the branch called auditpol /restore blindly and
            # reported "Restored" either way.
            #
            # CASE 3 IS NOT COVERED HERE, and that is stated rather than hidden:
            # 'auditpol /restore' rewrites the WHOLE policy from the backup, so a
            # subcategory an operator changed AFTER the -Apply is overwritten by it.
            # Narrowing that needs a per-subcategory resolution rather than a
            # whole-file restore, which is a larger change than this one. The
            # 'expectation' record Set-DsAccessAuditPolicy now writes (AT-2)
            # carries the subcategory list such a resolution would need; nothing
            # reads it here yet, and saying so is better than implying it does.
            if (Test-AuditPolicyMatchesBackup -BackupPath ([string] $change.backupPath)) {
                Write-Ok ('the audit policy already equals the state recorded in ' +
                          [System.IO.Path]::GetFileName([string] $change.backupPath) +
                          '; nothing to undo.')
                return 'restored'
            }

            Restore-AuditPolicyFromBackup -BackupPath $change.backupPath
            Write-Ok ('Restored the audit policy from ' +
                      [System.IO.Path]::GetFileName([string] $change.backupPath))
            return 'restored'
        }
        default {
            Write-Finding ('Cannot roll back change type "' + [string] $change.type +
                           '" - not implemented in this script.')
            return 'declined'
        }
    }
}

function Invoke-Main {
    $mode = 'Audit'
    if ($Apply)    { $mode = 'Apply' }
    if ($Rollback) { $mode = 'Rollback' }

    Write-Host ''
    Write-Host ('IronBlackBox - ' + $script:ScriptName + ' v' + $script:ScriptVersion + ' [' + $mode + ']') -ForegroundColor White
    Write-Host '  It adds AUDIT entries only. It never modifies a DACL, and it proves that.' -ForegroundColor Yellow

    # P-1: value checks BEFORE anything is read, locked or changed. These were
    # [Validate*] attributes; a binding-time failure exits 1, which collides with
    # "findings" (docs/DESIGN.md section 3). A throw here reaches exit 2.
    Assert-ParameterRange   -Name 'LdapPageSize' -Value $LdapPageSize -Minimum 1 -Maximum 1000
    Assert-ParameterRange   -Name 'LdapResultCap' -Value $LdapResultCap -Minimum 1 -Maximum 100000

    # -AbandonRun ALREADY names the run to act on, so a -RunId naming a different
    # one is a contradiction, not a preference - and the parameter sets accept the
    # pair. The resolution below used to compute the -RunId target and then throw
    # it away, so this combination acted silently on the abandoned run; worse, a
    # -RunId whose run was already rolled back made Get-RollbackTargetRun throw
    # and the run exit 2, defeating the escape hatch docs/DESIGN.md section 4.2
    # exists to provide, after the abandon target had already been approved.
    if (-not [string]::IsNullOrWhiteSpace($AbandonRun) -and
        -not [string]::IsNullOrWhiteSpace($RunId) -and
        -not [string]::Equals($RunId.Trim(), $AbandonRun.Trim(),
                              [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('-RunId ' + $RunId + ' and -AbandonRun ' + $AbandonRun + ' name different runs. ' +
               '-AbandonRun names the run to act on by itself; pass one or the other.')
    }

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')
    Assert-DirectoryServiceType

    # Suitability gate. Not applicable is exit 0 with a clear message: never a
    # finding (an RMM must not alert on a file server for not being a DC) and
    # never an error. Deliberately BEFORE the lock and the manifest, so an
    # -Apply on the wrong host writes nothing at all - not even a run record.
    #
    # -Rollback is exempt: the manifest, not the host's current role, is the
    # authority on what this toolkit changed.
    if ($mode -ne 'Rollback') {
        $role = Get-HostRoleState
        Write-Section 'Host role'
        if (-not $role.IsDomainController) {
            Write-Info ($role.RoleName + ' (DomainRole ' + [string] $role.DomainRole + ')')
            Write-Section 'Result'
            Write-Ok 'Not a domain controller: nothing in this script applies here. Nothing was changed.'
            Write-Info 'Directory object SACLs are set on a DC, against the domain this DC belongs to.'
            return 0
        }
    }

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        # auditpol needs somewhere to write its probe file, and -Audit must not
        # write into the toolkit root - so it scratches in the OS temp directory
        # and deletes what it wrote. The DNs reported are the real ones.
        [void] (Invoke-HostCheck -Role $role `
                    -WorkDirectory ([System.IO.Path]::GetTempPath().TrimEnd('\')))
        Write-Section 'Result'
        if ($script:Findings.Count -gt 0) {
            Write-Info ([string] $script:Findings.Count + ' finding(s). Re-run with -Apply to set them.')
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
        Write-Ok 'No findings: DS Access auditing is on and all three objects carry the audit ACE.'
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
                includeFailureAuditing = [bool] $IncludeFailureAuditing
                auditRightMask         = $script:AuditRightMask
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
                $verified = Invoke-HostCheck -Role $role -WorkDirectory $resolvedRoot
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
            Write-Info 'The audit policy is effective immediately. A SACL takes effect on the DC that holds'
            Write-Info 'it as soon as it replicates, so events appear on whichever DC the change is made'
            Write-Info 'against. THIS WAS NOT VERIFIED HERE - no domain controller has run this script.'
            Write-Info 'Prove it the only way that counts: modify a test GPO and look for 5136 in Security.'
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

        # Resolved ONCE. Two calls meant the -RunId one ran first and could throw
        # ("Run <id> has already been rolled back.") before the -AbandonRun target
        # was ever reached - see the guard in the parameter checks above.
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
                $outcome = Restore-AdAuditingChange -ChangeRecord $target.Changes[$i]
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
        #
        # AND THERE HAS TO BE SOMETHING TO ABANDON. Without the count below, an
        # operator who reached for -AbandonRun on a run that then rolled back
        # perfectly got 'completed-abandoned-by-operator' on the forensic record
        # and exit 1 - a clean rollback permanently mislabelled as an operator
        # giveup, and reported as one by Test-VisibilityDrift on every later run
        # (docs/DESIGN.md section 4.2, property 4). Nothing was left undone, so
        # the honest answer is the ordinary completed path and exit 0.
        $abandonable = @($declinedIds).Count + @($permanentIds).Count
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun) -and $failures -eq 0 -and $abandonable -eq 0) {
            Write-Info ('Nothing needed abandoning: every change in run ' + $target.RunId +
                        ' restored cleanly, so this is recorded as an ordinary completed rollback.')
        }
        if (-not [string]::IsNullOrWhiteSpace($AbandonRun) -and $failures -eq 0 -and $abandonable -gt 0) {
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

