<#
.SYNOPSIS
    Installs and configures Sysmon from a binary the operator has already
    staged on the host, after verifying that binary is signed by Microsoft.

.DESCRIPTION
    Sysmon is the single largest upgrade to a Windows host's forensic record:
    process creation with hashes and parent lineage, image loads, network
    connections, WMI persistence and named pipes, all in one channel. It is not
    part of Windows, so this script's job is to install it, point it at a
    configuration, and record enough to put the host back.

    THE TOOLKIT NEVER DOWNLOADS AND EXECUTES AT RUNTIME. That is a stated
    non-goal in docs/DESIGN.md section 8: SYSTEM + PowerShell + download +
    execute is a pattern EDRs flag, correctly, and this project does not ask an
    MSP to make an exception for it. The operator stages Sysmon64.exe and the
    configuration XML - by the release ZIP, by the RMM's own file transfer, by
    hand - and points -SysmonPath and -ConfigPath at them. Nothing is fetched,
    and nothing fetched is executed.

    THE NETWORK POSTURE, EXACTLY, for whoever has to whitelist this in an EDR.
    One thing here can make an outbound request, on every mode including the
    read-only default: the Authenticode gate builds the certificate chain with
    X509RevocationMode::Online, which reaches a CRL or OCSP responder when the
    host can. That is deliberate - a revocation check is worth making - and a
    check that cannot complete is tolerated rather than fatal, so an
    egress-filtered endpoint still installs. See $script:ToleratedChainFlags.

    Before the staged binary is executed at all, its Authenticode signature is
    verified as Microsoft's (docs/DESIGN.md section 7, docs/AUTHORING.md "Safety").
    Both the signature status AND the signer subject are checked: a valid
    signature by somebody else is not the same thing as a Microsoft signature,
    and the .NET documentation for SignatureStatus is explicit that Valid
    "means only that the signature is syntactically valid. It does not imply
    trust in any way"
    (https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.signaturestatus),
    so the certificate chain is built and inspected separately. No signature,
    no execution - the script reports a finding and stops. Sysinternals
    binaries are Microsoft-signed; if this check fails, that is exactly the
    case the gate exists for, and the actual signer subject is printed so the
    operator can see what they staged.

    NO CONFIGURATION IS SHIPPED AND NONE IS FETCHED. docs/SCRIPTS.md names
    Olaf Hartong's sysmonconfig.xml as the recommended starting point
    (https://github.com/olafhartong/sysmon-modular) and that recommendation
    stays a recommendation: a third-party configuration embedded in this file
    would become this project's to maintain, and fetching one at runtime is the
    non-goal above. -ConfigPath is therefore effectively mandatory. Sysmon
    installed with no configuration logs almost nothing an incident responder
    can use, so this script refuses to install without one rather than
    delivering a service that looks armed and is not.

    WHAT THIS SCRIPT DELIBERATELY DOES NOT DO:
      - Download anything. See above. There is no -Download switch and there
        will not be one.
      - Ship, generate or modify a Sysmon configuration. It installs the file
        it is given, byte for byte, and archives a copy so -Rollback has
        something to restore.
      - Replace a Sysmon configuration this toolkit did not apply, unless
        -ReplaceForeignConfig is passed. 'Sysmon64.exe -c' dumps the ACTIVE
        configuration as human-readable text, and that text is NOT a valid
        configuration file - it cannot be fed back to 'Sysmon64.exe -c'. So a
        configuration installed by somebody else cannot be captured in a
        restorable form, and replacing it silently would be the unrecoverable
        change docs/DESIGN.md section 4 exists to prevent.
      - Tune the configuration for the host, exclude noisy processes, or size
        the Sysmon channel. Channel sizing belongs to the event log policy in
        Enable-IRVisibility.
      - Uninstall a Sysmon that predates this toolkit. -Rollback undoes what a
        recorded -Apply did and nothing else.
      - Search for Sysmon.exe (32-bit). 64-bit hosts are the target; a 32-bit
        host must be given -SysmonPath explicitly.

    tools/check.ps1 proves syntax and API surface and nothing else
    (docs/DESIGN.md section 9); docs/VALIDATION.md is the only file allowed to
    say where this script has run, and its row is the one to read before
    deploying.

    One path is called out because its row does NOT cover it: -Apply with a
    DIFFERENT -ConfigPath against an already-installed Sysmon, which takes the
    configuration-update path ('-c') rather than the install path ('-i'). See
    the '-accepteula' note further down for why that combination matters.
         without -ReplaceForeignConfig.

.PARAMETER Audit
    Default. Strictly read-only. Reports whether Sysmon is installed, at what
    version, whether a configuration is loaded, and exactly what -Apply would
    run. The only thing it executes is the gated binary with 'Sysmon64.exe -c',
    which Microsoft documents as dumping the current configuration
    (https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

.PARAMETER Apply
    Installs Sysmon with the given configuration, or updates the configuration
    of an installed Sysmon. These are two different Sysmon operations ('-i' and
    '-c') and the script detects which one the host needs; conflating them
    fails.

.PARAMETER Rollback
    Restores the previous state recorded by a prior -Apply: the previously
    archived configuration, or an uninstall if Sysmon was not installed before.

.PARAMETER ToolkitRoot
    Base directory for the manifest and for the archived configurations and
    configuration dumps this script writes under <ToolkitRoot>\Sysmon.
    Default C:\ProgramData\IronBlackBox. Validated before use.

.PARAMETER SysmonPath
    Full path to a staged Sysmon64.exe. If omitted, a short list of local
    locations is searched (the toolkit root, <ToolkitRoot>\Sysmon, the
    directory holding this script, and PATH). Never downloaded.

.PARAMETER ConfigPath
    Full path to the Sysmon configuration XML to install. Effectively
    mandatory: without it this script reports a finding and installs nothing.

.PARAMETER ReplaceForeignConfig
    Acknowledges that the Sysmon configuration currently on the host was not
    applied by this toolkit and cannot be captured in a restorable form, and
    that replacing it is therefore a one-way change. Without this switch such a
    host is reported as a finding and left alone.

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
    .\Enable-Sysmon.ps1
    Reports Sysmon's state on this host and what applying would do. Changes
    nothing.

.EXAMPLE
    .\Enable-Sysmon.ps1 -Apply -SysmonPath 'D:\stage\Sysmon64.exe' -ConfigPath 'D:\stage\sysmonconfig.xml'
    Verifies the binary is Microsoft-signed, installs Sysmon with that
    configuration, and records the previous state.

.EXAMPLE
    .\Enable-Sysmon.ps1 -Rollback
    Restores the configuration this toolkit replaced, or uninstalls Sysmon if
    it was not installed before the run being rolled back.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.0.0
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
    [string] $SysmonPath,

    [Parameter()]
    [string] $ConfigPath,

    [Parameter()]
    [switch] $ReplaceForeignConfig,

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

$script:ScriptName    = 'Enable-Sysmon'
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

#region Sysmon plumbing -------------------------------------------------------

function Get-FileSha256 {
    # Upper-case hex, or $null when the file is absent. Every archived config is
    # identified by this hash, and -Rollback refuses a backup whose hash does not
    # match what was recorded.
    param([Parameter(Mandatory = $true)][string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return ([string] (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash).ToUpperInvariant()
}

function Get-BinaryVersion {
    param([Parameter(Mandatory = $true)][string] $Path)
    try { return [string] ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)).FileVersion }
    catch {
        Write-Verbose ('Could not read the version of ' + $Path + ': ' + $_.Exception.Message)
        return ''
    }
}

#endregion

#region Authenticode gate -----------------------------------------------------

# The signer's ORGANISATION, matched as a whole RDN and never as a substring.
#
# Measured on Server 2019 rather than assumed. A real Sysmon64.exe carries
# "CN=Microsoft Windows Publisher, O=Microsoft Corporation, L=Redmond,
# S=Washington, C=US", while wevtutil.exe, powershell.exe and notepad.exe on the
# same host carry "CN=Microsoft Windows, O=..." - so the CN differs between
# Sysinternals and Windows builds and only the O is stable. That is why this
# gate tests O and not CN.
#
# The organisation is also the part a CA validates against a legal entity, which
# CN and OU are not. That distinction is the whole reason for matching an exact
# RDN: this check used to be a substring test over the flattened subject, and
# "CN=Evil Corp, OU=O=Microsoft Corporation, O=Evil Corp, C=RU" passed it, as
# did "O=Microsoft Corporation Ltd" - both measured. docs/AUTHORING.md names this defect
# by name: verification must be "anchored on RDN boundaries rather than as a
# substring".
#
# A rejection prints the ACTUAL subject and every parsed RDN: read them and
# change this value deliberately rather than deleting the check.
$script:MicrosoftSubjectRdn = 'O=Microsoft Corporation'

# X509ChainStatusFlags names that do not by themselves mean "do not execute".
# Compared by NAME, and anything absent is refused - so the construction fails
# CLOSED: a flag spelled differently than assumed here causes a refusal, never an
# acceptance. The revocation flags are tolerated because MSP endpoints are
# routinely egress-filtered, and refusing to install Sysmon because a CRL fetch
# failed would make this gate a denial of service against the toolkit itself.
$script:ToleratedChainFlags = @('NoError', 'RevocationStatusUnknown', 'OfflineRevocation')

function Get-CertificateSubjectRdn {
    <#
        Splits a certificate subject into its RDNs so the organisation can be
        compared as a whole value.

        X500DistinguishedName.Format($true) puts exactly one RDN per line, and it
        does the quoting and escaping that hand-splitting on ',' gets wrong the
        first time a value contains one. Measured on Server 2019: the five RDNs
        of a real Sysmon64.exe come back as C=US / S=Washington / L=Redmond /
        O=Microsoft Corporation / CN=Microsoft Windows Publisher.

        Returns an empty array when anything at all goes wrong, so the caller
        fails CLOSED - no RDNs means no match means no execution.
    #>
    param([Parameter(Mandatory = $true)] $Certificate)

    $name = $null
    try { $name = $Certificate.SubjectName } catch { return @() }
    if ($null -eq $name) { return @() }
    try {
        return @(($name.Format($true) -split "`r`n|`n") |
                 ForEach-Object { $_.Trim() } |
                 Where-Object { -not [string]::IsNullOrEmpty($_) })
    }
    catch { return @() }
}

function Assert-SysmonBinaryTrusted {
    <#
        The gate that has to hold, because everything past it executes a binary
        as SYSTEM. docs/AUTHORING.md: downloaded binaries "must have their Authenticode
        signature verified as Microsoft before execution". docs/DESIGN.md
        section 7: "No signature, no execution."

        Three checks, all of which must pass: Status is 'Valid', the signer
        subject names Microsoft, and a chain builds with no status flag outside
        the tolerated set. The chain check is not belt-and-braces - Microsoft's
        documentation for the SignatureStatus enumeration says of Valid: "This
        means only that the signature is syntactically valid. It does not imply
        trust in any way."
        https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.signaturestatus
        Nor is the subject check redundant: a validly signed, correctly chained
        binary signed by somebody else passes the other two completely.

        Returns $true only if the binary may be executed, and NEVER throws for an
        untrusted one - that is a finding (exit 1), not an execution error
        (exit 2). Called before EVERY execution of a Sysmon binary, the installed
        one included: a binary already on the host is not more trustworthy than a
        staged one, and an attacker who replaced Sysmon64.exe in place is exactly
        what this toolkit exists to survive.
    #>
    param([Parameter(Mandatory = $true)][string] $Path)

    $refuse = ('AUTHENTICODE GATE: refusing to execute ' + $Path + ' - ')
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Finding ($refuse + 'the file does not exist')
        return $false
    }
    $signature = $null
    try { $signature = Get-AuthenticodeSignature -LiteralPath $Path }
    catch {
        Write-Finding ($refuse + 'the signature could not be read: ' + $_.Exception.Message)
        return $false
    }

    $status = [string] $signature.Status
    if ($status -ne 'Valid') {
        Write-Finding ($refuse + 'status is ' + $status + ' (' + [string] $signature.StatusMessage + ')')
        Write-Info 'No signature, no execution (docs/DESIGN.md section 7). Nothing was changed.'
        return $false
    }
    $cert = $signature.SignerCertificate
    if ($null -eq $cert) {
        Write-Finding ($refuse + 'it reports Valid but carries no signer certificate')
        return $false
    }
    $subject = [string] $cert.Subject
    $rdns = @(Get-CertificateSubjectRdn -Certificate $cert)
    if ($rdns.Count -eq 0) {
        Write-Finding ($refuse + 'the signer subject could not be parsed into RDNs. Subject: ' + $subject)
        return $false
    }
    $organisationMatches = $false
    foreach ($rdn in $rdns) {
        if ($rdn -ieq $script:MicrosoftSubjectRdn) { $organisationMatches = $true; break }
    }
    if (-not $organisationMatches) {
        Write-Finding ($refuse + 'no RDN in the signer subject is exactly "' +
                       $script:MicrosoftSubjectRdn + '". Subject: ' + $subject)
        Write-Info ('parsed RDNs: ' + ($rdns -join ' | '))
        return $false
    }

    $timestamped = ($null -ne $signature.TimeStamperCertificate)
    $offending = New-Object System.Collections.ArrayList
    # Revocation checked online where the host can reach a responder; ExcludeRoot
    # skips the self-signed root, which nothing but a CTL update can revoke.
    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chain
    $chain = $null
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode =
            [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag =
            [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $built = $chain.Build($cert)
        foreach ($entry in $chain.ChainStatus) {
            $flagName = [string] $entry.Status
            if ($script:ToleratedChainFlags -contains $flagName) { continue }
            # UNVERIFIED: an Authenticode signature is understood to stay valid
            # past its signing certificate's expiry when countersigned, so
            # NotTimeValid on a timestamped binary is expected rather than wrong.
            # Never exercised against a real expired-certificate Sysmon build -
            # the weakest tolerance here, and the only one that is not "the
            # network was unreachable".
            if ($flagName -eq 'NotTimeValid' -and $timestamped) { continue }
            [void] $offending.Add($flagName)
        }
        # Build() saying no while reporting nothing this code recognises fails
        # closed rather than having a reason invented for it.
        if (-not $built -and $offending.Count -eq 0) { [void] $offending.Add('chain-did-not-build') }
    }
    catch {
        Write-Finding ($refuse + 'the certificate chain could not be built: ' + $_.Exception.Message)
        return $false
    }
    finally {
        if ($null -ne $chain) {
            try { $chain.Dispose() }
            catch { Write-Verbose ('Disposing the chain failed: ' + $_.Exception.Message) }
        }
    }
    if ($offending.Count -gt 0) {
        Write-Finding ($refuse + 'the chain reports ' + (($offending.ToArray()) -join ', '))
        return $false
    }

    Write-Ok ('Authenticode: ' + [System.IO.Path]::GetFileName($Path) + ' is signed by Microsoft')
    Write-Info ('signer: ' + $subject + ' | timestamped: ' + [string] $timestamped)
    return $true
}

#endregion

#region Sysmon discovery ------------------------------------------------------

# Everything here DISCOVERS rather than asserts. Sysmon's documentation lists a
# configuration entry "DriverName - String - Uses specified name for driver and
# service images" (https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
# so 'Sysmon64' and 'SysmonDrv' are defaults, not invariants. Same lesson as
# verification/facts.json, psv2-feature-names-differ-by-sku: a hard-coded name
# silently matches nothing on the host the script was not written for. This token
# only ever widens a search.
$script:SysmonNameToken = 'sysmon'

# UNVERIFIED: the EventLog channel NAME. Microsoft's Sysmon page documents the
# Event Viewer DISPLAY path - "events are stored in Applications and Services
# Logs/Microsoft/Windows/Sysmon/Operational" - not the channel identifier, so
# this literal is the conventional translation of that path and has not been read
# off a host. A hint only: the channel is located by wildcard, and this is
# reported as "expected" when the wildcard finds nothing.
$script:SysmonChannelExpected = 'Microsoft-Windows-Sysmon/Operational'

function Get-ImagePathExecutable {
    <#
        Turns a service or driver ImagePath into a filesystem path. Service image
        paths are quoted and may carry arguments; driver paths carry the
        object-manager prefix '\??\' or are relative to %SystemRoot%. Any of those
        handed straight to Get-AuthenticodeSignature yields "the file does not
        exist" - and through the gate, a refusal to run on a host that is fine.
    #>
    param([Parameter()][AllowEmptyString()][string] $ImagePath = '')

    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return '' }
    $text = ($ImagePath.Trim() -replace '^\\\?\?\\', '')
    if ($text.StartsWith('"')) {
        $closing = $text.IndexOf('"', 1)
        if ($closing -gt 0) { return $text.Substring(1, $closing - 1) }
        return $text.Trim('"')
    }
    $match = [regex]::Match($text, '^(?<path>.+?\.(exe|sys))(\s|$)', 'IgnoreCase')
    if ($match.Success) { $text = $match.Groups['path'].Value }
    if ([System.IO.Path]::IsPathRooted($text)) { return $text }
    $systemRoot = $env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($systemRoot)) { return $text }
    return [System.IO.Path]::Combine($systemRoot.TrimEnd('\'), $text.TrimStart('\'))
}

function Get-SysmonDriverFromRegistry {
    <#
        The Sysmon driver, found where Win32_SystemDriver cannot see it.

        MEASURED, and it is the reason this function exists. On the lab, with
        Sysmon installed and demonstrably recording (428 events in the channel,
        33 process-creation events in two minutes):

          Win32_SystemDriver              345 drivers, ZERO matching *sysmon*
                                          - and boot-start drivers ARE in that
                                            set (ACPI, CLFS, acpiex...), so the
                                            omission is specific, not a class
                                            of driver being excluded wholesale
          Get-Service SysmonDrv           Running / Boot
          sc.exe query SysmonDrv          exit 0, KERNEL_DRIVER, RUNNING
          fltmc filters                   SysmonDrv, 2 instances, altitude 385201
          HKLM\...\Services\SysmonDrv     Type=1, Start=0

        SysmonDrv is a file system MINIFILTER, and Win32_SystemDriver does not
        enumerate it. Trusting that one source made the script report "service
        present but no matching kernel driver - Sysmon collects nothing" about a
        host whose Sysmon was working perfectly. Declaring a working forensic
        recorder dead is worse than saying nothing: it sends a technician
        hunting a broken install that is not broken, and teaches them to
        distrust the output.

        HKLM\SYSTEM is not subject to WOW64 registry redirection - that applies
        to HKLM\SOFTWARE - so reading the service keys directly does not
        reintroduce the bitness problem Win32_SystemDriver was chosen to avoid.

        Type 1 is a kernel driver and Type 2 a file system driver:
        https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-addservice-directive
    #>
    param([Parameter(Mandatory = $true)][string] $Pattern)

    $found = New-Object System.Collections.ArrayList
    $servicesKey = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $children = @()
    try { $children = @(Get-ChildItem -LiteralPath $servicesKey -ErrorAction Stop) }
    catch { return $found.ToArray() }

    foreach ($child in $children) {
        $name = [string] $child.PSChildName
        $properties = $null
        try { $properties = Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction Stop }
        catch { continue }

        $imagePath = ''
        if ($null -ne $properties.PSObject.Properties['ImagePath'] -and $null -ne $properties.ImagePath) {
            $imagePath = [string] $properties.ImagePath
        }
        if (-not ($name -like $Pattern -or $imagePath -like $Pattern)) { continue }

        # Drivers only. The Sysmon SERVICE lives under the same key and is
        # already found through Win32_Service; counting it here would make a
        # driverless install look driver-backed, which is the opposite mistake.
        $type = -1
        if ($null -ne $properties.PSObject.Properties['Type'] -and $null -ne $properties.Type) {
            $type = [int] $properties.Type
        }
        if ($type -ne 1 -and $type -ne 2) { continue }

        $state = 'Unknown'
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service) { $state = [string] $service.Status }

        [void] $found.Add([PSCustomObject] @{ Name = $name; State = $state; PathName = $imagePath })
    }
    return $found.ToArray()
}

function Get-SysmonInstallState {
    <#
        Service, kernel driver, the binary behind the service and its version.

        Read through CIM rather than the registry on purpose: Win32_Service and
        Win32_SystemDriver are not subject to WOW64 registry redirection, so the
        answer does not depend on whether an RMM launched the 32-bit
        powershell.exe - the structural defect the template's Split-RegistryPath
        comment describes for HKLM\SOFTWARE.
        https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service
        https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemdriver
    #>
    $pattern = ('*' + $script:SysmonNameToken + '*')
    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
        Where-Object { $_.Name -like $pattern -or $_.PathName -like $pattern })
    $drivers = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop |
        Where-Object { $_.Name -like $pattern -or $_.PathName -like $pattern })
    $driverSource = 'Win32_SystemDriver'
    if ($drivers.Count -eq 0) {
        # Win32_SystemDriver does not enumerate the Sysmon minifilter - measured,
        # see Get-SysmonDriverFromRegistry. Ask the registry before concluding
        # that a running Sysmon is collecting nothing.
        $drivers = @(Get-SysmonDriverFromRegistry -Pattern $pattern)
        if ($drivers.Count -gt 0) { $driverSource = 'HKLM\SYSTEM\CurrentControlSet\Services' }
    }

    $state = [PSCustomObject] @{
        Installed = ($services.Count -gt 0); ServiceName = ''; ServiceState = ''
        ServiceStart = ''; DriverName = ''; DriverState = ''; BinaryPath = ''
        BinaryVersion = ''; ServiceCount = $services.Count; DriverCount = $drivers.Count
        DriverSource = $driverSource
    }
    if ($services.Count -gt 0) {
        $state.ServiceName  = [string] $services[0].Name
        $state.ServiceState = [string] $services[0].State
        $state.ServiceStart = [string] $services[0].StartMode
        $state.BinaryPath   = Get-ImagePathExecutable -ImagePath ([string] $services[0].PathName)
        if (-not [string]::IsNullOrWhiteSpace($state.BinaryPath)) {
            $state.BinaryVersion = Get-BinaryVersion -Path $state.BinaryPath
        }
    }
    if ($drivers.Count -gt 0) {
        $state.DriverName  = [string] $drivers[0].Name
        $state.DriverState = [string] $drivers[0].State
    }
    return $state
}

function Get-SysmonConfigDump {
    <#
        Microsoft: "-c Update configuration of an installed Sysmon driver or dump
        the current configuration if no other argument is provided", with
        "sysmon -c" given as the dump example.
        https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

        THE DUMP IS NOT A CONFIGURATION FILE. It renders the loaded rules and
        cannot be fed back to 'Sysmon64.exe -c'. Every use of it here is for the
        operator and for the record, never as the source of a restore. That one
        fact is why -Rollback can only restore a configuration this toolkit
        archived itself, and why -ReplaceForeignConfig exists.
    #>
    param([Parameter(Mandatory = $true)][string] $BinaryPath)
    $result = Invoke-NativeCommand -FilePath $BinaryPath -Arguments @('-c')
    return [PSCustomObject] @{
        ExitCode = $result.ExitCode
        Lines    = @($result.Output)
        Text     = (($result.Output) -join "`r`n")
    }
}

function Get-SysmonChannel {
    <#
        Every event channel on this host whose name matches *sysmon*, as
        Get-WinEvent returns them.

        The ONE place the channel is located, so a measurement and a report can
        never disagree about which channel they are talking about.
        $script:SysmonChannelExpected is a hint and is marked UNVERIFIED above;
        DriverName renames the driver and service images, so the channel name is
        not this script's to assert. -ListLog takes a wildcard, so the search
        widens instead of guessing.
    #>
    return @(Get-WinEvent -ListLog ('*' + $script:SysmonNameToken + '*') -ErrorAction SilentlyContinue)
}

function Write-SysmonChannelReport {
    <#
        Reported because a disabled channel makes the whole exercise pointless:
        Sysmon can be installed, configured and running while its channel is off,
        and the host records nothing at all. Properties are read defensively -
        this script must not assert that a property exists on an object it has
        never seen on a Windows host.
    #>
    Write-Section 'Sysmon event channel'

    $logs = @(Get-SysmonChannel)
    if ($logs.Count -eq 0) {
        Write-Finding ('no event channel matching *' + $script:SysmonNameToken + '* on this host - ' +
                       'expected ' + $script:SysmonChannelExpected + ' once Sysmon is installed')
        return
    }
    foreach ($log in $logs) {
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
        $detail = ([string] $log.LogName + ' - ' + (($parts.ToArray()) -join ', '))
        if ($enabled -eq 'False') { Write-Finding ($detail + ' - DISABLED, Sysmon will record nothing') }
        else { Write-Ok $detail }
    }
}

function Resolve-SysmonBinary {
    <#
        NOTHING HERE TOUCHES THE NETWORK - see the header and docs/DESIGN.md
        section 8. -SysmonPath is the supported answer; the search below is a
        convenience for the common staging layouts, in a fixed order, stopping at
        the first hit. Returns '' when nothing is found.
    #>
    param([Parameter(Mandatory = $true)][string] $ResolvedRoot)

    if (-not [string]::IsNullOrWhiteSpace($SysmonPath)) {
        if (-not (Test-Path -LiteralPath $SysmonPath -PathType Leaf)) {
            throw ('-SysmonPath does not point at a file: ' + $SysmonPath)
        }
        return $SysmonPath
    }
    $candidates = New-Object System.Collections.ArrayList
    [void] $candidates.Add([System.IO.Path]::Combine($ResolvedRoot, 'Sysmon64.exe'))
    [void] $candidates.Add([System.IO.Path]::Combine(
        [System.IO.Path]::Combine($ResolvedRoot, 'Sysmon'), 'Sysmon64.exe'))
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        [void] $candidates.Add([System.IO.Path]::Combine($PSScriptRoot, 'Sysmon64.exe'))
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    # PATH last, and -CommandType Application so a function or alias named
    # 'Sysmon64.exe' cannot be what gets executed as SYSTEM.
    $onPath = @(Get-Command -Name 'Sysmon64.exe' -CommandType Application -ErrorAction SilentlyContinue)
    if ($onPath.Count -gt 0) { return [string] $onPath[0].Source }
    return ''
}

#endregion

#region Sysmon changes --------------------------------------------------------

<#
    Two change types, because installing Sysmon and reconfiguring an installed
    Sysmon are two operations with two different inverses. 'sysmoninstall':
    Sysmon was NOT installed, applied with '-accepteula -i <config>', inverse is
    an uninstall. 'sysmonconfig': Sysmon WAS installed, applied with
    '-accepteula -c <config>', inverse is re-applying the previously archived
    configuration. Microsoft documents them as distinct switches - "-i Install
    service and driver" and "-c Update configuration of an installed Sysmon
    driver" - so '-i' against an installed Sysmon, or '-c' against a host with
    none, fails. The host is inspected first and the operation chosen.
    https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

    UNVERIFIED: '-accepteula' is documented as accepting the EULA "on
    installation"; its behaviour combined with '-c' is untested. It is passed on
    both paths deliberately - an unexpected argument produces a non-zero exit
    this script reports, whereas an unaccepted EULA under SYSTEM produces an
    interactive prompt with no console to answer it: a hung hardening script on a
    production server.
#>

function Get-LastAppliedSysmonConfig {
    <#
        The configuration THIS TOOLKIT last put on this host, from the manifest:
        the archived copy's path and hash. $null when the toolkit has never
        configured Sysmon here - which is what makes an existing configuration
        "foreign". Rolled-back runs are skipped: their archive is no longer what
        the host is running, and treating it as current would make -Apply believe
        it had nothing to do.
    #>
    $records = Read-Manifest
    if ($records.Count -eq 0) { return $null }

    $rolledBack   = @{}
    $ourApplyRuns = @{}
    foreach ($record in $records) {
        # The PREFIX, not equality - the rollback doctrine in the Manifest region
        # says so, and Get-RollbackTargetRun already obeyed it while this did not.
        # -Rollback -AbandonRun writes 'completed-abandoned-by-operator', and that
        # run may well have RESTORED this configuration before the operator gave
        # up on the rest of it. Equality did not recognise the status, so the
        # archived config still read back as "currently applied" and a later
        # -Apply of that same file printed "nothing to do" over a host running the
        # configuration the rollback had put back.
        if ($record.recordType -eq 'rollback' -and
            ([string] $record.status).StartsWith('completed', [System.StringComparison]::Ordinal)) {
            $rolledBack[[string] $record.runId] = $true
        }
        if ($record.recordType -eq 'run' -and $record.mode -eq 'Apply' -and
            $record.script -eq $script:ScriptName) {
            $ourApplyRuns[[string] $record.runId] = $true
        }
    }
    for ($i = $records.Count - 1; $i -ge 0; $i--) {
        $record = $records[$i]
        if ($record.recordType -ne 'change') { continue }
        $runId = [string] $record.runId
        if (-not $ourApplyRuns.ContainsKey($runId) -or $rolledBack.ContainsKey($runId)) { continue }
        $change = $record.change
        if ($null -eq $change) { continue }
        if ($change.type -ne 'sysmoninstall' -and $change.type -ne 'sysmonconfig') { continue }
        if ([string]::IsNullOrWhiteSpace([string] $change.archivedConfigPath)) { continue }
        return [PSCustomObject] @{
            RunId = $runId
            Path  = [string] $change.archivedConfigPath
            Hash  = [string] $change.archivedConfigHash
        }
    }
    return $null
}

function Save-SysmonArtifact {
    # Writes one of this run's records under <ToolkitRoot>\Sysmon and returns its
    # path. Only ever called from -Apply: -Audit writes nothing, anywhere
    # (docs/DESIGN.md section 2).
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [Parameter(Mandatory = $true)][string] $FileName,
        [Parameter()][AllowEmptyString()][string] $Content = '',
        [Parameter()][AllowEmptyString()][string] $CopyFrom = ''
    )
    if (-not (Test-Path -LiteralPath $Directory)) {
        [void] (New-Item -Path $Directory -ItemType Directory -Force)
    }
    $target = [System.IO.Path]::Combine($Directory, $FileName)
    if (-not [string]::IsNullOrWhiteSpace($CopyFrom)) {
        Copy-Item -LiteralPath $CopyFrom -Destination $target -Force
    }
    else {
        # No BOM: a verbatim record, not a PowerShell source file.
        [System.IO.File]::WriteAllText($target, $Content, (New-Object System.Text.UTF8Encoding($false)))
    }
    return $target
}

function Invoke-SysmonCommand {
    # Sysmon's exit code is the only signal this script has for whether an install
    # or a reconfiguration landed, so it is never ignored.
    param(
        [Parameter(Mandatory = $true)][string] $BinaryPath,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $What
    )
    Write-Info ('running: ' + [System.IO.Path]::GetFileName($BinaryPath) + ' ' + ($Arguments -join ' '))
    $result = Invoke-NativeCommand -FilePath $BinaryPath -Arguments $Arguments
    if ($result.ExitCode -ne 0) {
        throw ($What + ' failed with exit code ' + [string] $result.ExitCode + ': ' +
               (($result.Output) -join ' '))
    }
    foreach ($line in $result.Output) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Verbose ('sysmon: ' + $line) }
    }
}

function Invoke-HostCheck {
    <#
        Note the accumulation idiom, and copy it exactly. Never write
        '$changed = $changed -or (...)': -or short-circuits, so once $changed is
        $true every later call is NEVER MADE and the script silently stops
        applying settings after the first one that worked.

        ResolvedRoot is where the staged binary is looked for; WorkDirectory is
        where -Apply may write this run's archives. In -Audit they are the paths
        -Apply would use and nothing is written to them, so the audit does not lie
        about what applying would do.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $ResolvedRoot,
        [Parameter(Mandatory = $true)][string] $WorkDirectory
    )
    $changeCount = 0

    Write-Section 'Sysmon installation'
    $state = Get-SysmonInstallState
    if ($state.Installed) {
        Write-Ok ('service "' + $state.ServiceName + '" - ' + $state.ServiceState + ', start ' +
                  $state.ServiceStart)
        if ($state.DriverCount -gt 0) {
            Write-Ok ('driver "' + $state.DriverName + '" - ' + $state.DriverState +
                      ' (via ' + $state.DriverSource + ')')
        }
        else {
            Write-Finding 'service present but no matching kernel driver - Sysmon collects nothing'
        }
        $versionText = $state.BinaryVersion
        if ([string]::IsNullOrWhiteSpace($versionText)) { $versionText = 'version unreadable' }
        Write-Info ('binary: ' + $state.BinaryPath + ' (' + $versionText + ')')
        if ($state.ServiceCount -gt 1) {
            Write-Finding ([string] $state.ServiceCount + ' matching services; acting on "' +
                           $state.ServiceName + '" - check the others by hand')
        }
    }
    else {
        Write-Finding 'Sysmon is not installed on this host - it is recording nothing'
    }

    Write-Section 'Staged binary and Authenticode gate'
    $staged = Resolve-SysmonBinary -ResolvedRoot $ResolvedRoot
    $stagedTrusted = $false
    if ([string]::IsNullOrWhiteSpace($staged)) {
        Write-Finding ('no Sysmon64.exe is staged. Stage one and pass -SysmonPath; this toolkit does ' +
                       'not download binaries at runtime (docs/DESIGN.md section 8).')
    }
    else {
        $stagedVersion = Get-BinaryVersion -Path $staged
        if ([string]::IsNullOrWhiteSpace($stagedVersion)) { $stagedVersion = 'version unreadable' }
        Write-Info ('staged: ' + $staged + ' (' + $stagedVersion + ')')
        $stagedTrusted = Assert-SysmonBinaryTrusted -Path $staged
    }

    # The binary used for reads. The installed one is preferred - it is the one
    # whose configuration is being dumped - and it goes through the same gate.
    Write-Section 'Active Sysmon configuration'
    # ONLY the installed binary, and only when Sysmon is actually installed.
    #
    # The staged binary used to be a fallback here, and that was a fail-open.
    # Measured on the lab: 'Sysmon64.exe -c' run from a staged copy on a host
    # with NO Sysmon installed EXITS 0 and prints its banner followed by
    # "Sysmon is not installed on this computer". The script read exit 0, took
    # the nine banner lines for content, and reported "[ok] 9 line(s) of active
    # configuration dumped" - two sections after correctly reporting that Sysmon
    # was not installed at all. Same class as the fsutil and dnscmd parsers in
    # the review log kept in the development repository: a tool's exit code is not a claim about its
    # output. There is no active configuration on a host with no Sysmon, so the
    # question is not asked.
    $readBinary = ''
    if ($state.Installed -and -not [string]::IsNullOrWhiteSpace($state.BinaryPath)) {
        if (Assert-SysmonBinaryTrusted -Path $state.BinaryPath) { $readBinary = $state.BinaryPath }
    }

    $dumpText = ''
    if (-not $state.Installed) {
        Write-Info 'Sysmon is not installed, so there is no active configuration to read.'
    }
    elseif ([string]::IsNullOrWhiteSpace($readBinary)) {
        Write-Info 'no trusted Sysmon binary available to dump the configuration with.'
    }
    else {
        $dump = Get-SysmonConfigDump -BinaryPath $readBinary
        if ($dump.ExitCode -ne 0) {
            Write-Finding ('"-c" exited ' + [string] $dump.ExitCode +
                           ' - the active configuration could not be read')
        }
        else {
            $dumpText = $dump.Text
            Write-Ok ([string] $dump.Lines.Count + ' line(s) of active configuration dumped')
            Write-Info 'that dump renders the loaded rules; it is NOT a config file and cannot be re-applied.'
        }
    }

    Write-SysmonChannelReport

    Write-Section 'Configuration to install'
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        Write-Finding ('-ConfigPath was not given. Sysmon installed with no configuration logs almost ' +
                       'nothing a responder can use, so nothing is installed without one.')
        Write-Info ('docs/SCRIPTS.md recommends Olaf Hartong''s sysmonconfig.xml as a starting point ' +
                    '(https://github.com/olafhartong/sysmon-modular); neither shipped nor fetched here.')
        return $changeCount
    }
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw ('-ConfigPath does not point at a file: ' + $ConfigPath)
    }
    $desiredHash = Get-FileSha256 -Path $ConfigPath
    Write-Info ('config: ' + $ConfigPath)
    Write-Info ('SHA256: ' + $desiredHash)

    $lastApplied = Get-LastAppliedSysmonConfig
    $operation = 'config'
    if (-not $state.Installed) { $operation = 'install' }
    elseif ($null -eq $lastApplied) {
        if (-not $ReplaceForeignConfig) {
            Write-Finding ('Sysmon is installed with a configuration this toolkit did not apply, and ' +
                           '"-c" output is not a configuration file, so it cannot be captured in a ' +
                           'restorable form. Pass -ReplaceForeignConfig to replace it anyway, ' +
                           'accepting that -Rollback cannot put it back.')
            return $changeCount
        }
        Write-Info '-ReplaceForeignConfig: the loaded configuration will NOT be restorable by -Rollback.'
    }
    elseif ($lastApplied.Hash -eq $desiredHash -and
            (Get-FileSha256 -Path $lastApplied.Path) -eq $lastApplied.Hash) {
        Write-Ok 'the configuration this toolkit applied is the one requested - nothing to do'
        return $changeCount
    }

    # '-c' runs with the INSTALLED binary where there is one: it updates the
    # configuration of an installed driver, and a staged binary of a different
    # version is the wrong tool for that.
    $applyBinary = $staged
    if ($operation -eq 'config' -and -not [string]::IsNullOrWhiteSpace($readBinary)) {
        $applyBinary = $readBinary
    }
    # Not named $switch: PowerShell's automatic $switch variable holds a switch
    # statement's enumerator, the same class of collision as $mode (docs/AUTHORING.md).
    $sysmonSwitch = '-c'
    if ($operation -eq 'install') { $sysmonSwitch = '-i' }
    $wouldRun = ('-accepteula ' + $sysmonSwitch + ' "' + $ConfigPath + '"')

    if ([string]::IsNullOrWhiteSpace($applyBinary)) {
        Write-Finding ('no Sysmon binary is available to run "' + $wouldRun + '"')
        return $changeCount
    }
    if (-not $Apply) {
        Write-Finding ('would run: "' + [System.IO.Path]::GetFileName($applyBinary) + ' ' + $wouldRun + '"')
        Write-Info ('-Apply archives that file under the toolkit root first and hands Sysmon the ' +
                    'archive, so the path in the command above is where the content comes from, not ' +
                    'the path Sysmon is given.')
        if ($operation -eq 'install') { Write-Info 'INSTALL path: Sysmon is not on this host.' }
        else { Write-Info 'RECONFIGURE path: Sysmon is installed, only its configuration changes.' }
        return $changeCount
    }
    # The gate applies to the binary about to be executed. The installed one was
    # already checked above; a staged one may not have been.
    if ($applyBinary -eq $staged -and -not $stagedTrusted) { return $changeCount }

    # Archive what the rollback and the record need, THEN write the change record,
    # THEN change the host - the order docs/DESIGN.md section 4 requires.
    $archivedConfig = Save-SysmonArtifact -Directory $WorkDirectory `
        -FileName ('config-' + $script:CurrentRunId + '.xml') -CopyFrom $ConfigPath
    # THE ARCHIVE IS WHAT GETS INSTALLED, and this is where it is proven to be
    # the file that was hashed. -ConfigPath used to be read three times on this
    # path - hashed, copied, then handed to Sysmon - and the staging directory is
    # outside the toolkit root by design: the help invites "D:\stage" or the RMM's
    # own file transfer, neither of which this script ACLs. A swap between the
    # hash and the exec would have loaded somebody else's XML as SYSTEM while the
    # manifest recorded the hash of the good file, and -Rollback would have put
    # the good file back afterwards, leaving nothing in the record to see it by.
    # The archive lives under the toolkit root, whose ACL this script sets.
    $archivedHash = Get-FileSha256 -Path $archivedConfig
    if (-not [string]::Equals($archivedHash, $desiredHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ($ConfigPath + ' changed between being hashed and being archived - hashed ' +
               $desiredHash + ', the archive at ' + $archivedConfig + ' hashes ' + $archivedHash +
               '. Nothing was installed.')
    }
    Write-Info ('installing from the archived copy ' + $archivedConfig + ', same SHA256: what Sysmon ' +
                'loads is then the file this record hashes, not a later read of the staged path')
    $dumpPath = ''
    if (-not [string]::IsNullOrWhiteSpace($dumpText)) {
        $dumpPath = Save-SysmonArtifact -Directory $WorkDirectory `
            -FileName ('config-dump-before-' + $script:CurrentRunId + '.txt') -Content $dumpText
    }
    # binaryVersion is recorded so -Rollback can tell "the Sysmon this run
    # installed" from "a Sysmon somebody upgraded since", and decline rather than
    # uninstall a deliberate newer install.
    # TWO LITERAL RECORDS, one per change type, rather than one hashtable whose
    # .type an 'if' rewrites afterwards. The output is identical - 'sysmoninstall'
    # never carried the four config fields, because the block that added them only
    # ran for a reconfigure - but the shapes are now visible where they are
    # written instead of having to be reconstructed by following a mutation.
    #
    # That matters beyond readability: tools/check.ps1 check 6 compares the field
    # names every writer of a change type uses, across all scripts, because two
    # spellings of one field made the drift detector silently blind twice. It
    # reads literal hashtables, and this was the ONE call in the repository it
    # could not see. Rather than teach the gate to tolerate a blind spot, the
    # call was made readable.
    $installFields = @{
        previousInstalled = [bool] $state.Installed
        binaryPath = $applyBinary; binaryVersion = (Get-BinaryVersion -Path $applyBinary)
        configPath = $ConfigPath; configHash = $desiredHash
        archivedConfigPath = $archivedConfig
        archivedConfigHash = $archivedHash
        previousConfigDump = $dumpPath
    }
    if ($operation -eq 'config') {
        $previousArchivedPath = ''
        $previousArchivedHash = ''
        if ($null -ne $lastApplied) {
            $previousArchivedPath = [string] $lastApplied.Path
            $previousArchivedHash = [string] $lastApplied.Hash
        }
        [void] (Write-ManifestChange -Change @{
            type = 'sysmonconfig'
            previousInstalled = $installFields.previousInstalled
            binaryPath = $installFields.binaryPath
            binaryVersion = $installFields.binaryVersion
            configPath = $installFields.configPath
            configHash = $installFields.configHash
            archivedConfigPath = $installFields.archivedConfigPath
            archivedConfigHash = $installFields.archivedConfigHash
            previousConfigDump = $installFields.previousConfigDump
            replacedForeignConfig = [bool] ($null -eq $lastApplied)
            previousArchivedConfigPath = $previousArchivedPath
            previousArchivedConfigHash = $previousArchivedHash
            description = ('Sysmon reconfigured with ' + [System.IO.Path]::GetFileName($ConfigPath))
        })
    }
    else {
        [void] (Write-ManifestChange -Change @{
            type = 'sysmoninstall'
            previousInstalled = $installFields.previousInstalled
            binaryPath = $installFields.binaryPath
            binaryVersion = $installFields.binaryVersion
            configPath = $installFields.configPath
            configHash = $installFields.configHash
            archivedConfigPath = $installFields.archivedConfigPath
            archivedConfigHash = $installFields.archivedConfigHash
            previousConfigDump = $installFields.previousConfigDump
            description = ('Sysmon installed with ' + [System.IO.Path]::GetFileName($ConfigPath))
        })
    }

    Invoke-SysmonCommand -BinaryPath $applyBinary `
        -Arguments @('-accepteula', $sysmonSwitch, $archivedConfig) -What ('Sysmon ' + $operation)
    if ($operation -eq 'install') {
        $after = Get-SysmonInstallState
        if (-not $after.Installed) {
            throw 'Sysmon reported a successful install but no matching service is present.'
        }
        Write-Ok ('Sysmon installed - service "' + $after.ServiceName + '" (' + $after.ServiceState + ')')
        if ($after.DriverCount -eq 0) {
            Write-Finding 'no matching kernel driver after install - Sysmon will not collect'
        }
    }
    else { Write-Ok 'Sysmon configuration updated' }

    $confirm = Get-SysmonConfigDump -BinaryPath $applyBinary
    if ($confirm.ExitCode -ne 0) {
        throw ('Sysmon reported success but "-c" then exited ' + [string] $confirm.ExitCode)
    }
    Write-Ok ('configuration reads back - ' + [string] $confirm.Lines.Count + ' line(s)')
    # docs/AUTHORING.md, "Exit codes": a script that applied its setting but
    # cannot demonstrate the effect returns 1, not 0. Structural here rather than
    # a lab limitation - the only readback Sysmon offers is a text dump that
    # cannot be compared with the file installed.
    # Ask the host, rather than telling the operator to go and ask it.
    #
    # "-c" dumps a text RENDERING of the loaded rules, not the configuration
    # file, so it can never prove the loaded rules match the XML that was
    # handed over - that limitation is real and stays stated. What CAN be
    # proven is the thing that actually matters: that Sysmon is recording.
    # Starting a process and finding the event ID 1 it produces is a direct
    # measurement, and the script does it instead of leaving a to-do behind.
    # The channel comes back FROM the measurement, not from the expected literal:
    # naming a channel the script never looked in is how a working recorder gets
    # reported dead.
    $recording = Test-SysmonRecording
    if ($recording.Recording) {
        Write-Ok ('Sysmon is RECORDING: a process started by this script produced event ID 1 in ' +
                  $recording.Channel + '. Note this proves recording, NOT that the loaded ' +
                  'rules match ' + [System.IO.Path]::GetFileName($ConfigPath) + ' - "-c" dumps a text ' +
                  'rendering, not the file, so that comparison cannot be made on any host.')
    }
    elseif (-not $recording.Observed) {
        # NOT a finding, because nothing was observed. The [limit] lines inside
        # Test-SysmonRecording already said why the probe could not run, and the
        # only honest verdict here is that this run does not know.
        Write-Info ('applied. Whether Sysmon is RECORDING was not established by this run - the ' +
                    'probe process could not be started, see the [limit] above. This is not a ' +
                    'statement that Sysmon is failing, and it is not a statement that it works: ' +
                    'confirm recording before treating this host as covered.')
    }
    else {
        Write-Finding ('applied, but NOT recording: a process started by this script produced no ' +
                       'event ID 1 in ' + $recording.Channel + '. Sysmon is installed and ' +
                       'is not collecting - check the driver and the configuration before treating ' +
                       'this host as covered.')
    }
    $changeCount++
    return $changeCount
}

function Test-SysmonRecording {
    <#
        Whether starting a process produces a Sysmon process-creation event.
        Returns Recording plus the channel(s) the measurement was taken in, so
        the caller reports the channel it actually looked at rather than the
        literal it expected to find.

        THE CHANNEL IS DISCOVERED, NOT ASSERTED. This used to filter on
        $script:SysmonChannelExpected, which is marked UNVERIFIED where it is
        declared and is explicitly "a hint only" - and a miss returned $false,
        which the caller prints as "Sysmon is installed and is not collecting".
        That is the defect class docs/VALIDATION.md records for the driver -
        "declaring a working forensic recorder dead is worse than saying
        nothing" - reintroduced one section after the driver search was widened
        to a wildcard to escape it. The channel now goes through the same
        Get-SysmonChannel.

        Every matching channel is queried rather than only the first. A host
        with two is unusual, and picking one of them would put the guess back.

        The canary is 'cmd.exe /c exit 0' - it starts, does nothing and stops.
        Any process would do: Sysmon event ID 1 is process creation, listed on
        Microsoft's Sysmon page
        (https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and
        MEASURED here - docs/VALIDATION.md's 2026-08-25 row records recording
        proven on the lab by observing event ID 1 from a process this script
        started.

        The channel is written asynchronously, so this polls rather than
        sleeping once and guessing. Measured on the lab, the event was present
        well inside the window.
    #>
    $channels = @(Get-SysmonChannel | ForEach-Object { [string] $_.LogName })
    if ($channels.Count -eq 0) {
        return [PSCustomObject] @{
            Recording = $false
            # Observed, because the absence of any Sysmon channel IS the
            # observation - nothing had to be started to establish it.
            Observed  = $true
            Channel   = ('no channel matching *' + $script:SysmonNameToken + '* (expected ' +
                         $script:SysmonChannelExpected + ')')
        }
    }
    $channelText = ($channels -join ', ')

    $since = (Get-Date).AddSeconds(-5)

    # ANCHORED, not $env:ComSpec.
    #
    # This line exists to create one harmless process so that Sysmon's recording
    # can be OBSERVED rather than assumed. It used to run & "$env:ComSpec",
    # which is an environment variable - and this script runs as SYSTEM. Anything
    # able to set ComSpec for that context chose the executable a SYSTEM process
    # would launch, which is an arbitrary-execution primitive handed out by the
    # hardening toolkit itself. It is also the one place in this script where a
    # native target was not anchored, so it contradicted its own rule.
    #
    # -RequireAnchored returns $null rather than falling back to a bare name, and
    # a $null here means the probe is not run at all: the recording check then
    # reports "not observed", which is the honest answer and the safe direction.
    # It never means "assume it works".
    $probeExe = Get-NativeToolPath -FileName 'cmd.exe' -RequireAnchored
    if ([string]::IsNullOrWhiteSpace($probeExe)) {
        Write-HostLimit ('cmd.exe could not be resolved under %SystemRoot%, so no process could be ' +
                         'started to observe Sysmon recording. Whether Sysmon records is UNPROVEN by ' +
                         'this run - it is not a claim either way.')
        return [PSCustomObject] @{ Recording = $false; Observed = $false; Channel = $channelText }
    }
    # Observed = $false on a probe that never ran, and this is not a detail.
    # The caller's failure text reads "a process started by this script produced
    # no event ID 1 ... Sysmon is installed and is not collecting" - a statement
    # about a process that, on this path, was never started. Reporting a check
    # that could not run as a check that failed is exactly the false claim
    # docs/AUTHORING.md's cardinal rule forbids, and it would send an operator hunting a
    # Sysmon driver fault that does not exist.
    try { & $probeExe /c exit 0 | Out-Null }
    catch {
        Write-HostLimit ('the probe process could not be started (' + $_.Exception.Message +
                         '), so Sysmon recording was not observed by this run. That is not a ' +
                         'statement that Sysmon is failing.')
        return [PSCustomObject] @{ Recording = $false; Observed = $false; Channel = $channelText }
    }

    for ($attempt = 1; $attempt -le 10; $attempt++) {
        Start-Sleep -Seconds 2
        foreach ($channel in $channels) {
            $observed = 0
            try {
                $observed = @(Get-WinEvent -FilterHashtable @{
                    LogName = $channel; Id = 1; StartTime = $since
                } -ErrorAction Stop).Count
            }
            catch { $observed = 0 }
            if ($observed -gt 0) {
                return [PSCustomObject] @{ Recording = $true; Observed = $true; Channel = $channel }
            }
        }
    }
    # The probe ran and the polling window elapsed: a real observation.
    return [PSCustomObject] @{ Recording = $false; Observed = $true; Channel = $channelText }
}

#endregion

#region Main -----------------------------------------------------------------

function Get-TrustedInstalledBinary {
    # The installed Sysmon binary, or '' with a finding explaining why it may not
    # be executed. Shared by both rollback paths so the gate cannot be skipped on
    # one of them.
    param([Parameter(Mandatory = $true)] $State)

    if ([string]::IsNullOrWhiteSpace($State.BinaryPath) -or
        -not (Test-Path -LiteralPath $State.BinaryPath -PathType Leaf)) {
        Write-Finding ('the Sysmon service points at "' + $State.BinaryPath +
                       '", which is not a readable file')
        return ''
    }
    if (-not (Assert-SysmonBinaryTrusted -Path $State.BinaryPath)) { return '' }
    return [string] $State.BinaryPath
}

function Restore-SysmonChange {
    <#
        Routes a change record to its inverse. This script writes no registry
        values, so it does not carry the template's Registry region and has no
        Restore-TrackedChange to delegate to: anything that is not one of its own
        two change types is DECLINED, loudly.

        Returns 'restored' or 'declined'; throws on failure. Declining is the
        point in three places, and each is a state the toolkit must not paper
        over: a configuration it never archived cannot be restored; an archive
        whose hash does not match what was recorded is not the file that was
        applied; and a Sysmon whose version is not the one this run installed was
        changed by somebody else since.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    $type = [string] $change.type
    if ($type -ne 'sysmoninstall' -and $type -ne 'sysmonconfig') {
        Write-Finding ('Cannot roll back change type "' + $type + '" - not implemented in this script.')
        return 'declined'
    }
    $state = Get-SysmonInstallState

    if ($type -eq 'sysmoninstall') {
        if (-not $state.Installed) {
            Write-Ok 'Sysmon is already absent - the state this run changed is already restored'
            return 'restored'
        }
        $recordedVersion = [string] $change.binaryVersion
        if (-not [string]::IsNullOrWhiteSpace($recordedVersion) -and
            -not [string]::IsNullOrWhiteSpace($state.BinaryVersion) -and
            $recordedVersion -ne $state.BinaryVersion) {
            Write-Finding ('Sysmon here is version ' + $state.BinaryVersion + '; this run installed ' +
                           $recordedVersion + '. It has been changed since, so this script will not ' +
                           'uninstall it. Use "Sysmon64.exe -u" by hand if that is the intent.')
            return 'declined'
        }
        $binary = Get-TrustedInstalledBinary -State $state
        if ([string]::IsNullOrWhiteSpace($binary)) { return 'declined' }

        Invoke-SysmonCommand -BinaryPath $binary -Arguments @('-u') -What 'Sysmon uninstall'
        if ((Get-SysmonInstallState).Installed) {
            throw 'Sysmon reported a successful uninstall but a matching service is still present.'
        }
        Write-Ok 'Sysmon uninstalled - the service, the driver and the channel are gone'

        # Do not overstate it. Measured on the lab: after 'Sysmon64.exe -u' the
        # service, the SysmonDrv minifilter and the Operational channel are all
        # gone, but Sysmon's own copy of itself is STILL on disk at
        # %SystemRoot%\Sysmon64.exe - Sysmon puts it there during -i and its
        # uninstall does not take it away. Naming it beats claiming a host is
        # "back to having no Sysmon" when a diff would show otherwise. It is
        # inert with no service and no driver, and it is not deleted here: the
        # toolkit does not delete binaries, and on a host where somebody else had
        # installed Sysmon first that file is not ours to remove.
        $leftBehind = [System.IO.Path]::Combine($env:SystemRoot, 'Sysmon64.exe')
        if (Test-Path -LiteralPath $leftBehind -PathType Leaf) {
            Write-Info ($leftBehind + ' is still on disk - Sysmon''s own uninstall leaves it. ' +
                        'It is inert without the service and driver, and this script does not delete it.')
        }
        return 'restored'
    }

    # sysmonconfig
    #
    # A-2 NOTE: this branch resolves TWO ways, not three, and that is a
    # limitation rather than an oversight. Case 2 and case 3 both need the LIVE
    # configuration compared against the archived file, and Sysmon does not
    # expose one: 'Sysmon64.exe -c' prints a rendered dump of the running rules,
    # not the XML that produced them, so the two cannot be compared without
    # guessing at the transformation. The consequences are stated rather than
    # hidden:
    #   - No A-2 convergence defect. Re-installing the archived configuration is
    #     idempotent and returns 'restored', so the run always finishes.
    #   - There IS a case-3 exposure: a configuration an operator installed AFTER
    #     the -Apply is overwritten by this rollback. Mitigated only in that the
    #     archived file is hash-verified first, so what goes back is exactly what
    #     this toolkit replaced. Restoring the previous configuration is the
    #     documented purpose of -Rollback, and the archive it came from is left in
    #     place afterwards, so the operator's version is not recoverable from here.
    # Settling this needs a measured, reversible mapping between the '-c' dump and
    # the XML. Until that exists, do not invent a comparison.
    $previousPath = [string] $change.previousArchivedConfigPath
    if ([string]::IsNullOrWhiteSpace($previousPath)) {
        Write-Finding ('this run replaced a Sysmon configuration that was never archived by this ' +
                       'toolkit, and "-c" output is not a configuration file. Nothing to restore from.')
        return 'declined'
    }
    if (-not (Test-Path -LiteralPath $previousPath -PathType Leaf)) {
        Write-Finding ('the archived previous configuration is missing: ' + $previousPath)
        return 'declined'
    }
    $recordedHash = [string] $change.previousArchivedConfigHash
    $actualHash = [string] (Get-FileSha256 -Path $previousPath)
    if (-not [string]::Equals($recordedHash, $actualHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Finding ('the archived previous configuration does not match its recorded hash - refusing ' +
                       'to install it. Recorded ' + $recordedHash + ', on disk ' + $actualHash)
        return 'declined'
    }
    if (-not $state.Installed) {
        Write-Finding ('Sysmon is no longer installed, so its configuration cannot be restored. The ' +
                       'previous configuration is preserved at ' + $previousPath)
        return 'declined'
    }
    $binary = Get-TrustedInstalledBinary -State $state
    if ([string]::IsNullOrWhiteSpace($binary)) { return 'declined' }

    Invoke-SysmonCommand -BinaryPath $binary `
        -Arguments @('-accepteula', '-c', $previousPath) -What 'Sysmon configuration restore'
    $confirm = Get-SysmonConfigDump -BinaryPath $binary
    if ($confirm.ExitCode -ne 0) {
        throw ('the configuration was restored but "-c" then exited ' + [string] $confirm.ExitCode)
    }
    Write-Ok ('Restored the Sysmon configuration from ' + [System.IO.Path]::GetFileName($previousPath))
    return 'restored'
}

function Invoke-Main {
    $mode = 'Audit'
    if ($Apply)    { $mode = 'Apply' }
    if ($Rollback) { $mode = 'Rollback' }

    Write-Host ''
    Write-Host ('IronBlackBox - ' + $script:ScriptName + ' v' + $script:ScriptVersion + ' [' + $mode + ']') -ForegroundColor White

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')
    # The same WorkDirectory -Apply uses, so -Audit reports the real paths - but
    # nothing on the -Audit path writes to it.
    $sysmonDirectory = [System.IO.Path]::Combine($resolvedRoot, 'Sysmon')

    if ($mode -eq 'Audit') {
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly)
        [void] (Invoke-HostCheck -ResolvedRoot $resolvedRoot -WorkDirectory $sysmonDirectory)
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
        Write-Ok 'No findings: Sysmon is installed with the configuration this toolkit applied.'
        return 0
    }

    Enter-ToolkitLock -ToolkitRootPath $resolvedRoot
    try {
        $allowMissingStamp = ($mode -eq 'Rollback')
        [void] (Initialize-ToolkitRoot -Path $resolvedRoot -AllowMissingStamp:$allowMissingStamp)
        Assert-ManifestUsable

        if ($mode -eq 'Apply') {
            [void] (Start-ManifestRun -Mode 'Apply' -Parameters @{
                toolkitRoot          = $resolvedRoot
                sysmonPath           = [string] $SysmonPath
                configPath           = [string] $ConfigPath
                replaceForeignConfig = [bool] $ReplaceForeignConfig
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
                $verified = Invoke-HostCheck -ResolvedRoot $resolvedRoot -WorkDirectory $sysmonDirectory
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
            Write-Info ('No reboot needed: Microsoft documents "Neither install nor uninstall requires ' +
                        'a reboot." https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon')
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
                $outcome = Restore-SysmonChange -ChangeRecord $target.Changes[$i]
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
