<#
.SYNOPSIS
    Removes the Windows PowerShell 2.0 engine, the classic way to run
    PowerShell on a hardened host without ScriptBlock logging recording it.

.DESCRIPTION
    PowerShell 2.0 predates ScriptBlock logging, module logging and
    transcription. On a host where Enable-IRVisibility has turned all three on,
    'powershell -Version 2' runs code that none of them capture. Removing the
    v2 engine closes that.

    This script reports on, and acts on, two separate things - because on a real
    host they disagree:

      1. Whether the v2 OPTIONAL FEATURE is installed.
      2. Whether the v2 ENGINE CAN ACTUALLY RUN.

    The second is what matters, and it is not implied by the first. PowerShell
    2.0 needs the .NET 2.0 CLR, which ships with .NET Framework 3.5. On a host
    without .NET 3.5, 'powershell -Version 2' fails outright even while the
    feature reports as Enabled - so there is no bypass to close, and removing
    the feature buys nothing. Measured on the lab: see verification/facts.json.

    Two APIs report on the feature and they do not agree. On Windows Server
    2019, DISM reported MicrosoftWindowsPowerShellV2 as Enabled while
    ServerManager reported PowerShell-V2 as Removed, on the same host, at the
    same moment. This script uses DISM (Get/Disable-WindowsOptionalFeature),
    which exists on both client and server SKUs, and reports the ServerManager
    view alongside it when the two differ rather than picking a winner
    silently.

    Feature names are DISCOVERED, not hard-coded: the set differs by SKU
    (Windows 10/11 also carries MicrosoftWindowsPowerShellV2Root, which
    Server 2019 does not).

    What this script will NOT do: touch .NET Framework 3.5. Removing it would
    neutralise PSv2 far more thoroughly, and would also break every legacy
    application on the host that depends on it. That is not a decision a
    hardening script gets to make.

.PARAMETER Audit
    Default. Strictly read-only. Reports whether a v2 bypass is actually
    possible on this host.

.PARAMETER Apply
    Disables the v2 optional feature(s), recording their previous state first.

.PARAMETER Rollback
    Re-enables the feature(s) that a prior -Apply disabled.

.PARAMETER ToolkitRoot
    Base directory for the manifest. Default C:\ProgramData\IronBlackBox.

.PARAMETER RunId
    -Rollback only. The run to roll back.
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
    .\Remove-PowerShellV2.ps1
    Reports whether PowerShell 2.0 can run on this host. Changes nothing.

.EXAMPLE
    .\Remove-PowerShellV2.ps1 -Apply
    Disables the v2 feature. A restart is usually required to complete it.

.EXAMPLE
    .\Remove-PowerShellV2.ps1 -Rollback
    Re-enables what -Apply disabled.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.1.1
    License : MIT

    Windows PowerShell 5.1. Uses the in-box DISM module. Requires local
    administrator; enforced in code by Assert-Elevated.
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

$script:ScriptName    = 'Remove-PowerShellV2'
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
$script:RestartNeeded = $false

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
#region PowerShell v2 detection ----------------------------------------------

function Test-PSv2CanRun {
    <#
        The question that actually matters: can an attacker get a v2 engine on
        this host? Answered by trying, not by inspecting feature state.

        PowerShell 2.0 requires the .NET 2.0 CLR (shipped with .NET Framework
        3.5). Without it, 'powershell -Version 2' exits non-zero even while DISM
        reports the feature Enabled. TWO non-zero codes have been measured, for
        two different reasons, and both are conclusive:

          -65536   "Version v2.0.50727 of the .NET Framework is not installed"
                   - the feature is present but the CLR it needs is not.
                   Server 2019, 2026-08-23.
          -327680  "Cannot find registry key
                   SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine. The
                   Windows PowerShell 2 engine is not installed on this
                   computer." - the engine itself is gone. Server 2019,
                   2026-09-09, after the feature had been disabled.

        An earlier version of this comment cited only -65536, as though it were
        the code. It is one of them.

        THE EXIT CODE IS NOT THE ANSWER, and trusting it produced a false
        positive on every Windows 11 endpoint.

        Measured 2026-09-09 on Windows 11 Pro build 26200, where PowerShell 2.0
        is gone entirely - no MicrosoftWindowsPowerShellV2* feature, no
        HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine key, no
        .NET 3.5: 'powershell.exe -Version 2' prints "PowerShell 2.0 has been
        deprecated. Using default PowerShell instead.", RUNS UNDER 5.1, and
        EXITS 0. The earlier version of this function read that 0 and reported
        "PowerShell 2.0 CAN RUN on this host - ScriptBlock logging can be
        bypassed" as a finding. That is a claim of an exposure that does not
        exist, and no -Apply could clear it because there is nothing to remove -
        a permanently red monitor on a whole fleet of workstations, which
        docs/DESIGN.md section 3.1 exists to prevent. It also broke this
        project's own hard rule that a native tool's exit code is not a claim
        about its output.

        So the child is ASKED WHAT VERSION IT IS, and the answer decides:

          major 2      the v2 engine really ran - the exposure is real
          major 5 (etc) -Version 2 fell back, so v2 is not present
          no answer    UNDETERMINED, reported as such and never as an exposure

        The version travels as a marked ASCII token because the host's own
        deprecation notice arrives as UTF-16 read as ANSI - measured, it comes
        back as "P o w e r S h e l l   2 . 0", which CONTAINS the digit 2. A
        naive scan for a digit would read that notice as proof of what it
        denies. Both the clean and the interleaved forms are matched.
    #>
    # ANCHORED, never the bare name. This script runs as SYSTEM, so '& powershell.exe'
    # would let any directory on the machine PATH that a lesser principal can write to
    # decide what an -Audit executes - and -Audit is the mode an RMM schedules
    # everywhere. It also removes a false all-clear: a PATH that has lost its
    # WindowsPowerShell entry made the launch throw, which this function reported as
    # "cannot run" on the one question the script exists to answer.
    # Install location and executable name:
    # https://learn.microsoft.com/en-us/powershell/scripting/whats-new/migrating-from-windows-powershell-51-to-powershell-7
    # ("Windows PowerShell 5.1: $Env:windir\System32\WindowsPowerShell\v1.0" and
    # "In Windows PowerShell, the PowerShell executable is named powershell.exe").
    #
    # Not a bitness fix, deliberately: for a 32-bit host process WOW64 redirects
    # %windir%\System32 to %windir%\SysWOW64
    # (https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector),
    # so an RMM that launched SysWOW64\powershell.exe still probes the 32-bit engine.
    # A 32-bit v2 engine that runs is a bypass too, so that answer is not wrong;
    # pinning the native engine through the documented Sysnative alias is left until a
    # 32-bit run on the lab shows the two answers can differ.
    $systemRoot = $env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($systemRoot)) { $systemRoot = 'C:\Windows' }
    $engine = [System.IO.Path]::Combine($systemRoot, 'System32\WindowsPowerShell\v1.0\powershell.exe')
    if (-not [System.IO.File]::Exists($engine)) {
        # Answering "cannot run" from here would be a guess dressed as an all-clear.
        # Saying the script could not do its job is exit 2, which is the truth.
        throw ('Windows PowerShell is not at ' + $engine + ', so whether the v2 engine ' +
               'can run on this host cannot be determined.')
    }

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $raw = @()
    $code = 0
    try {
        # The child reports its own major version behind a marker no prose can
        # produce. 'IBBV=' is matched rather than a bare digit precisely because
        # the deprecation notice contains one.
        #
        # -EncodedCommand, not -Command, and this is not a style choice. Passing
        # '"IBBV=" + $PSVersionTable.PSVersion.Major' through -Command strips the
        # inner double quotes during argument handling, so the child receives
        # 'IBBV= + $PSVersionTable...' - a syntax error - and exits 1. Measured:
        # that made this probe answer "engine unavailable" for a malformed
        # command rather than for a missing engine, which on a host where v2 DOES
        # run would be a false ALL-CLEAR. Base64 UTF-16LE has no quoting to lose.
        $probeCommand = '"IBBV=" + $PSVersionTable.PSVersion.Major'
        $encoded = [System.Convert]::ToBase64String(
            [System.Text.Encoding]::Unicode.GetBytes($probeCommand))
        $raw = @(& $engine -Version 2 -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1)
        $code = $LASTEXITCODE
    }
    catch {
        $ErrorActionPreference = $previous
        return [PSCustomObject] @{ CanRun = $false; Determined = $true
                                   Detail = ('launch threw: ' + $_.Exception.Message) }
    }
    finally {
        $ErrorActionPreference = $previous
    }

    # NUL characters stripped, and a whitespace-free variant kept, because a
    # UTF-16 stream read as ANSI arrives interleaved.
    $text  = (@($raw) -join ' ') -replace "`0", ''
    $dense = $text -replace '\s', ''
    $found = [regex]::Match($text, 'IBBV=(\d+)')
    if (-not $found.Success) { $found = [regex]::Match($dense, 'IBBV=(\d+)') }

    if ($found.Success) {
        $major = [int] $found.Groups[1].Value
        if ($major -eq 2) {
            return [PSCustomObject] @{ CanRun = $true; Determined = $true
                Detail = 'the child engine reported PSVersion major 2, so a v2 engine really ran' }
        }
        return [PSCustomObject] @{ CanRun = $false; Determined = $true
            Detail = ('-Version 2 fell back to PowerShell ' + [string] $major +
                      ', so no v2 engine is present on this host') }
    }

    # No version came back. A non-zero exit is the documented "engine
    # unavailable" answer and is conclusive; a zero exit with no readable
    # version is not, and is not going to be dressed up as one.
    if ($code -ne 0) {
        return [PSCustomObject] @{ CanRun = $false; Determined = $true
            Detail = ('powershell.exe -Version 2 exited ' + [string] $code + ' (engine unavailable)') }
    }
    return [PSCustomObject] @{ CanRun = $false; Determined = $false
        Detail = ('powershell.exe -Version 2 exited 0 but reported no version, so whether a v2 ' +
                  'engine ran could NOT be established. Output was: ' +
                  $(if ($text.Length -gt 160) { $text.Substring(0, 160) + '...' } else { $text })) }
}

function Get-DotNet35State {
    <#
        Reported, never changed. Its absence is why PSv2 cannot run on a host
        like the lab, and its presence is what makes removing the feature
        worthwhile - but removing .NET 3.5 to harden PowerShell would break
        every legacy application depending on it.
    #>
    # The key path and the meaning of Install are Microsoft's, not this project's:
    # https://learn.microsoft.com/en-us/dotnet/framework/install/how-to-determine-which-versions-are-installed
    # its .NET Framework 1.0-4.0 table gives 3.5 as
    # 'HKLM\Software\Microsoft\NET Framework Setup\NDP\v3.5' with 'Install REG_DWORD
    # equals 1', and the page notes the subkey does NOT begin with a period.
    #
    # UNVERIFIED: the same page warns that a 32-bit process on 64-bit Windows reads
    # the redirected SOFTWARE\Wow6432Node view of that path. Whether the redirected
    # view carries Install for v3.5 on a host whose native view does has not been
    # checked, so an RMM launching the 32-bit host may report .NET 3.5 as absent.
    # That under-states the exposure rather than over-stating it, and the engine
    # probe above answers the exposure question by trying regardless.
    $key = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5'
    if (-not (Test-Path -LiteralPath $key)) {
        return [PSCustomObject] @{ Present = $false; Detail = 'NDP\v3.5 registry key absent' }
    }
    $value = (Get-ItemProperty -LiteralPath $key).Install
    if ($value -eq 1) {
        return [PSCustomObject] @{ Present = $true; Detail = 'NDP\v3.5 Install = 1' }
    }
    return [PSCustomObject] @{ Present = $false; Detail = ('NDP\v3.5 Install = ' + $value) }
}

function Get-PSv2Feature {
    <#
        Discovered rather than hard-coded: the feature set differs by SKU.
        Windows 10/11 carries MicrosoftWindowsPowerShellV2Root alongside
        MicrosoftWindowsPowerShellV2; Server 2019 has only the latter (measured
        on the lab). A hard-coded name would silently match nothing on the SKU
        it was not written for.

        DISM is used because Get-WindowsOptionalFeature exists on both client
        and server. Get-WindowsFeature (ServerManager) is server-only, and it
        disagrees - see Compare-FeatureView.
    #>
    $all = Get-WindowsOptionalFeature -Online
    return @($all | Where-Object { $_.FeatureName -like 'MicrosoftWindowsPowerShellV2*' } |
        Sort-Object FeatureName)
}

function Compare-FeatureView {
    <#
        Reports the ServerManager view when it contradicts DISM, instead of
        quietly preferring one. On the lab, at the same moment on the same host:
        DISM said MicrosoftWindowsPowerShellV2 = Enabled, ServerManager said
        PowerShell-V2 = Removed. An operator deciding whether their fleet is
        exposed deserves to see that the OS does not have one answer.
    #>
    param([Parameter(Mandatory = $true)] $DismFeatures)

    if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 1) { return }
    if (-not (Get-Module -ListAvailable -Name ServerManager)) { return }

    try {
        $sm = Get-WindowsFeature -Name 'PowerShell-V2' -ErrorAction Stop
    }
    catch {
        Write-Info ('ServerManager view unavailable: ' + $_.Exception.Message)
        return
    }
    if ($null -eq $sm) { return }

    $dismEnabled = [bool] @($DismFeatures | Where-Object { $_.State -eq 'Enabled' }).Count
    $smInstalled = ($sm.InstallState -eq 'Installed')
    if ($dismEnabled -ne $smInstalled) {
        Write-Info ('NOTE: the two Windows APIs disagree. DISM reports the v2 feature ' +
                    $(if ($dismEnabled) { 'Enabled' } else { 'not Enabled' }) +
                    '; ServerManager reports PowerShell-V2 as ' + $sm.InstallState +
                    '. This script acts on the DISM view.')
    }
}

#endregion

#region Feature changes -------------------------------------------------------

function Set-TrackedFeatureState {
    <#
        Disables or enables one optional feature, recording its previous state
        to the manifest BEFORE acting - the same discipline as a registry value.

        -NoRestart always: a hardening script does not get to reboot a
        production server. Whether a restart is pending is reported to the
        operator and to the manifest.

        Returns $true if it changed something.
    #>
    param(
        [Parameter(Mandatory = $true)][string] $FeatureName,
        [Parameter(Mandatory = $true)][ValidateSet('Enabled', 'Disabled')][string] $Desired,
        [Parameter(Mandatory = $true)][string] $Description
    )

    # $ErrorActionPreference is 'Stop' script-wide, so a DISM error here is
    # terminating and the $null guard below only ever covers a $null RETURN. The
    # error is re-thrown with the feature named rather than degraded to "not present
    # on this SKU": the name came out of Get-PSv2Feature on this host moments ago, so
    # a failure now is a servicing-stack problem, and a failed write in -Apply is
    # exit 2 by docs/DESIGN.md section 3.1 - not a finding.
    $feature = $null
    try { $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop }
    catch {
        throw ('Could not read optional feature ' + $FeatureName + ': ' + $_.Exception.Message)
    }
    if ($null -eq $feature) {
        Write-Finding ($Description + ' - feature not present on this SKU')
        return $false
    }

    $currentState = [string] $feature.State
    # DISM reports several states; only 'Enabled' means the payload is active.
    # 'DisabledWithPayloadRemoved' is disabled AND unrecoverable without media,
    # which matters for rollback: re-enabling it would need a source.
    $isEnabled = ($currentState -eq 'Enabled')
    $wantEnabled = ($Desired -eq 'Enabled')

    if ($isEnabled -eq $wantEnabled) {
        Write-Ok ($Description + ' - already ' + $currentState)
        return $false
    }

    if (-not $Apply) {
        Write-Finding ($Description + ' - currently ' + $currentState + ', would set to ' + $Desired)
        return $false
    }

    [void] (Write-ManifestChange -Change @{
        type          = 'windowsfeature'
        featureName   = $FeatureName
        previousState = $currentState
        newState      = $Desired
        mechanism     = 'dism'
        description   = $Description
    })

    if ($wantEnabled) {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop
    }
    else {
        $result = Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop
    }

    if ($null -ne $result -and $result.RestartNeeded) { $script:RestartNeeded = $true }

    # Confirm by re-reading, as with a registry write.
    $after = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName
    $afterEnabled = ([string] $after.State -eq 'Enabled')
    if ($afterEnabled -ne $wantEnabled -and -not $script:RestartNeeded) {
        throw ('Feature did not read back as ' + $Desired + ': ' + $FeatureName +
               ' is ' + $after.State)
    }

    Write-Ok ($Description + ' - now ' + $after.State +
              $(if ($script:RestartNeeded) { ' (restart pending)' } else { '' }))
    return $true
}

function Restore-FeatureChange {
    <#
        Returns 'restored' or 'declined'; throws on failure.

        Declines rather than guesses when the previous state was
        DisabledWithPayloadRemoved: re-enabling that needs installation media
        this script has no business going looking for.
    #>
    param([Parameter(Mandatory = $true)] $ChangeRecord)

    $change = $ChangeRecord.change
    if ($change.type -ne 'windowsfeature') {
        Write-Finding ('Cannot roll back change type "' + $change.type + '" - not implemented in this script.')
        return 'declined'
    }

    # THE CONSTRAINT, from the script and not from the record. The recorded name
    # went straight into Enable-WindowsOptionalFeature as SYSTEM, so a planted or
    # hand-edited record made -Rollback mean "install any Windows feature on this
    # host" - Telnet client, SMB1, TFTP, IIS. docs/DESIGN.md section 4: the
    # manifest is operator-writable input, not trusted state.
    #
    # The pattern is the same one Get-PSv2Feature discovers with (line 1091), so the
    # rollback can only ever touch what an -Apply of this script could have
    # touched: MicrosoftWindowsPowerShellV2 on Server, plus the ...V2Root that
    # Windows 10/11 carries alongside it.
    $recordedFeature = [string] $change.featureName
    if ($recordedFeature -notlike 'MicrosoftWindowsPowerShellV2*') {
        Write-Finding ('Refusing to roll back feature "' + $recordedFeature + '": this script only ever ' +
                       'changes MicrosoftWindowsPowerShellV2*, so the record did not come from it. ' +
                       'Enabling an arbitrary Windows feature is not a rollback.')
        return 'declined'
    }

    $previous = [string] $change.previousState
    if ($previous -ne 'Enabled' -and $previous -ne 'Disabled') {
        Write-Finding ($change.featureName + ' was "' + $previous +
                       '" before this run; restoring that state needs installation media. Leaving it alone.')
        return 'declined'
    }

    # Same trap, and here it mattered: $ErrorActionPreference is 'Stop' script-wide,
    # so DISM raising an error for a name it cannot resolve on THIS host - a record
    # written where ...V2Root exists, replayed on a SKU that has no such feature -
    # was terminating, Invoke-Main counted it as a FAILURE, and the run exited 2 and
    # stayed retryable forever. "The host holds neither value" is a decline, not a
    # failure: docs/DESIGN.md section 4.1 case 3.
    $feature = $null
    $lookupError = ''
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $change.featureName -ErrorAction Stop
    }
    catch { $lookupError = $_.Exception.Message }
    if ($null -eq $feature) {
        Write-Finding ($change.featureName + ' could not be read on this host, so nothing was ' +
                       'restored and the run stays retryable. ' + $lookupError)
        return 'declined'
    }

    if ([string] $feature.State -eq $previous) {
        Write-Ok ($change.featureName + ' is already ' + $previous)
        return 'restored'
    }

    if ($previous -eq 'Enabled') {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName $change.featureName -NoRestart -ErrorAction Stop
    }
    else {
        $result = Disable-WindowsOptionalFeature -Online -FeatureName $change.featureName -NoRestart -ErrorAction Stop
    }
    if ($null -ne $result -and $result.RestartNeeded) { $script:RestartNeeded = $true }

    Write-Ok ('Restored ' + $change.featureName + ' to ' + $previous)
    return 'restored'
}

function Invoke-HostCheck {
    <#
        Reports the exposure first, then acts. The order matters: an operator
        reading -Audit output needs to know whether a bypass is actually
        possible before being told which feature to turn off.

        In -Apply the exposure is reported again AFTER the change, by re-running
        the same probe, and that second answer is the one that becomes a finding.
        The first is printed only.

        Note the accumulation idiom. Never write '$x = $x -or (...)': -or
        short-circuits and the later calls are never made.
    #>
    Write-Section 'PowerShell 2.0 exposure'

    $canRun = Test-PSv2CanRun
    $dotNet = Get-DotNet35State
    $features = Get-PSv2Feature

    Write-Info ('.NET Framework 3.5 (provides the v2 CLR): ' +
                $(if ($dotNet.Present) { 'PRESENT' } else { 'absent' }) + ' - ' + $dotNet.Detail)

    if ($features.Count -eq 0) {
        Write-Info 'No MicrosoftWindowsPowerShellV2* optional feature exists on this SKU.'
    }
    else {
        foreach ($f in $features) {
            Write-Info ($f.FeatureName + ' = ' + $f.State)
        }
        Compare-FeatureView -DismFeatures $features
    }

    if ($canRun.CanRun) {
        if ($Apply) {
            # Printed, not raised. The same probe runs again below, after the feature
            # is disabled, and THAT answer is the one the exit code is built on:
            # raising the finding here as well would count one exposure twice and,
            # worse, would leave exit 1 standing on a host where the removal worked.
            Write-Info ('PowerShell 2.0 CAN RUN on this host - ScriptBlock logging can be bypassed. ' +
                        $canRun.Detail)
        }
        else {
            Write-Finding ('PowerShell 2.0 CAN RUN on this host - ScriptBlock logging can be bypassed. ' +
                           $canRun.Detail)
        }
    }
    elseif ($canRun.Determined) {
        Write-Ok ('PowerShell 2.0 cannot run: ' + $canRun.Detail)
    }
    else {
        # NEITHER an exposure nor an all-clear, and it is not going to be
        # rounded into one. A finding here would assert a bypass nobody
        # observed; a Write-Ok would clear a host nobody checked.
        Write-HostLimit ('whether PowerShell 2.0 can run on this host was NOT established. ' +
                         $canRun.Detail + ' Check it by hand with: powershell.exe -Version 2 ' +
                         '-NoProfile -Command ''$PSVersionTable.PSVersion.ToString()'' - a 2.x ' +
                         'answer means the engine is there, a 5.x answer means the switch fell back.')
    }

    Write-Section 'PowerShell 2.0 feature removal'

    $changeCount = 0
    if ($features.Count -eq 0) {
        Write-Ok 'nothing to remove'
    }
    else {
        # Still remove the feature even when the engine cannot currently run.
        # .NET 3.5 is one 'Enable-WindowsOptionalFeature NetFx3' away from being
        # back - installed by an admin for a legacy app, or by an attacker who has
        # already got that far - and at that moment the v2 engine becomes usable
        # again. Removing the feature makes the exposure not come back.
        if (-not $canRun.CanRun) {
            Write-Info 'The engine cannot run today, but the feature is still present:'
            Write-Info 'installing .NET 3.5 later would make it usable again, so the feature is worth removing.'
        }

        foreach ($f in $features) {
            if (Set-TrackedFeatureState -FeatureName $f.FeatureName -Desired 'Disabled' `
                -Description ('optional feature ' + $f.FeatureName)) { $changeCount++ }
        }
    }

    # OBSERVE THE EFFECT. Set-TrackedFeatureState re-reads DISM, which proves only
    # that the FEATURE is off - and the whole thesis of this script (.DESCRIPTION,
    # and psv2-needs-dotnet35 in verification/facts.json) is that feature state is
    # not the exposure question. The exposure question is answered by a command
    # failing, which is observable, so it is observed here rather than assumed. This
    # is the AppLocker/Sysmon lesson in docs/AUTHORING.md applied to the mode that changed
    # something.
    if ($Apply -and $canRun.CanRun) {
        Write-Section 'PowerShell 2.0 exposure after the change'
        $afterRun = Test-PSv2CanRun
        if (-not $afterRun.CanRun) {
            Write-Ok ('PowerShell 2.0 can no longer run: ' + $afterRun.Detail)
        }
        elseif ($script:RestartNeeded) {
            Write-Finding ('PowerShell 2.0 STILL RUNS and a RESTART is pending: ' + $afterRun.Detail +
                           '. Reboot, then re-run to confirm the engine is gone.')
        }
        else {
            # Worded off $changeCount, because "the feature is off and the engine
            # still runs" and "there was no feature to turn off here" are different
            # stories and the operator has to be told the right one.
            $why = 'no restart is pending, and nothing this run did closed the exposure'
            if ($changeCount -gt 0) {
                $why = ('the feature reads back as disabled and no restart is pending, so the engine ' +
                        'is loading from something this script does not control')
            }
            Write-Finding ('PowerShell 2.0 STILL RUNS after this run: ' + $afterRun.Detail + '. ' +
                           $why + ' - do not treat this host as covered until that is understood.')
        }
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
    Write-Host ('IronBlackBox - ' + $script:ScriptName + ' v' + $script:ScriptVersion + ' [' + $mode + ']') -ForegroundColor White

    # BEFORE anything is read, locked or changed, because a bad argument must cost
    # nothing. -RunId and -AbandonRun both name a run and the rollback path below
    # resolves ONE target: it used to resolve -RunId and then overwrite it from
    # -AbandonRun, so '-Rollback -RunId A -AbandonRun B' discarded A without a word.
    # Abandoning naming its run is the first of the four properties docs/DESIGN.md
    # section 4.2 relies on, so two different run ids is refused rather than quietly
    # resolved in favour of one. The same id twice is redundant, not ambiguous. This
    # throw reaches the bottom catch, which is exit 2 - not the 1 a binding-time
    # failure would have produced.
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
        Write-Ok 'No findings: PowerShell 2.0 is not a bypass on this host.'
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
            if ($script:RestartNeeded) {
                Write-Info 'A RESTART is required to complete the removal. Until then the engine may still load.'
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

        # One resolution, one target. -AbandonRun names the run it abandons, so it IS
        # the explicit run id when supplied; the check at the top of Invoke-Main has
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
                $outcome = Restore-FeatureChange -ChangeRecord $target.Changes[$i]
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
        if ($script:RestartNeeded) {
            Write-Info 'A RESTART is required to complete the change.'
        }
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
