<#
.SYNOPSIS
    Compares the host against everything IronBlackBox recorded changing, and
    reports what has since been turned off.

.DESCRIPTION
    The flagship of anti-tampering/, and the script the manifest design exists
    to make possible. Every other state-changing script records what it changed
    and what the previous value was; this one reads all of that back and asks,
    for each change, whether the host still holds it.

    READ-ONLY, and there is no -Apply or -Rollback. Detecting drift and
    repairing it are different jobs: repair means re-running the script that
    owns the setting, which knows how to record what it does. A drift detector
    that silently re-applied would be changing a production host from a
    scheduled task, with no operator deciding it should happen.

    Exit 0 means no drift among the changes this toolkit recorded. Exit 1 means
    drift, which is the RMM-alertable state.

    WHAT IT CANNOT SEE, and says so on every run. The comparison is only as
    complete as the manifest. If a script ran -Apply on a host that was already
    compliant - configured by GPO, say - it recorded a run with changeCount 0
    and no change records, because there was nothing to change. Those settings
    are therefore invisible here: if a GPO stops enforcing them tomorrow, this
    script will not notice, because it was never told they were expected. Rather
    than let exit 0 imply "the host is fine", the coverage section names every
    such blind spot.

    Runs that were deliberately rolled back are excluded. A rolled-back change
    is supposed to be gone; reporting it as drift would train an operator to
    ignore the output.

.PARAMETER ToolkitRoot
    Base directory holding the manifest. Default C:\ProgramData\IronBlackBox.

.PARAMETER Detailed
    Also list every change that is still intact, not just the drifted ones.

.EXAMPLE
    .\Test-VisibilityDrift.ps1
    Reports what has drifted. Exit 1 if anything has.

.EXAMPLE
    .\Test-VisibilityDrift.ps1 -Detailed
    Also lists what is still in place.

.NOTES
    Author  : Secur01
    Project : IronBlackBox - https://github.com/Secur01/IronBlackBox
    Version : 1.0.1
    License : MIT

    Windows PowerShell 5.1. Read-only. Requires local administrator to read the
    audit policy and the event channel descriptors.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] $ToolkitRoot = 'C:\ProgramData\IronBlackBox',

    [Parameter()]
    [switch] $Detailed
)

$ErrorActionPreference = 'Stop'
# Version 1.0, not 2.0: 2.0 also throws on a non-existent property, and the
# manifest records read back from JSON legitimately carry different property
# sets per recordType. Catching typo'd variables is the win worth having here.
Set-StrictMode -Version 1.0

$script:ScriptName    = 'Test-VisibilityDrift'
$script:ScriptVersion = '1.0.1'

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
#region Drift comparison ------------------------------------------------------

function Get-ExpectedChange {
    <#
        Every change this toolkit still expects to hold, newest wins.

        Unlike the other scripts, this reads the manifest across ALL scripts -
        it is auditing the toolkit's whole footprint, not its own.

        Runs with a completed rollback are excluded: a rolled-back change is
        supposed to be gone, and reporting it as drift would teach the operator
        to ignore this script.

        Deduplication is by target identity, not by changeId, so a later run
        that set the same value again supersedes the earlier record rather than
        being reported twice.
    #>
    $records = Read-Manifest
    if ($records.Count -eq 0) { return @{ Expected = @(); Blind = @(); Abandoned = @() } }

    $rolledBack = @{}
    foreach ($record in $records) {
        # The 'completed' PREFIX, not equality, and this is the fix for R-1.
        #
        # A rollback records 'completed-with-permanent-declines' when everything
        # it could undo was undone and what is left cannot be undone by this
        # toolkit at all. Testing for equality treated those runs as never rolled
        # back, so this detector kept expecting every change they contained -
        # including all the ones that HAD been restored. Measured on the domain
        # member: 29 changes reported as drifted on a host where every one of
        # them was correctly back to its previous value. One un-undoable change
        # poisoned its whole run, and the flagship cried wolf on a clean host.
        #
        # A permanently-declined change is not lost from view either: the host
        # still holds what was applied, so the drift comparison for it simply
        # matches and says nothing. Which is the truth - it is still there.
        if ($record.recordType -eq 'rollback' -and
            ([string] $record.status).StartsWith('completed', [System.StringComparison]::Ordinal)) {
            $rolledBack[[string] $record.runId] = $true
        }
    }

    # PER-CHANGE, which is the half the run-level exclusion above cannot do.
    #
    # A rollback that restored eighteen changes and legitimately declined one -
    # because a LATER run of the same script had since touched that value -
    # records 'failed'. The run therefore stays eligible, and a detector working
    # only per-run goes on expecting all nineteen, so the eighteen it did undo
    # are reported as drift forever. Measured that way on the domain member: 29
    # false drifts, every one of them a change this toolkit had itself put back.
    #
    # Host state cannot settle it. A value returned to its pre-hardening state by
    # a rollback and a value an attacker switched off look exactly alike from
    # here. Only the rollback's own account of what it restored tells them apart,
    # which is why it now writes one.
    $restoredChanges = @{}
    foreach ($record in $records) {
        if ($record.recordType -ne 'rollback') { continue }
        foreach ($id in @($record.restoredChangeIds)) {
            if (-not [string]::IsNullOrWhiteSpace([string] $id)) { $restoredChanges[[string] $id] = $true }
        }
    }

    # Runs an operator ABANDONED with -Rollback -AbandonRun. Their changes stop
    # being expected - that is what abandoning means - but they are NAMED in the
    # coverage report rather than quietly disappearing. Somebody who decided to
    # stop being told about a change should still be able to see, on any later
    # run, that the decision was made and when.
    $abandoned = New-Object System.Collections.ArrayList
    foreach ($record in $records) {
        if ($record.recordType -ne 'rollback') { continue }
        if ([string] $record.status -ne 'completed-abandoned-by-operator') { continue }
        $run = $records | Where-Object {
            $_.recordType -eq 'run' -and [string] $_.runId -eq [string] $record.runId
        } | Select-Object -First 1
        $scriptName = '<unknown>'
        if ($null -ne $run) { $scriptName = [string] $run.script }
        [void] $abandoned.Add([PSCustomObject] @{
            Script = $scriptName
            RunId  = [string] $record.runId
            When   = [string] $record.timestampUtc
            Count  = @($record.abandonedChangeIds).Count
        })
    }

    # Runs that reported changing nothing: the host already matched, so no
    # change records exist and nothing here can be verified. Tracked so the
    # coverage report can name them instead of letting exit 0 look complete.
    $blind = New-Object System.Collections.ArrayList
    foreach ($record in $records) {
        if ($record.recordType -ne 'run-end') { continue }
        if ([int] $record.changeCount -ne 0) { continue }
        $runId = [string] $record.runId
        $run = $records | Where-Object { $_.recordType -eq 'run' -and $_.runId -eq $runId } | Select-Object -First 1
        if ($null -eq $run) { continue }
        if ($run.mode -ne 'Apply') { continue }
        [void] $blind.Add([PSCustomObject] @{ Script = [string] $run.script; When = [string] $run.startedUtc })
    }

    $expected = New-Object System.Collections.Specialized.OrderedDictionary
    foreach ($record in $records) {
        if ($record.recordType -ne 'change') { continue }
        if ($rolledBack.ContainsKey([string] $record.runId)) { continue }
        # This exact change was restored by a rollback, whatever the rest of that
        # rollback managed. Expecting it back would be reporting the toolkit's own
        # correct behaviour as drift.
        if ($restoredChanges.ContainsKey([string] $record.changeId)) { continue }

        $run = $records | Where-Object { $_.recordType -eq 'run' -and $_.runId -eq $record.runId } | Select-Object -First 1
        $scriptName = '<unknown>'
        if ($null -ne $run) {
            if ($run.mode -ne 'Apply') { continue }
            $scriptName = [string] $run.script
        }

        $change = $record.change
        switch ([string] $change.type) {
            'registry'       { $key = 'registry|'       + $change.path + '|' + $change.name; break }
            'auditpol'       { $key = 'auditpol|'       + $record.runId; break }
            'channelaccess'  { $key = 'channelaccess|'  + $change.channel; break }
            'windowsfeature' { $key = 'windowsfeature|' + $change.featureName; break }
            'eventchannel'   { $key = 'eventchannel|'   + $change.channel; break }
            'service'        { $key = 'service|'        + [string] (Get-ChangeField -Change $change -Name @('serviceName', 'service')); break }
            'servicestartup' { $key = 'service|'        + [string] (Get-ChangeField -Change $change -Name @('serviceName', 'service')); break }
            'scheduledtask'  { $key = 'scheduledtask|'  + $change.taskPath + '|' + $change.taskName; break }
            'shadowstorage'  { $key = 'shadowstorage|'  + $change.volume; break }
            'usnjournal'     { $key = 'usnjournal|'     + $change.volume; break }
            # Types with no natural per-target identity are keyed per record, so
            # each one is reported rather than collapsing into a single entry.
            default          { $key = 'other|' + [string] $change.type + '|' + $record.changeId }
        }
        $entry = [PSCustomObject] @{
            Key    = $key
            Type   = [string] $change.type
            Change = $change
            Script = $scriptName
            When   = [string] $record.recordedUtc
        }
        if ($expected.Contains($key)) { $expected[$key] = $entry }
        else { $expected.Add($key, $entry) }
    }

    # AT-2: expectation records carry the FULL intended target set for a script,
    # not just what it changed - so a subcategory that was already enabled at
    # apply time, which produced no change record and was therefore invisible
    # here, is now verified. Same rolled-back-run exclusion as changes: an
    # expectation from a rolled-back run is not enforced. Newest per (script,
    # type) wins, so re-applying refreshes the intended set.
    foreach ($record in $records) {
        if ($record.recordType -ne 'expectation') { continue }
        if ($rolledBack.ContainsKey([string] $record.runId)) { continue }
        $run = $records | Where-Object { $_.recordType -eq 'run' -and $_.runId -eq $record.runId } | Select-Object -First 1
        $scriptName = '<unknown>'
        if ($null -ne $run) {
            if ($run.mode -ne 'Apply') { continue }
            $scriptName = [string] $run.script
        }
        $change = $record.change
        $key = 'expect|' + $scriptName + '|' + [string] $change.type
        $entry = [PSCustomObject] @{
            Key    = $key
            Type   = [string] $change.type
            Change = $change
            Script = $scriptName
            When   = [string] $record.recordedUtc
        }
        if ($expected.Contains($key)) { $expected[$key] = $entry }
        else { $expected.Add($key, $entry) }
    }

    return @{ Expected = @($expected.Values); Blind = @($blind.ToArray())
             Abandoned = @($abandoned.ToArray()) }
}

function Test-RegistryExpectation {
    param([Parameter(Mandatory = $true)] $Entry)

    $change = $Entry.Change
    $state = Get-RegistryValueState -Path $change.path -Name $change.name
    $label = ($change.path + '\' + $change.name)

    if (-not $state.Exists) {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label
            Detail = 'the value is gone' }
    }
    if ([string] $state.Kind -ne [string] $change.newKind) {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label
            Detail = ('type changed from ' + $change.newKind + ' to ' + $state.Kind) }
    }
    if (-not (Test-ManifestValueEqual -Left $state.Value -Right $change.newValue -Kind ([string] $change.newKind))) {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label
            Detail = 'the value no longer matches what was applied' }
    }
    return [PSCustomObject] @{ Status = 'OK'; Label = $label; Detail = 'unchanged' }
}

function Test-AuditPolExpectation {
    <#
        Re-reads the audit policy and checks the subcategories the run enabled
        are still at least as enabled. Reading is via 'auditpol /backup', whose
        last column is a numeric setting value, so this never parses localised
        text.
    #>
    param(
        [Parameter(Mandatory = $true)] $Entry,
        [Parameter(Mandatory = $true)][string] $WorkDirectory
    )

    $change = $Entry.Change
    $wanted = @($change.subcategories)
    if ($wanted.Count -eq 0) {
        return [PSCustomObject] @{ Status = 'OK'; Label = 'audit policy'; Detail = 'no subcategories recorded' }
    }

    $probe = [System.IO.Path]::Combine($WorkDirectory, 'drift-auditpol.csv')
    $result = Invoke-NativeCommand -FilePath (Get-NativeToolPath -FileName 'auditpol.exe') `
                  -Arguments @('/backup', ('/file:' + $probe))
    if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $probe)) {
        return [PSCustomObject] @{ Status = 'UNCHECKABLE'; Label = 'audit policy'
            Detail = ('auditpol /backup failed with exit ' + $result.ExitCode) }
    }

    $state = @{}
    $lines = @(Get-Content -LiteralPath $probe)
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $fields = $lines[$i] -split ','
        if ($fields.Count -lt 7) { continue }
        $parsed = 0
        if ([int]::TryParse($fields[$fields.Count - 1].Trim(),
                [System.Globalization.NumberStyles]::Integer,
                    [System.Globalization.CultureInfo]::InvariantCulture, [ref] $parsed)) {
            $state[$fields[3].Trim().ToUpperInvariant()] = $parsed
        }
    }
    if ($state.Count -eq 0) {
        return [PSCustomObject] @{ Status = 'UNCHECKABLE'; Label = 'audit policy'
            Detail = 'the backup produced no readable rows' }
    }

    $off = @()
    foreach ($guid in $wanted) {
        $key = ([string] $guid).ToUpperInvariant()
        if (-not $state.ContainsKey($key)) { $off += ([string] $guid + ' (absent)'); continue }
        # 0 means no auditing at all. Anything non-zero is still recording
        # something; this script does not re-litigate which bits, because the
        # applying script only ever adds.
        if ($state[$key] -eq 0) { $off += [string] $guid }
    }

    if ($off.Count -gt 0) {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = 'audit policy'
            Detail = ([string] $off.Count + ' of ' + [string] $wanted.Count +
                      ' subcategor(y/ies) switched off: ' + ($off -join ', ')) }
    }
    return [PSCustomObject] @{ Status = 'OK'; Label = 'audit policy'
        Detail = ('all ' + [string] $wanted.Count + ' subcategories still enabled') }
}

function Test-ChannelAccessExpectation {
    <#
        Compares by decoded per-SID mask, never by descriptor text: .NET and
        Windows render the same descriptor differently (CCDCLC vs 0x7), so a
        string comparison would report drift on every run.
    #>
    param([Parameter(Mandatory = $true)] $Entry)

    $change = $Entry.Change
    $label = ('channel ' + $change.channel)

    $result = Invoke-NativeCommand -FilePath (Get-NativeToolPath -FileName 'wevtutil.exe') `
                  -Arguments @('gl', [string] $change.channel)
    if ($result.ExitCode -ne 0) {
        return [PSCustomObject] @{ Status = 'UNCHECKABLE'; Label = $label
            Detail = 'wevtutil gl failed' }
    }
    $current = $null
    foreach ($line in $result.Output) {
        if ($line -match '^\s*channelAccess:\s*(.+)$') { $current = $Matches[1].Trim(); break }
    }
    if ([string]::IsNullOrWhiteSpace($current)) {
        return [PSCustomObject] @{ Status = 'UNCHECKABLE'; Label = $label
            Detail = 'no channelAccess in wevtutil output' }
    }

    try {
        $nowMap = Get-SddlMaskMap -Sddl $current
        $wantMap = Get-SddlMaskMap -Sddl ([string] $change.newSddl)
    }
    catch {
        return [PSCustomObject] @{ Status = 'UNCHECKABLE'; Label = $label
            Detail = ('could not decode a descriptor: ' + $_.Exception.Message) }
    }

    $loosened = @()
    foreach ($sid in $wantMap.Keys) {
        $now = 0
        if ($nowMap.ContainsKey($sid)) { $now = $nowMap[$sid] }
        $gained = $now -band (-bnot $wantMap[$sid])
        if ($gained -ne 0) { $loosened += ($sid + ' gained 0x' + ('{0:X}' -f $gained)) }
    }
    foreach ($sid in $nowMap.Keys) {
        if (-not $wantMap.ContainsKey($sid)) {
            $loosened += ($sid + ' was added')
        }
    }

    if ($loosened.Count -gt 0) {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label
            Detail = ('the descriptor was loosened: ' + ($loosened -join '; ')) }
    }
    return [PSCustomObject] @{ Status = 'OK'; Label = $label; Detail = 'no principal gained access' }
}

function Get-ChangeField {
    <#
        Reads one logical field out of a manifest change record, trying each name
        it has ever been written under.

        The manifest is APPEND-ONLY, so a record written last month keeps the
        field names it was written with. Renaming a field in the writers does not
        rename it on disk, which is why this reader has to stay bilingual rather
        than the writers simply being tidied up.

        Two splits were found by measuring, not by reading the code:

          eventchannel  three scripts write newMaxSize / previousMaxSize
                        (Enable-IRVisibility, Enable-DnsVisibility,
                        Enable-LolbinAudit) and two write newMaxSizeBytes /
                        previousMaxSizeBytes (Enable-LegacyAuthAudit,
                        Enable-WefCollector). This function read only the first
                        spelling, so a shrunk AppLocker or ForwardedEvents
                        channel was silently never checked.
          service       Protect-ForensicArtifacts writes serviceName and
                        Set-TimelineIntegrity writes service, so W32Time changes
                        could never verify at all - they keyed on an empty string.

        A drift detector that misses in silence is worse than one that is absent,
        because it reassures. tools/check.ps1 now fails the build when two scripts
        write the same change type with different field names, so the next split
        is caught before it ships instead of by an audit.
    #>
    param(
        [Parameter(Mandatory = $true)] $Change,
        [Parameter(Mandatory = $true)][string[]] $Name
    )

    foreach ($candidate in $Name) {
        $property = $Change.PSObject.Properties[$candidate]
        if ($null -eq $property) { continue }
        if ($null -eq $property.Value) { continue }
        if (($property.Value -is [string]) -and [string]::IsNullOrWhiteSpace($property.Value)) { continue }
        return $property.Value
    }
    return $null
}

function Get-SddlMaskMap {
    param([Parameter(Mandatory = $true)][string] $Sddl)
    $map = @{}
    $sd = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false, $false, $Sddl)
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace.AceType -ne 'AccessAllowed') { continue }
        $key = $ace.SecurityIdentifier.Value
        if ($map.ContainsKey($key)) { $map[$key] = $map[$key] -bor $ace.AccessMask }
        else { $map[$key] = $ace.AccessMask }
    }
    return $map
}

function Test-FeatureExpectation {
    param([Parameter(Mandatory = $true)] $Entry)

    $change = $Entry.Change
    $label = ('feature ' + $change.featureName)
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName ([string] $change.featureName)
    }
    catch {
        return [PSCustomObject] @{ Status = 'UNCHECKABLE'; Label = $label
            Detail = ('DISM query failed: ' + $_.Exception.Message) }
    }
    if ($null -eq $feature) {
        return [PSCustomObject] @{ Status = 'UNCHECKABLE'; Label = $label
            Detail = 'feature no longer present on this host' }
    }

    $want = [string] $change.newState
    $now  = [string] $feature.State
    # 'Disabled' was the goal; DisabledWithPayloadRemoved is more disabled, not
    # less, so it is not drift.
    if ($want -eq 'Disabled' -and $now -like 'Disabled*') {
        return [PSCustomObject] @{ Status = 'OK'; Label = $label; Detail = ('still ' + $now) }
    }
    if ($now -eq $want) {
        return [PSCustomObject] @{ Status = 'OK'; Label = $label; Detail = ('still ' + $now) }
    }
    return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label
        Detail = ('was set to ' + $want + ', now ' + $now) }
}

function Test-EventChannelExpectation {
    <#
        An event channel that was enabled and sized by the toolkit, and has since
        been disabled or shrunk, is exactly the kind of quiet loss this script
        exists to catch: the host keeps running and simply stops recording.

        Note the unit trap, recorded in verification/facts.json: wevtutil
        reports and takes BYTES, while the EventLog *policy* MaxSize is in
        KILOBYTES. This compares wevtutil's bytes against the bytes the
        applying script recorded, so both sides are the same unit.
    #>
    param([Parameter(Mandatory = $true)] $Entry)

    $change = $Entry.Change
    $label = ('channel ' + $change.channel)

    $result = Invoke-NativeCommand -FilePath (Get-NativeToolPath -FileName 'wevtutil.exe') `
                  -Arguments @('gl', [string] $change.channel)
    if ($result.ExitCode -ne 0) {
        return [PSCustomObject] @{ Status = 'UNCHECKABLE'; Label = $label
            Detail = 'wevtutil gl failed - the channel may no longer exist' }
    }

    $enabled = $null
    $maxSize = $null
    foreach ($line in $result.Output) {
        if ($line -match '^\s*enabled:\s*(\S+)\s*$')  { $enabled = $Matches[1].Trim() }
        if ($line -match '^\s*maxSize:\s*(\d+)\s*$')   { $maxSize = [int64] $Matches[1] }
    }

    # An UNPARSED field is not a field reading 'off'. wevtutil gl can exit 0 and
    # still not yield the exact shapes above - an extra field on the line, or a
    # key name this parser does not know: verification/facts.json row
    # 'wevtutil-gl-reports-logfilename' marks whether these key names are
    # localised on a non-English host as UNVERIFIED, and records that the code
    # reading that same output block "fails closed if the key is not found".
    # This one did the opposite. The 'enabled' half resolved the unknown to
    # $false and printed "the channel has been DISABLED" about a channel nobody
    # had touched; the 'maxSize' half resolved it to silence. Both are now
    # reported as unknown, the way Test-UsnJournalExpectation already reports an
    # unparseable fsutil line rather than guessing which way it fell.
    $problems = @()
    $unknown = @()
    if ($null -ne $change.newEnabled) {
        $wantEnabled = ([string] $change.newEnabled -eq 'true' -or [string] $change.newEnabled -eq 'True')
        if ($wantEnabled) {
            if ($null -eq $enabled) {
                $unknown += ('no "enabled:" line could be parsed out of wevtutil gl output, so ' +
                             'whether the channel is still enabled is unknown - not proven disabled')
            }
            elseif ($enabled -ne 'true') { $problems += 'the channel has been DISABLED' }
        }
    }
    $recordedSize = Get-ChangeField -Change $change -Name @('newMaxSize', 'newMaxSizeBytes')
    if ($null -ne $recordedSize) {
        if ($null -eq $maxSize) {
            $unknown += ('no "maxSize:" line could be parsed out of wevtutil gl output, so whether ' +
                         'the channel still holds the ' + [string] $recordedSize +
                         ' bytes applied is unknown - not proven intact')
        }
        else {
            $wantSize = [int64] $recordedSize
            # Shrunk, not merely different: wevtutil rounds to 64KB multiples, so an
            # exact-match test would report drift on a host nobody touched.
            if ($maxSize -lt $wantSize) {
                $problems += ('the channel was shrunk from ' + [string] $wantSize + ' to ' + [string] $maxSize + ' bytes')
            }
        }
    }

    # A measured drift outranks an unknown: one field that could not be read
    # does not make a shrink this run DID measure any less true.
    if ($problems.Count -gt 0) {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label; Detail = ($problems -join '; ') }
    }
    if ($unknown.Count -gt 0) {
        return [PSCustomObject] @{ Status = 'NOT-VERIFIED'; Label = $label; Detail = ($unknown -join '; ') }
    }
    return [PSCustomObject] @{ Status = 'OK'; Label = $label; Detail = 'still enabled and no smaller' }
}

function Test-ServiceExpectation {
    <#
        A service the toolkit set to Automatic and started, now disabled or
        stopped. W32Time and DPS are the cases: both stop producing the evidence
        their script turned on, silently.
    #>
    param([Parameter(Mandatory = $true)] $Entry)

    $change = $Entry.Change
    $serviceName = [string] (Get-ChangeField -Change $change -Name @('serviceName', 'service'))
    if ([string]::IsNullOrWhiteSpace($serviceName)) {
        return [PSCustomObject] @{ Status = 'UNCHECKABLE'; Label = 'service (unnamed)'
            Detail = 'the record names no service under any field name this reader knows' }
    }
    $label = ('service ' + $serviceName)

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label
            Detail = 'the service is no longer present on this host' }
    }

    $problems = @()
    if ($null -ne $change.newStartType) {
        $want = [string] $change.newStartType
        $now  = [string] $service.StartType
        # Automatic is the only start type worth policing here. A service moved
        # from Automatic to Manual still runs today and will not after a reboot,
        # which is the quiet version of being switched off.
        if ($want -eq 'Automatic' -and $now -ne 'Automatic') {
            $problems += ('start type changed from Automatic to ' + $now)
        }
    }
    if ($null -ne $change.newStatus) {
        if ([string] $change.newStatus -eq 'Running' -and [string] $service.Status -ne 'Running') {
            $problems += ('the service is ' + [string] $service.Status)
        }
    }

    if ($problems.Count -gt 0) {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label; Detail = ($problems -join '; ') }
    }
    return [PSCustomObject] @{ Status = 'OK'; Label = $label
        Detail = ('still ' + [string] $service.StartType + '/' + [string] $service.Status) }
}

function Test-ScheduledTaskExpectation {
    <#
        A scheduled task the toolkit registered, now gone or disabled. Deleting
        the tamper-alert task is the obvious first move against it, so its
        absence is a finding in its own right.
    #>
    param([Parameter(Mandatory = $true)] $Entry)

    $change = $Entry.Change
    $label = ('scheduled task ' + [string] $change.taskPath + [string] $change.taskName)

    try {
        $task = Get-ScheduledTask -TaskPath ([string] $change.taskPath) `
                    -TaskName ([string] $change.taskName) -ErrorAction Stop
    }
    catch {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label
            Detail = 'the task has been DELETED' }
    }
    if ($null -eq $task) {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label; Detail = 'the task has been DELETED' }
    }
    if ([string] $task.State -eq 'Disabled') {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label; Detail = 'the task has been DISABLED' }
    }
    return [PSCustomObject] @{ Status = 'OK'; Label = $label; Detail = ('state ' + [string] $task.State) }
}

function Test-UsnJournalExpectation {
    <#
        A USN journal the toolkit sized up, now smaller - or gone. Both mean the
        volume keeps less rename-and-delete history than the toolkit arranged
        for, which on a ransomware investigation is the difference between a
        timeline and a guess.

        Sizes are compared as a FLOOR. A host above what was applied is not
        drift: Enable-UsnJournalTracking treats its size as a minimum, and
        somebody raising it further is doing the right thing.

        Measured behaviour that shapes this: fsutil exits 0 whether it changed
        the size or not, so what was recorded as applied may never have landed.
        A journal at the size recorded BEFORE the change is therefore reported
        as unverifiable rather than as drift - the two are indistinguishable
        from here.
    #>
    param([Parameter(Mandatory = $true)] $Entry)

    $change = $Entry.Change
    $volume = [string] $change.volume
    $label = ('USN journal on ' + $volume)

    $result = Invoke-NativeCommand -FilePath (Get-NativeToolPath -FileName 'fsutil.exe') `
                  -Arguments @('usn', 'queryjournal', $volume)
    if ($result.ExitCode -ne 0) {
        # Not drift: a non-zero exit means the state is UNKNOWN, and Microsoft
        # documents a state in which a journal exists and every query errors.
        return [PSCustomObject] @{ Status = 'NOT-VERIFIED'; Label = $label
            Detail = ('fsutil usn queryjournal exited ' + [string] $result.ExitCode +
                      ', so the journal state here is unknown - not proven absent') }
    }

    $current = $null
    foreach ($line in $result.Output) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if (-not [regex]::IsMatch($line, '(?i)maximum\s+size')) { continue }
        $match = [regex]::Match($line, '(0x[0-9a-fA-F]+|[0-9]+)\s*$')
        if ($match.Success) { $current = ConvertFrom-NativeInteger -Text $match.Groups[1].Value }
    }
    if ($null -eq $current) {
        return [PSCustomObject] @{ Status = 'NOT-VERIFIED'; Label = $label
            Detail = 'the journal maximum size could not be parsed out of fsutil output' }
    }

    $applied = ConvertFrom-NativeInteger -Text ([string] $change.newMaxSize)
    if ($null -eq $applied) {
        return [PSCustomObject] @{ Status = 'NOT-VERIFIED'; Label = $label
            Detail = 'the recorded applied size could not be read from the manifest' }
    }

    if ([long] $current -ge [long] $applied) {
        return [PSCustomObject] @{ Status = 'OK'; Label = $label
            Detail = ('maximum size ' + [string] $current + ' bytes, at or above the ' +
                      [string] $applied + ' bytes applied') }
    }

    $previous = ConvertFrom-NativeInteger -Text ([string] $change.previousMaxSize)
    if ($null -ne $previous -and [long] $current -eq [long] $previous) {
        return [PSCustomObject] @{ Status = 'NOT-VERIFIED'; Label = $label
            Detail = ('maximum size is ' + [string] $current + ' bytes, exactly what was recorded ' +
                      'BEFORE the change - so either the resize never landed (fsutil exits 0 either ' +
                      'way) or it was undone. Indistinguishable from here.') }
    }

    return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label
        Detail = ('maximum size is ' + [string] $current + ' bytes, below the ' + [string] $applied +
                  ' bytes applied - the volume keeps less history than was arranged') }
}

function Test-ShadowStorageExpectation {
    <#
        Shadow storage the toolkit sized up, now smaller or gone. A smaller
        maximum means fewer snapshots survive, and Microsoft documents that
        resizing can make existing ones disappear outright.

        A floor again, for the same reason as the USN journal: more than was
        applied is not drift.
    #>
    param([Parameter(Mandatory = $true)] $Entry)

    $change = $Entry.Change
    $volume = [string] $change.volume
    $label = ('shadow storage for ' + $volume)

    $applied = ConvertFrom-NativeInteger -Text ([string] $change.newMaxSpaceBytes)
    if ($null -eq $applied) {
        return [PSCustomObject] @{ Status = 'NOT-VERIFIED'; Label = $label
            Detail = 'the recorded applied maximum could not be read from the manifest' }
    }

    $wanted = $volume.TrimEnd('\').TrimEnd(':').ToUpperInvariant()

    # -ErrorAction Stop, and both queries hoisted out of the loop. They used to
    # run with -ErrorAction SilentlyContinue, which made a denied, faulted or
    # unregistered WMI repository indistinguishable from an absent association -
    # and the absent branch below tells the operator, in the imperative, that
    # every snapshot on the volume is gone. verification/facts.json row
    # 'cim-nativeerrorcode-distinguishes-absent-from-unreadable' states the rule
    # this now follows: a class present but not READABLE is never "absent".
    # Test-UsnJournalExpectation above already refuses to turn a failed query
    # into a claim about state; so does this.
    $storageInstances = @()
    $volumeInstances  = @()
    try {
        $storageInstances = @(Get-CimInstance -ClassName Win32_ShadowStorage -ErrorAction Stop)
        $volumeInstances  = @(Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop)
    }
    catch {
        return [PSCustomObject] @{ Status = 'UNCHECKABLE'; Label = $label
            Detail = ('Win32_ShadowStorage/Win32_Volume could not be queried (' +
                      $_.Exception.Message + ') - the shadow storage state here is unknown, ' +
                      'not proven deleted') }
    }

    # The volume has to be IDENTIFIED before its absence from Win32_ShadowStorage
    # can mean anything. Enable-VssPreservation draws the same line on the
    # applying side: its Get-ShadowStorageForVolume carries a separate
    # 'Correlated' flag precisely because a volume that cannot be identified "is
    # a different and worse answer than 'no association'".
    $deviceIds = @()
    foreach ($vol in $volumeInstances) {
        if ([string]::IsNullOrWhiteSpace($vol.DriveLetter)) { continue }
        $letter = ([string] $vol.DriveLetter).TrimEnd('\').TrimEnd(':').ToUpperInvariant()
        if ($letter -ne $wanted) { continue }
        $deviceIds += [string] $vol.DeviceID
    }
    if ($deviceIds.Count -eq 0) {
        return [PSCustomObject] @{ Status = 'NOT-VERIFIED'; Label = $label
            Detail = ('no volume with drive letter ' + $wanted + ': is present on this host, so ' +
                      'whether its shadow storage still exists cannot be determined from here') }
    }

    # LARGEST match, not last-wins. A protected volume can carry more than one
    # shadow storage association - one per diff volume, which is why the applying
    # script records a 'diffVolume' alongside the volume - and the floor test
    # below asks whether the maximum that was applied is still somewhere on this
    # volume. Keeping whichever instance WMI happened to return last reported
    # drift on the strength of the smallest.
    $current = $null
    foreach ($instance in $storageInstances) {
        $deviceId = ''
        $reference = $instance.Volume
        if ($null -ne $reference) {
            if ($reference -is [Microsoft.Management.Infrastructure.CimInstance]) {
                $deviceId = [string] $reference.CimInstanceProperties['DeviceID'].Value
            }
            else { $deviceId = [string] $reference }
        }
        foreach ($id in $deviceIds) {
            if ([string]::IsNullOrEmpty($id)) { continue }
            if (-not ($deviceId -like ('*' + $id + '*'))) { continue }
            $candidate = [long] $instance.MaxSpace
            if ($null -eq $current -or $candidate -gt [long] $current) { $current = $candidate }
        }
    }

    if ($null -eq $current) {
        return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label
            Detail = ('no shadow storage association for ' + $volume + ' exists any more - it was ' +
                      'deleted, and every snapshot in it went with it') }
    }
    if ([long] $current -ge [long] $applied) {
        return [PSCustomObject] @{ Status = 'OK'; Label = $label
            Detail = ('maximum ' + [string] $current + ' bytes, at or above the ' + [string] $applied +
                      ' bytes applied') }
    }
    return [PSCustomObject] @{ Status = 'DRIFT'; Label = $label
        Detail = ('maximum is ' + [string] $current + ' bytes, below the ' + [string] $applied +
                  ' bytes applied - fewer snapshots will survive than was arranged') }
}

# Change types this script KNOWS about but deliberately does not verify, with
# the reason. The distinction matters: a type listed here is a declared limit
# and is reported as information, whereas an unrecognised type is a real gap -
# it means a script introduced a change type and nobody taught this one about
# it, and that stays a finding.
$script:UnverifiableTypes = @{
    'defenderbaseline'        = 'a point-in-time snapshot, not host state - there is nothing to compare it against'
    'defenderexclusion'       = 'Protect-DefenderConfig owns the exclusion diff and reports added exclusions itself'
    'sysmoninstall'           = 'verifying it means running Sysmon64.exe -c; that belongs to Enable-Sysmon'
    'sysmonconfig'            = 'the active config hash needs Sysmon64.exe -c; Enable-Sysmon reports it'
    'applockerpolicy'         = 'the previous policy is stored as a file; comparing effective policy needs Get-AppLockerPolicy'
    'dnsserversetting'        = 'needs the DNS Server role and dnscmd; Enable-DnsVisibility reports it'
    'wefsubscriptionmanager'  = 'a forwarding target; whether events actually arrive is the collector-side question'
    'wefsubscription'         = 'subscription runtime status needs wecutil gr on the collector'
    'winrmconfig'             = 'WinRM listener state is reported by Enable-WefClient, and this script must not touch WinRM'
    'adobjectsacl'            = 'needs a domain controller and an LDAP bind'
}

function Invoke-HostCheck {
    param([Parameter(Mandatory = $true)][string] $WorkDirectory)

    $collected = Get-ExpectedChange
    $expected = @($collected.Expected)
    $blind = @($collected.Blind)
    $abandonedRuns = @($collected.Abandoned)

    Write-Section 'Recorded changes'

    if ($expected.Count -eq 0) {
        Write-Info 'The manifest records no active changes for this host.'
        Write-Info 'Either no IronBlackBox script has applied anything here, or everything was rolled back.'
    }

    $drift = 0
    $unchecked = 0
    $notVerified = 0
    foreach ($entry in $expected) {
        switch ($entry.Type) {
            'registry'       { $verdict = Test-RegistryExpectation -Entry $entry; break }
            'auditpol'       { $verdict = Test-AuditPolExpectation -Entry $entry -WorkDirectory $WorkDirectory; break }
            'channelaccess'  { $verdict = Test-ChannelAccessExpectation -Entry $entry; break }
            'windowsfeature' { $verdict = Test-FeatureExpectation -Entry $entry; break }
            'eventchannel'   { $verdict = Test-EventChannelExpectation -Entry $entry; break }
            'service'        { $verdict = Test-ServiceExpectation -Entry $entry; break }
            'servicestartup' { $verdict = Test-ServiceExpectation -Entry $entry; break }
            'scheduledtask'  { $verdict = Test-ScheduledTaskExpectation -Entry $entry; break }
            'usnjournal'     { $verdict = Test-UsnJournalExpectation -Entry $entry; break }
            'shadowstorage'  { $verdict = Test-ShadowStorageExpectation -Entry $entry; break }
            default {
                if ($script:UnverifiableTypes.ContainsKey($entry.Type)) {
                    # A declared limit, not drift. Reporting these as findings
                    # would make this script exit 1 on every correctly hardened
                    # host, which is the fastest way to teach an operator to
                    # ignore it.
                    $verdict = [PSCustomObject] @{ Status = 'NOT-VERIFIED'
                        Label = ('change type ' + $entry.Type)
                        Detail = $script:UnverifiableTypes[$entry.Type] }
                }
                else {
                    $verdict = [PSCustomObject] @{ Status = 'UNCHECKABLE'
                        Label = ('change type ' + $entry.Type)
                        Detail = 'UNRECOGNISED change type - a script recorded this and this one was never taught to verify it' }
                }
            }
        }

        if ($verdict.Status -eq 'DRIFT') {
            $drift++
            Write-Finding ('[' + $entry.Script + '] ' + $verdict.Label + ' - ' + $verdict.Detail)
        }
        elseif ($verdict.Status -eq 'UNCHECKABLE') {
            $unchecked++
            Write-Finding ('[' + $entry.Script + '] ' + $verdict.Label +
                           ' - CANNOT VERIFY: ' + $verdict.Detail)
        }
        elseif ($verdict.Status -eq 'NOT-VERIFIED') {
            $notVerified++
            if ($Detailed) {
                Write-Info ('[' + $entry.Script + '] ' + $verdict.Label + ' - not verified here: ' + $verdict.Detail)
            }
        }
        elseif ($Detailed) {
            Write-Ok ('[' + $entry.Script + '] ' + $verdict.Label + ' - ' + $verdict.Detail)
        }
    }

    Write-Section 'Coverage'
    Write-Info ([string] $expected.Count + ' recorded change(s) examined: ' +
                [string] $drift + ' drifted, ' + [string] $unchecked + ' unverifiable, ' +
                [string] $notVerified + ' not verified here by design')
    if ($notVerified -gt 0 -and -not $Detailed) {
        Write-Info ('  (re-run with -Detailed to list the ' + [string] $notVerified +
                    ' change(s) this script deliberately does not verify)')
    }

    if ($blind.Count -gt 0) {
        Write-Info ''
        Write-Info 'BLIND SPOTS. These runs found the host already compliant and so recorded'
        Write-Info 'no changes. Nothing about those settings is verifiable here - if something'
        Write-Info 'stops enforcing them, this script will not notice:'
        foreach ($b in $blind) {
            Write-Info ('  ' + $b.Script + ' (' + $b.When + ')')
        }
    }

    if ($abandonedRuns.Count -gt 0) {
        Write-Info ''
        Write-Info 'ABANDONED BY AN OPERATOR. Somebody ran -Rollback -AbandonRun on these, so'
        Write-Info 'their changes are no longer expected and no longer reported. Whatever those'
        Write-Info 'changes left on the host is still there. This is a decision, not a'
        Write-Info 'measurement, and it is listed here so it stays visible after the fact:'
        foreach ($a in $abandonedRuns) {
            Write-Info ('  ' + $a.Script + ' run ' + $a.RunId + ' (' + $a.When + '): ' +
                        [string] $a.Count + ' change(s) abandoned')
        }
    }

    if ($drift -eq 0 -and $unchecked -eq 0 -and $expected.Count -gt 0) {
        Write-Ok 'every recorded change is still in place'
    }

    return $drift
}

#endregion

#region Main -----------------------------------------------------------------

function Invoke-Main {
    Write-Host ''
    Write-Host ('IronBlackBox - ' + $script:ScriptName + ' v' + $script:ScriptVersion + ' [Audit]') -ForegroundColor White

    Assert-Elevated
    $resolvedRoot = Assert-SafeToolkitPath -Path $ToolkitRoot
    $script:ManifestPath = [System.IO.Path]::Combine($resolvedRoot, 'manifest.jsonl')

    if (-not (Test-Path -LiteralPath $script:ManifestPath)) {
        Write-Section 'Result'
        Write-Info ('No manifest at ' + $script:ManifestPath + '.')
        Write-Info 'Nothing has been applied on this host, so there is nothing to have drifted.'
        # Deliberately 0, not 1. "The toolkit was never run here" is not drift,
        # and an RMM alerting on it would cry wolf on every unmanaged host.
        return 0
    }

    # Read-only: no lock, no Initialize-ToolkitRoot without -ReadOnly, and the
    # manifest is never written to - not even a run record. A drift detector
    # that appends to the file it audits would grow it on every scheduled run.
    #
    # -AllowMissingStamp for the same reason the parameter exists for -Rollback:
    # someone deleting a 60-byte marker file must not disable the detector. The
    # stamp guard runs BEFORE the -ReadOnly early return, so without this a
    # toolkit root holding a perfectly readable manifest but no .ironblackbox
    # threw, hit the bottom catch, and exited 2 - "broken script" to an RMM
    # rather than "host under attack", on every run, forever. Deleting one
    # dot-file is the first thing an attacker tries against an anti-tampering
    # tool. Nothing is being adopted here: -ReadOnly never touches the DACL or
    # the owner, so the guard has no ownership to refuse, and the manifest.jsonl
    # confirmed above is stronger evidence that this root is ours than the stamp
    # it is standing in for.
    [void] (Initialize-ToolkitRoot -Path $resolvedRoot -ReadOnly -AllowMissingStamp)

    # auditpol needs a scratch file. Use the OS temp directory, never the
    # toolkit root, so this stays strictly read-only where it matters.
    $drift = Invoke-HostCheck -WorkDirectory ([System.IO.Path]::GetTempPath().TrimEnd('\'))

    Write-Section 'Result'
    if ($drift -gt 0) {
        Write-Info ([string] $drift + ' change(s) have drifted. Re-run the owning script with -Apply to restore them.')
        return 1
    }
    if ($script:Findings.Count -gt 0) {
        Write-Info 'No drift detected, but some changes could not be verified - see above.'
        return 1
    }
    if ($script:HostLimits.Count -gt 0) {
        Write-Ok ([string] $script:HostLimits.Count + ' host limit(s) reported above: true '  +
              'on this host and not clearable by any -Apply, so they do not raise the '  +
              'exit code.')
        return 0
    }
    Write-Ok 'No drift.'
    return 0
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
