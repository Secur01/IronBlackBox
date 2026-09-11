<#
.SYNOPSIS
    Static gate for IronBlackBox .ps1 files. Runs under pwsh 7 on Linux.

.DESCRIPTION
    Thirteen checks, all mandatory except PSScriptAnalyzer when the module
    is absent (see -RequireAnalyzer). Checks 1-5 and 7-10 judge one file at a
    time; 6, 11 and 13 are cross-file, because the defects they exist for are
    invisible from inside any single file; 12 judges code that is not a file
    at all:

      1. Encoding    - every .ps1 must start with a UTF-8 BOM (EF BB BF).
      2. AST parse   - Parser.ParseFile() must produce zero parse errors.
                        This is separate from PSScriptAnalyzer because PSSA
                        exits 0 even on a file that does not parse.
      3. Banned PS7  - constructs that do not exist in Windows PowerShell
         syntax        5.1: ternary, null-coalescing, null-conditional,
                        pipeline chain operators, ForEach-Object -Parallel,
                        Get-Date -AsUTC, $IsWindows, multi-child Join-Path.
                        Detection is AST-based wherever the PS7 parser
                        exposes a dedicated node/property for the construct
                        (ternary, ??, ??=, && / ||). Two checks are known
                        approximations, each explained at the check itself:
                        null-conditional ?./?[ is still an experimental,
                        off-by-default PS7 feature, so the default parser
                        never builds a NullConditional AST node for it - the
                        check instead regex-scans for literal '?.'/'?[' and
                        excludes matches inside comment/string tokens; and
                        the Join-Path check counts path-shaped arguments
                        rather than fully binding parameters (it cannot bind
                        without executing the pipeline).
      4. PSScriptAnalyzer, via tools/PSScriptAnalyzerSettings.psd1
         (-Severity Error,Warning), only if the module is installed.
         Missing module is a warning unless -RequireAnalyzer is passed, in
         which case it is a gate failure (useful in CI once the module is
         guaranteed present, without blocking local use before it is
         installed).
      5. Helper drift - helpers are copied verbatim from
         docs/SCRIPT-TEMPLATE.ps1 into scripts (docs/DESIGN.md section 6).
         Fails a script whose copy of a shared #region (matched by name,
         excluding script-specific 'Main'/'EXAMPLE*') differs from the
         template, ignoring trailing whitespace and leading/trailing blank
         lines. Omitting a template region is allowed.
      6. Manifest field names, across scripts - two scripts writing the
         same change type with different field names is invisible from
         inside either one, and made the drift detector silently blind
         twice.
      7. Command names resolve - every command called is defined in the
         file, resolvable, native, or on the listed-cmdlet allowlist.
      8. Registry ownership - a script carrying the registry restorer must
         declare the keys it writes.
      9. Script-scope variables are assigned - every $script: variable read
         is assigned in the same file (AST-based; an earlier regex version
         read a comment as code).
     10. Mandatory parameters are supplied - every call to a locally
         defined function passes its mandatory parameters, counting
         positional arguments.
     11. Script-shared regions - a #region marked [shared] and present in
         more than one script must be byte-identical in every copy.
     12. Embedded handler templates - two scripts BUILD a helper script
         inside a single-quoted here-string, write it under the toolkit
         root and run it from a SYSTEM scheduled task. Every check above
         works on the AST of the outer script, where a here-string is one
         string literal, so none of them had ever looked at that code -
         several hundred lines of PowerShell reaching real endpoints with
         no BOM check, no parse, no PS7 scan and no analyzer. This renders
         each @@PLACEHOLDER@@ as @() and runs 2, 3 and 4 over the result.
         It fails a FILE whose text holds a here-string template the walk
         did not parse - a gate that misses code which ships must not report
         success - while a repository with no templates at all passes and
         says so, because IronBlackBox-IR legitimately has none.
     13. Same-named functions, across scripts - a function defined under the
         same name in several scripts must hold the same code, compared with
         comments removed and whitespace normalised. 75 names are in that
         position here and 65 agree; the rest are listed with a reason in
         tools/divergent-functions.txt, which is REPO-LOCAL because it
         describes this repository's scripts. A shared name is what makes a
         divergence dangerous: it tells the author of the next fix that the
         copies are the same, so a defect corrected in one goes on living in
         the other - how the critical DACL bug survived in IronBlackBox-IR
         after being fixed in dev. A stale or unexplained entry fails too.

    This script is itself written in Windows PowerShell 5.1-compatible
    syntax, even though it only ever runs under pwsh 7 - dogfooding the
    constraint it enforces on every other script in the repo.

.PARAMETER Path
    Files or directories to check. Defaults to the three script-family
    directories plus docs/SCRIPT-TEMPLATE.ps1.

.PARAMETER RequireAnalyzer
    Treat a missing PSScriptAnalyzer module as a gate failure instead of a
    warning.
#>
[CmdletBinding()]
param(
    [string[]] $Path,
    [switch] $RequireAnalyzer
)

$repoRoot = Split-Path -Parent $PSScriptRoot

# The script families this gate knows about. Only the ones that EXIST are
# checked, so this same file works unchanged in both repositories: the public
# IronBlackBox carries logging-hardening and anti-tampering, and the private
# IronBlackBox-IR carries ir-collection. A missing family is not an error -
# listing a directory that is not there would make the gate fail on a clean
# checkout of either one.
$script:FamilyName = @('logging-hardening', 'anti-tampering', 'ir-collection')
$script:FamilyDirs = @()
foreach ($name in $script:FamilyName) {
    $candidate = Join-Path $repoRoot $name
    if (Test-Path -LiteralPath $candidate -PathType Container) {
        $script:FamilyDirs += $candidate
    }
}

# Named once and used twice - here for the default argument, and below for the
# cross-script gates' full-repository list. Two copies of this literal are two
# lists that will eventually disagree about what the repository contains.
$script:ExtraFiles = @(
    (Join-Path (Join-Path $repoRoot 'docs') 'SCRIPT-TEMPLATE.ps1')
)
if (-not $Path -or $Path.Count -eq 0) {
    $Path = @($script:FamilyDirs) + @($script:ExtraFiles)
}

function Write-Section($Text) { Write-Host "== $Text ==" -ForegroundColor Cyan }
function Write-Ok($Text)      { Write-Host "  [PASS] $Text" -ForegroundColor Green }
function Write-Fail($Text)    { Write-Host "  [FAIL] $Text" -ForegroundColor Red }

function Get-Regions {
    # Parses #region/#endregion into a name -> body map for Check 5. Regions
    # do not nest here; a nested #region is a parse failure of the file,
    # reported rather than silently mis-paired.
    param([Parameter(Mandatory = $true)][string] $FilePath)

    $lines   = @(Get-Content -LiteralPath $FilePath)
    $regions = [ordered] @{}
    $current = $null

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*#region\s+(?<name>.+?)\s*-*\s*$') {
            # '[shared]' in the header DECLARES that this region is a helper set
            # copied between scripts, so the cross-script gate compares the
            # copies. It is stripped from the name here, because the name is what
            # matches against the template and a marker must not change that.
            #
            # A declaration and not an inference: six scripts have a region called
            # 'Checks', each holding its own script-specific checks, and they are
            # SUPPOSED to differ. Comparing every same-named region would have
            # made this gate permanently red, which gets it muted.
            # CAPTURED BEFORE the inner -match, because -match REPLACES $Matches:
            # reading $Matches['name'] after testing for the marker returned the
            # inner match's groups, which have no 'name', so every region carrying
            # the marker would have been named $null. It passed the build only
            # because no region carried one yet.
            $regionName = [string] $Matches['name']
            $isShared = $false
            if ($regionName -match '^(?<bare>.+?)\s*\[shared\]$') {
                $isShared = $true
                $regionName = [string] $Matches['bare']
            }
            if ($null -ne $current) {
                throw ('nested #region at line ' + ($i + 1) + ' (already inside "' + $current.Name + '")')
            }
            $current = [PSCustomObject] @{
                Name      = $regionName
                StartLine = $i + 2
                Lines     = New-Object System.Collections.Generic.List[string]
                Shared    = $isShared
            }
        }
        elseif ($line -match '^\s*#endregion\b') {
            if ($null -eq $current) { throw ('unmatched #endregion at line ' + ($i + 1)) }
            # A DUPLICATE NAME USED TO OVERWRITE SILENTLY. This is an [ordered]
            # hashtable and its keys are case-insensitive, so two regions called
            # 'Native commands' - or one called 'Native Commands' - left only the
            # LAST body in the map, and check 5 then compared only that one to the
            # template. An edited earlier copy passed every gate.
            if ($regions.Contains($current.Name)) {
                throw ('duplicate #region name "' + $current.Name + '" at line ' + ($i + 1) +
                       '; only one body per name can be compared to the template')
            }
            $regions[$current.Name] = [PSCustomObject] @{ Lines = $current.Lines.ToArray()
                                                          StartLine = $current.StartLine
                                                          Shared = $current.Shared }
            $current = $null
        }
        elseif ($null -ne $current) {
            [void] $current.Lines.Add($line)
        }
    }
    if ($null -ne $current) { throw ('unclosed #region "' + $current.Name + '"') }
    return $regions
}

function Get-TrimmedRegionBody {
    # Strips trailing whitespace per line (meaningless) and blank lines at the
    # very start/end of the body (meaningless), keeping the original offset so
    # callers can still report real line numbers.
    param([string[]] $Lines)

    $trimmed = @($Lines | ForEach-Object { $_.TrimEnd() })
    $start = 0
    while ($start -lt $trimmed.Count -and $trimmed[$start] -eq '') { $start++ }
    $end = $trimmed.Count - 1
    while ($end -ge $start -and $trimmed[$end] -eq '') { $end-- }
    if ($start -gt $end) { return [PSCustomObject] @{ Lines = @(); Offset = $start } }
    return [PSCustomObject] @{ Lines = @($trimmed[$start..$end]); Offset = $start }
}

function Compare-RegionBody {
    # Positional, case-sensitive compare - indentation/comments must match
    # exactly (docs/DESIGN.md section 6). The leading ',' on the return below
    # is required: PowerShell unrolls a returned 0/1-element array into
    # $null / a bare string, which would make a 1-line diff index into that
    # string's characters instead of naming the line.
    param($TemplateRegion, $ScriptRegion)

    $t = Get-TrimmedRegionBody -Lines $TemplateRegion.Lines
    $s = Get-TrimmedRegionBody -Lines $ScriptRegion.Lines
    $max = [Math]::Max($t.Lines.Count, $s.Lines.Count)

    $diffs = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $max; $i++) {
        $tLine = $null
        $sLine = $null
        if ($i -lt $t.Lines.Count) { $tLine = $t.Lines[$i] }
        if ($i -lt $s.Lines.Count) { $sLine = $s.Lines[$i] }
        if ($tLine -cne $sLine) {
            $diffs.Add('template line ' + ($TemplateRegion.StartLine + $t.Offset + $i) +
                        ' vs script line ' + ($ScriptRegion.StartLine + $s.Offset + $i))
        }
    }
    return ,$diffs.ToArray()
}

$files = New-Object System.Collections.Generic.List[string]
foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $item = Get-Item -LiteralPath $p
    if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $p -Filter '*.ps1' -Recurse -File |
            ForEach-Object { $files.Add($_.FullName) }
    }
    else {
        $files.Add($item.FullName)
    }
}

# THE CROSS-SCRIPT GATES NEED THE WHOLE REPOSITORY, NOT THE ARGUMENT.
#
# Three gates below ask "do the copies of this agree?" - manifest field names,
# shared regions, and same-named functions. Given one file they compare it
# against nothing, and the divergence gate then reports every allow-list entry
# as "no script defines" or "its copies now AGREE". Measured 2026-09-10:
# `tools/check.ps1 logging-hardening/Enable-WefCollector.ps1` printed FOUR
# failures that do not exist, and that single-file form is exactly what
# docs/AUTHORING.md step 2 tells an author to run. A gate that cries wolf on the
# documented workflow gets ignored, so those three read $allFiles while every
# per-file gate keeps reading $files.
$allFiles = New-Object System.Collections.Generic.List[string]
foreach ($p in (@($script:FamilyDirs) + @($script:ExtraFiles))) {
    if (Test-Path -LiteralPath $p -PathType Container) {
        Get-ChildItem -LiteralPath $p -Filter '*.ps1' -Recurse -File |
            ForEach-Object { $allFiles.Add($_.FullName) }
    }
    elseif (Test-Path -LiteralPath $p -PathType Leaf) {
        $allFiles.Add((Get-Item -LiteralPath $p).FullName)
    }
}


if ($files.Count -eq 0) {
    Write-Host "No .ps1 files found under the given path(s). Nothing to check." -ForegroundColor Yellow
    exit 0
}

$analyzerSettingsPath = Join-Path $repoRoot (Join-Path 'tools' 'PSScriptAnalyzerSettings.psd1')

$analyzerAvailable = [bool](Get-Module -ListAvailable -Name PSScriptAnalyzer)
if (-not $analyzerAvailable) {
    $msg = "PSScriptAnalyzer module not found - Check 4 will be skipped."
    if ($RequireAnalyzer) { Write-Host $msg -ForegroundColor Red }
    else { Write-Host "$msg (not a gate failure; pass -RequireAnalyzer to make it one)" -ForegroundColor Yellow }
}

$bannedCommandParams = @(
    @{ Command = 'ForEach-Object'; Parameter = 'Parallel' },
    @{ Command = 'Get-Date';       Parameter = 'AsUTC' }
)

function Get-BannedPs7Finding {
    <#
        Every banned-PS7 check, over one AST, returned as a list of strings.

        Extracted from check 3 so that check 12 can run the identical rules over
        a GENERATED handler rendered out of a here-string. Two copies of these
        rules would be two sets of rules: the file that lives in the repository
        would be held to a standard the file that actually reaches an endpoint
        is not.

        Takes $SourceText rather than a path because the text it must judge does
        not always exist on disk.
    #>
    param(
        [Parameter(Mandatory = $true)] $Ast,
        [Parameter(Mandatory = $true)] $Tokens,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $SourceText
    )
    $ast = $Ast
    $tokens = $Tokens
    $findings = New-Object System.Collections.Generic.List[string]

    $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TernaryExpressionAst] }, $true) |
        ForEach-Object { $findings.Add("line $($_.Extent.StartLineNumber): ternary operator '?:' is PS7+, not PS 5.1") }

    $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.PipelineChainAst] }, $true) |
        ForEach-Object { $findings.Add("line $($_.Extent.StartLineNumber): pipeline chain operator '&&'/'||' is PS7+, not PS 5.1") }

    $ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        $args[0].Operator -eq [System.Management.Automation.Language.TokenKind]::QuestionQuestion
    }, $true) | ForEach-Object { $findings.Add("line $($_.Extent.StartLineNumber): null-coalescing '??' is PS7+, not PS 5.1") }

    $ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $args[0].Operator -eq [System.Management.Automation.Language.TokenKind]::QuestionQuestionEquals
    }, $true) | ForEach-Object { $findings.Add("line $($_.Extent.StartLineNumber): null-coalescing assignment '??=' is PS7+, not PS 5.1") }

    # Null-conditional (?. / ?[ ) is trickier than the other operators:
    # unlike ternary/??/??=, PSNullConditionalOperators is still an
    # experimental feature (confirmed against
    # learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_experimental_features),
    # disabled by default even on current pwsh. With the feature off -
    # the state this script always runs in - the parser does not
    # produce a NullConditional AST node at all; it folds the '?' into
    # the variable/member name token instead, so an AST-only check
    # would silently miss every real occurrence. The check below is
    # therefore textual: it regex-scans for literal '?.'/'?[' and
    # discards any match that falls inside a comment or string-literal
    # token (per the real tokens for this file), which removes the
    # common false positives (a '?.' inside a comment or a regex
    # pattern string). It is approximate - report a hit and read the
    # line before assuming it is really null-conditional syntax.
    $unsafeSpans = $tokens | Where-Object {
        $_.Kind -in @('Comment', 'StringLiteral', 'StringExpandable', 'HereStringLiteral', 'HereStringExpandable')
    } | ForEach-Object { , @($_.Extent.StartOffset, $_.Extent.EndOffset) }
    $rawText = $SourceText
    foreach ($m in [regex]::Matches($rawText, '\?[\.\[]')) {
        $inUnsafe = $false
        foreach ($span in $unsafeSpans) {
            if ($m.Index -ge $span[0] -and $m.Index -lt $span[1]) { $inUnsafe = $true; break }
        }
        if (-not $inUnsafe) {
            $lineNum = ($rawText.Substring(0, $m.Index).Split("`n")).Count
            $findings.Add("line $lineNum`: possible null-conditional '?.'/'?[' (textual heuristic - PS7+, not PS 5.1)")
        }
    }

    foreach ($bp in $bannedCommandParams) {
        $ast.FindAll({
            $args[0] -is [System.Management.Automation.Language.CommandAst] -and
            $args[0].GetCommandName() -eq $bp.Command
        }, $true) | ForEach-Object {
            $hasParam = $_.CommandElements | Where-Object {
                $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq $bp.Parameter
            }
            if ($hasParam) { $findings.Add("line $($_.Extent.StartLineNumber): $($bp.Command) -$($bp.Parameter) is PS7+, not PS 5.1") }
        }
    }

    # Join-Path: PS 5.1 only accepts -Path and -ChildPath. A third
    # path-shaped argument (named -AdditionalChildPath, or a third
    # positional value) is PS6+. Heuristic: cannot fully bind
    # parameters without invoking the pipeline, so this may miss or
    # over-flag unusual argument orderings - review manually if hit.
    $ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.CommandAst] -and
        $args[0].GetCommandName() -eq 'Join-Path'
    }, $true) | ForEach-Object {
        $hasAdditional = $_.CommandElements | Where-Object {
            $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'AdditionalChildPath'
        }
        $positionalCount = ($_.CommandElements | Where-Object { $_ -isnot [System.Management.Automation.Language.CommandParameterAst] } | Select-Object -Skip 1).Count
        if ($hasAdditional -or $positionalCount -gt 2) {
            $findings.Add("line $($_.Extent.StartLineNumber): Join-Path with more than one child path (-AdditionalChildPath) is PS6+, not PS 5.1")
        }
    }

    $ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] -and $args[0].VariablePath.UserPath -eq 'IsWindows'
    }, $true) | ForEach-Object { $findings.Add("line $($_.Extent.StartLineNumber): `$IsWindows does not exist in Windows PowerShell 5.1") }
    return $findings
}


# Check 5 setup: parse the template once so every family script below is
# compared against the same reference.
$familyDirs = @($script:FamilyDirs)
$templatePath = Join-Path (Join-Path $repoRoot 'docs') 'SCRIPT-TEMPLATE.ps1'
$templateRegions    = $null
$templateParseError = $null
if (Test-Path -LiteralPath $templatePath) {
    try { $templateRegions = Get-Regions -FilePath $templatePath }
    catch { $templateParseError = $_.Exception.Message }
}

$overallFail = $false

foreach ($file in $files) {
    Write-Section (Resolve-Path -LiteralPath $file -Relative -ErrorAction SilentlyContinue)
    $fileFail = $false

    # Check 1: UTF-8 BOM
    $bytes = [System.IO.File]::ReadAllBytes($file)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-Ok "UTF-8 BOM present"
    } else {
        Write-Fail "Missing UTF-8 BOM (PS 5.1 misreads BOM-less UTF-8 as ANSI)"
        $fileFail = $true
    }

    # Check 2: AST parse
    $parseErrors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        foreach ($e in $parseErrors) {
            Write-Fail ("Parse error at line {0}: {1}" -f $e.Extent.StartLineNumber, $e.Message)
        }
        $fileFail = $true
    } else {
        Write-Ok "AST parses cleanly"
    }

    # Check 3: banned PS7-only syntax (AST-based)
    if ($ast) {
        $findings = Get-BannedPs7Finding -Ast $ast -Tokens $tokens -SourceText ([System.IO.File]::ReadAllText($file))

        if ($findings.Count -gt 0) {
            foreach ($f in $findings) { Write-Fail $f }
            $fileFail = $true
        } else {
            Write-Ok "No banned PS7-only syntax found"
        }
    }

    # Check 4: PSScriptAnalyzer
    # -Settings pulls in tools/PSScriptAnalyzerSettings.psd1: it enables
    # PSUseCompatibleSyntax targeting 5.1 (AST-based, catches syntax the
    # Check 3 heuristics above do not - the two are complementary, not
    # redundant) and records this repo's deliberate rule exclusions
    # (PSAvoidUsingWriteHost, PSReviewUnusedParameter,
    # PSUseShouldProcessForStateChangingFunctions - see docs/DESIGN.md).
    # Resolved from $repoRoot so the gate works from any working directory.
    if ($analyzerAvailable) {
        Import-Module PSScriptAnalyzer -ErrorAction Stop
        $results = Invoke-ScriptAnalyzer -Path $file -Settings $analyzerSettingsPath -Severity Error, Warning
        if ($results) {
            foreach ($r in $results) {
                Write-Fail "line $($r.Line): [$($r.Severity)] $($r.RuleName) - $($r.Message)"
            }
            $fileFail = $true
        } else {
            Write-Ok "PSScriptAnalyzer: no Error/Warning findings"
        }
    } elseif ($RequireAnalyzer) {
        Write-Fail "PSScriptAnalyzer unavailable and -RequireAnalyzer was passed"
        $fileFail = $true
    }

    # Check 5: helper drift against docs/SCRIPT-TEMPLATE.ps1 (family dirs only).
    $sep = [System.IO.Path]::DirectorySeparatorChar
    $isFamilyScript = [bool] ($familyDirs | Where-Object { $file.StartsWith($_ + $sep, [System.StringComparison]::Ordinal) })

    if ($isFamilyScript) {
        if ($null -eq $templateRegions) {
            $reason = 'not found'
            if ($templateParseError) { $reason = 'failed to parse into regions (' + $templateParseError + ')' }
            Write-Fail ('cannot check helper drift: docs/SCRIPT-TEMPLATE.ps1 ' + $reason)
            $fileFail = $true
        } else {
            $scriptRegions = $null
            try { $scriptRegions = Get-Regions -FilePath $file }
            catch {
                Write-Fail ('cannot check helper drift: failed to parse into regions (' + $_.Exception.Message + ')')
                $fileFail = $true
            }

            if ($null -ne $scriptRegions) {
                $sharedFound = $false
                $anyDrift    = $false
                foreach ($regionName in $scriptRegions.Keys) {
                    if ($regionName -eq 'Main' -or $regionName -like 'EXAMPLE*') { continue }
                    if (-not $templateRegions.Contains($regionName)) { continue }
                    $sharedFound = $true
                    $diffs = Compare-RegionBody -TemplateRegion $templateRegions[$regionName] -ScriptRegion $scriptRegions[$regionName]
                    if ($diffs.Count -gt 0) {
                        $anyDrift = $true

                        # The compare is positional, not LCS-based, so one
                        # inserted or deleted line shifts every line after it
                        # and the raw diff count balloons — 220 "differences"
                        # for a single removed comment. The verdict is still
                        # right, but reporting that number would send someone
                        # hunting for a wholesale rewrite. When the line counts
                        # differ at all, say so instead of counting.
                        $tCount = (Get-TrimmedRegionBody -Lines $templateRegions[$regionName].Lines).Lines.Count
                        $sCount = (Get-TrimmedRegionBody -Lines $scriptRegions[$regionName].Lines).Lines.Count
                        if ($tCount -ne $sCount) {
                            $detail = ('' + $tCount + ' lines in template vs ' + $sCount +
                                       ' in script; first difference below')
                        }
                        else {
                            $detail = ('' + $diffs.Count + ' lines differ')
                        }

                        Write-Fail ((Split-Path -Leaf $file) + " — region '" + $regionName +
                                    "' diverges from docs/SCRIPT-TEMPLATE.ps1 (" + $detail + ')')
                        $show = 5
                        if ($tCount -ne $sCount) { $show = 1 }
                        for ($k = 0; $k -lt [Math]::Min($show, $diffs.Count); $k++) { Write-Fail ('    ' + $diffs[$k]) }
                        if ($tCount -ne $sCount) {
                            Write-Fail '    fix by re-copying the whole region from the template'
                        }
                    }
                }
                if ($anyDrift) { $fileFail = $true }
                elseif (-not $sharedFound) { Write-Ok 'no shared helper regions' }
                else { Write-Ok 'helper regions match docs/SCRIPT-TEMPLATE.ps1' }
            }
        }
    }

    if ($fileFail) { $overallFail = $true }
}

# ---------------------------------------------------------------------------
# Manifest field-name consistency, across files rather than within one.
#
# Every other check in this script judges a file on its own. This one cannot:
# the defect it exists to catch is two scripts writing the SAME change type with
# DIFFERENT field names, which is invisible from inside either file.
#
# It shipped twice. Three scripts wrote 'eventchannel' with newMaxSize and two
# with newMaxSizeBytes, so Test-VisibilityDrift - which read only the first
# spelling - silently never checked a shrunk AppLocker or ForwardedEvents
# channel. And Protect-ForensicArtifacts wrote 'service' with serviceName while
# Set-TimelineIntegrity wrote service, so a W32Time change could never verify at
# all. A drift detector that misses in silence is worse than one that is absent,
# because it reassures.
#
# Renaming a field does not fix a manifest already on disk, so the reader stays
# bilingual for what has been written. This gate is what stops the NEXT split.
Write-Host ""
Write-Section 'Manifest field names, across scripts'
$changeTypes = @{}
$recordsSeen = 0
# Calls whose argument this gate cannot read statically. Counted rather than
# skipped, and asserted against the number below, because a blind spot that is
# not counted is a blind spot that grows.
$unreadableWrites = New-Object System.Collections.ArrayList
# ANY unreadable write is a failure, with no allowance.
#
# The first version of this carried an "expected count" of the one call that
# passed its record by variable. That number was repo-specific and the file it
# lived in is shared byte-for-byte with IronBlackBox-IR, which has no such call -
# so the shared gate failed the other repository on a constant that described
# this one. The right fix was not a per-repo exception but making the call
# readable: Enable-Sysmon now writes its two change types as two literal
# records. A gate with no exceptions is also a gate with nothing to keep in step.

# ON THE AST, not on a regex over the file text.
#
# The regex version only ever matched an INLINE '-Change @{ ... }', so it saw 39
# of the 40 Write-ManifestChange calls and none at all of Write-ManifestRecord -
# which is where the 'expectation' records live, the ones Test-VisibilityDrift
# reads to verify the full intended audit set. Two scripts write those, and
# nothing was comparing their field names: exactly the defect this gate exists
# for, in the record type it could not see.
foreach ($file in $allFiles) {
    $manifestTokens = $null
    $manifestErrors = $null
    $manifestAst = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref] $manifestTokens, [ref] $manifestErrors)
    if ($null -eq $manifestAst) { continue }
    $shortName = [System.IO.Path]::GetFileName($file)

    foreach ($command in $manifestAst.FindAll({
        $args[0] -is [System.Management.Automation.Language.CommandAst]
    }, $true)) {
        $commandName = $command.GetCommandName()
        $typeKey = ''
        $parameterName = ''
        if ($commandName -eq 'Write-ManifestChange')      { $typeKey = 'type';       $parameterName = 'Change' }
        elseif ($commandName -eq 'Write-ManifestRecord')  { $typeKey = 'recordType'; $parameterName = 'Record' }
        else { continue }

        # The value that follows -Change / -Record.
        $argument = $null
        $elements = @($command.CommandElements)
        for ($index = 0; $index -lt $elements.Count - 1; $index++) {
            if ($elements[$index] -is [System.Management.Automation.Language.CommandParameterAst] -and
                $elements[$index].ParameterName -eq $parameterName) {
                $argument = $elements[$index + 1]
            }
        }
        if ($argument -isnot [System.Management.Automation.Language.HashtableAst]) {
            [void] $unreadableWrites.Add($shortName + ':' + [string] $command.Extent.StartLineNumber +
                                        ' (' + $commandName + ' -' + $parameterName + ' is not a literal hashtable)')
            continue
        }

        $keys = New-Object System.Collections.ArrayList
        $type = ''
        foreach ($pair in $argument.KeyValuePairs) {
            $keyName = ([string] $pair.Item1.Extent.Text).Trim().Trim("'").Trim('"')
            if (-not $keys.Contains($keyName)) { [void] $keys.Add($keyName) }
            if ($keyName -eq $typeKey) {
                $valueAst = $pair.Item2
                # Only a literal names a type. Anything computed is unreadable
                # rather than guessed at.
                $inner = $valueAst
                if ($inner -is [System.Management.Automation.Language.PipelineAst] -and
                    $inner.PipelineElements.Count -eq 1) { $inner = $inner.PipelineElements[0] }
                if ($inner -is [System.Management.Automation.Language.CommandExpressionAst]) { $inner = $inner.Expression }
                if ($inner -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $type = [string] $inner.Value
                }
            }
        }
        if ([string]::IsNullOrWhiteSpace($type)) {
            [void] $unreadableWrites.Add($shortName + ':' + [string] $command.Extent.StartLineNumber +
                                        ' (' + $commandName + " has no literal '" + $typeKey + "')")
            continue
        }

        # Keyed by record kind AND type, so a 'change' record type and a change
        # of type 'change' are never compared against each other.
        $bucket = ($commandName + '/' + $type)
        if (-not $changeTypes.ContainsKey($bucket)) { $changeTypes[$bucket] = @{} }
        $changeTypes[$bucket][$shortName] = @($keys.ToArray() | Sort-Object)
        $recordsSeen++
    }
}

if ($unreadableWrites.Count -gt 0) {
    Write-Fail ('this gate could not read ' + [string] $unreadableWrites.Count +
                ' manifest write(s), so their field names are unchecked. Pass the record as a ' +
                'literal hashtable at the call site - if one call writes two shapes, write two ' +
                'calls:')
    foreach ($entry in $unreadableWrites) { Write-Fail ('    ' + $entry) }
    $overallFail = $true
}

# Record types that legitimately have MORE THAN ONE SHAPE, with the reason.
#
# The defect this gate was built for is two writers spelling the SAME field
# differently - newMaxSize against newMaxSizeBytes - so a reader looking for one
# silently missed the other. Two writers emitting DIFFERENT fields is a separate
# thing, and 'rollback' really does have two variants: the normal outcome
# carries permanentChangeIds, and the operator-abandon outcome (written by the
# template's shared Invoke-AbandonRun) carries abandonedChangeIds instead, with
# status = 'completed-abandoned-by-operator' telling a reader which it is
# holding. Nothing is permanently declined in an abandon, so the field would be
# a lie there.
#
# Listing a type here means the differing fields are REPORTED rather than
# failing the build. It does not stop the gate: a same-purpose field spelled two
# ways inside one variant is still caught, and every other record type is still
# held to a single shape.
$recordVariants = @{
    'Write-ManifestRecord/rollback' =
        'two variants keyed by status - the normal outcome writes permanentChangeIds, the operator-abandon outcome writes abandonedChangeIds'
}

$fieldFail = $false
foreach ($type in ($changeTypes.Keys | Sort-Object)) {
    $writers = $changeTypes[$type]
    if ($writers.Keys.Count -lt 2) { continue }
    # The union minus the intersection: every field that is not written by every
    # writer of this type.
    $union = New-Object System.Collections.ArrayList
    foreach ($w in $writers.Keys) {
        foreach ($k in $writers[$w]) { if (-not $union.Contains($k)) { [void] $union.Add($k) } }
    }
    $inconsistent = New-Object System.Collections.ArrayList
    foreach ($k in $union) {
        $count = 0
        foreach ($w in $writers.Keys) { if ($writers[$w] -contains $k) { $count++ } }
        if ($count -ne $writers.Keys.Count) { [void] $inconsistent.Add($k) }
    }
    if ($inconsistent.Count -gt 0 -and $recordVariants.ContainsKey($type)) {
        Write-Ok ("manifest write '" + $type + "' has declared variants (" +
                    [string] $recordVariants[$type] + "); fields not written by every writer: " +
                    (($inconsistent.ToArray() | Sort-Object) -join ', '))
        continue
    }
    if ($inconsistent.Count -gt 0) {
        Write-Fail ("manifest write '" + $type + "' is made by " + [string] $writers.Keys.Count +
                    ' scripts with differing field names: ' + (($inconsistent.ToArray() | Sort-Object) -join ', '))
        foreach ($w in ($writers.Keys | Sort-Object)) {
            Write-Host ("           " + $w + ': ' + ($writers[$w] -join ', ')) -ForegroundColor DarkGray
        }
        $fieldFail = $true
    }
}
if ($recordsSeen -eq 0) {
    # Fail CLOSED. A parser that silently matches nothing looks exactly like a
    # clean repository, and this file has 18 scripts that write change records.
    Write-Fail 'no Write-ManifestChange records were parsed at all - this check is broken, not the repo'
    $overallFail = $true
}
elseif ($fieldFail) {
    Write-Fail '    a reader cannot find a field it does not know the name of - align the writers'
    $overallFail = $true
}
else {
    Write-Ok ('every change type is written with the same field names by every script (' +
              [string] $recordsSeen + ' record(s) across ' + [string] $changeTypes.Keys.Count + ' type(s))')
}

# ---------------------------------------------------------------------------
# Every command a script calls must exist.
#
# This gate exists because two invented function names shipped: a call to
# Format-Mib in Enable-IRVisibility, which reached a live host and made -Audit
# exit 2 on the idempotence branch, and a call to Get-ChannelAccess in
# Protect-EventLogs, caught only by reading the file afterwards. Neither is a
# syntax error, PSScriptAnalyzer does not resolve command names, and the AST
# parses happily - so nothing in this script saw either one.
#
# A name is acceptable if the file defines it, if this PowerShell can resolve it,
# if it ends in .exe, or if it is on the Windows-only list below. That list was
# derived by enumerating what these 19 files actually call - not guessed - so
# adding to it is a deliberate act, while a typo'd helper is not on it.
$windowsOnlyCommands = @(
    'Add-MpPreference', 'Disable-WindowsOptionalFeature', 'Enable-WindowsOptionalFeature',
    'Get-Acl', 'Get-AppLockerFileInformation', 'Get-AppLockerPolicy', 'Get-AuthenticodeSignature',
    'Get-CimAssociatedInstance', 'Get-CimClass', 'Get-CimInstance', 'Get-LocalGroupMember',
    'Get-MpComputerStatus', 'Get-MpPreference', 'Get-NetTCPConnection', 'Get-WinSystemLocale',
    'Get-Partition', 'Get-PhysicalDisk', 'Get-ScheduledTask', 'Get-Service',
    'Get-WindowsFeature', 'Get-WindowsOptionalFeature', 'Get-WinEvent', 'Invoke-CimMethod',
    'New-EventLog', 'New-ScheduledTaskAction', 'New-ScheduledTaskPrincipal',
    'New-ScheduledTaskSettingsSet', 'New-ScheduledTaskTrigger', 'Register-ScheduledTask',
    'Remove-CimInstance', 'Remove-EventLog', 'Remove-MpPreference', 'Restart-Service',
    'Set-Acl',
    'Set-AppLockerPolicy', 'Set-Service', 'Start-Service', 'Stop-Service',
    'Unregister-ScheduledTask', 'Write-EventLog'
)

Write-Host ""
Write-Section 'Command names resolve'
$unresolvedTotal = 0
foreach ($file in $files) {
    $parseTokens = $null
    $parseErrors = $null
    $fileAst = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref] $parseTokens, [ref] $parseErrors)
    if ($null -eq $fileAst) { continue }
    $definedHere = @($fileAst.FindAll({
        $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object { $_.Name })
    $missing = New-Object System.Collections.ArrayList
    foreach ($commandAst in $fileAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $commandAst.GetCommandName()
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($name.EndsWith('.exe', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($name.EndsWith('.cmd', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($name.EndsWith('.bat', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($definedHere -contains $name) { continue }
        if ($windowsOnlyCommands -contains $name) { continue }
        if (Get-Command -Name $name -ErrorAction SilentlyContinue) { continue }
        if (-not $missing.Contains($name)) { [void] $missing.Add($name) }
    }
    # A NATIVE TOOL NAMED WITHOUT A PATH. The check above deliberately skips
    # anything ending in .exe/.cmd/.bat because those are not PowerShell commands
    # - which left the whole class unguarded. These scripts run as SYSTEM, so a
    # bare name hands the choice of binary to whatever resolves it: PATH for '&
    # wevtutil.exe', and the Task Scheduler service for a task action registered
    # as -Execute 'powershell.exe'. Both shipped. A security review found them;
    # nothing in this file would have.
    #
    # Rooted-ness is the test, not a known-tools list: a list only ever catches
    # the tools someone thought of.
    $bare = New-Object System.Collections.ArrayList
    foreach ($commandAst in $fileAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $named = $commandAst.GetCommandName()
        if (-not [string]::IsNullOrWhiteSpace($named) -and
            ($named -match '\.(exe|cmd|bat|vbs|ps1)$') -and
            (-not [System.IO.Path]::IsPathRooted($named))) {
            if (-not $bare.Contains($named)) { [void] $bare.Add($named) }
        }
        # -Execute / -FilePath bound to a literal with no directory separator.
        foreach ($element in $commandAst.CommandElements) {
            if ($element -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
            if ($element.ParameterName -notin @('Execute', 'FilePath')) { continue }
            $bound = $element.Argument
            if ($null -eq $bound) {
                $index = $commandAst.CommandElements.IndexOf($element)
                if ($index -ge 0 -and ($index + 1) -lt $commandAst.CommandElements.Count) {
                    $bound = $commandAst.CommandElements[$index + 1]
                }
            }
            if ($bound -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { continue }
            $literal = [string] $bound.Value
            if ([string]::IsNullOrWhiteSpace($literal)) { continue }
            if ($literal.IndexOf('\') -ge 0 -or $literal.IndexOf('/') -ge 0) { continue }
            $entry = ('-' + $element.ParameterName + " '" + $literal + "'")
            if (-not $bare.Contains($entry)) { [void] $bare.Add($entry) }
        }
    }
    if ($bare.Count -gt 0) {
        Write-Fail ([System.IO.Path]::GetFileName($file) + ' names ' + [string] $bare.Count +
                    ' native target(s) without a path, leaving the choice of binary to PATH or to ' +
                    'the Task Scheduler service, in code that runs as SYSTEM: ' +
                    (($bare.ToArray() | Sort-Object) -join ', ') +
                    '. Resolve with Get-NativeToolPath or Get-PowerShellHostPath.')
        $unresolvedTotal += $bare.Count
    }
    if ($missing.Count -gt 0) {
        Write-Fail ([System.IO.Path]::GetFileName($file) + ' calls ' + [string] $missing.Count +
                    ' command(s) that are not defined in it, not resolvable, and not on the ' +
                    'Windows-only list: ' + (($missing.ToArray() | Sort-Object) -join ', '))
        $unresolvedTotal += $missing.Count
    }
}
if ($unresolvedTotal -gt 0) {
    Write-Fail '    define the function, fix the name, or add a real Windows cmdlet to the list above'
    $overallFail = $true
}
else { Write-Ok 'every command called is defined, resolvable, native, or a listed Windows cmdlet' }

# ---------------------------------------------------------------------------
# A script's -Rollback must only accept registry keys the script actually writes.
#
# The template's Restore-TrackedChange reads $script:OwnedRegistryKey. The gate
# here is that the declaration cannot be forgotten or left stale:
#
#   calls Set-TrackedRegistryValue  -> must declare at least one key
#   carries the restorer but calls  -> must declare an EMPTY array, which makes a
#   the setter nowhere                 registry record a refusal. Measured: 11 of
#                                      18 scripts were in this state, each
#                                      carrying a restorer that would write any
#                                      HKLM value a planted record named.
Write-Host ""
Write-Section 'Registry ownership is declared'
$ownershipFail = $false
foreach ($file in $files) {
    $text = Get-Content -LiteralPath $file -Raw
    $shortName = [System.IO.Path]::GetFileName($file)
    # The template is a buffet, not a running script: its example calls exist to
    # be copied, and it declares an empty array so a copy that forgets to fill it
    # in refuses rather than writes.
    if ($shortName -eq 'SCRIPT-TEMPLATE.ps1') { continue }
    $hasRestorer = ($text -match '(?m)^function Restore-TrackedChange\b')
    if (-not $hasRestorer) { continue }
    $declMatch = [regex]::Match($text, '(?s)\$script:OwnedRegistryKey\s*=\s*@\((.*?)\)')
    if (-not $declMatch.Success) {
        Write-Fail ($shortName + ' carries Restore-TrackedChange but declares no $script:OwnedRegistryKey')
        $ownershipFail = $true
        continue
    }
    $declaredCount = @([regex]::Matches($declMatch.Groups[1].Value, "'[^']+'")).Count
    # Count real invocations, not the function definition or a mention in a comment.
    $parseTokens = $null
    $parseErrors = $null
    $fileAst = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref] $parseTokens, [ref] $parseErrors)
    $setterCalls = 0
    if ($null -ne $fileAst) {
        $setterCalls = @($fileAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
            Where-Object { $_.GetCommandName() -eq 'Set-TrackedRegistryValue' }).Count
    }
    if ($setterCalls -gt 0 -and $declaredCount -eq 0) {
        Write-Fail ($shortName + ' calls Set-TrackedRegistryValue ' + [string] $setterCalls +
                    ' time(s) but declares no owned key, so its own -Rollback would refuse every change')
        $ownershipFail = $true
    }
    elseif ($setterCalls -eq 0 -and $declaredCount -gt 0) {
        Write-Fail ($shortName + ' declares ' + [string] $declaredCount + ' owned key(s) but never calls ' +
                    'Set-TrackedRegistryValue - the declaration is stale and widens the rollback for nothing')
        $ownershipFail = $true
    }
}
if ($ownershipFail) {
    Write-Fail '    align $script:OwnedRegistryKey with what the script actually writes'
    $overallFail = $true
}
else { Write-Ok 'every script carrying the registry restorer declares the keys it writes' }

Write-Host ""
Write-Section 'Script-scope variables are assigned'
#
# A $script:Name that is READ and never assigned in the same file. PowerShell
# resolves it to $null under Set-StrictMode -Version 1.0 for a plain variable, but
# these scripts read them as arrays and hashtables, and the failure surfaces at
# RUNTIME as "The variable '$script:X' cannot be retrieved because it has not been
# set" - a clean exit 2 that makes the whole script unrunnable.
#
# It exists because splitting a script produced exactly that, five times in one
# file: the moved functions read state declared in the preamble that stayed
# behind. Every gate here passed, and the LAB found it. A gate that reads the file
# can find it in a second.
$scopeFail = $false
foreach ($file in $files) {
    $fileAst = $null
    try { $fileAst = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref] $null, [ref] $null) }
    catch { continue }
    if ($null -eq $fileAst) { continue }

    # THE AST AND NOT A REGEX. The first version scanned raw text and failed
    # Set-TimelineIntegrity on '# NOT $script:Snapshot or anything that could
    # collide with a parameter name' - a COMMENT warning the next author off that
    # very name. A gate that reads comments as code is a gate that goes red on
    # good documentation, and a red gate gets muted.
    $assigned = New-Object System.Collections.Generic.HashSet[string]
    foreach ($assignment in $fileAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        $left = $assignment.Left
        if ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
        if ($left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $left.VariablePath.IsScript) {
            [void] $assigned.Add($left.VariablePath.UserPath)
        }
    }
    # A VARIABLE THE AUTHOR TESTS FOR is not a variable the author forgot.
    # Test-Path 'variable:script:X' is the explicit "this may not exist" idiom, and
    # the collectors use it around $script:ManifestPath - which a read-only script
    # legitimately never sets. Flagging it made this gate red on ten files for
    # code that is already careful.
    # FROM THE AST, not from the file text - and this one is the direction that
    # matters. The assignment scan above was moved off a regex because reading a
    # comment as code made the gate RED on good documentation. This exemption had
    # the same bug pointing the other way: a raw-text match meant a COMMENT
    # mentioning variable:script:Foo silently excused $script:Foo from the check.
    # A false positive is noisy; a fail-open exemption is a gate that reports
    # success while measuring nothing, which is the failure this whole file exists
    # to avoid. Only a real string literal counts, because the idiom under
    # exemption - Test-Path 'variable:script:X' - is one.
    foreach ($literal in $fileAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)) {
        foreach ($probe in [regex]::Matches([string] $literal.Value, "^variable:script:(\w+)$")) {
            [void] $assigned.Add('script:' + $probe.Groups[1].Value)
        }
    }

    $never = New-Object System.Collections.ArrayList
    foreach ($reference in $fileAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
        if (-not $reference.VariablePath.IsScript) { continue }
        $name = $reference.VariablePath.UserPath
        if ($assigned.Contains($name)) { continue }
        if (-not $never.Contains($name)) { [void] $never.Add($name) }
    }
    if ($never.Count -gt 0) {
        # UserPath and NOT UnqualifiedPath. Measured: for '$script:Foo' UserPath is
        # 'script:Foo' and UnqualifiedPath is the EMPTY STRING. Switching to
        # UnqualifiedPath to tidy a doubled '$script:' in this message turned every
        # name into '', which was then always in the assigned set - so the gate
        # silently stopped measuring anything and passed on everything. A gate that
        # measures nothing looks exactly like a gate that measures everything, which
        # is a lesson docs/VALIDATION.md already records about a test harness. The
        # prefix here is a bare '$'.
        Write-Fail ([System.IO.Path]::GetFileName($file) + ' reads ' + [string] $never.Count +
                    ' script-scope variable(s) it never assigns: $' +
                    (($never.ToArray() | Sort-Object) -join ', $'))
        $scopeFail = $true
    }
}
if ($scopeFail) { $overallFail = $true }
else { Write-Ok 'every $script: variable read is assigned in the same file' }

Write-Host ""
Write-Section 'Mandatory parameters are supplied'
#
# A call to a function DEFINED IN THE SAME FILE that omits one of its Mandatory
# parameters. PowerShell does not fail this at parse time: in a non-interactive
# session it throws at the call, so it is an exit 2 on a path that may not run
# until a customer host takes it.
#
# Also from the split: the new script called Test-DefenderPresence and
# Test-DefenderPosture without -Status, because the dependency analysis followed
# the CALL graph and those two receive their input as a PARAMETER. Nothing here
# looked at parameters, so every gate passed.
$mandatoryFail = $false
foreach ($file in $files) {
    $fileAst = $null
    try { $fileAst = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref] $null, [ref] $null) }
    catch { continue }
    if ($null -eq $fileAst) { continue }
    $required = @{}
    foreach ($def in $fileAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        $names = New-Object System.Collections.ArrayList
        if ($null -ne $def.Body.ParamBlock) {
            foreach ($declared in $def.Body.ParamBlock.Parameters) {
                foreach ($attribute in $declared.Attributes) {
                    if ($attribute.Extent.Text -match 'Mandatory\s*=\s*\$true') {
                        [void] $names.Add($declared.Name.VariablePath.UserPath)
                        break
                    }
                }
            }
        }
        $required[$def.Name] = @($names.ToArray())
    }
    foreach ($commandAst in $fileAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $called = $commandAst.GetCommandName()
        if ([string]::IsNullOrWhiteSpace($called) -or -not $required.ContainsKey($called)) { continue }
        if ($required[$called].Count -eq 0) { continue }
        # POSITIONAL ARGUMENTS COUNT TOO. The first version looked at named
        # parameters only, on the stated assumption that every call in this project
        # passes by name. That is true of the dev scripts and FALSE of the
        # collectors: IronBlackBox-IR's Export-Autoruns calls Add-Coverage
        # positionally twelve times, which is valid PowerShell, and the gate went
        # red on all twelve. Twelve false failures is the permanently-red gate this
        # file keeps warning about, arriving in the gate itself.
        $supplied = @($commandAst.CommandElements |
            Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
            ForEach-Object { $_.ParameterName })
        # Bare arguments: elements that are neither the command name, nor a
        # parameter, nor the value that follows a parameter written as '-Name value'
        # (where the AST leaves the value as its own element).
        $positional = 0
        $skipNext = $false
        for ($e = 1; $e -lt $commandAst.CommandElements.Count; $e++) {
            $element = $commandAst.CommandElements[$e]
            if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
                $skipNext = ($null -eq $element.Argument)
                continue
            }
            if ($skipNext) { $skipNext = $false; continue }
            $positional++
        }
        $absent = @($required[$called] | Where-Object { $supplied -notcontains $_ })
        if ($absent.Count -gt $positional) {
            Write-Fail ([System.IO.Path]::GetFileName($file) + ' line ' +
                        [string] $commandAst.Extent.StartLineNumber + ': ' + $called +
                        ' called without -' + ($absent -join ' -') +
                        ' and with ' + [string] $positional + ' positional argument(s)')
            $mandatoryFail = $true
        }
    }
}
if ($mandatoryFail) { $overallFail = $true }
else { Write-Ok 'every call to a locally defined function supplies its mandatory parameters' }

Write-Host ""
Write-Section 'Script-shared regions, across scripts'
#
# A region the TEMPLATE does not have was invisible to check 5, which compares
# each script's regions against the template's and skips any name it does not
# find there. So two scripts could share a region by name and drift apart with
# nothing looking - which is what decision 3 of the review log kept in the development repository was, and
# what it cost: Invoke-NativeCommand sat in script-local regions in fourteen
# scripts, and Remove-TrackedScheduledTask - a ROLLBACK function - reached three
# distinct versions across three scripts before anyone diffed them.
#
# Not every helper belongs in the template. The template's Registry region is 441
# lines for writing values with manifest tracking; a script that only READS two
# HKLM values should not carry it, and a scheduled-task helper is of no use to the
# fifteen scripts that register no task. This gate is what makes a region shared
# between SOME scripts safe: name it the same in each, and the build fails the
# moment the copies differ.
$sharedRegionBodies = @{}
foreach ($file in $allFiles) {
    if ([System.IO.Path]::GetFileName($file) -eq 'SCRIPT-TEMPLATE.ps1') { continue }
    $regions = $null
    try { $regions = Get-Regions -FilePath $file }
    catch { continue }   # already reported by check 5
    if ($null -eq $regions) { continue }
    foreach ($regionName in $regions.Keys) {
        if ($regionName -eq 'Main' -or $regionName -like 'EXAMPLE*') { continue }
        if ($null -ne $templateRegions -and $templateRegions.Contains($regionName)) { continue }
        # Only DECLARED shared regions. Six scripts have a 'Checks' region holding
        # their own checks; comparing by name alone made this gate red on those and
        # a red gate gets muted.
        if (-not $regions[$regionName].Shared) { continue }
        if (-not $sharedRegionBodies.ContainsKey($regionName)) {
            $sharedRegionBodies[$regionName] = New-Object System.Collections.ArrayList
        }
        # Trimmed the same way check 5 trims, so leading and trailing blank lines
        # inside a region are not a difference.
        $body = (Get-TrimmedRegionBody -Lines $regions[$regionName].Lines).Lines
        [void] $sharedRegionBodies[$regionName].Add([PSCustomObject] @{
            File = [System.IO.Path]::GetFileName($file)
            Text = ($body -join "`n")
        })
    }
}
$sharedRegionFail = $false
$sharedRegionCount = 0
foreach ($regionName in ($sharedRegionBodies.Keys | Sort-Object)) {
    $copies = @($sharedRegionBodies[$regionName])
    if ($copies.Count -lt 2) { continue }
    $sharedRegionCount++
    $distinct = @($copies | Select-Object -ExpandProperty Text -Unique)
    if ($distinct.Count -eq 1) { continue }
    $sharedRegionFail = $true
    Write-Fail ('region "' + $regionName + '" is shared by ' + [string] $copies.Count +
                ' script(s) and has ' + [string] $distinct.Count +
                ' distinct version(s) - it is in no template region, so nothing else compares them')
    # Grouped by content, so the report says which files agree with which rather
    # than listing every file separately.
    $groupIndex = 0
    foreach ($group in ($copies | Group-Object -Property Text)) {
        $groupIndex++
        Write-Fail ('    version ' + [string] $groupIndex + ': ' +
                    (($group.Group | ForEach-Object { $_.File } | Sort-Object) -join ', '))
    }
    Write-Fail '    make the copies identical, or move the region into docs/SCRIPT-TEMPLATE.ps1'
}
if ($sharedRegionFail) { $overallFail = $true }
elseif ($sharedRegionCount -eq 0) { Write-Ok 'no region is shared between scripts outside the template' }
else { Write-Ok ([string] $sharedRegionCount + ' region(s) shared between scripts are identical in every copy') }

# ---------------------------------------------------------------------------
# Embedded handler templates (G-1).
#
# Two scripts build a helper script inside a single-quoted here-string, write it
# under the toolkit root and register a SYSTEM scheduled task to run it. That is
# real PowerShell - 400+ lines of it in Deploy-TamperAlerts - executing on every
# armed endpoint, and until this gate existed NOTHING looked at it: every check
# above works on the AST of the OUTER script, where a here-string is a single
# string literal. No BOM check, no parse, no banned-PS7 scan, no analyzer.
#
# The failure that gap allows is the worst-shaped one in the toolkit. A syntax
# error or a PS7-only construct in that text passes CI green, deploys, and the
# handler dies the moment the task fires - while `-Audit` still reports the
# watcher healthy, because it verifies that the task exists, that its action
# names this root's handler, and that the handler's bytes match the template. It
# compares the handler to what it SHOULD be. Nothing ever asked whether the
# thing runs.
#
# Placeholders are rendered before parsing. @() is used for all of them because
# it parses in every position they occupy - a bare expression ($watch = @@WATCH@@),
# a foreach source, and inside a quoted string ('@@VOLUME@@' becomes '@()',
# still a string). The point is to make the text parseable, not to reproduce
# what the script substitutes at run time.
Write-Host ""
Write-Section 'Embedded handler templates'
$handlerFail = $false
$handlerCount = 0
foreach ($file in $files) {
    $handlerTokens = $null
    $handlerParseErrors = $null
    $outerAst = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref] $handlerTokens, [ref] $handlerParseErrors)
    if ($null -eq $outerAst) { continue }
    $shortName = [System.IO.Path]::GetFileName($file)

    # A TEXTUAL probe, deliberately independent of the AST walk below, and the
    # only thing standing between this gate and silent blindness. If the walk
    # stops finding templates - a renamed variable, a changed AST shape, a typo
    # in the StringConstantType comparison - a count-based assertion cannot tell
    # that from a repository that legitimately has none. IronBlackBox-IR is
    # exactly that repository: its collectors are read-only and deploy no
    # handler, so "zero templates" is the correct answer there and a global
    # non-zero requirement would fail a healthy repo. Tying the requirement to
    # evidence inside each file works in both.
    $probeCount = [regex]::Matches([System.IO.File]::ReadAllText($file), "Template\s*=\s*@'").Count
    $foundInFile = 0

    $assignments = $outerAst.FindAll({
        $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst]
    }, $true)
    foreach ($assignment in $assignments) {
        if ($assignment.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
        $varName = $assignment.Left.VariablePath.UserPath
        # UserPath, not UnqualifiedPath: for $script:HandlerTemplate the latter
        # returns the EMPTY STRING, which is how an earlier gate in this file
        # came to measure nothing while reporting success.
        if ($varName -notmatch 'Template$') { continue }

        $expr = $assignment.Right
        if ($expr -is [System.Management.Automation.Language.CommandExpressionAst]) { $expr = $expr.Expression }
        if ($expr -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { continue }
        if ($expr.StringConstantType -ne 'SingleQuotedHereString') { continue }

        $handlerCount++
        $foundInFile++
        $label = ($shortName + ' $' + $varName)
        $rendered = [regex]::Replace($expr.Value, '@@[A-Za-z0-9_]+@@', '@()')
        if ($rendered -match '@@') {
            Write-Fail ($label + ': placeholder left unrendered after substitution - the gate cannot judge this text')
            $handlerFail = $true
            continue
        }

        $renderedTokens = $null
        $renderedErrors = $null
        [void] [System.Management.Automation.Language.Parser]::ParseInput($rendered, [ref] $renderedTokens, [ref] $renderedErrors)
        if ($renderedErrors -and $renderedErrors.Count -gt 0) {
            foreach ($e in $renderedErrors) {
                Write-Fail ($label + ': handler line ' + [string] $e.Extent.StartLineNumber + ': ' + $e.Message)
            }
            $handlerFail = $true
            continue
        }

        $renderedAst = [System.Management.Automation.Language.Parser]::ParseInput($rendered, [ref] $renderedTokens, [ref] $renderedErrors)
        $handlerFindings = Get-BannedPs7Finding -Ast $renderedAst -Tokens $renderedTokens -SourceText $rendered
        if ($handlerFindings.Count -gt 0) {
            foreach ($f in $handlerFindings) { Write-Fail ($label + ': handler ' + $f) }
            $handlerFail = $true
            continue
        }

        if ($analyzerAvailable) {
            Import-Module PSScriptAnalyzer -ErrorAction Stop
            # -ScriptDefinition, because this text has no path of its own.
            $handlerResults = Invoke-ScriptAnalyzer -ScriptDefinition $rendered `
                -Settings $analyzerSettingsPath -Severity Error, Warning
            if ($handlerResults) {
                foreach ($r in $handlerResults) {
                    Write-Fail ($label + ': handler line ' + [string] $r.Line + ': [' + [string] $r.Severity + '] ' +
                                [string] $r.RuleName + ' - ' + [string] $r.Message)
                }
                $handlerFail = $true
                continue
            }
        }
        # The analyzer half of that verdict is only true when the analyzer ran.
        $handlerVerdict = ' rendered line(s) parse and carry no banned PS7 syntax'
        if ($analyzerAvailable) { $handlerVerdict = $handlerVerdict + ', and pass the analyzer' }
        else { $handlerVerdict = $handlerVerdict + ' (PSScriptAnalyzer is absent, so it was not run on them)' }
        Write-Ok ($label + ': ' + [string] (($rendered -split "`n").Count) + $handlerVerdict)
    }

    if ($foundInFile -lt $probeCount) {
        Write-Fail ($shortName + ': the text holds ' + [string] $probeCount + " here-string template " +
                    'assignment(s) but this gate parsed ' + [string] $foundInFile +
                    ' - it is not seeing code that ships, which is a defect in the gate, not in the file')
        $handlerFail = $true
    }
}
if ($handlerFail) { $overallFail = $true }
elseif ($handlerCount -eq 0) {
    # Correct and worth printing rather than staying silent: a reader has to be
    # able to tell "nothing to check here" from "this gate did not run".
    Write-Ok 'no script in this repository builds a handler from a here-string template'
}

# ---------------------------------------------------------------------------
# Same-named functions across scripts (check 13).
#
# Check 11 compares #regions explicitly marked [shared], and check 5 compares
# regions against the template. Between them sits everything else: a function
# that exists under the same name in several scripts without living in any
# marked region. 75 names are in that position here, and 65 of them hold the same
# code once comments and whitespace are set aside - so nothing was measuring the
# ten that do not.
#
# A shared name is what makes that dangerous. It tells a reader, and the author
# of the next fix, that the copies are the same thing; so a defect corrected in
# one copy goes on living in the other while the diff looks clean. That is
# exactly how the critical DACL bug survived in IronBlackBox-IR after it had
# been fixed in dev.
#
# Comments are removed and whitespace normalised before comparing, because a
# differing docstring is not a divergence and an alignment space is not code.
# Measured: without that normalisation this check reported 16 divergences where
# 10 exist - and one of the six false ones was a security guard whose two copies
# are identical apart from five lines of explanation.
Write-Host ""
Write-Section 'Same-named functions, across scripts'
$divergentAllowPath = Join-Path $repoRoot (Join-Path 'tools' 'divergent-functions.txt')
$allowedDivergent = @{}
if (Test-Path -LiteralPath $divergentAllowPath) {
    foreach ($line in (Get-Content -LiteralPath $divergentAllowPath)) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        $parts = $trimmed -split '\s+', 2
        $reason = ''
        if ($parts.Count -eq 2) { $reason = $parts[1].Trim() }
        $allowedDivergent[$parts[0]] = $reason
    }
}

function Get-FunctionCodeOnly {
    <#
        One function's code with every comment blanked and whitespace collapsed.
        The comment tokens come from the file's own token stream, so a '#' inside
        a string is not mistaken for a comment - the mistake an earlier gate in
        this file made by regex-matching source text.
    #>
    param(
        [Parameter(Mandatory = $true)] $FunctionAst,
        [Parameter(Mandatory = $true)] $Tokens
    )
    $text = $FunctionAst.Extent.Text
    $start = $FunctionAst.Extent.StartOffset
    $builder = New-Object System.Text.StringBuilder($text)
    foreach ($token in $Tokens) {
        if ($token.Kind -ne 'Comment') { continue }
        $from = $token.Extent.StartOffset - $start
        $to   = $token.Extent.EndOffset - $start
        if ($from -lt 0 -or $to -gt $text.Length) { continue }
        for ($i = $from; $i -lt $to; $i++) {
            if ($builder[$i] -ne "`n" -and $builder[$i] -ne "`r") { [void] $builder.Replace($builder[$i], ' ', $i, 1) }
        }
    }
    $lines = @($builder.ToString() -split "`r?`n" |
               ForEach-Object { ($_ -replace '\s+', ' ').Trim() } |
               Where-Object { $_ -ne '' })
    return ($lines -join "`n")
}

$functionsByName = @{}
foreach ($file in $allFiles) {
    if ([System.IO.Path]::GetFileName($file) -eq 'SCRIPT-TEMPLATE.ps1') { continue }
    $fnTokens = $null
    $fnErrors = $null
    $fnAst = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref] $fnTokens, [ref] $fnErrors)
    if ($null -eq $fnAst) { continue }
    foreach ($definition in $fnAst.FindAll({
        $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)) {
        $name = $definition.Name
        if (-not $functionsByName.ContainsKey($name)) {
            $functionsByName[$name] = New-Object System.Collections.ArrayList
        }
        [void] $functionsByName[$name].Add([PSCustomObject] @{
            File = [System.IO.Path]::GetFileName($file)
            Code = (Get-FunctionCodeOnly -FunctionAst $definition -Tokens $fnTokens)
        })
    }
}

$divergentFail = $false
$sharedNames = 0
$identicalNames = 0
$justified = New-Object System.Collections.ArrayList
$unusedAllow = New-Object System.Collections.ArrayList
foreach ($name in ($allowedDivergent.Keys | Sort-Object)) { [void] $unusedAllow.Add($name) }

foreach ($name in ($functionsByName.Keys | Sort-Object)) {
    $copies = @($functionsByName[$name])
    if ($copies.Count -lt 2) { continue }
    $sharedNames++
    $versions = @($copies | Select-Object -ExpandProperty Code -Unique)
    if ($versions.Count -eq 1) { $identicalNames++; continue }

    if ($allowedDivergent.ContainsKey($name)) {
        [void] $justified.Add($name)
        [void] $unusedAllow.Remove($name)
        if ([string]::IsNullOrWhiteSpace($allowedDivergent[$name])) {
            Write-Fail ('"' + $name + '" is listed in tools/divergent-functions.txt with NO reason - ' +
                        'the list is a record of deliberate decisions, not a mute switch')
            $divergentFail = $true
        }
        continue
    }

    $divergentFail = $true
    Write-Fail ('"' + $name + '" is defined in ' + [string] $copies.Count + ' script(s) with ' +
                [string] $versions.Count + ' different code bodies, and is not in ' +
                'tools/divergent-functions.txt')
    foreach ($group in ($copies | Group-Object -Property Code)) {
        Write-Fail ('    version: ' + (($group.Group | ForEach-Object { $_.File } | Sort-Object) -join ', '))
    }
    Write-Fail '    make the copies identical, or add the name with a reason if the difference is deliberate'
}

# A stale entry is a defect too: it means a divergence was resolved and the list
# now excuses something that no longer exists, which is how an allowlist quietly
# becomes permission for the next one.
foreach ($name in @($unusedAllow.ToArray())) {
    if (-not $functionsByName.ContainsKey($name)) {
        Write-Fail ('tools/divergent-functions.txt lists "' + $name + '", which no script defines - ' +
                    'remove the stale entry')
        $divergentFail = $true
        continue
    }
    Write-Fail ('tools/divergent-functions.txt lists "' + $name + '", but its copies now AGREE - ' +
                'remove the entry so the gate holds them to that')
    $divergentFail = $true
}

if ($divergentFail) { $overallFail = $true }
elseif ($sharedNames -eq 0) {
    Write-Fail 'no function name was found in two or more scripts - this gate measures nothing'
    $overallFail = $true
}
else {
    Write-Ok ([string] $sharedNames + ' function name(s) appear in 2+ scripts: ' +
              [string] $identicalNames + ' identical, ' + [string] $justified.Count +
              ' deliberately different and justified in tools/divergent-functions.txt')
}

Write-Host ""
if ($overallFail) {
    Write-Host "check.ps1: FAILED ($($files.Count) file(s) checked)" -ForegroundColor Red
    exit 1
} else {
    Write-Host "check.ps1: PASSED ($($files.Count) file(s) checked)" -ForegroundColor Green
    exit 0
}
