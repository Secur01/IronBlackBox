#
# PSScriptAnalyzer settings for IronBlackBox.
#
# Every exclusion below is a deliberate design decision recorded in
# docs/DESIGN.md, not a finding swept under the rug. Adding an exclusion
# requires a reason written here.
#
@{
    # Target the PowerShell version that actually runs on MSP endpoints.
    # This is what makes PSUseCompatibleSyntax meaningful: it flags syntax that
    # parses under pwsh 7 on the dev machine but fails on a 5.1 endpoint.
    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1')
        }
    }

    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # Operator console output is the point. These scripts are run
        # interactively by a technician and unattended by an RMM that captures
        # stdout; coloured section headers, findings in yellow and failures in
        # red are how the operator reads the result. Write-Output would mix
        # human text into the pipeline, and Write-Information is invisible by
        # default under 5.1.
        'PSAvoidUsingWriteHost',

        # False positive across this repo's structure. Every script binds its
        # parameters in a param() block and consumes them inside Invoke-Main
        # and the helpers; PSSA does not trace usage across function
        # boundaries, so it reports every parameter as unused. -Audit is also
        # genuinely referenced only as a parameter-set name, which is its job.
        'PSReviewUnusedParameter',

        # This repo implements the same intent with a different mechanism, and
        # the built-in one is unusable here. -WhatIf/-Confirm depend on a host
        # that can prompt; these scripts run as SYSTEM with no user profile,
        # where a prompt is a hang, and a hung hardening script on a production
        # server is the failure mode this project exists to avoid. The
        # replacement is the mode contract: -Audit is the -WhatIf, it is the
        # DEFAULT, and it is strictly read-only. See docs/DESIGN.md section 2.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
