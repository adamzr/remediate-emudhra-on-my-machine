# PSScriptAnalyzer settings, used by CI for every .ps1 in the repository.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # These scripts are run interactively by a person; Write-Host is their user-facing output.
        'PSAvoidUsingWriteHost'
    )
}
