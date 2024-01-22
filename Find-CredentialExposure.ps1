function Find-CredentialExposure {
<#
    .SYNOPSIS
        Search Recorded Future for exposed credentials
    .DESCRIPTION
        Search Recorded Future for exposed credentials
        Provides information about Breaches and Dumps the credential is associated with
        Sends a hash of the credential to the API, so this uses the Get-HashOfString function, with SHA1 instead of default SHA256
    .PARAMETER Email
        [Mandatory]
        The Email credential to search for
    .NOTES
        Author: Joel Ashman
        v0.1 - (2024-01-02) Initial version
    .EXAMPLE
        Find-CredentialExposure -Email kramer@monks.com 
    #>

    #requires -version 5

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Email,
        [Parameter()]
        [string]$Breach,
        [Parameter()]
        [string]$Dump,
        [Parameter()]
        [string]$Malware
    )

    # Function within a function?  Not sure if this is the best way. Ideally, a Powershell module containing all of our tools would be built
    function Get-HashOfString{
        <#
        .SYNOPSIS
            Computes the hash of a given input string
        .DESCRIPTION
            Computes the hash of a given input string
            Uses default hashing algorithm (SHA256) without parameter.
            Can be specified to use SHA1, SHA256, SHA384, SHA512, or MD5
        .PARAMETER String
            [Mandatory] String Parameter
            The string that you want to hash
            Enclose this in quotes if it has a space
        .PARAMETER Algorithm
            String Parameter
            Hashing algorithm to use. Options are: SHA1, SHA256, SHA384, SHA512, or MD5
            If no value is specified, or if the parameter is omitted, the default value is SHA256
        .NOTES
            Author: Joel Ashman (Shamelessly taken from below url) 
            https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.3
            v0.1 - (2023-12-29) Initial version
        .EXAMPLE
            Get-HashOfString -String "Boxing Day Test"
        #>

        #requires -version 5

        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [string]$String,
            [Parameter()]
            [string]$Algo
        )
        
        if ($Algo){$Algo = $Algo} # Ensure that the Algorithm is set
        else{$Algo = "SHA256"}
        Write-Warning "Hashing algorithm selected: $($Algo)"
        # Set up the input stream so that we can hash the string
        $StringAsStream = [System.IO.MemoryStream]::new()
        $Writer = [System.IO.StreamWriter]::new($StringAsStream)
        $Writer.write($String)
        $Writer.Flush()
        $StringAsStream.Position = 0
        try{
            (Get-FileHash -InputStream $stringAsStream -Algorithm $Algo| Select-Object Hash).hash # Calculate the hash of the string
        }
        catch{Write-Warning "Error: $($Error.Errors.Message)"}
    }

    # Main function starts here
    $ApiToken = "7901a2b25e944b9eae0a305d9a061b14" # Not a secure way to store this - should investigate another option
    $RecordedFutureCredLookupUrl = "https://api.recordedfuture.com/identity/credentials/lookup"
    $Header = @{"X-RFToken" = $ApiToken} # Authorisation header for RF API
    $EmailHash = Get-HashOfString -String $Email -Algo SHA1
    $Params = @{ # Build the table to hold the request body data (case sensitive)
        'subjects_sha1' = @($EmailHash)
        ## The filtering via the API seems to have mixed results, so not in use at present
        ## It seems better to grab all results for a credential, and then filter on the PowerShell side
        #'filter' = @{
            #'breach_properties' = @{
            #    'name' = $Breach
            #}
            #'dump_properties' = @{
            #    'name' = $Dump
            #}
            #'malware_families' = @($Malware)
        #}
    }
    $Body = $Params | ConvertTo-Json # Convert the table to JSON for the API to accept it
    # POST request to the API
    try{
        (Invoke-restmethod -Method Post -Headers $Header -Uri $RecordedFutureCredLookupUrl -Body $Body -ContentType application/json).identities.credentials
    }
    catch{
        if($Error.Errors -eq $null){Write-Warning "Error: $($Error[0].ErrorDetails.message)"}
        else{Write-Warning "Error: $($Error.Errors.Message)"}
    }
}
