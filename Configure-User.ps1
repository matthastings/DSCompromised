function Configure-User {
<#
.SYNOPSIS

Configure DSC pull server for user persistence 

.DESCRIPTION

Script ensures a user is present and member of a defined group.

Must be run on the DSC server before configuring any endpoints.

.PARAMETER Username

Name of account to be created on endpoints

.PARAMETER Password

Password used for user account. Password must meet complexity requirements of any infected endpoint or user account will not be created.
Note: Password is stored in clear text within the MOF file.

.PARAMETER Group

Optionally specifies the group the user should be added to. Default is 'Adminstrators'

.EXAMPLE

PS C:\> Configure-User -Username test_user -Password Long_And_Complex!

Description
-----------

Creates user account 'test_user' with password 'Long_And_Complex!' and adds user to local administrators group. 
If the user is deleted or group membership removed the user will automatically be recreated and/or readded to the group.


.EXAMPLE


PS C:\> Configure-User -Username test_user -Password Long_And_Complex! -Group RemoteAdmins

Description
-----------
Creates user account 'test_user' with password 'Long_And_Complex!' and adds user to local 'RemoteAdmins' group. 
If the user is deleted or group membership removed the user will automatically be recreated and/or readded to the group.


#>
    [CmdletBinding()] Param(
    [Parameter(Mandatory = $True)]
    [String] $Username,

    [Parameter(Mandatory = $True)]
    [String] $Password,

        [Parameter(Mandatory = $False)]
        [String] $Group = "Administrators"
    )

    $GUID = [guid]::NewGuid()

    $configData = @{
            AllNodes = @(
                            @{
                                NodeName = [string]$GUID;
                                PSDscAllowPlainTextPassword = $true
                                }
                )
            }

    Configuration CreateAdmin {
        Param(
        [Parameter(Mandatory = $True)]
        [String[]] $NodeGUID
        )
        
        $pass = ConvertTo-SecureString $Password -AsPlainText -Force 
        $credObject = New-Object System.Management.Automation.PSCredential($Username, $pass)

        Node $NodeGUID {
        

            User newUser {
                UserName                 = $Username
                Password                 = $credObject
                PasswordNeverExpires     = $false
                Ensure                   = "Present"
            }
            Group Admins {
                Ensure               = "Present"
                GroupName            = $Group
                MembersToInclude     = $Username
                DependsOn            = "[User]newUser"

            
            } 
        }
    }

    CreateAdmin -NodeGUID $GUID -ConfigurationData $configData -OutputPath "$env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration"
    New-DscChecksum -ConfigurationPath "$env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration\" -OutPath "$env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration"

}