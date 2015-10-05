function Configure-Server {

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

PS C:\> Configure-Server -CompliancePort 9000 -ConfigPort 443

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
                Ensure 					= "Present"
                EndpointName 			= "PSDSCPullServer"
                Port 					= $ConfigPort
                PhysicalPath 			= "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
                CertificateThumbPrint 	= "AllowUnencryptedTraffic"
                ModulePath 				= "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
                ConfigurationPath 		= "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
                State 					= "Started"
                DependsOn 				= "[WindowsFeature]DSCServiceFeature"
            }

            xDscWebService PSDSCComplianceServer
            {
                Ensure 					= "Present"
                EndpointName 			= "PSDSCComplianceServer"
                Port 					= $CompliancePort
                PhysicalPath 			= "$env:SystemDrive\inetpub\wwwroot\PSDSCComplianceServer"
                CertificateThumbPrint 	= "AllowUnencryptedTraffic"
                State 					= "Started"
                IsComplianceServer 		= $true
                DependsOn 				= ("[WindowsFeature]DSCServiceFeature","[xDSCWebService]PSDSCPullServer")
            }
        }
    }

    SetupPullServer -ComputerName dsc-server

}