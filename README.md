# DSCompromised
PowerShell framework for managing and infecting systems via Windows Desired State Configuration (DSC)
DSC is a built-in feature in Windows Management Framework 4.0 (PowerShell v4) and is installed natively
on Windows operating systems beginning with  Server 2012 R2 and Windows 8.1. 

## Getting Started

### Set up pull server

1. Must have PowerShell 4.0 or later installed
2. Install DSC service
    - `Add-WindowsFeature Dsc-Service -IncludeManagementTools`
    - This will only work on Server 2012 R2 or later
    - See [link](https://davewyatt.wordpress.com/2014/06/07/how-to-install-a-dsc-pull-server-on-windows-2008-r2/) for steps to go through the pain of installing on Server 2008
3. Download [xPSDesiredStateConfiguration Module](https://gallery.technet.microsoft.com/xPSDesiredStateConfiguratio-417dc71d)
4. Unzip the contentsto $env:ProgramFiles\WindowsPowerShell\Modules and relaunch PS 
5. To confirm installation run `Get-DSCResource` and confirm the following modules are present:
    - xDscWebService
    - xWindowsProcess
    - xService
    - xRemoteFile
    - xPackage
    - xGroup
    - xFileUpload
6. Verify winrm is running with command `winrm quickconfig`
7. Run `Configure-Server` function from `Configure-Server.psm1`

### Create Configuration

1. On server run generate varaibles as `Configure-Payload` or `Configure-User` objects
2. Run `Generate-Config`. The output of this function is a GUID
2. Save **GUID** for victim configuration
3. Save **Pull Server Address** for victime configuration

### Configure Victim

<<<<<<< HEAD
1. On victim run import `Configure-Victim.ps1` and run `Configure-Victim
2. Provide **GUID** and **Remote Address** as arguments
=======
1. On victim run `Configure-Victim.ps1`
2. Provide **GUID** as argument 
>>>>>>> b9dda71411166f1f876a93ba7bd67fd1cff223bd

## Troubleshooting

- If you get the error `Invoke-CimMethod : The SendConfigurationApply function did not succeed.` when attempting to run a very short-lived process (e.g. a console app that requires arguments that have been omitted, thereby terminating immediately), it may be due to the OS mis-interpreting that the configuration failed. The process still executed.