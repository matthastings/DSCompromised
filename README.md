# DSCompromised
PowerShell framework for managing and infecting systems via Windows Desired State Configuration

## Getting Started

### Set up pull server

1. Must have PowerShell 4.0 or later installed
2. Download and install [xPSDesiredStateConfiguration Module](https://gallery.technet.microsoft.com/xPSDesiredStateConfiguratio-417dc71d)
3. Install DSC service
	- `Add-WindowsFeature Dsc-Service -IncludeManagementTools`
4. Confirm WinRM is running `winrm quickconfig`
4. Run `Configure-Server.ps1` 

### Create Configuration

1. On server run `Configure-Payload` or `Configure-User` scripts
2. Save **GUID** for victim configuration

### Configure Victim

1. On victim run `Configure-Victim.ps1`
2. Provide **GUID** as argument 
3. Provide **Pull Server Address** as argument