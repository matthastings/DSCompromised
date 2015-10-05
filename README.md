# DSCompromised
PowerShell framework for managing and infecting systems via Windows Desired State Configuration

## Getting Started

### Set up pull server

1. Must have PowerShell 4.0 or later installed
2. Install DSC service
	- `Add-WindowsFeature Dsc-Service`
3. Download and install [xPSDesiredStateConfiguration Module](https://gallery.technet.microsoft.com/xPSDesiredStateConfiguratio-417dc71d)
4. Run `Configure-Server.ps1` 

### Create Configuration

1. On server run `Configure-Payload` or `Configure-User` scripts
2. Save **GUID** for victim configuration

### Configure Victim

1. On victim run `Configure-Victim.ps1`
2. Provide **GUID** as argument 