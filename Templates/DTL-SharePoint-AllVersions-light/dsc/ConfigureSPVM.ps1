configuration ConfigureSPVM
{
    param
    (
        [Parameter(Mandatory)] [String]$DNSServer,
        [Parameter(Mandatory)] [String]$DomainFQDN,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$DomainAdminCreds
    )

    Import-DscResource -ModuleName ComputerManagementDsc, ActiveDirectoryDsc, xDnsServer, NetworkingDsc, xPSDesiredStateConfiguration

    [String] $DomainNetbiosName = (Get-NetBIOSName -DomainFQDN $DomainFQDN)
    $Interface = Get-NetAdapter| Where-Object Name -Like "Ethernet*"| Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)
    [System.Management.Automation.PSCredential] $DomainAdminCredsQualified = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($DomainAdminCreds.UserName)", $DomainAdminCreds.Password)
    [String] $ComputerName = Get-Content env:computername

    Node localhost
    {
        LocalConfigurationManager
        {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        DnsServerAddress SetDNS { Address = $DNSServer; InterfaceAlias = $InterfaceAlias; AddressFamily  = 'IPv4' }

        # ADUser CreateDumbAccount { DomainName = $DomainFQDN; UserName = "DumbAccount" }

        WaitForADDomain WaitForDCReady
        {
            DomainName              = $DomainFQDN
            WaitTimeout             = 1800
            RestartCount            = 2
            WaitForValidCredentials = $True
            PsDscRunAsCredential    = $DomainAdminCredsQualified
            DependsOn               = "[DnsServerAddress]SetDNS"
        }

        # xScript ForceReboot1
        # {
        #     # If the TestScript returns $false, DSC executes the SetScript to bring the node back to the desired state
        #     TestScript = {
        #         return (Test-Path HKLM:\SOFTWARE\DscScriptExecution\flag_ForceReboot1)
        #     }
        #     SetScript = {
        #         New-Item -Path HKLM:\SOFTWARE\DscScriptExecution\flag_ForceReboot1 -Force
        #         $global:DSCMachineStatus = 1
        #     }
        #     GetScript = { }
        #     PsDscRunAsCredential = $DomainAdminCredsQualified
        #     DependsOn = "[WaitForADDomain]WaitForDCReady"
        # }

        # PendingReboot RebootOnSignalFromForceReboot1
        # {
        #     Name             = "RebootOnSignalFromForceReboot1"
        #     SkipCcmClientSDK = $true
        #     DependsOn        = "[xScript]ForceReboot1"
        # }

        Computer JoinDomain
        {
            Name       = $ComputerName
            DomainName = $DomainFQDN
            Credential = $DomainAdminCredsQualified
            DependsOn  = "[WaitForADDomain]WaitForDCReady"
        }

        # xScript ForceReboot2
        # {
        #     # If the TestScript returns $false, DSC executes the SetScript to bring the node back to the desired state
        #     TestScript = {
        #         return (Test-Path HKLM:\SOFTWARE\DscScriptExecution\ForceReboot2)
        #     }
        #     SetScript = {
        #         New-Item -Path HKLM:\SOFTWARE\DscScriptExecution\ForceReboot2 -Force
        #         $global:DSCMachineStatus = 1
        #     }
        #     GetScript = { }
        #     PsDscRunAsCredential = $DomainAdminCredsQualified
        #     DependsOn = "[Computer]JoinDomain"
        # }

        # PendingReboot RebootOnSignalFromJoinDomain
        # {
        #     Name             = "RebootOnSignalFromJoinDomain"
        #     SkipCcmClientSDK = $true
        #     DependsOn        = "[xScript]ForceReboot2"
        #     # DependsOn        = "[Computer]JoinDomain"
        # }
    }
}

function Get-NetBIOSName
{
    [OutputType([string])]
    param(
        [string]$DomainFQDN
    )

    if ($DomainFQDN.Contains('.')) {
        $length=$DomainFQDN.IndexOf('.')
        if ( $length -ge 16) {
            $length=15
        }
        return $DomainFQDN.Substring(0,$length)
    }
    else {
        if ($DomainFQDN.Length -gt 15) {
            return $DomainFQDN.Substring(0,15)
        }
        else {
            return $DomainFQDN
        }
    }
}

<#
# Azure DSC extension logging: C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC\2.21.0.0
# Azure DSC extension configuration: C:\Packages\Plugins\Microsoft.Powershell.DSC\2.21.0.0\DSCWork

Install-Module -Name PendingReboot
help ConfigureSPVM

$DomainAdminCreds = Get-Credential -Credential "yvand"
$DNSServer = "10.1.1.4"
$DomainFQDN = "contoso.local"

$outputPath = "C:\Packages\Plugins\Microsoft.Powershell.DSC\2.80.3.0\DSCWork\ConfigureSPVM.0\ConfigureSPVM"
ConfigureSPVM -DomainAdminCreds $DomainAdminCreds -DNSServer $DNSServer -DomainFQDN $DomainFQDN -ConfigurationData @{AllNodes=@(@{ NodeName="localhost"; PSDscAllowPlainTextPassword=$true })} -OutputPath $outputPath
Set-DscLocalConfigurationManager -Path $outputPath
Start-DscConfiguration -Path $outputPath -Wait -Verbose -Force

#>
