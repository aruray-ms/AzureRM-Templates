configuration ConfigureSPVM
{
    param
    (
        [Parameter(Mandatory)] [String]$DNSServer,
        [Parameter(Mandatory)] [String]$DomainFQDN,
        [Parameter(Mandatory)] [String]$DCName,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$DomainAdminCreds
    )

    Import-DscResource -ModuleName ComputerManagementDsc, ActiveDirectoryDsc, xDnsServer

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

        WindowsFeature AddADTools      { Name = "RSAT-AD-Tools";      Ensure = "Present"; }
        WindowsFeature AddADPowerShell { Name = "RSAT-AD-PowerShell"; Ensure = "Present"; }
        WindowsFeature AddDnsTools     { Name = "RSAT-DNS-Server";    Ensure = "Present"; }
        DnsServerAddress SetDNS { Address = $DNSServer; InterfaceAlias = $InterfaceAlias; AddressFamily  = 'IPv4' }

        WaitForADDomain WaitForDCReady
        {
            DomainName              = $DomainFQDN
            WaitTimeout             = 1800
            RestartCount            = 2
            WaitForValidCredentials = $True
            PsDscRunAsCredential    = $DomainAdminCredsQualified
            DependsOn               = "[DnsServerAddress]SetDNS"
        }

        PendingReboot RebootOnSignalFromWaitForDCReady
        {
            Name             = "RebootOnSignalFromWaitForDCReady"
            SkipCcmClientSDK = $true
            DependsOn        = "[WaitForADDomain]WaitForDCReady"
        }

        Computer JoinDomain
        {
            Name       = $ComputerName
            DomainName = $DomainFQDN
            Credential = $DomainAdminCredsQualified
            DependsOn  = "[PendingReboot]RebootOnSignalFromWaitForDCReady"
        }

        PendingReboot RebootOnSignalFromJoinDomain
        {
            Name             = "RebootOnSignalFromJoinDomain"
            SkipCcmClientSDK = $true
            DependsOn        = "[Computer]JoinDomain"
        }        
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
$SPSetupCreds = Get-Credential -Credential "spsetup"
$SPFarmCreds = Get-Credential -Credential "spfarm"
$SPSvcCreds = Get-Credential -Credential "spsvc"
$SPAppPoolCreds = Get-Credential -Credential "spapppool"
$SPPassphraseCreds = Get-Credential -Credential "Passphrase"
$SPSuperUserCreds = Get-Credential -Credential "spSuperUser"
$SPSuperReaderCreds = Get-Credential -Credential "spSuperReader"
$DNSServer = "10.1.1.4"
$DomainFQDN = "contoso.local"
$DCName = "DC"
$SQLName = "SQL"
$SQLAlias = "SQLAlias"
$SharePointVersion = 2019

$outputPath = "C:\Packages\Plugins\Microsoft.Powershell.DSC\2.80.0.3\DSCWork\ConfigureSPVM.0\ConfigureSPVM"
ConfigureSPVM -DomainAdminCreds $DomainAdminCreds -SPSetupCreds $SPSetupCreds -SPFarmCreds $SPFarmCreds -SPSvcCreds $SPSvcCreds -SPAppPoolCreds $SPAppPoolCreds -SPPassphraseCreds $SPPassphraseCreds -SPSuperUserCreds $SPSuperUserCreds -SPSuperReaderCreds $SPSuperReaderCreds -DNSServer $DNSServer -DomainFQDN $DomainFQDN -DCName $DCName -SQLName $SQLName -SQLAlias $SQLAlias -SharePointVersion $SharePointVersion -ConfigurationData @{AllNodes=@(@{ NodeName="localhost"; PSDscAllowPlainTextPassword=$true })} -OutputPath $outputPath
Set-DscLocalConfigurationManager -Path $outputPath
Start-DscConfiguration -Path $outputPath -Wait -Verbose -Force

#>
