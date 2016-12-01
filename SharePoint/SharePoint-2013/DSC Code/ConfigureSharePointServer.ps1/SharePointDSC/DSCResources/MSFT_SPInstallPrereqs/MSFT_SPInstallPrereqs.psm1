$Script:SP2013Features = @("Application-Server", "AS-NET-Framework", 
                            "AS-TCP-Port-Sharing", "AS-Web-Support", "AS-WAS-Support", 
                            "AS-HTTP-Activation", "AS-Named-Pipes", "AS-TCP-Activation","Web-Server", 
                            "Web-WebServer", "Web-Common-Http", "Web-Default-Doc", "Web-Dir-Browsing", 
                            "Web-Http-Errors", "Web-Static-Content", "Web-Http-Redirect", "Web-Health", 
                            "Web-Http-Logging", "Web-Log-Libraries", "Web-Request-Monitor", 
                            "Web-Http-Tracing", "Web-Performance", "Web-Stat-Compression", 
                            "Web-Dyn-Compression", "Web-Security", "Web-Filtering", "Web-Basic-Auth", 
                            "Web-Client-Auth", "Web-Digest-Auth", "Web-Cert-Auth", "Web-IP-Security", 
                            "Web-Url-Auth", "Web-Windows-Auth", "Web-App-Dev", "Web-Net-Ext", 
                            "Web-Net-Ext45", "Web-Asp-Net", "Web-Asp-Net45", "Web-ISAPI-Ext", 
                            "Web-ISAPI-Filter", "Web-Mgmt-Tools", "Web-Mgmt-Console", "Web-Mgmt-Compat", 
                            "Web-Metabase", "Web-Lgcy-Scripting", "Web-WMI", "Web-Scripting-Tools", 
                            "NET-Framework-Features", "NET-Framework-Core", "NET-Framework-45-ASPNET", 
                            "NET-WCF-HTTP-Activation45", "NET-WCF-Pipe-Activation45", 
                            "NET-WCF-TCP-Activation45", "Server-Media-Foundation", 
                            "Windows-Identity-Foundation", "PowerShell-V2", "WAS", "WAS-Process-Model", 
                            "WAS-NET-Environment", "WAS-Config-APIs", "XPS-Viewer")

$Script:SP2016Win16Features = @("Web-Server", "Web-WebServer", 
                                "Web-Common-Http", "Web-Default-Doc", "Web-Dir-Browsing", 
                                "Web-Http-Errors", "Web-Static-Content", "Web-Health", 
                                "Web-Http-Logging", "Web-Log-Libraries", "Web-Request-Monitor", 
                                "Web-Http-Tracing", "Web-Performance", "Web-Stat-Compression", 
                                "Web-Dyn-Compression", "Web-Security", "Web-Filering", "Web-Basic-Auth", 
                                "Web-Digest-Auth", "Web-Windows-Auth", "Web-App-Dev", "Web-Net-Ext", 
                                "Web-Net-Ext45Web-Asp-Net", "Web-Asp-Net45", "Web-ISAPI-Ext", 
                                "Web-ISAPI-Filter", "Web-Mgmt-Tools", "Web-Mgmt-Console", 
                                "Web-Mgmt-Compat", "Web-Metabase", "Web-Lgcy-Scripting", "Web-WMI", 
                                "NET-Framework-Features", "NET-HTTP-Activation", "NET-Non-HTTP-Activ", 
                                "NET-Framework-45-ASPNET", "NET-WCF-Pipe-Activation45", 
                                "Windows-Identity-Foundation", "WAS", "WAS-Process-Model", 
                                "WAS-NET-Environment", "WAS-Config-APIs", "XPS-Viewer")

$Script:SP2016Win12r2Features = @("Application-Server", "AS-NET-Framework", 
                                "AS-Web-Support", "Web-Server", "Web-WebServer", "Web-Common-Http", 
                                "Web-Default-Doc", "Web-Dir-Browsing", "Web-Http-Errors", 
                                "Web-Static-Content", "Web-Http-Redirect", "Web-Health", 
                                "Web-Http-Logging", "Web-Log-Libraries", "Web-Request-Monitor", 
                                "Web-Performance", "Web-Stat-Compression", "Web-Dyn-Compression", 
                                "Web-Security", "Web-Filtering", "Web-Basic-Auth", "Web-Client-Auth", 
                                "Web-Digest-Auth", "Web-Cert-Auth", "Web-IP-Security", "Web-Url-Auth", 
                                "Web-Windows-Auth", "Web-App-Dev", "Web-Net-Ext", "Web-Net-Ext45", 
                                "Web-Asp-Net45", "Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-Mgmt-Tools", 
                                "Web-Mgmt-Console", "Web-Mgmt-Compat", "Web-Metabase", 
                                "Web-Lgcy-Mgmt-Console", "Web-Lgcy-Scripting", "Web-WMI", 
                                "Web-Scripting-Tools", "NET-Framework-Features", "NET-Framework-Core", 
                                "NET-HTTP-Activation", "NET-Non-HTTP-Activ", "NET-Framework-45-ASPNET", 
                                "NET-WCF-HTTP-Activation45", "Windows-Identity-Foundation", 
                                "PowerShell-V2", "WAS", "WAS-Process-Model", "WAS-NET-Environment", 
                                "WAS-Config-APIs")


function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]  
        [System.String]  
        $InstallerPath,

        [parameter(Mandatory = $true)]  
        [System.Boolean] 
        $OnlineMode,
        
        [parameter(Mandatory = $false)] 
        [System.String] 
        $SXSpath,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $SQLNCli,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $PowerShell,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $NETFX,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $IDFX,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $Sync,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $AppFabric,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $IDFX11,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $MSIPCClient,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $WCFDataServices,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $KB2671763,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $WCFDataServices56,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $MSVCRT11,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $MSVCRT14,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $KB3092423,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $ODBC,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $DotNetFx,
        
        [parameter(Mandatory = $false)] 
        [ValidateSet("Present","Absent")] 
        [System.String] 
        $Ensure = "Present"
    )
    
    Write-Verbose -Message "Detecting SharePoint version from binaries"
    $majorVersion = (Get-SPDSCAssemblyVersion -PathToAssembly $InstallerPath)
    if ($majorVersion -eq 15) 
    {
        Write-Verbose -Message "Version: SharePoint 2013"
    }
    if ($majorVersion -eq 16) 
    {
        Write-Verbose -Message "Version: SharePoint 2016"
    }

    Write-Verbose -Message "Getting installed windows features"

    $osVersion = Get-SPDscOSVersion 
    if ($majorVersion -eq 15) 
    {
        $WindowsFeatures = Get-WindowsFeature -Name $Script:SP2013Features
    }
    if ($majorVersion -eq 16) 
    {
        if ($osVersion.Major -eq 10) 
        {
            # Server 2016
            $WindowsFeatures = Get-WindowsFeature -Name $Script:SP2016Win16Features
        }
        elseif ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3)
        {
            # Server 2012 R2
            $WindowsFeatures = Get-WindowsFeature -Name $Script:SP2016Win12r2Features
        }
        else 
        {
            throw "SharePoint 2016 only supports Windows Server 2016 or 2012 R2"        
        } 
    }
    
    $windowsFeaturesInstalled = $true
    foreach ($feature in $WindowsFeatures) 
    {
        if ($feature.Installed -eq $false) 
        {
            $windowsFeaturesInstalled = $false
            Write-Verbose -Message "Windows feature $($feature.Name) is not installed"
        }
    }

    Write-Verbose -Message "Checking windows packages from the registry"

    $x86Path = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $installedItemsX86 = Get-ItemProperty -Path $x86Path | Select-Object -Property DisplayName
    
    $x64Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $installedItemsX64 = Get-ItemProperty -Path $x64Path | Select-Object -Property DisplayName

    $installedItems = $installedItemsX86 + $installedItemsX64 | Select-Object -Property DisplayName -Unique

    # Common prereqs
    $prereqsToTest = @(
        [PSObject]@{
            Name = "AppFabric 1.1 for Windows Server"
            SearchType = "Equals"
            SearchValue = "AppFabric 1.1 for Windows Server"
        },
        [PSObject]@{
            Name = "Microsoft CCR and DSS Runtime 2008 R3"
            SearchType = "Equals"
            SearchValue = "Microsoft CCR and DSS Runtime 2008 R3"
        },
        [PSObject]@{
            Name = "Microsoft Identity Extensions"
            SearchType = "Equals"
            SearchValue = "Microsoft Identity Extensions"
        },
        [PSObject]@{
            Name = "Microsoft Sync Framework Runtime v1.0 SP1 (x64)"
            SearchType = "Equals"
            SearchValue = "Microsoft Sync Framework Runtime v1.0 SP1 (x64)"
        },
        [PSObject]@{
            Name = "WCF Data Services 5.6.0 Runtime"
            SearchType = "Equals"
            SearchValue = "WCF Data Services 5.6.0 Runtime"
        }
    )
    
    #SP2013 prereqs
    if ($majorVersion -eq 15) 
    {
        $prereqsToTest += @(
            [PSObject]@{
                Name = "Active Directory Rights Management Services Client 2.*"
                SearchType = "Like"
                SearchValue = "Active Directory Rights Management Services Client 2.*"
            },
            [PSObject]@{
                Name = "Microsoft SQL Server Native Client (2008 R2 or 2012)"
                SearchType = "Match"
                SearchValue = "SQL Server (2008 R2|2012) Native Client"
            },
            [PSObject]@{
                Name = "WCF Data Services 5.0 (for OData v3) Primary Components"
                SearchType = "Equals"
                SearchValue = "WCF Data Services 5.0 (for OData v3) Primary Components"
            }
        )
    }

    #SP2016 prereqs
    if ($majorVersion -eq 16) 
    {
        $prereqsToTest += @(
            [PSObject]@{
                Name = "Active Directory Rights Management Services Client 2.1"
                SearchType = "Equals"
                SearchValue = "Active Directory Rights Management Services Client 2.1"
            },
            [PSObject]@{
                Name = "Microsoft SQL Server 2012 Native Client"
                SearchType = "Equals"
                SearchValue = "Microsoft SQL Server 2012 Native Client"
            },
            [PSObject]@{
                Name = "Microsoft ODBC Driver 11 for SQL Server"
                SearchType = "Equals"
                SearchValue = "Microsoft ODBC Driver 11 for SQL Server"
            },
            [PSObject]@{
                Name = "Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030"
                SearchType = "Equals"
                SearchValue = "Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030"
            },
            [PSObject]@{
                Name = "Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030"
                SearchType = "Equals"
                SearchValue = "Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030"
            },
            [PSObject]@{
                Name = "Microsoft Visual C++ 2015 x64 Minimum Runtime - 14.0.23026"
                SearchType = "Equals"
                SearchValue = "Microsoft Visual C++ 2015 x64 Minimum Runtime - 14.0.23026"
            },
            [PSObject]@{
                Name = "Microsoft Visual C++ 2015 x64 Additional Runtime - 14.0.23026"
                SearchType = "Equals"
                SearchValue = "Microsoft Visual C++ 2015 x64 Additional Runtime - 14.0.23026"
            }
        )            
    }
    $prereqsInstalled = Test-SPDscPrereqInstallStatus -InstalledItems $installedItems `
                                                      -PrereqsToCheck $prereqsToTest
        
    $results = @{
        InstallerPath = $InstallerPath
        OnlineMode = $OnlineMode
        SXSpath = $SXSpath
        SQLNCli = $SQLNCli
        PowerShell = $PowerShell
        NETFX = $NETFX
        IDFX = $IDFX
        Sync = $Sync
        AppFabric = $AppFabric
        IDFX11 = $IDFX11
        MSIPCClient = $MSIPCClient
        WCFDataServices = $WCFDataServices
        KB2671763 = $KB2671763
        WCFDataServices56 = $WCFDataServices56
        MSVCRT11 = $MSVCRT11
        MSVCRT14 = $MSVCRT14
        KB3092423 = $KB3092423
        ODBC = $ODBC
        DotNetFx = $DotNetFx
    }

    if ($prereqsInstalled -eq $true -and $windowsFeaturesInstalled -eq $true) 
    {
        $results.Ensure = "Present"
    } 
    else 
    {
        $results.Ensure = "Absent"
    }
    
    return $results
}

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]  
        [System.String]  
        $InstallerPath,

        [parameter(Mandatory = $true)]  
        [System.Boolean] 
        $OnlineMode,
        
        [parameter(Mandatory = $false)] 
        [System.String] 
        $SXSpath,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $SQLNCli,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $PowerShell,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $NETFX,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $IDFX,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $Sync,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $AppFabric,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $IDFX11,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $MSIPCClient,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $WCFDataServices,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $KB2671763,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $WCFDataServices56,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $MSVCRT11,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $MSVCRT14,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $KB3092423,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $ODBC,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $DotNetFx,
        
        [parameter(Mandatory = $false)] 
        [ValidateSet("Present","Absent")] 
        [System.String] 
        $Ensure = "Present"
    )

    if ($Ensure -eq "Absent") 
    {
        throw [Exception] ("SharePointDsc does not support uninstalling SharePoint or its " + `
                           "prerequisites. Please remove this manually.")
        return
    }

    Write-Verbose -Message "Detecting SharePoint version from binaries"
    $majorVersion = Get-SPDSCAssemblyVersion -PathToAssembly $InstallerPath
    $osVersion = Get-SPDscOSVersion

    if ($majorVersion -eq 15) 
    {
        $ndpKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP"
        $dotNet46Check = Get-ChildItem -Path $ndpKey -Recurse `
                         | Get-ItemProperty -name Version,Release -ErrorAction SilentlyContinue `
                         | Where-Object -FilterScript { 
                             $_.PSChildName -match '^(?!S)\p{L}' -and $_.Version -like "4.6.*"
                           }
        if ($null -ne $dotNet46Check -and $dotNet46Check.Length -gt 0) 
        {
            throw [Exception] ("A known issue prevents installation of SharePoint 2013 on " + `
                               "servers that have .NET 4.6 already installed. See details at " + `
                               "https://support.microsoft.com/en-us/kb/3087184")
            return
        }
        
        Write-Verbose -Message "Version: SharePoint 2013"
        $requiredParams = @("SQLNCli","PowerShell","NETFX","IDFX","Sync","AppFabric","IDFX11",
                            "MSIPCClient","WCFDataServices","KB2671763","WCFDataServices56")
        $WindowsFeatures = Get-WindowsFeature -Name $Script:SP2013Features
    }
    if ($majorVersion -eq 16) 
    {
        Write-Verbose -Message "Version: SharePoint 2016"
        $requiredParams = @("SQLNCli","Sync","AppFabric","IDFX11","MSIPCClient","KB3092423",
                            "WCFDataServices56","DotNetFx","MSVCRT11","MSVCRT14","ODBC")
        if ($osVersion.Major -eq 10) 
        {
            # Server 2016
            $WindowsFeatures = Get-WindowsFeature -Name $Script:SP2016Win16Features
        } 
        elseif ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3)
        {
            # Server 2012 R2
            $WindowsFeatures = Get-WindowsFeature -Name $Script:SP2016Win12r2Features
        }
        else 
        {
            throw "SharePoint 2016 only supports Windows Server 2016 or 2012 R2"        
        }
    }
    
    # SXSstore for feature install specified, we will manually install features from the 
    # store, rather then relying on the prereq installer to download them
    if ($SXSpath) { 
        Write-Verbose -Message "Getting installed windows features"
        foreach ($feature in $WindowsFeatures) 
        {
            if ($feature.Installed -ne $true) 
            {
                Write-Verbose "Installing $($feature.name)"
                $installResult = Install-WindowsFeature -Name $feature.Name -Source $SXSpath
                if ($installResult.restartneeded -eq "yes") 
                {
                    $global:DSCMachineStatus = 1
                }
                if ($installResult.Success -ne $true) 
                { 
                    throw "Error installing $($feature.name)"
                }
            }
        }
    
        # see if we need to reboot after feature install
        if ($global:DSCMachineStatus -eq 1) 
        {
            return
        } 
    }
    
    $prereqArgs = "/unattended"
    if ($OnlineMode -eq $false) 
    {
        $requiredParams | ForEach-Object -Process {
            if (($PSBoundParameters.ContainsKey($_) -eq $true `
                    -and [string]::IsNullOrEmpty($PSBoundParameters.$_)) `
                -or (-not $PSBoundParameters.ContainsKey($_))) 
            {
                throw "In offline mode for version $majorVersion parameter $_ is required"
            }
            if ((Test-Path $PSBoundParameters.$_) -eq $false) 
            {
                throw ("The $_ parameter has been passed but the file cannot be found at the " + `
                       "path supplied: `"$($PSBoundParameters.$_)`"")
            }
        }
        $requiredParams | ForEach-Object -Process {
            $prereqArgs += " /$_`:`"$($PSBoundParameters.$_)`""
        }
    }

    Write-Verbose -Message "Calling the SharePoint Pre-req installer"
    Write-Verbose -Message "Args for prereq installer are: $prereqArgs"
    $process = Start-Process -FilePath $InstallerPath -ArgumentList $prereqArgs -Wait -PassThru

    switch ($process.ExitCode) 
    {
        0 
        {
            Write-Verbose -Message "Prerequisite installer completed successfully."
        }
        1 
        {
            throw "Another instance of the prerequisite installer is already running"
        }
        2 
        {
            throw "Invalid command line parameters passed to the prerequisite installer"
        }
        1001 
        {
            Write-Verbose -Message ("A pending restart is blocking the prerequisite " + `
                                    "installer from running. Scheduling a reboot.")
            $global:DSCMachineStatus = 1
        }
        3010 
        {
            Write-Verbose -Message ("The prerequisite installer has run correctly and needs " + `
                                    "to reboot the machine before continuing.")
            $global:DSCMachineStatus = 1
        }
        default 
        {
            throw ("The prerequisite installer ran with the following unknown " + `
                   "exit code $($process.ExitCode)")
        }
    }
    
    $rebootKey1 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\" + `
                  "Component Based Servicing\RebootPending"
    $rebootTest1 = Get-Item -Path $rebootKey1 -ErrorAction SilentlyContinue

    $rebootKey2 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\" + `
                  "Auto Update\RebootRequired"
    $rebootTest2 = Get-Item -Path $rebootKey2 -ErrorAction SilentlyContinue

    $sessionManagerKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $sessionManager = Get-Item -Path $sessionManagerKey | Get-ItemProperty
    $pendingFileRenames = $sessionManager.PendingFileRenameOperations.Count

    if (($null -ne $rebootTest1) -or ($null -ne $rebootTest2) -or ($pendingFileRenames -gt 0))
    {
        Write-Verbose -Message ("SPInstallPrereqs has detected the server has pending a " + `
                                "reboot. Flagging to the DSC engine that the server should " + `
                                "reboot before continuing.")
        $global:DSCMachineStatus = 1   
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]  
        [System.String]  
        $InstallerPath,

        [parameter(Mandatory = $true)]  
        [System.Boolean] 
        $OnlineMode,
        
        [parameter(Mandatory = $false)] 
        [System.String] 
        $SXSpath,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $SQLNCli,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $PowerShell,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $NETFX,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $IDFX,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $Sync,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $AppFabric,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $IDFX11,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $MSIPCClient,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $WCFDataServices,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $KB2671763,        
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $WCFDataServices56,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $MSVCRT11,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $MSVCRT14,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $KB3092423,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $ODBC,
        
        [parameter(Mandatory = $false)] 
        [System.String]  
        $DotNetFx,
        
        [parameter(Mandatory = $false)] 
        [ValidateSet("Present","Absent")] 
        [System.String] 
        $Ensure = "Present"
    )

    if ($Ensure -eq "Absent") 
    {
        throw [Exception] ("SharePointDsc does not support uninstalling SharePoint or its " + `
                           "prerequisites. Please remove this manually.")
        return
    }

    $PSBoundParameters.Ensure = $Ensure
    $CurrentValues = Get-TargetResource @PSBoundParameters

    Write-Verbose -Message "Checking installation of SharePoint prerequisites"
    
    return Test-SPDscParameterState -CurrentValues $CurrentValues `
                                        -DesiredValues $PSBoundParameters -ValuesToCheck @("Ensure")
}

function Test-SPDscPrereqInstallStatus
{
    param
    (
        [Parameter(Mandatory = $false)]
        [Object]
        $InstalledItems,

        [Parameter(Mandatory = $true)]
        [psobject[]]
        $PrereqsToCheck
    )

    if ($null -eq $InstalledItems) {
        return $false
    }

    $itemsInstalled = $true
    $PrereqsToCheck | ForEach-Object -Process {
        $itemToCheck = $_
        switch ($itemToCheck.SearchType) 
        {
            "Equals" 
            {
                if ($null -eq ($InstalledItems | Where-Object -FilterScript {
                    $null -ne $_.DisplayName -and $_.DisplayName.Trim() -eq $itemToCheck.SearchValue
                })) 
                {
                    $itemsInstalled = $false
                    Write-Verbose -Message ("Prerequisite $($itemToCheck.Name) was not found " + `
                                            "on this system")
                }
            }
            "Match" 
            { 
                if ($null -eq ($InstalledItems | Where-Object -FilterScript {
                    $null -ne $_.DisplayName -and $_.DisplayName.Trim() -match $itemToCheck.SearchValue
                })) 
                {
                    $itemsInstalled = $false
                    Write-Verbose -Message ("Prerequisite $($itemToCheck.Name) was not found " + `
                                            "on this system")
                }
            }
            "Like" 
            { 
                if ($null -eq ($InstalledItems | Where-Object -FilterScript {
                    $null -ne $_.DisplayName -and $_.DisplayName.Trim() -like $itemToCheck.SearchValue
                })) 
                {
                    $itemsInstalled = $false
                    Write-Verbose -Message ("Prerequisite $($itemToCheck.Name) was not found " + `
                                            "on this system")
                }
            }
            Default 
            { 
                throw ("Unable to search for a prereq with mode '$($itemToCheck.SearchType)'. " + `
                       "please use either 'Equals', 'Like' or 'Match'")
            }
        }
    }
    return $itemsInstalled
}

Export-ModuleMember -Function *-TargetResource
