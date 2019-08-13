<#
    .SYNOPSIS
    Tool for collecting VBR cofiguration and generating word documentation. 

    .DESCRIPTION

    VeeamConfigurationDump is a tool for collecting VBR cofiguration and generating word documentation. 

    The script has 2 running modes: 
    1. Data collection - connects to a backup server and gathers configuration.
            Output file name format: name_mmddyyyy_hhmmss.ext (where .ext can be .log, .csv or .html)

    2. Offline processing - uses previously generated data files to update a MS Word document
        - needs a specific ms word file to be uploaded in the working folder
        - needs the collected data files to be uploaded in the working folder
        - it does not match the timestamp in filename

    Script logs
        All logs are sent to session log file with the name  session_mmddyyyy_hhmmss.log
    
    Parameters
    $extendedLogging - default value $False. When true, the script will create per job text file
                    containing job configuration details. 
    $configReportFileName - ms word file name. The word document contains special text (tags) 
                    used by the script to add text. Any word document with the tags in it 
                    can be used by the script.

    Make sure .doc is not in protected view.
    
    Tag list
        v1.1.0
            <insert VBR description>,<insert vmw proxy servers table>, <insert hv proxy servers table>,
            <insert repo table>, <insert sobr table>, <insert sobr extents table>, <insert wan acc table>,
            <insert backup window interval>, <insert backup window table>, <insert backup jobs table>,
            <insert replication jobs table>, <insert backup copy jobs table>


    .EXAMPLE
    .\VeeamConfigurationDump.ps1

    .NOTES
    Version: 1.1.3
    Author: Razvan Ionescu
    Last Updated: August 2019

    Requires:
    Veeam Backup & Replication v9.5 Update 3

#>

### PARAMETERS ###
# Extended logging mode #
$extendedLogging = $False
# Word template file name #
$configReportFileName = "VEEAM_Configuration.docx"

### Load PS modules
Try {
    Add-PSSnapin -Name VeeamPSSnapin -EA Stop
} catch {
    Write-Host -foregroundcolor cyan  "VeeamPSSnapin not found. Script can be used only in offline data processing mode"
    Write-Host -foregroundcolor cyan  "For data collection: please install VBR Console on the machine running the script."
    $offlineModeOnly = $True
}

### START FUNCTION DEFINITION ###
Function Show-Menu {
    [cmdletbinding()]
    Param(
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Enter your menu text")]
        [ValidateNotNullOrEmpty()]
        [string]$Menu,
        [Parameter(Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$Title = "My Menu",
        [Alias("cls")]
        [switch]$ClearScreen
    )
     
    #clear the screen if requested
    if ($ClearScreen) { 
        Clear-Host 
    }
     
    #build the menu prompt
    $menuPrompt = $title
    $menuprompt+="`n"
    $menuprompt+="-"*$title.Length
    $menuprompt+="`n"
    $menuPrompt+=$menu    
    Read-Host -Prompt $menuPrompt    
}


function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}

function Check-LogFolder ($logFileDir) {
    if ($logFileDir -notmatch '.+?\\$') {
        $logFileDir += '\'
    }
    if(!(Test-Path -Path $logFileDir )) {
        Write-Host -foregroundcolor yellow "$($logFileDir) not found. Creating folder..."
        try {
            New-Item -ItemType directory -Path $logFileDir -ea Stop
            Write-Host -foregroundcolor cyan " working directory: $($logFileDir) created. Script will exit. "
        } catch {
            Write-Host -foregroundcolor magenta " could not create working directory: $($logFileDir). "
            Write-Host -foregroundcolor red " $($_.Exception.ItemName) : $($_.Exception.Message) "
        }
        exit
    } else {
        Write-Host "... log folder $($logFileDir) exists"
    }
    return $logFileDir
}

function Connect-VBR($vbrServer, $sessionLog) {
    Disconnect-VBRServer -ErrorAction SilentlyContinue
    if (-not (Test-Connection -ComputerName $vbrServer -Count 1 -ea SilentlyContinue)){
        Write-Host -foregroundcolor yellow "Cannot ping VBR server $($srvName)"
        Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) Cannot ping VBR server $($srvName)"
    }
    try {
        if ($vbrServer -eq "localhost") {
            Write-Host "Connecting to $($vbrServer) with current session credentials. To enter other credentials, use FQDN or IP of backup server."
            Connect-VBRServer -Server $vbrServer
        } else {
            $vbrPsCredentials = Get-Credential -Message "Please enter username and password for connecting to VBR server"
            Connect-VBRServer -Server $vbrServer -Credential $vbrPsCredentials
        }
    }
    catch {
        Write-Host "Connection error $($_.Exception.ItemName) : $($_.Exception.Message)"
        Add-Content -Path  $sessionLog -Value "Connection error $($_.Exception.ItemName) : $($_.Exception.Message)"
        exit
    }
}

function Check-VBRVersion() {
    $version = [string](([Veeam.Backup.Common.SProductVersions]::Current).Major) + "." + [string](([Veeam.Backup.Common.SProductVersions]::Current).Minor) + "." + [string](([Veeam.Backup.Common.SProductVersions]::Current).Build) + "." + [string](([Veeam.Backup.Common.SProductVersions]::Current).Revision)
    return $version
}

function Check-VBRGeneralConfig($logFile, $configReport, $sessionLog) {
    Write-Host "... checking configuration backup"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) checking configuration backup"
    $vbrConfigJob = Get-VBRConfigurationBackupJob
    Add-Content -Path  $logFile -Value "`r`nVBR Configuration backup set to $($vbrConfigJob.Enabled)"
    if ($vbrConfigJob.Enabled -match "True") {
        Add-Content -Path  $logFile -Value " VBR Configuration backup encryption set to $($vbrConfigJob.Enabled)"
    }
    $storageLatency = [Veeam.Backup.Core.SBackupOptions]::DatastoreParallelProcessingOptions
    Add-Content -Path  $logFile -Value "`r`nStorage latency control set to $($storageLatency.LimitParallelTasksByDatastoreLatency)"

    Write-Host "... checking datastore latency"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) checking datastore latency"
    if ($storageLatency.LimitParallelTasksByDatastoreLatency -match "True") {
        Add-Content -Path  $logFile -Value " Datastore latency $($storageLatency.MaxDatastoreLatencyMs) ms"
        Add-Content -Path  $logFile -Value " Throttle latency $($storageLatency.MinDatastoreLatency4ThrottleMs) ms"
    }
    
    Write-Host "... checking traffic rules"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) checking traffic rules"
    $trafficRules = [Veeam.Backup.Core.SBackupOptions]::GetTrafficThrottlingRules()
    if ($trafficRules.GetRules()) {
        Add-Content -Path  $logFile -Value "`r`nNetwork rules have been defined..."
        foreach ($rule in $trafficRules.GetRules()) {
            if ($rule.ThrottlingEnabled -match "True") {
                Add-Content -Path  $logFile -Value " Network throttling is enabled between $($rule.FirstDiapason) and $($rule.FirstDiapason) at $($rule.SpeedLimit) $($rule.SpeedUnit)"
            } 
            if ($rule.EncryptionEnabled -match "True") {
                Add-Content -Path  $logFile -Value " Encryption is enabled between $($rule.FirstDiapason) and $($rule.FirstDiapason)"
            }
        }
    }

    Add-Content -Path  $logFile -Value "`r`nMultiple download streams status: $($trafficRules.UseMultipleDownloadStreams) number of streams is $($trafficRules.DownloadStreamCount)"
    $backupPreferredNetworks = [Veeam.Backup.Core.SBackupOptions]::GetBackupTrafficNetworks()
    if ($backupPreferredNetworks.UseNetworks -match "True") {
        Add-Content -Path  $logFile -Value "`r`nPreferred backup networks are configured..."
        foreach ($net in $backupPreferredNetworks.GetNetworks()) {
            Add-Content -Path  $logFile -Value " Network: $(([System.Net.IPAddress]"$($net.NetworkAddress)").IPAddressToString)/$( $net.CIDR)"
        }	
    } 

    if ([Veeam.Backup.Core.SBackupOptions]::GetEnterpriseServerInfo().IsConnected) {
        Add-Content -Path  $logFile -Value "`r`nEnterprise Manager: $([Veeam.Backup.Core.SBackupOptions]::GetEnterpriseServerInfo().ServerName)"
        Add-Content -Path  $logFile -Value " Skip license push: $([Veeam.Backup.Core.SBackupOptions]::GetEnterpriseServerInfo().SkipLicensePush)"
    }

    Add-Content -Path  $logFile -Value "`r`nStorage settings:"
    Add-Content -Path  $logFile -Value " Backup storage free space enabled: $([Veeam.Backup.Core.SBackupOptions]::GetThresholdInfo().Enable) - threshold $([Veeam.Backup.Core.SBackupOptions]::GetThresholdInfo().Percent) %"
    Add-Content -Path  $logFile -Value " Production storage free space enabled: $([Veeam.Backup.Core.SBackupOptions]::GetThresholdInfo().SourceEnable) - threshold $([Veeam.Backup.Core.SBackupOptions]::GetThresholdInfo().SourceFreePercent) %"
    Add-Content -Path  $logFile -Value " Production storage skip VM processing enabled: $([Veeam.Backup.Core.SBackupOptions]::GetThresholdInfo().SkipVmsOnSourceLowFreeSpace) - threshold $([Veeam.Backup.Core.SBackupOptions]::GetThresholdInfo().SkipVmsSourceFreeSpacePercent) %"
   
    Add-Content -Path  $logFile -Value "`r`nHistory settings:"
    Add-Content -Path  $logFile -Value " Keep history for  $([Veeam.Backup.Core.SBackupOptions]::GetSessionKeep().Keep) days - keep all sessions: $([Veeam.Backup.Core.SBackupOptions]::GetSessionKeep().KeepAllSession)"

    if ([Veeam.Backup.Core.SBackupOptions]::GetMailOptions().Enabled) {
        Add-Content -Path  $logFile -Value "`r`nEmail notifications settings:"
        Add-Content -Path  $logFile -Value " Server: $([Veeam.Backup.Core.SBackupOptions]::GetMailOptions().Server) Port: $([Veeam.Backup.Core.SBackupOptions]::GetMailOptions().Port) To Address: $([Veeam.Backup.Core.SBackupOptions]::GetMailOptions().To)"
        Add-Content -Path  $logFile -Value " Send notifications - On succes: $([Veeam.Backup.Core.SBackupOptions]::GetMailOptions().OnSuccess) - On warning: $([Veeam.Backup.Core.SBackupOptions]::GetMailOptions().OnWarning) - On failure: $([Veeam.Backup.Core.SBackupOptions]::GetMailOptions().OnFailure) - Only last retry: $([Veeam.Backup.Core.SBackupOptions]::GetMailOptions().OnLastRetryOnly)"
    } else {
        Add-Content -Path  $logFile -Value "`r`nEmail notifications not enabled on this server"
    }
    
    Add-Content -Path  $logFile -Value "`r`nLinux hosts trust setting: $([Veeam.Backup.Core.SBackupOptions]::LinuxHostsTrustMode)" 

    Sleep -Seconds 2
    
}
  
function Check-BackupWindow($backupWindowStart, $backupWindowEnd, $allJobs, $logFile, $configReport, $sessionLog) {
    $backupWindowArray = @()
    $backupWindowArray = @('Job Name,Next Run,Is Outside Window')
    Write-Host -foreground white "... checking backup window"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) checking backup window..."

    Add-Content -Path  $logFile -Value "Backup window is $($backupWindowStart) to $($backupWindowEnd)"
    foreach ($job in $allJobs) {
        if ($job.ScheduleOptions.NextRun)	{
            $nextRunTime = [datetime]$job.ScheduleOptions.NextRun
            $nextRunTime = $nextRunTime.ToShortTimeString()
            if ((New-TimeSpan -Start $backupWindowStart -End $nextRunTime).TotalMinutes -ge 0 -and (New-TimeSpan -Start $nextRunTime -End $backupWindowEnd).TotalMinutes -ge 0)	{
                $item = $job.Name + "," + $nextRunTime + "," + "False"
            } elseif (((New-TimeSpan -Start $backupWindowStart -End $nextRunTime).TotalMinutes -ge 0 -and (New-TimeSpan -Start $nextRunTime -End $backupWindowEnd).TotalMinutes -lt 0) -and ($backupWindowEnd -like "*AM*")) {
                $item = $job.Name + "," + $nextRunTime + "," + "False"
            } elseif (((New-TimeSpan -Start $backupWindowStart -End $nextRunTime).TotalMinutes -lt 0 -and (New-TimeSpan -Start $nextRunTime -End $backupWindowEnd).TotalMinutes -ge 0) -and ($backupWindowStart -like "*PM*")) {
                $item = $job.Name + "," + $nextRunTime + "," + "False"
            } else {
                $item = $job.Name + "," + $nextRunTime + "," + "True"
            }
        }
        $backupWindowArray += $item
    }
    $backupWindowArray | foreach { Add-Content -Path  $logFile -Value $_ }

}

function Check-SOBR($sobrList, $logFileSOBR, $logFileExtents, $configReport, $sessionLog) {
    Write-Host -foreground white "... checking Scale Out Backup Repositories"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) checking SoBR..."
    $sobrArray = @('Sobr Name,Policy Type,Use PerVM Backup Files')
    if ($extendedLogging) { 
        $sobrExtentArray = @('Sobr Name,Name,Max Task Count,Num CPU,Memory GB,Total Size GB,Free Space GB,Data Rate Limit MBps,Optimize Block Align,Uncompress,One Backup File Per Vm,Is Auto Detect Affinity Proxies,Is Rotated Drive Repository,Is San Snapshot Only,Has Backup Chain Length Limitation,Is Dedup Storage,Split Storages Per Vm')
    } else {
        $sobrExtentArray = @('Sobr Name,Name,Max Task Count,Num CPU,Memory GB,Total Size GB,Free Space GB,Data Rate Limit MBps')
    }

    if (!$sobrList) {
        Write-Host -foreground white "WARN: no SoBR found on" $config.Configuration.Server
        Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) WARN: no SoBR found on $($config.Configuration.Server)"
    } else {
        foreach ($sobr in $sobrList) {
            foreach ($extent in $sobr.Extent)	{
                $numCpu = 0
                $memoryGB = 0
                  # get server name where repo role is installed
                $repoServer = Get-VBRServer | Where {$_.Id -match $extent.Repository.Info.HostId}
                if ($repoServer) {
                    # get cpu and memory
                    $srv = [Veeam.Backup.Core.CPhysicalHost]::GetByHost($extent.Repository.Info.HostId)
                    $numCPU = $srv.HardwareInfo.CoresCount
                    $memoryGB = [math]::Round($srv.HardwareInfo.PhysicalRAMTotal/1GB,2)
                } else {
                    $numCpu=-1
                    $memoryGB=-1
                }
                # create array item
                #$sobrExtentArray = @('"SobrName","Name","MaxTaskCount","numCPU","memoryGB","TotalSizeGB","FreeSpaceGB","DataRateLimitMBps","OptimizeBlockAlign","Uncompress","OneBackupFilePerVm","IsAutoDetectAffinityProxies","IsRotatedDriveRepository","IsSanSnapshotOnly","HasBackupChainLengthLimitation","IsDedupStorage","SplitStoragesPerVm"')
                if ($extendedLogging) { 
                    $item = $sobr.Name + "," + $extent.Repository.Name + "," + $extent.Repository.Options.MaxTaskCount + "," + $numCpu + "," + $memoryGB + "," + [math]::Round(($extent.Repository.Info.CachedTotalSpace)/1GB,2) + "," + [math]::Round(($extent.Repository.Info.CachedFreeSpace)/1GB,2) + "," + $extent.Repository.Options.CombinedDataRateLimit + "," + $extent.Repository.Options.OptimizeBlockAlign + "," + $extent.Repository.Options.Uncompress + "," + $extent.Repository.Options.OneBackupFilePerVm + "," + $extent.Repository.Options.IsAutoDetectAffinityProxies + "," + $extent.Repository.IsRotatedDriveRepository + "," + $extent.Repository.IsSanSnapshotOnly + "," + $extent.Repository.HasBackupChainLengthLimitation + "," + $extent.Repository.IsDedupStorage + "," + $extent.Repository.SplitStoragesPerVm
                } else {
                    $item = $sobr.Name + "," + $extent.Repository.Name + "," + $extent.Repository.Options.MaxTaskCount + "," + $numCpu + "," + $memoryGB + "," + [math]::Round(($extent.Repository.Info.CachedTotalSpace)/1GB,2) + "," + [math]::Round(($extent.Repository.Info.CachedFreeSpace)/1GB,2) + "," + $extent.Repository.Options.CombinedDataRateLimit
                }
                $sobrExtentArray += $item
            }
            $sobrExtentArray | foreach { Add-Content -Path  $logFileExtents -Value $_ }

            $sobrExtentArray = @()
  
            $item = $sobr.Name + "," + $sobr.PolicyType + "," + $sobr.UsePerVMBackupFiles
            $sobrArray += $item
        }
        $sobrArray | foreach { Add-Content -Path  $logFileSOBR -Value $_ }
    }
  }

function Check-Repo($repoList, $logFile, $configReport) {
    if ($extendedLogging) { 
        $repoArray = @('Repo Name,Repo Server Name,Max Task Count,Num CPU,Memory GB,Total Size GB,Free Space GB,Data Rate Limit MBps,Optimize Block Align,Uncompress,One Backup File Per Vm,Is Auto Detect Affinity Proxies,Is Rotated Drive Repository,Is San Snapshot Only,Has Backup Chain Length Limitation,Is Dedup Storage,Split Storages Per Vm')
    } else {
        $repoArray = @('Repo Name,Repo Server Name,Max Task Count,Num CPU,Memory GB,Total Size GB,Free Space GB,Data Rate Limit MBps')
    }
    Write-Host -foreground white "... checking backup repositories"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) checking backup repositories"
    if (!$repoList) {
        Write-Host -foreground white "WARN: no repository found on $($config.Configuration.Server)"
        Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) WWARN: no repository found on $($config.Configuration.Server)"
    } else {
        foreach ($repo in $repoList) {
            $numCpu = 0
            $memoryGB = 0
            $repoServerName = "N/A"
            # get server name where repo role is installed
            $repoServer = Get-VBRServer | Where {$_.Id -match $repo.Info.HostId}
            if ($repoServer) {
                $repoServerName = $repoServer.Name
                # get cpu and memory
                $srv = [Veeam.Backup.Core.CPhysicalHost]::GetByHost($repo.Info.HostId) 
                $numCPU = $srv.HardwareInfo.CoresCount 
                $memoryGB = [math]::Round($srv.HardwareInfo.PhysicalRAMTotal/1GB,2)
            } else {
                $numCpu=-1
                $memoryGB=-1
                $repoServerName="N/A"
            }
            # create array item
            #$repoArray = @('Repo Name,Repo Server Name,Max Task Count,Num CPU,Memory GB,Total Size GB,Free Space GB,Data Rate Limit MBps')
            if ($extendedLogging) { 
                $item = $repo.Name + "," + $repoServerName + "," + $repo.Options.MaxTaskCount + "," + $numCpu + "," + $memoryGB + "," + [math]::Round(($repo.Info.CachedTotalSpace)/1GB,2) + "," + [math]::Round(($repo.Info.CachedFreeSpace)/1GB,2) + "," + $repo.Options.CombinedDataRateLimit + "," + $repo.Options.OptimizeBlockAlign + "," + $repo.Options.Uncompress + "," + $repo.Options.OneBackupFilePerVm + "," + $repo.Options.IsAutoDetectAffinityProxies + "," + $repo.IsRotatedDriveRepository + "," + $repo.IsSanSnapshotOnly + "," + $repo.HasBackupChainLengthLimitation + "," + $repo.IsDedupStorage + "," + $repo.SplitStoragesPerVm
            } else {
                $item = $repo.Name + "," + $repoServerName + "," + $repo.Options.MaxTaskCount + "," + $numCpu + "," + $memoryGB + "," + [math]::Round(($repo.Info.CachedTotalSpace)/1GB,2) + "," + [math]::Round(($repo.Info.CachedFreeSpace)/1GB,2) + "," + $repo.Options.CombinedDataRateLimit
            }
            $repoArray += $item
        }
        $repoArray | foreach { Add-Content -Path  $logFile -Value $_ }
    }
}

function Check-ProxyVi($viProxyList, $logFile, $configReport, $sessionLog) {
    Write-Host -foreground white "... checking VMware proxies"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) checking VMware proxies"
    # extended logging
    if ($extendedLogging) {
        $viProxyArray = @('Name,Max Tasks Count,Num CPU,Memory GB,Is Disabled,Transport Mode,Failover To Network,Use Ssl,Is Auto Detect Affinity Repositories,Is Auto Vddk Mode,Is Auto Detect Disks')
    } else {
        $viProxyArray = @('Name,Max Tasks Count,Num CPU,Memory GB,Is Disabled,Transport Mode,Failover To Network,Use Ssl')
    }
    if (!$viProxyList)  {
        Write-Host -foreground white "WARN: no VMware proxy found"
        Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) WARN: no VMware proxy found"
    } else {
        foreach ($viProxy in $viProxyList) {
            $numCpu = 0
            $memoryGB = 0
            # get cpu and memory
            $srv = [Veeam.Backup.Core.CPhysicalHost]::GetByHost($viProxy.Info.HostId) 
            $numCPU = $srv.HardwareInfo.CoresCount 
            $memoryGB = [math]::Round($srv.HardwareInfo.PhysicalRAMTotal/1GB,2)
            # create array item
            # $viProxyArray = @('Name,Max Tasks Count,Num CPU,Memory GB,Is Disabled,Transport Mode,Failover To Network,Use Ssl')
            if ($extendedLogging) {
                $item = $viProxy.Name + "," + $viProxy.Options.MaxTasksCount + "," + $numCpu + "," + $memoryGB + "," + $viProxy.IsDisabled + "," + $viProxy.Options.TransportMode + "," + $viProxy.Options.FailoverToNetwork + "," + $viProxy.Options.UseSsl + "," + $viProxy.Options.IsAutoDetectAffinityRepositories  + "," + $viProxy.Options.IsAutoVddkMode  + "," + $viProxy.Options.IsAutoDetectDisks
            } else {
                $item = $viProxy.Name + "," + $viProxy.Options.MaxTasksCount + "," + $numCpu + "," + $memoryGB + "," + $viProxy.IsDisabled + "," + $viProxy.Options.TransportMode + "," + $viProxy.Options.FailoverToNetwork + "," + $viProxy.Options.UseSsl
            }
            $viProxyArray += $item
        }
        $viProxyArray | foreach { Add-Content -Path $logFile -Value $_ }
    }
}
  
function Check-ProxyHv($config, $hvProxyList, $logFile, $configReport) {
    Write-Host -foreground white "... checking Hyper-V proxies"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) checking Hyper-V proxies"
    $hvProxyArray = @('Name,Max Tasks Count,Num CPU,Memory GB,Is Disabled,Type,Is Auto Detect Volumes')
    if (!$hvProxyList) {
        Write-Host -foreground white "WARN: no Hyper-V proxy found"
        Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) WARN: No Hyper-V proxy found"
    } else {
        foreach ($hvProxy in $hvProxyList) {
            $numCpu = 0
            $memoryGB = 0
            # get cpu and memory
            $srv = [Veeam.Backup.Core.CPhysicalHost]::GetByHost($hvProxy.HostId) 
            $numCPU = $srv.HardwareInfo.CoresCount 
            $memoryGB = [math]::Round($srv.HardwareInfo.PhysicalRAMTotal/1GB,2)
            # create array item
            # $hvProxyArray = @('Name,Max Tasks Count,Num CPU,Memory GB,Is Disabled,Type,Is Auto Detect Volumes')
            $item = $hvProxy.Name + "," + $hvProxy.MaxTasksCount + "," + $numCpu + "," + $memoryGB + "," + $hvProxy.IsDisabled + "," + $hvProxy.Type + "," + $hvProxy.Options.IsAutoDetectVolumes
            $hvProxyArray += $item

        }
        $hvProxyArray | foreach { Add-Content -Path  $logFile -Value $_ }
    }
}
  
function Check-WANAcc($wanAccList, $logFile, $configReport, $sessionLog) {
    Write-Host -foreground white "... checking WAN accelerators"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) checking WAN accelerators"
    $wanAccArray = @('Name,Server Name,Num CPU,Memory GB,Traffic Port,Mgmt Port')
    if (!$wanAccList) {
        Write-Host -foreground white "WARN: no WAN accelerator found"
        Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) WARN: no WAN accelerator found"
    } else {
        foreach ($wanAcc in $wanAccList) {
            $numCpu = 0
            $memoryGB = 0
            # get server name where proxy role is installed
            $wanAccServer = Get-VBRServer | Where {$_.Id -match $wanAcc.HostId}
            # get cpu and memory
            $srv = [Veeam.Backup.Core.CPhysicalHost]::GetByHost($wanAcc.HostId) 
            $numCPU = $srv.HardwareInfo.CoresCount 
            $memoryGB = [math]::Round($srv.HardwareInfo.PhysicalRAMTotal/1GB,2)
            # create array item
            # $wanAccArray = @('Name,Server Name,Num CPU,Memory GB,Traffic Port,Mgmt Port')
            $item = $wanAccServer.Name + "," + $wanAccServer.Name + "," + $numCpu + "," + $memoryGB  + "," + $wanAcc.GetWaTrafficPort()  + "," + $wanAcc.GetWaMgmtPort()
            $wanAccArray += $item
        }
        $wanAccArray | foreach { Add-Content -Path  $logFile -Value $_ }
    }
}

### 
#   BfSS enabled, limit VMs, failover to standard backup, failover to primary storage snap

  function Check-JobConfiguration($job, $allSessions, $jobCsvFile, $logFile, $configReport, $sessionLog) {
        $jobSize = 0
        $jobSize = [math]::round($job.Info.includedSize/1GB - $job.Info.excludedSize/1GB,2)

        if ($job.ScheduleOptions.NextRun) {
            $nextRun = $job.ScheduleOptions.NextRun
        } else {
            $nextRun = "N/A"
        }

        if ($job.JobType -eq "BackupSync") {
            $lastRunStatus = Check-LastRun -jobName $job.Name -jobSessions $allSessions -sessionLog $sessionLog
        } else {
            $lastRunStatus = $job.GetLastResult()
        }

        if ($job.TypeToString -eq "Hyper-V Backup") {
            $excludeSwap = $job.HvSourceOptions.ExcludeSwapFile
            $excludeDeletedBlocks = $job.HvSourceOptions.DirtyBlocksNullingEnabled
            $useCbt = $job.HvSourceOptions.UseChangeTracking
            $toolsQuiesce = $job.HvSourceOptions.EnableHvQuiescence
            $crashConsistent = $job.HvSourceOptions.CanDoCrashConsistent
            $mutipleVmPerSnapshot = $job.HvSourceOptions.GroupSnapshotProcessing
        } elseif ($job.TypeToString -eq "VMware Backup") {
            $excludeSwap = $job.ViSourceOptions.ExcludeSwapFile
            $excludeDeletedBlocks = $job.ViSourceOptions.DirtyBlocksNullingEnabled
            $useCbt = $job.ViSourceOptions.UseChangeTracking
            $toolsQuiesce =$job.ViSourceOptions.VMToolsQuiesce
            $crashConsistent = "N/A"
            $mutipleVmPerSnapshot = "N/A"
        } else {
            $excludeSwap = "N/A"
            $excludeDeletedBlocks = "N/A"
            $useCbt = $job.ViSourceOptions.UseChangeTracking
            $toolsQuiesce = "N/A"
            $crashConsistent = "N/A"
            $mutipleVmPerSnapshot = "N/A"
        }

        $sourceProxyAutoSelection = $job.Options.JobOptions.SourceProxyAutoDetect
        if (-Not $sourceProxyAutoSelection) {
            $sourceProxyNo = $job.GetProxy().Count
            foreach ($proxy in $job.GetProxy()) { $sourceProxyList += " " + $proxy.Name }
        } else {
            $sourceProxyNo = "Auto"
            $sourceProxyList = "Auto"
        }
        $targetProxyAutoSelection = "N/A"
        $targetProxyNo = "N/A"
        $targetProxyList = "N/A"


        if ($job.JobType -eq "Replica") {
            $targetProxyAutoSelection = $job.Options.JobOptions.TargetProxyAutoDetect
            if (-Not $targetProxyAutoSelection) {
                $targetProxyNo = $job.GetTargetProxies().Count
                foreach ($proxy in $job.GetTargetProxies()) { $targetProxyList += " " + $proxy.Name }   
            } else {
                $targetProxyNo = "Auto"
                $targetProxyList = "Auto"
            }
        }

        if ($extendedLogging) {
            Add-Content -Path  $logFile -Value "$($job.Name) / $($job.TypeToString)"
            $jobNameText = "`r`n$($job.Name)"
    
            Add-Content -Path  $logFile -Value "`r`n### JOB SUMMARY"
            Add-Content -Path  $logFile -Value "Target repo: $($job.GetTargetRepository().Name)"
            Add-Content -Path  $logFile -Value "Approximate job size: $($jobSize) GB"

            Add-Content -Path  $logFile -Value "Next run: $($nextRun)"
    
            Add-Content -Path  $logFile -Value "Last run status: $($lastRunStatus)"
    
            Add-Content -Path  $logFile -Value "`r`n### JOB DETAILS"
            Add-Content -Path  $logFile -Value "`r`nAutomatic source proxy selection: $($sourceProxyAutoSelection)"
            Add-Content -Path  $logFile -Value "`r`n# Selected source proxies: $($sourceProxyNo)"
            Add-Content -Path  $logFile -Value " `r`nSource proxy list: $($sourceProxyList)"
    
            if ($job.JobType -eq "Replica") {
                    Add-Content -Path  $logFile -Value "`r`nAutomatic target proxy selection: $($targetProxyAutoSelection)"
                    Add-Content -Path  $logFile -Value "`r`n# Selected target proxies: $($targetProxyNo)"
                    Add-Content -Path  $logFile -Value " `r`nTarget proxy list: $($targetProxyList)"
            }       
    
            Add-Content -Path  $logFile -Value "`r`nRestore points: $($job.Options.BackupStorageOptions.RetainCycles)"
            Add-Content -Path  $logFile -Value "Backup type: $($job.Options.BackupTargetOptions.Algorithm)  Active full backup: $($job.Options.BackupStorageOptions.EnableFullBackup) Synthetic fulls: $($job.Options.BackupTargetOptions.TransformFullToSyntethic) "
            Add-Content -Path  $logFile -Value "Active full days: $($job.Options.BackupTargetOptions.FullBackupDays)  Synthetic full days: $($job.Options.BackupTargetOptions.TransformToSyntethicDays) - Incremental to synthetic: $($job.Options.BackupTargetOptions.TransformIncrementsToSyntethic)"
            Add-Content -Path  $logFile -Value "`r`nAdvanced settings storage:"
            Add-Content -Path  $logFile -Value " Enabled deduplication: $($job.Options.BackupStorageOptions.EnableDeduplication)"
            Add-Content -Path  $logFile -Value " Compression level: $($job.Options.BackupStorageOptions.CompressionLevel)" # backup jobs: 0-none  4-dedup_friendly 5-optimal 6-high 9-extreme 
            Add-Content -Path  $logFile -Value " Storage optimization - block size: $($job.Options.BackupStorageOptions.StgBlockSize)"
           
            Add-Content -Path  $logFile -Value " Exclude swap files: $($excludeSwap)"
            Add-Content -Path  $logFile -Value " Exclude deleted file blocks: $($excludeDeletedBlocks)"
            Add-Content -Path  $logFile -Value " `r`nChange block tracking: $($useCbt)"
            Add-Content -Path  $logFile -Value "`r`nTools quiescing: $($toolsQuiesce)"
            Add-Content -Path  $logFile -Value "Crash consistent : $($crashConsistent)"
            Add-Content -Path  $logFile -Value "Process multiple VMs per volume snapshot : $($mutipleVmPerSnapshot)"

            Add-Content -Path  $logFile -Value " `r`nEncryption enabled: $($job.Options.BackupStorageOptions.StorageEncryptionEnabled)"
    
        } 
        
        # standard output to CSV file
        # 'Job Name,Job Type,Target Repo,Job Size,Last Run Status,Next Run,
        #  Restore Points,Src Proxy Auto,Src Proxy #,Src Proxy List,
        #  Tgt Proxy Auto,Tgt Proxy #,Tgt Proxy List, Backup Type,
        #  Active full backups,Synthetic fulls,
        #  Dedup,Compression,Block Size,
        #  Swap files,Delete blocks,CBT,Tools Quiesce,Encryption'
        $item = $job.Name + ',' + $job.TypeToString + ',' + $job.GetTargetRepository().Name + ',' + $jobSize + ',' + $lastRunStatus + ',' + $nextRun `
                + ',' + $job.Options.BackupStorageOptions.RetainCycles + ',' + $sourceProxyAutoSelection + ',' + $sourceProxyNo + ',' + $sourceProxyList `
                + ',' + $targetProxyAutoSelection + ',' + $targetProxyNo + ',' + $targetProxyList + ',' + $job.Options.BackupTargetOptions.Algorithm `
                + ',' + $job.Options.BackupStorageOptions.EnableFullBackup + ',' + $job.Options.BackupTargetOptions.TransformFullToSyntethic `
                + ',' + $job.Options.BackupStorageOptions.EnableDeduplication + ',' + $job.Options.BackupStorageOptions.CompressionLevel + ',' + $job.Options.BackupStorageOptions.StgBlockSize `
                + ',' + $excludeSwap + ',' + $excludeDeletedBlocks + ',' +  $useCbt + ',' + $toolsQuiesce + ',' + $job.Options.BackupStorageOptions.StorageEncryptionEnabled

        $jobDetails += $item
        $jobDetails | foreach { Add-Content -Path  $jobCsvFile -Value $_ } 
}
  
function Create-JobOverview($allJobs, $allSessions, $logFile, $configReport, $sessionLog) {
    $jobsArray = @('Job Name,Job Type,Target Repo,Job Size GB,Restore Points,Last Run Status,Next Run')
    foreach ($job in $allJobs) {
        if ($job.ScheduleOptions.NextRun) {
            $nextRun = $job.ScheduleOptions.NextRun
        } else {
            $nextRun = "N/A"
        }
        $jobSize = 0
        $jobSize = [math]::round($job.Info.includedSize/1GB - $job.Info.excludedSize/1GB,2)
        # JobType - Backup, BackupSync, Replica
        if ($job.JobType -eq "BackupSync") {
            $lastRunStatus = Check-LastRun -jobName $job.Name -jobSessions $allSessions -sessionLog $sessionLog
        } else {
            $lastRunStatus = $job.GetLastResult()
        }
        $item = $job.Name + "," + $job.TypeToString + "," +  $job.GetTargetRepository().Name + "," +  $jobSize + "," +  $job.Options.BackupStorageOptions.RetainCycles `
                + "," + $lastRunStatus + "," + $nextRun
        $jobsArray += $item
    }
    $jobsArray | foreach { Add-Content -Path  $logFile -Value $_ }
}
function Check-LastRun($jobName, $jobSessions, $sessionLog) {
    $lastRun = ""
    $tmpSession = @()
    $tmpSession = $jobSessions |  ?{$_.JobName -eq $jobName} | Sort-Object -Descending -Property EndTime
    if ($tmpSession.Count -gt 0) {
        $lastRun = $tmpSession[1].Result
    } else {
        $lastRun = "N/A"
    }
    return $lastRun
}

function Get-RunTime() {
    $rt =  Get-Date -format MMddyyyy_hhmmss
    return $rT
}

function Get-TaskDuration {
    param ($duration)
    $days = ""
    if ($duration.Days -gt 0) {
      $days = "{0}:" -f $duration.Days
    }
    "{0}{1}:{2,2:D2}:{3,2:D2}" -f $days,$duration.Hours,$duration.Minutes,$duration.Seconds
  }

function Get-BackupSessions($jobType, $hourstoCheck, $logFile) {

    ### HTML ####
$title = "Session Details "
$header = @"
<html>
<head>
    <title>$title</title>
        <style>  
            body {font-family: Calibri; background-color:#ffffff;}
            table {font-family: Calibri;width: 97%;font-size: 14;border-collapse:collapse;}
            th {background-color: #e2e2e2;border: 1px solid #a7a9ac;border-bottom: none;}
            td {background-color: #ffffff;border: 1px solid #a7a9ac;padding: 2px 3px 2px 3px;}
        </style>
</head>
"@

$bodyStart = @"
<body>
    <center>
"@

$subtitleHeader = @"
<table>
            <tr>
                <td style="height: 35px;background-color: #c6e2ff;color: #000000;font-size: 16px;padding: 5px 0 0 15px;border-top: 5px solid white;border-bottom: none;">
"@


$subtitleEndTable = @"
</td>
            </tr>
        </table>
"@

$bodyEnd = @"
</body>
"@

 
    $allJobs = @()
    $allJobs = Get-VBRJob
    #$allJobsBk = @($allJobs | ?{$_.JobType -eq "Backup"})
    $allJobsBk = @($allJobs | ?{$_.JobType -eq $jobType})
    $allSessions = @()
    $allSessions = Get-VBRBackupSession

    # Backup Sessions Within Timeframe
    # $sessListBk = @($allSessions | ?{($_.EndTime -ge (Get-Date).AddHours(-$hourstoCheck) -or $_.CreationTime -ge (Get-Date).AddHours(-$hourstoCheck) -or $_.State -eq "Working") -and $_.JobType -eq "Backup"})
    $sessListBk = @($allSessions | ?{($_.EndTime -ge (Get-Date).AddHours(-$hourstoCheck) -or $_.CreationTime -ge (Get-Date).AddHours(-$hourstoCheck) -or $_.State -eq "Working") -and $_.JobType -eq $jobType})
    $tempSessListBk = $sessListBk
    $sessListBk = @()
    Foreach($job in $allJobsBk) {
        $sessListBk += $tempSessListBk | ?{$_.Jobname -eq $job.name} | Sort-Object EndTime -Descending | Select-Object -First 1
    }

    # Backup Session Details
    $totalXferBk = 0
    $totalReadBk = 0
    $sessListBk | %{$totalXferBk += $([Math]::Round([Decimal]$_.Progress.TransferedSize/1GB, 2))}
    $sessListBk | %{$totalReadBk += $([Math]::Round([Decimal]$_.Progress.ReadSize/1GB, 2))}

    $arrSessWFBk = $sessListBk | Sort Creationtime | Select @{Name="Job Name"; Expression = {$_.Name}},
    @{Name="Backup Type"; Expression = {$_.SessionInfo.SessionAlgorithm}},
    @{Name="Start Time"; Expression = {$_.CreationTime}},
    @{Name="Stop Time"; Expression = {$_.EndTime}},
    @{Name="Duration (HH:MM:SS)"; Expression = {Get-TaskDuration -duration $_.Progress.Duration}},                    
    @{Name="Bottleneck"; Expression = {$_.Progress.BottleneckInfo.Bottleneck.ToString()}},
    @{Name="Avg Speed (MB/s)"; Expression = {[Math]::Round($_.Progress.AvgSpeed/1MB,2)}},
    @{Name="Total (GB)"; Expression = {[Math]::Round($_.Progress.ProcessedSize/1GB,2)}},
    @{Name="Processed (GB)"; Expression = {[Math]::Round($_.Progress.ProcessedUsedSize/1GB,2)}},
    @{Name="Data Read (GB)"; Expression = {[Math]::Round($_.Progress.ReadSize/1GB,2)}},
    @{Name="Transferred (GB)"; Expression = {[Math]::Round($_.Progress.TransferedSize/1GB,2)}},
    @{Name="Dedupe"; Expression = {
    If ($_.Progress.ReadSize -eq 0) {0}
    Else {([string][Math]::Round($_.BackupStats.GetDedupeX(),1)) +"x"}}},
    @{Name="Compression"; Expression = {
    If ($_.Progress.ReadSize -eq 0) {0}
    Else {([string][Math]::Round($_.BackupStats.GetCompressX(),1)) +"x"}}},
    @{Name="Details"; Expression = {
    If ($_.GetDetails() -eq ""){$_ | Get-VBRTaskSession | %{If ($_.GetDetails()){$_.Name + ": " + ($_.GetDetails()).Replace("<br />","ZZbrZZ")}}}
    Else {($_.GetDetails()).Replace("<br />","ZZbrZZ")}}}, Result
    $bodySessWFBk = $arrSessWFBk | ConvertTo-HTML -Fragment
    $bodySessWFBk = $subtitleHeader + "Last Backup Sessions" + $subtitleEndTable + $bodySessWFBk 

    $htmlOut = $header + $bodyStart + $bodySessWFBk + $bodyEnd
    $htmlOut |  Out-File $logFile 
}

function Add-WordTable ($configReport, $docTag, $content, $logFile, $sessionLog) {
    try {
        Write-Host -ForegroundColor cyan " > processing tag $($docTag)"
        $objWord = New-Object -Com Word.Application -ea Stop 
        $objWord.Visible = $False
        $doc = $objWord.Documents.Open($configReport)
        $selection = $objWord.Selection
        if ($selection.Find.Execute($docTag)) {
            $header= @()

            $header = $content[0].Split(",")
            $rows = $content.Length
            $cols = $header.Length
            $table = $selection.Tables.add(
                $selection.range,$rows,$cols,
                [Microsoft.Office.Interop.Word.WdDefaultTableBehavior]::wdWord9TableBehavior,
                [Microsoft.Office.Interop.Word.WdAutoFitBehavior]::wdAutoFitContent
            )
            $table.Style ="Light Shading - Accent 3"
        
            $tmpArray = @()
            for ($i=0;$i -lt $content.Length; $i++) {
                $tmpArray = $content[$i].Split(",")
                for ($j=0;$j -lt $tmpArray.Length;$j++) {
                    $table.cell($i+1,$j+1).range.text = $tmpArray[$j]
                }
            }           
        } else {
            Write-Host "[WARN] Could not find $($docTag) in $($configReport). No updates."
            Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) [WARN] Could not find $($docTag) in $($configReport). No updates."
        }
    
        $doc.Close()
        $objWord.Quit()
        # Stop Winword Process
        $rc = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($objWord)
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) $($_.Exception.ItemName) : $($_.Exception.Message)"
    }
}

function Add-WordParagraph ($configReport, $docTag, $fontType, $fontStyle, $content, $logFile, $sessionLog) {
    try {
        Write-Host -ForegroundColor cyan " > processing tag $($docTag)"
        $objWord = New-Object -Com Word.Application -ea Stop 
        $objWord.Visible = $False
        $doc = $objWord.Documents.Open($configReport)
        $selection = $objWord.Selection
        if ($selection.Find.Execute($docTag)) {
            $selection.Style = $fontStyle
            foreach ($line in $content) {
                if ($fontType -eq "bold")  {
                    $selection.Font.Bold = $True
                    $selection.TypeText("$($line)`v")
                } elseif ($fontType -eq "italic") {
                    $selection.Font.Italic = $True
                    $selection.TypeText("$($line)`v")
                } else {
                    $selection.TypeText("$($line)`v")
                }    
            }
    
        } else {
            Write-Host "[WARN] Could not find $($docTag) in $($configReport). No updates."
            Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) [WARN] Could not find $($docTag) in $($configReport). No updates."         
        }
        $doc.Close()
        $objWord.Quit()
        # Stop Winword Process
        $rc = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($objWord)
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) $($_.Exception.ItemName) : $($_.Exception.Message)"
    }
}


# offline data processing 
function Update-Report($logFileDir, $configReport, $sessionLog) {

    # VBR general configuration
    Write-Host "general config - updating configuration report"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) general config - updating configuration report"

    $logFileName = "vbr_general_config*"
    $logFile = $logFileDir + $logFileName + ".log"
    try {
        $vbrConfigText = Get-Content (Get-ChildItem -Path $logFile)[0]
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [WARN] VBR general config file not uploaded $($_.Exception.ItemName) : $($_.Exception.Message)"
        $vbrConfigText = "Could not find file for vbr_general_config"
        Write-Host -ForegroundColor magenta " > could not find file for vbr_general_config"
    }

    $docTag = "<insert VBR description>"
    $fontStyle = "Body Text"
    Add-WordParagraph -configReport $configReport -docTag $docTag -fontStyle $fontStyle -Content $vbrConfigText -logFile $logFile -sessionLog $sessionLog   
  
    # backup window
    Write-Host "backup window - updating configuration report"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) backup window - updating configuration report"

    $logFileName = "backup_window*"
    $logFile = $logFileDir + $logFileName + ".csv"
    $backupWindowArray = @()
    try {
        $tmpContent = Get-Content (Get-ChildItem -Path $logFile)[0]
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [WARN] Backup window file not uploaded $($_.Exception.ItemName) : $($_.Exception.Message)"
        $tmpContent = $False
        Write-Host -ForegroundColor magenta " > could not find file for backup_window"
    }
    $fontStyle = "Body Text"
    $fontType = "Bold"
    
    $docTag = "<insert backup window interval>"
    if ($tmpContent) {
        $backupWindowText = $tmpContent[0]
    } else {
        $backupWindowText = "Could not find file for backup_window"
    }
    Add-WordParagraph -configReport $configReport -docTag $docTag -fontStyle $fontStyle -fontType $fontType -Content $backupWindowText -logFile $logFile

    $docTag = "<insert backup window table>"
    if ($tmpContent) {
        $backupWindowArray = $tmpContent[1..$tmpContent.Length]
    } else {
        $backupWindowArray = @("Could not find file for backup_window")
    }
    Add-WordTable -configReport $configReport -docTag $docTag -Content $backupWindowArray -logFile $logFile -sessionLog $sessionLog

    # SoBR
    Write-Host "SoBR - updating configuration report"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) SoBR - updating configuration report"

    $logFileNameSOBR = "sobr_configuration*"
    $logFileSOBR = $logFileDir + $logFileNameSOBR + ".csv"
    try {
        $sobrArray = Get-Content (Get-ChildItem -Path $logFileSOBR)[0]
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [WARN] SoBR file not uploaded $($_.Exception.ItemName) : $($_.Exception.Message)"
        $sobrArray = @("Could not find file for sobr_configuration")
        Write-Host -ForegroundColor magenta " > could not find file for sobr_configuration"
    }
    $docTag = "<insert sobr table>"
    Add-WordTable -configReport $configReport -docTag $docTag -Content $sobrArray -logFile $logFileSOBR

    $logFileNameExtents = "sobr_extent_configuration*"
    $logFileExtents = $logFileDir + $logFileNameExtents + ".csv"
    try {
        $sobrExtentArrayContent = Get-Content (Get-ChildItem -Path $logFileExtents)[0]
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [WARN] SoBR extents file not uploaded $($_.Exception.ItemName) : $($_.Exception.Message)"
        $sobrExtentArrayContent = @("Could not find file for sobr_extent_configuration")
        Write-Host -ForegroundColor magenta " > could not find file for sobr_extent_configuration"
    }
    $docTag = "<insert sobr extents table>"
    Add-WordTable -configReport $configReport -docTag $docTag -Content $sobrExtentArrayContent -logFile $logFileExtents -sessionLog $sessionLog

    # Repositories
    Write-Host "backup repo - updating configuration report"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) backup repo - updating configuration report"
    $logFileName = "repository_configuration*"
    $logFile = $logFileDir + $logFileName + ".csv"
    try {
        $repoArray = Get-Content (Get-ChildItem -Path $logFile)[0]
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [WARN] Repo configuration file not uploaded $($_.Exception.ItemName) : $($_.Exception.Message)"
        $repoArray = @("Could not find file for repository_configuration")
        Write-Host -ForegroundColor magenta " > could not find file for repository_configuration"
    }
    $docTag = "<insert repo table>"
    Add-WordTable -configReport $configReport -docTag $docTag -Content $repoArray -logFile $logFile -sessionLog $sessionLog

    # VMware Proxies
    Write-Host "VMware proxy - updating configuration report"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) VMware proxy - updating configuration report"
    $logFileName = "proxy_vmw_configuration*"
    $logFile = $logFileDir + $logFileName + ".csv"
    try {
        $viProxyArray = Get-Content (Get-ChildItem -Path $logFile)[0]
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [WARN] VMware proxy configuration file not uploaded $($_.Exception.ItemName) : $($_.Exception.Message)"
        $viProxyArray = @("Could not find file for proxy_vmw_configuration")
        Write-Host -ForegroundColor magenta " > could not find file for proxy_vmw_configuration"
    }
    $docTag = "<insert vmw proxy servers table>"
    Add-WordTable -configReport $configReport -docTag $docTag -Content $viProxyArray -logFile $logFile -sessionLog $sessionLog

    # Hyper-V Proxies
    Write-Host "Hyper-V proxies - updating configuration report"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) Hyper-V proxies - updating configuration report"
    $logFileName = "proxy_hv_configuration*"
    $logFile = $logFileDir + $logFileName + ".csv"
    try {
        $hvProxyArray = Get-Content (Get-ChildItem -Path $logFile)[0]
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [WARN] Hyper-V proxy configuration file not uploaded $($_.Exception.ItemName) : $($_.Exception.Message)"
        $hvProxyArray = @("Could not find file for proxy_hv_configuration")
        Write-Host -ForegroundColor magenta " > could not find file for proxy_hv_configuration"
    }
    $docTag = "<insert hv proxy servers table>"
    Add-WordTable -configReport $configReport -docTag $docTag -Content $hvProxyArray -logFile $logFile -sessionLog $sessionLog

    # WAN Accelerators
    Write-Host "WAN accelerators - updating configuration report"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) WAN accelerators - updating configuration report"
    $logFileName = "wan_acc_configuration*"
    $logFile = $logFileDir + $logFileName + ".csv"
    try {
        $wanAccArray = Get-Content (Get-ChildItem -Path $logFile)[0]
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [WARN] WAN accelerator configuration file not uploaded $($_.Exception.ItemName) : $($_.Exception.Message)"
        $wanAccArray = @("Could not find file for wan_acc_configuration")
        Write-Host -ForegroundColor magenta " > could not find file for wan_acc_configuration"
    }
    $docTag = "<insert wan acc table>"
    Add-WordTable -configReport $configReport -docTag $docTag -Content $wanAccArray -logFile $logFile -sessionLog $sessionLog

    # Jobs overview
    Write-Host "jobs overview - updating configuration report"
    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) jobs overview - updating configuration report"
    $logFileName = "all_jobs_summary*"
    $logFile = $logFileDir + $logFileName + ".csv"
    try {
        $jobsArray = Get-Content (Get-ChildItem -Path $logFile)[0]
    } catch {
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [WARN] Jobs overview file not uploaded $($_.Exception.ItemName) : $($_.Exception.Message)"
        $jobsArray = @("Could not find file for all_jobs_summary")
        Write-Host -ForegroundColor magenta " > could not find file for all_jobs_summary"
    }
    
    $jobsArrayBackupCopy = @()
    $jobsArrayReplication = @()
    $jobsArrayBackup = @()
    $jobsArrayBackupCopy += $jobsArray[0]
    $jobsArrayReplication += $jobsArray[0]
    $jobsArrayBackup += $jobsArray[0]
    foreach ($j in $jobsArray) {
        if ($j  -match " Backup Copy," -or $j -match " backup copy,") {
            $jobsArrayBackupCopy += $j
        } elseif ($j -match " Replication,") {
            $jobsArrayReplication += $j
        } elseif ($j -match " Backup," -or $j -match " Policy,")  {
            $jobsArrayBackup += $j
        } else {
            Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) [WARN] jobs overview - uknown job type $($j)"        
        }
    }

    $docTag = "<insert backup copy jobs table>"
    Add-WordTable -configReport $configReport -docTag $docTag -Content $jobsArrayBackupCopy -logFile $logFile -sessionLog $sessionLog
    $docTag = "<insert replication jobs table>"
    Add-WordTable -configReport $configReport -docTag $docTag -Content $jobsArrayReplication -logFile $logFile -sessionLog $sessionLog
    $docTag = "<insert backup jobs table>"
    Add-WordTable -configReport $configReport -docTag $docTag -Content $jobsArrayBackup -logFile $logFile -sessionLog $sessionLog

    
}

### END FUNCTION DEFINITION ###


### MAIN

# Check log folder
$logFileDir = 'C:\temp\'
Write-Host -ForegroundColor Magenta "Please enter working directory. Default value is [$($logFileDir)]"
$logLocation = Read-Host "Enter folder name or use default [$($logFileDir)]"
if ($logLocation) {
    $logFileDir = $logLocation
} 

if ($logFileDir -notmatch '.+?\\$') {
    $logFileDir += '\'
}

$logFilePath = Check-LogFolder -logFileDir $logFileDir

$runTime = Get-RunTime
$sessionLog = $logFilePath + "\session_" + $runTime + ".log"

# choose operation mode
$modeMenu=@"
1 Data collection
2 Offline processing
Q Quit
    
Select a task by number or Q to quit
"@

Switch (Show-Menu -menu $modeMenu -title "Choose operation mode" -clear) {
"1" {   # Data collection
        if ($offlineModeOnly) {
            Write-Host -foregroundcolor Cyan "Nice try. Running in offline mode"
            $offlineProcessing = $True
        } else {
            $offlineProcessing = $False
        }
        Break
    } 
"2" {   # Offline processing        
        $offlineProcessing = $True
        Break
    }

"Q" {
        Write-Host "Log files saved in $($logFileDir)" -ForegroundColor Cyan
        Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) Log files saved in $($logFileDir)"
        Return
    }
Default {
        Write-Warning "Invalid Choice. Assuming offline processing"
        $offlineProcessing = $True
        Break
    }
}


if ($offlineProcessing) {
    # make sure files are loaded in working dir
    Write-Host -foregroundcolor Magenta "Offline processing mode selected"
    Write-Host -foregroundcolor Magenta "Please make sure data files and template have been loaded to $($logFileDir)"
    $continueProcessing = Read-Host "Load files and type 'yes' to continue. Type anything else to quit."
    # check word template is loaded in working dir
    if ($continueProcessing.ToLower() -eq "yes") {
        # Word File - configuration report
        $configReport = $logFilePath + $configReportFileName
        $createReport = $False 
        if (Test-Path $configReport) {
            Write-Host "Configuration report found: $($configReport)"
            $createReport = $True
        } else {
            Write-Host -ForegroundColor Red "Could not find $($configReport)"
            $createReport =  Read-Host "Load $($configReport) and type 'yes' to continue. Type anything else to quit."
            if ($createReport.ToLower() -eq "yes") {
                if (Test-Path $configReport) {
                    $createReport = $True
                } else {
                    Write-Host "Could not find $($configReport). Exitting." -ForegroundColor Cyan
                    Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [ERR] Could not find $($configReport). Exitting."  
                    exit                   
                }
            } else {
                Write-Host "Exit" -ForegroundColor Cyan
                Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [ERR] $($configReport) not found"  
                exit
            }
        }

    } else {
        Write-Host "Exit" -ForegroundColor Cyan
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [WARN] Offline processing stopped by user"
    }
    # Process offline data
    if ($createReport) {
        Update-Report -logFileDir $logFileDir -configReport $configReport -sessionLog $sessionLog
    } else {
        Write-Host "Exit" -ForegroundColor Cyan
        Add-Content -Path $sessionLog -Value "$(Get-TimeStamp) [ERR] Offline mode exited - $($createReport)"    
    }

} else {
    # Connect backup server
    Write-Host -foregroundcolor Magenta "Data collection mode selected"
    Write-Host -foregroundcolor Magenta "Connect to server or enter q to quit"
    $vbrServer = Read-Host "Input backup server name or IP. Press enter for default [localhost]"
    if ($vbrServer -eq "q") {
        Write-Host "Exit" -ForegroundColor Cyan
        exit
    } elseif ($vbrServer) {
        Connect-VBR -vbrServer $vbrServer -sessionLog $sessionLog
    } else {
        $vbrServer = "localhost"
        Connect-VBR -vbrServer $vbrServer -sessionLog $sessionLog
    }

$menu=@"
1 Check VBR general configuration
2 Check backup window 
3 Check repositories 
4 Check proxies
5 Check WAN Accelerators
6 Check jobs
7 Get backup sessions
8 Get replica sessions
Q Quit
 
Select a task by number or Q to quit
"@

    Do { 
        Switch (Show-Menu -menu $menu -title "Data collection" -clear) {
        "1" {   # VBR general configuration
                $runTime = Get-RunTime
                $logFileName = 'vbr_general_config'
                $logFile = $logFilePath + $logFileName + '_' + $runTime + '.log' 
                $curVersion = Check-VBRVersion
                Add-Content -Path  $logFile -Value "Installed VBR version $($curVersion)"
                Check-VBRGeneralConfig -logFile $logFile -sessionLog $sessionLog
                Sleep -seconds 1
            } 
        "2" {   # check backup window for jobs        
                $backupWindowStart = "10:00PM"
                $backupWindowEnd = "04:00AM"
                Write-Host -ForegroundColor Magenta "Please enter start and end times using the following format: $($backupWindowStart)"
                $backupWindowStartRead = Read-Host "Enter backup window start time or use default [$($backupWindowStart)]"
                $backupWindowEndRead = Read-Host "Enter backup window end time or use default [$($backupWindowEnd)]"          
                if ($backupWindowStartRead) {
                    $backupWindowStart = $backupWindowStartRead
                } 
                if ($backupWindowEndRead) {
                    $backupWindowEnd = $backupWindowEndRead
                }
                $runTime = Get-RunTime
                Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) backup window - get backup jobs"
                $allJobs = Get-VBRJob | Sort-Object -Property Name
                $logFileName = 'backup_window'
                $logFile = $logFilePath + $logFileName + '_' + $runTime + '.csv'
                Check-BackupWindow -backupWindowStart $backupWindowStart -backupWindowEnd $backupWindowEnd -allJobs $allJobs -logFile $logFile -sessionLog $sessionLog
                Sleep -seconds 1
            }
        "3" {   # check repositories 
                $runTime = Get-RunTime
                # check SOBR 
                Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) get SoBR list"
                $sobrList =  Get-VBRBackupRepository -ScaleOut | Sort-Object -Property Name
                $logFileNameSOBR = 'sobr_configuration'
                $logFileNameExtents = 'sobr_extent_configuration'
                $logFileSOBR = $logFilePath + $logFileNameSOBR + '_' + $runTime + '.csv'
                $logFileExtents = $logFilePath + $logFileNameExtents + '_' + $runTime + '.csv'
                Check-SOBR -sobrList $sobrList -logFileSOBR $logFileSOBR -logFileExtents $logFileExtents -sessionLog $sessionLog
                # Check repositories
                Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) get repo list"
                $repoList = Get-VBRBackupRepository | Sort-Object -Property Name
                $logFileName = 'repository_configuration'
                $logFile = $logFilePath + $logFileName + '_' + $runTime + '.csv'
                Check-Repo -repoList $repoList -logFile $logFile -sessionLog $sessionLog
                Sleep -seconds 1
            }
        "4" {   # check proxies
                $runTime = Get-RunTime
                # Check proxy - VMware
                Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) get VMW proxy list"
                $viProxyList = Get-VBRViProxy | Sort-Object -Property Name
                $logFileName = 'proxy_vmw_configuration'
                $logFile = $logFilePath + $logFileName + '_' + $runTime + '.csv'
                Check-ProxyVi -viProxyList $viProxyList -logFile $logFile -sessionLog $sessionLog
                # Check proxy - Hyper-V
                Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) get HV proxy list"
                $hvProxyList = Get-VBRHvProxy | Sort-Object -Property Name
                $logFileName = 'proxy_hv_configuration'
                $logFile = $logFilePath + $logFileName + '_' + $runTime + '.csv'
                Check-ProxyHv -hvProxyList $hvProxyList -logFile $logFile -sessionLog $sessionLog
                Sleep -seconds 1
            }
        "5" {   # Check WAN accelerator
                $runTime = Get-RunTime
                $wanAccList = Get-VBRWANAccelerator | Sort-Object -Property Name
                $logFileName = 'wan_acc_configuration'
                $logFile = $logFilePath + $logFileName + '_' + $runTime + '.csv'
                Check-WANAcc -wanAccList $wanAccList -logFile $logFile -sessionLog $sessionLog
                Sleep -seconds 1
            }
        "6" {   # Check jobs 
                $runTime = Get-RunTime
                Write-Host "... checking jobs"
                Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) checking jobs"
                Write-Host "... retrieving all jobs"
                Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) retrieving jobs "
                $allJobs = Get-VBRJob | Sort-Object -Property Name
                # check  if any backup copy jobs are configured
                $backupCopyJobs = @($allJobs | ? {$_.JobType -eq "BackupSync"})
                if ($backupCopyJobs.Count -gt 0) {
                    Write-Host "... retrieving all sessions"
                    Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) retrieving sessions "
                    $allSessions = Get-VBRBackupSession
                    $allSessions = @($allSessions | ?{$_.JobType -eq "BackupSync"})
                }
                # generate jobs summary
                $logFileName = 'all_jobs_summary' 
                $logFile = $logFilePath + $logFileName + '_' + $runTime + '.csv'
                Create-JobOverview -allJobs $allJobs -allSessions $allSessions -logFile $logFile -sessionLog $sessionLog
                $logFileName = 'all_jobs'
                $jobCsvFile = $logFilePath + $logFileName + '_' + $runTime + '.csv'
                $jobDetails = @('Job Name,Job Type,Target Repo,Job Size,Last Run Status,Next Run,Restore Points,Src Proxy Auto,Src Proxy #,Src Proxy List,Tgt Proxy Auto,Tgt Proxy #,Tgt Proxy List, Backup Type,Active full backups,Synthetic fulls,Dedup,Compression,Block Size,Swap files,Delete blocks,CBT,Tools Quiesce,Encryption')
                Add-Content -Path  $jobCsvFile -Value $jobDetails

                foreach ($job in $allJobs) {
                    $jobName = $job.Name -replace '\/','_'
                    $jobName = $jobName -replace '\\','_'
                    $logFileName = 'job_' + $jobName
                    $logFile = $logFilePath + $logFileName + '_' + $runTime + '.log'
                    Check-JobConfiguration -job $job -allSessions $allSessions -jobCsvFile $jobCsvFile -logFile $logFile
                }
                Sleep -seconds 1
            }
        "7" {   # Backup sessions 
                $hoursToCheck = 24
                $hoursToCheckInput = Read-Host "Enter interval for backup sessions or use default [$($hoursToCheck)]"
                if ($hoursToCheckInput) {
                    $hoursToCheck = $hoursToCheckInput
                }
                $logFileName = "backup_sessions_last_$($HoursToCheck).html" 
                $logFile = $logFilePath + $logFileName
                Write-Host "... getting sessions"
                Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) getting backup sessions for last $($HoursToCheck) hours"
                Get-BackupSessions -jobType "Backup" -hourstoCheck $hoursToCheck -logFile $logFile -sessionLog $sessionLog

                Sleep -seconds 1
        }
        "8" {   # Replica sessions 
                $hoursToCheck = 24
                $hoursToCheckInput = Read-Host "Enter interval for replica sessions or use default [$($hoursToCheck)]"
                if ($hoursToCheckInput) {
                    $hoursToCheck = $hoursToCheckInput
                }
                $logFileName = "replica_sessions_last_$($HoursToCheck).html" 
                $logFile = $logFilePath + $logFileName
                Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) getting replica sessions for last $($HoursToCheck) hours"
                Get-BackupSessions -jobType "Replica" -hourstoCheck $hoursToCheck -logFile $logFile -sessionLog $sessionLog

                Sleep -seconds 1
        }
        "Q" {
                Write-Host "Log files saved in $($logFileDir)" -ForegroundColor Cyan
                Add-Content -Path  $sessionLog -Value "$(Get-TimeStamp) Log files saved in $($logFileDir)"
                Return
            }
        Default {
                Write-Warning "Invalid Choice. Try again."
                Sleep -milliseconds 750
            }
        }
    } While ($True)


}

