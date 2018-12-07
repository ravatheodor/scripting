<#
    .SYNOPSIS
    VeeamConfigurationDump is a configuration collection script for Veeam Backup and Replication

    .DESCRIPTION

    VeeamConfigurationDump is collects configuration from VBR and dumps it to log files. 
    
    It is menu driven. 
    
    Script will check log folder exists and exit if it does not find it.

    Opne PowerShell with Run as Administrator.

    .EXAMPLE
    .\VeeamConfigurationDump.ps1

    .NOTES
    Version: 0.0.5
    Author: Razvan Ionescu
    Last Updated: December 2018

    Requires:
    Veeam Backup & Replication v9.5 Update 3

#>

### Load PS modules
Try {
    Add-PSSnapin -Name VeeamPSSnapin
} catch {
    Write-Output "VeeamPSSnapin not found. Please install VBR Console on the machine running the script"
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


function Check-LogFolder ($logFileDir) {
    if ($logFileDir -notmatch '.+?\\$') {
        $logFileDir += '\'
    }
    if(!(Test-Path -Path $logFileDir )) {
        Write-Host -foregroundcolor yellow " Please, first create folder" $logFileDir
        exit
    } else {
        Write-Host "... log folder" $logFileDir "exists"
    }
    return $logFileDir
}

function Connect-VBR($vbrServer) {
    Disconnect-VBRServer -ErrorAction SilentlyContinue
    if (-not (Test-Connection -ComputerName $vbrServer -Count 1 -ea SilentlyContinue)){
        Write-Output -foregroundcolor yellow "Cannot ping VBR server" $srvName
        # Add-Content -Path  $errorLog -Value "Cannot ping VBR server $srvName"
    }
    try {
        $vbrPsCredentials = Get-Credential -Message "Please enter username and password for connecting to VBR server"
        Connect-VBRServer -Server $vbrServer -Credential $vbrPsCredentials
    }
    catch {
        Write-Output "Connection error $($_.Exception.ItemName) : $($_.Exception.Message)"
        # Add-Content -Path  $errorLog -Value "Connection error $($_.Exception.ItemName) : $($_.Exception.Message)"
        exit
    }
}

function Check-VBRVersion() {
    $version = [string](([Veeam.Backup.Common.SProductVersions]::Current).Major) + "." + [string](([Veeam.Backup.Common.SProductVersions]::Current).Minor) + "." + [string](([Veeam.Backup.Common.SProductVersions]::Current).Build) + "." + [string](([Veeam.Backup.Common.SProductVersions]::Current).Revision)
    return $version
}

function Check-VBRGeneralConfig($logFile) {
    Write-Host "... checking configuration backup"
    $vbrConfigJob = Get-VBRConfigurationBackupJob
    Add-Content -Path  $logFile -Value "`r`nVBR Configuration backup set to $($vbrConfigJob.Enabled)"
    if ($vbrConfigJob.Enabled -match "True") {
        Add-Content -Path  $logFile -Value " VBR Configuration backup encryption set to $($vbrConfigJob.Enabled)"
    }
    $storageLatency = [Veeam.Backup.Core.SBackupOptions]::DatastoreParallelProcessingOptions
    Add-Content -Path  $logFile -Value "`r`nStorage latency control set to $($storageLatency.LimitParallelTasksByDatastoreLatency)"

    Write-Host "... checking datastore latency"
    if ($storageLatency.LimitParallelTasksByDatastoreLatency -match "True") {
        Add-Content -Path  $logFile -Value " Datastore latency $($storageLatency.MaxDatastoreLatencyMs) ms"
        Add-Content -Path  $logFile -Value " Throttle latency $($storageLatency.MinDatastoreLatency4ThrottleMs) ms"
    }
    
    Write-Host "... checking traffic rules"
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
    Add-Content -Path  $logFile -Value " Production storage skip VM processing enabled : $([Veeam.Backup.Core.SBackupOptions]::GetThresholdInfo().SkipVmsOnSourceLowFreeSpace) - threshold $([Veeam.Backup.Core.SBackupOptions]::GetThresholdInfo().SkipVmsSourceFreeSpacePercent) %"
    

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
  
function Check-BackupWindow($backupWindowStart, $backupWindowEnd, $allJobs, $logFile) {
    Write-Host -foreground white "... checking backup window"
    Add-Content -Path  $logFile -Value "Backup window is $($backupWindowStart) to $($backupWindowEnd)"
    foreach ($job in $allJobs) {
        if ($job.ScheduleOptions.NextRun)	{
            $nextRunTime = [datetime]$job.ScheduleOptions.NextRun
            $nextRunTime = $nextRunTime.ToShortTimeString()
            $nextRunBWStart = (New-TimeSpan -Start $backupWindowStart -End $nextRunTime).TotalMinutes
            $nextRunBWStop = (New-TimeSpan -Start $nextRunTime -End $backupWindowEnd).TotalMinutes
            if ((New-TimeSpan -Start $backupWindowStart -End $nextRunTime).TotalMinutes -ge 0 -and (New-TimeSpan -Start $nextRunTime -End $backupWindowEnd).TotalMinutes -ge 0)	{
                Add-Content -Path  $logFile -Value "INFO: Job $($job.Name) will run at $($nextRunTime)"
            } elseif (((New-TimeSpan -Start $backupWindowStart -End $nextRunTime).TotalMinutes -ge 0 -and (New-TimeSpan -Start $nextRunTime -End $backupWindowEnd).TotalMinutes -lt 0) -and ($backupWindowEnd -like "*AM*")) {
                Add-Content -Path  $logFile -Value "INFO: Job $($job.Name) will run at $($nextRunTime)"
            } elseif (((New-TimeSpan -Start $backupWindowStart -End $nextRunTime).TotalMinutes -lt 0 -and (New-TimeSpan -Start $nextRunTime -End $backupWindowEnd).TotalMinutes -ge 0) -and ($backupWindowStart -like "*PM*")) {
                Add-Content -Path  $logFile -Value "INFO: Job $($job.Name) will run at $($nextRunTime)"
            } else {
                Add-Content -Path  $logFile -Value "WARN: Job $($job.Name) will run at $($nextRunTime)"
            }
        }
    }
}

function Check-SOBR($sobrList, $logFileSOBR, $logFileExtents ) {
    Write-Host -foreground white "... checking Scale Out Backup Repositories"
    $sobrArray = @('"SobrName","PolicyType","UsePerVMBackupFiles"')
    $sobrExtentArray = @('"SobrName","Name","MaxTaskCount","numCPU","memoryGB","TotalSizeGB","FreeSpaceGB","DataRateLimitMBps","OptimizeBlockAlign","Uncompress","OneBackupFilePerVm","IsAutoDetectAffinityProxies","IsRotatedDriveRepository","IsSanSnapshotOnly","HasBackupChainLengthLimitation","IsDedupStorage","SplitStoragesPerVm"')
    if (!$sobrList) {
        Write-Host -foreground white "WARN: No SoBR found on" $config.Configuration.Server
        Add-Content -Path  $logFileSOBR -Value "WARN: No SoBR found on $($config.Configuration.Server)"
    } else {
        foreach ($sobr in $sobrList) {
            foreach ($extent in $sobr.Extent)	{
                $numCpu = 0
                $memoryGB = 0
                  # get server name where repo role is installed
                $repoServer = Get-VBRServer | Where {$_.Id -match $extent.Repository.Info.HostId}
                if ($repoServer) {
                    $repoServerName = $repoServer.Name
                    # get cpu and memory
                    $srv = [Veeam.Backup.Core.CPhysicalHost]::GetByHost($extent.Repository.Info.HostId) 
                    $numCPU = $srv.HardwareInfo.CPUCount * $srv.HardwareInfo.CoresCount 
                    $memoryGB = [math]::Round($srv.HardwareInfo.PhysicalRAMTotal/1GB,2)
                } else {
                    $numCpu=-1
                    $memoryGB=-1
                    $repoServerName="N/A"
                }
                # create array item
                #$sobrExtentArray = @('"SobrName","Name","MaxTaskCount","numCPU","memoryGB","TotalSizeGB","FreeSpaceGB","DataRateLimitMBps","OptimizeBlockAlign","Uncompress","OneBackupFilePerVm","IsAutoDetectAffinityProxies","IsRotatedDriveRepository","IsSanSnapshotOnly","HasBackupChainLengthLimitation","IsDedupStorage","SplitStoragesPerVm"')
                $item = $sobr.Name + "," + $extent.Repository.Name + "," + $extent.Repository.Options.MaxTaskCount + "," + $numCpu + "," + $memoryGB + "," + [math]::Round(($extent.Repository.Info.CachedTotalSpace)/1GB,2) + "," + [math]::Round(($extent.Repository.Info.CachedFreeSpace)/1GB,2) + "," + $extent.Repository.Options.CombinedDataRateLimit + "," + $extent.Repository.Options.OptimizeBlockAlign + "," + $extent.Repository.Options.Uncompress + "," + $extent.Repository.Options.OneBackupFilePerVm + "," + $extent.Repository.Options.IsAutoDetectAffinityProxies + "," + $extent.Repository.IsRotatedDriveRepository + "," + $extent.Repository.IsSanSnapshotOnly + "," + $extent.Repository.HasBackupChainLengthLimitation + "," + $extent.Repository.IsDedupStorage + "," + $extent.Repository.SplitStoragesPerVm
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
  

function Check-Repo($repoList, $logFile) {

    $repoArray = @('"repoName","repoServerName","MaxTaskCount","numCPU","memoryGB","TotalSizeGB","FreeSpaceGB","DataRateLimitMBps","OptimizeBlockAlign","Uncompress","OneBackupFilePerVm","IsAutoDetectAffinityProxies","IsRotatedDriveRepository","IsSanSnapshotOnly","HasBackupChainLengthLimitation","IsDedupStorage","SplitStoragesPerVm"')
    
    Write-Host -foreground white "... checking Backup Repositories"
    if (!$repoList) {
        Write-Host -foreground white "WARN: No repository found on" $config.Configuration.Server
        Add-Content -Path  $logFileSOBR -Value "WARN: No repository found on $($config.Configuration.Server)"
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
                $numCPU = $srv.HardwareInfo.CPUCount * $srv.HardwareInfo.CoresCount 
                $memoryGB = [math]::Round($srv.HardwareInfo.PhysicalRAMTotal/1GB,2)
            } else {
                $numCpu=-1
                $memoryGB=-1
                $repoServerName="N/A"
            }
            # create array item
            #$repoArray = @('"repoName","repoServerName","MaxTaskCount","numCPU","memoryGB","TotalSizeGB","FreeSpaceGB","DataRateLimitMBps","OptimizeBlockAlign","Uncompress","OneBackupFilePerVm","IsAutoDetectAffinityProxies","IsRotatedDriveRepository","IsSanSnapshotOnly","HasBackupChainLengthLimitation","IsDedupStorage","SplitStoragesPerVm"')
            $item = $repo.Name + "," + $repoServerName + "," + $repo.Options.MaxTaskCount + "," + $numCpu + "," + $memoryGB + "," + [math]::Round(($repo.Info.CachedTotalSpace)/1GB,2) + "," + [math]::Round(($repo.Info.CachedFreeSpace)/1GB,2) + "," + $repo.Options.CombinedDataRateLimit + "," + $repo.Options.OptimizeBlockAlign + "," + $repo.Options.Uncompress + "," + $repo.Options.OneBackupFilePerVm + "," + $repo.Options.IsAutoDetectAffinityProxies + "," + $repo.IsRotatedDriveRepository + "," + $repo.IsSanSnapshotOnly + "," + $repo.HasBackupChainLengthLimitation + "," + $repo.IsDedupStorage + "," + $repo.SplitStoragesPerVm
            $repoArray += $item
        }
        $repoArray | foreach { Add-Content -Path  $logFile -Value $_ }
    }
}


function Check-ProxyVi($viProxyList, $logFile) {
    Write-Host -foreground white "... checking VMware proxies"
    $viProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","TransportMode","FailoverToNetwork","UseSsl","IsAutoDetectAffinityRepositories","IsAutoVddkMode","IsAutoDetectDisks"')
    if (!$viProxyList)  {
        Add-Content -Path  $logFile -Value "WARN: No VMware proxy found"
    } else {
        foreach ($viProxy in $viProxyList) {
            $numCpu = 0
            $memoryGB = 0
            # get server name where proxy role is installed
            $viProxyServer = Get-VBRServer | Where {$_.Id -match $viProxy.Info.HostId}
            # get cpu and memory
            $srv = [Veeam.Backup.Core.CPhysicalHost]::GetByHost($viProxy.Info.HostId) 
            $numCPU = $srv.HardwareInfo.CPUCount * $srv.HardwareInfo.CoresCount 
            $memoryGB = [math]::Round($srv.HardwareInfo.PhysicalRAMTotal/1GB,2)
            # create array item
            # $viProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","TransportMode","FailoverToNetwork","UseSsl","IsAutoDetectAffinityRepositories","IsAutoVddkMode","IsAutoDetectDisks"')
            $item = $viProxy.Name + "," + $viProxy.Options.MaxTasksCount + "," + $numCpu + "," + $memoryGB + "," + $viProxy.IsDisabled + "," + $viProxy.Options.TransportMode + "," + $viProxy.Options.FailoverToNetwork 			 + "," + $viProxy.Options.UseSsl + "," + $viProxy.Options.IsAutoDetectAffinityRepositories  + "," + $viProxy.Options.IsAutoVddkMode  + "," + $viProxy.Options.IsAutoDetectDisks
            $viProxyArray += $item
        }
        $viProxyArray | foreach { Add-Content -Path $logFile -Value $_ }
    }
}
  
function Check-ProxyHv($config, $hvProxyList, $logFile) {
    Write-Host -foreground white "... checking Hyper-V proxies"
    $hvProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","Type","IsAutoDetectVolumes"')
    if (!$hvProxyList) {
        Add-Content -Path  $logFile -Value "WARN: No Hyper-V proxy found"
    } else {
        foreach ($hvProxy in $hvProxyList) {
            $numCpu = 0
            $memoryGB = 0
            # get server name where proxy role is installed
            $hvProxyServer = Get-VBRServer | Where {$_.Id -match $hvProxy.HostId}
            # get cpu and memory
            $srv = [Veeam.Backup.Core.CPhysicalHost]::GetByHost($hvProxy.HostId) 
            $numCPU = $srv.HardwareInfo.CPUCount * $srv.HardwareInfo.CoresCount 
            $memoryGB = [math]::Round($srv.HardwareInfo.PhysicalRAMTotal/1GB,2)
            # create array item
            # $hvProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","Type","IsAutoDetectVolumes"')
            $item = $hvProxy.Name + "," + $hvProxy.MaxTasksCount + "," + $numCpu + "," + $memoryGB + "," + $hvProxy.IsDisabled + "," + $hvProxy.Type + "," + $hvProxy.Options.IsAutoDetectVolumes
            $hvProxyArray += $item

        }
        $hvProxyArray | foreach { Add-Content -Path  $logFile -Value $_ }
    }
}
  
function Check-WANAcc($wanAccList, $logFile) {
    Write-Host -foreground white "... checking WAN accelerators"
    $wanAccArray = @('"Name","ServerName","numCPU","memoryGB","TrafficPort","MgmtPort"')
    if (!$wanAccList) {
        Add-Content -Path  $logFile -Value "WARN: No WAN accelerator found"
    } else {
        foreach ($wanAcc in $wanAccList) {
            $numCpu = 0
            $memoryGB = 0
            # get server name where proxy role is installed
            $wanAccServer = Get-VBRServer | Where {$_.Id -match $wanAcc.HostId}
            # get cpu and memory
            $srv = [Veeam.Backup.Core.CPhysicalHost]::GetByHost($wanAcc.HostId) 
            $numCPU = $srv.HardwareInfo.CPUCount * $srv.HardwareInfo.CoresCount 
            $memoryGB = [math]::Round($srv.HardwareInfo.PhysicalRAMTotal/1GB,2)
            # create array item
            # $wanAccArray = @('"Name","ServerName","numCPU","memoryGB","TrafficPort","MgmtPort"')
            $item = $wanAccServer.Name + "," + $wanAccServer.Name + "," + $numCpu + "," + $memoryGB  + "," + $wanAcc.GetWaTrafficPort()  + "," + $wanAcc.GetWaMgmtPort()
            $wanAccArray += $item
        }
        $wanAccArray | foreach { Add-Content -Path  $logFile -Value $_ }
    }
  }


#   maintenance - health check enabled
#   compression level/storage optimization
#   BfSS enabled, limit VMs, failover to standard backup, failover to primary storage snap

  function Check-JobConfiguration($job, $logFile) {
        Add-Content -Path  $logFile -Value "$($job.Name) / $($job.TypeToString)"
        $jobSize = 0
        $proxyList = " Proxy list:"

        $jobSize = [math]::round($job.Info.includedSize/1GB - $job.Info.excludedSize/1GB,2)
        # jobConfigArray = @('"Name","JobType",TargetRepoName","LastRun","JobSize"')
        Add-Content -Path  $logFile -Value "`r`n### JOB SUMMARY"
        Add-Content -Path  $logFile -Value "Target repo: $($job.GetTargetRepository().Name)"
        Add-Content -Path  $logFile -Value "Approximate job size: $($jobSize) GB"
        if ($job.ScheduleOptions.NextRun) {
            Add-Content -Path  $logFile -Value "Next run: $($job.ScheduleOptions.NextRun)"
        } else {
            Add-Content -Path  $logFile -Value "Job is not scheduled"
        }

        Add-Content -Path  $logFile -Value "Last run status: $($job.GetLastResult())"

        Add-Content -Path  $logFile -Value "`r`n### JOB DETAILS"
        if (-Not $job.Options.JobOptions.SourceProxyAutoDetect) {
            Add-Content -Path  $logFile -Value "`r`nAutomatic proxy selection: $($job.Options.JobOptions.SourceProxyAutoDetect)"
            Add-Content -Path  $logFile -Value " Selected proxies: $($job.GetProxy().Count)"
            foreach ($proxy in $job.GetProxy()) { $proxyList += " " + $proxy.Name }
            Add-Content -Path  $logFile -Value $proxyList
        } else {
            Add-Content -Path  $logFile -Value "`r`nAutomatic proxy selection: $($job.Options.JobOptions.SourceProxyAutoDetect)"
        }


        Add-Content -Path  $logFile -Value "`r`nRestore points: $($job.Options.BackupStorageOptions.RetainCycles)"
        Add-Content -Path  $logFile -Value "Backup type: $($job.Options.BackupTargetOptions.Algorithm)  Active full backup: $($job.Options.BackupStorageOptions.EnableFullBackup) Syntethic fulls: $($job.Options.BackupTargetOptions.TransformFullToSyntethic) "
        Add-Content -Path  $logFile -Value "Active full days: $($job.Options.BackupTargetOptions.FullBackupDays)  Synthetic full days: $($job.Options.BackupTargetOptions.TransformToSyntethicDays) - Incremental to synthetic: $($job.Options.BackupTargetOptions.TransformIncrementsToSyntethic)"
        Add-Content -Path  $logFile -Value "`r`nAdavanced settings storage:"
        Add-Content -Path  $logFile -Value " Enabled deduplication: $($job.Options.BackupStorageOptions.EnableDeduplication)"
        Add-Content -Path  $logFile -Value " Compression level: $($job.Options.BackupStorageOptions.CompressionLevel)" # backup jobs: 0-none  4-dedup_friendly 5-optimal 6-high 9-extreme 
        Add-Content -Path  $logFile -Value " Storage optimization - block size: $($job.Options.BackupStorageOptions.StgBlockSize)"
       
        if ($job.TypeToString -eq "Hyper-V Backup") {
            Add-Content -Path  $logFile -Value " Exclude swap files: $($job.HvSourceOptions.ExcludeSwapFile)"
            Add-Content -Path  $logFile -Value " Exclude deleted file blocks: $($job.HvSourceOptions.DirtyBlocksNullingEnabled)"
            Add-Content -Path  $logFile -Value " `r`nChange block tracking: $($job.HvSourceOptions.UseChangeTracking)"
            Add-Content -Path  $logFile -Value "Hyper-V Tools quiescing: $($job.HvSourceOptions.EnableHvQuiescence)"
            Add-Content -Path  $logFile -Value "Crash consistent : $($job.HvSourceOptions.CanDoCrashConsistent)"
            Add-Content -Path  $logFile -Value "Process multiple VMs per volume snapshot : $($job.HvSourceOptions.GroupSnapshotProcessing)"
        } elseif ($job.TypeToString -eq "VMware Backup") {
            Add-Content -Path  $logFile -Value " Exclude swap files: $($job.ViSourceOptions.ExcludeSwapFile)"
            Add-Content -Path  $logFile -Value " Exclude deleted file blocks: $($job.ViSourceOptions.DirtyBlocksNullingEnabled)"
            Add-Content -Path  $logFile -Value " `r`nChange block tracking: $($job.ViSourceOptions.UseChangeTracking)"
            Add-Content -Path  $logFile -Value "VMware tools quiescing: $($job.ViSourceOptions.VMToolsQuiesce)"
        } else {
            Add-Content -Path  $logFile -Value " `r`nChange block tracking: $($job.ViSourceOptions.UseChangeTracking)"
        }
        Add-Content -Path  $logFile -Value " `r`nEncryption enabled: $($job.Options.BackupStorageOptions.StorageEncryptionEnabled)"
}
  
function Create-JobOverview($allJobs, $logFile) {
    $jobsArray = @('"Name","JobType","TargetRepo","JobSizeGB","LastRunState","NextRun"')
    foreach ($job in $allJobs) {
        $jobSize = 0
        $jobSize = [math]::round($job.Info.includedSize/1GB - $job.Info.excludedSize/1GB,2)
        $item = $job.Name + "," + $job.TypeToString + "," +  $job.GetTargetRepository().Name + "," +  $jobSize + "," + $job.GetLastResult() + "," + $job.ScheduleOptions.NextRun
        $jobsArray += $item
    }
    $jobsArray | foreach { Add-Content -Path  $logFile -Value $_ }
}

function Get-RunTime() {
    $rT = (Get-Date).ToShortDateString()
    $rT = $rT -replace '\/','_'
    $rT = $rT + "_" + (Get-Date).ToShortTimeString()
    $rT = $rT -replace ':','_'
    $rT = $rT -replace ' ','_'
    return $rT
}

### END FUNCTION DEFINITION ###

### 
# Check log folder
$logFileDir = 'C:\temp\'
Write-Host -ForegroundColor Magenta "Enter folder where logs will be saved. Default value is [$($logFileDir)]"
Write-Host -ForegroundColor Magenta "Folder must exist. "
$logLocation = Read-Host "Enter folder name or use default [$($logFileDir)]"
if ($logLocation) {
    $logFileDir = $logLocation
} 
$logFilePath = Check-LogFolder -logFileDir $logFileDir

# Connect backup server
Write-Host -foregroundcolor Magenta "Connect to server or enter q to quit"
$vbrServer = Read-Host "Input server name or IP. Press enter for default [localhost]"
if ($vbrServer -eq "q") {
    Write-Host "Exit" -ForegroundColor Cyan
    exit
} elseif ($vbrServer) {
    Connect-VBR -vbrServer $vbrServer
} else {
    $vbrServer = "localhost"
    Connect-VBR -vbrServer $vbrServer
}

$menu=@"
1 Check VBR general configuration
2 Check backup window 
3 Check repositories 
4 Check proxies
5 Check WAN Accelerators
6 Check jobs
Q Quit
 
Select a task by number or Q to quit
"@

Do { 
    Switch (Show-Menu -menu $menu -title "VBR Configuration Check" -clear) {
    "1" {   # VBR general configuration
            $runTime = Get-RunTime
            $logFileName = 'vbr_general_config'
            $logFile = $logFilePath + $logFileName + '_' + $runTime + '.log' 
            $curVersion = Check-VBRVersion
            Add-Content -Path  $logFile -Value "Installed VBR version $($curVersion)"
            Check-VBRGeneralConfig -logFile $logFile
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
            $allJobs = Get-VBRJob
            $logFileName = 'backup_window'
            $logFile = $logFilePath + $logFileName + '_' + $runTime + '.log'
            Check-BackupWindow -backupWindowStart $backupWindowStart -backupWindowEnd $backupWindowEnd -allJobs $allJobs -logFile $logFile
            Sleep -seconds 1
        }
    "3" {   # check repositories 
            $runTime = Get-RunTime
            # check SOBR 
            $sobrList =  Get-VBRBackupRepository -ScaleOut
            $logFileNameSOBR = 'sobr_configuration'
            $logFileNameExtents = 'sobr_extent_configuration'
            $logFileSOBR = $logFilePath + $logFileNameSOBR + '_' + $runTime + '.log'
            $logFileExtents = $logFilePath + $logFileNameExtents + '_' + $runTime + '.log'
            Check-SOBR -sobrList $sobrList -logFileSOBR $logFileSOBR -logFileExtents $logFileExtents
            # Check repositories
            $repoList = Get-VBRBackupRepository
            $logFileName = 'repository_configuration'
            $logFile = $logFilePath + $logFileName + '_' + $runTime + '.log'
            Check-Repo -repoList $repoList -logFile $logFile
            Sleep -seconds 1
        }
    "4" {   # check proxies
            $runTime = Get-RunTime
            # Check proxy - VMware
            $viProxyList = Get-VBRViProxy
            $logFileName = 'proxy_vmw_configuration'
            $logFile = $logFilePath + $logFileName + '_' + $runTime + '.log'
            Check-ProxyVi -viProxyList $viProxyList -logFile $logFile
            # Check proxy - Hyper-V
            $hvProxyList = Get-VBRHvProxy
            $logFileName = 'proxy_hv_configuration'
            $logFile = $logFilePath + $logFileName + '_' + $runTime + '.log'
            Check-ProxyHv -hvProxyList $hvProxyList -logFile $logFile
            Sleep -seconds 1
        }
    "5" {   # Check WAN accelerator
            $runTime = Get-RunTime
            $wanAccList = Get-VBRWANAccelerator
            $logFileName = 'wan_acc_configuration'
            $logFile = $logFilePath + $logFileName + '_' + $runTime + '.log'
            Check-WANAcc -wanAccList $wanAccList -logFile $logFile
            Sleep -seconds 1
        }
    "6" {   # Check jobs - NEEDS UPDATE 
            $runTime = Get-RunTime
            Write-Host "... checking jobs"
            $allJobs = Get-VBRJob
            # generate jobs summary
            $logFileName = 'all_jobs_summary' 
            $logFile = $logFilePath + $logFileName + '_' + $runTime + '.log'
            Create-JobOverview -allJobs $allJobs -logFile $logFile
            # job details
            foreach ($job in $allJobs) {
                $jobName = $job.Name -replace '\/','_'
                $jobName = $jobName -replace '\\','_'
                $logFileName = 'job_' + $jobName
                $logFile = $logFilePath + $logFileName + '_' + $runTime + '.log'
                Check-JobConfiguration -job $job -logFile $logFile
            }
            Sleep -seconds 1
        }
    "Q" {
            Write-Host "Log files saved in $($logFileDir)" -ForegroundColor Cyan
            Return
        }
    Default {
            Write-Warning "Invalid Choice. Try again."
            Sleep -milliseconds 750
        }
    }
} While ($True)


