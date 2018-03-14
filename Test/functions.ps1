<#
    .SYNOPSIS
    HealthCheck is a environmnet analysis script for Veeam Backup and Replication

    .DESCRIPTION

    HealthCheck is a script that analysis the configuration of an existing
    Veeam Backup and Replication environment. It takes as input configuration
    settings defined in config.xml file residing in the same directory.
    It outputs mismatches to console and logs all findings to csv files.

    .EXAMPLE
    .\HealthCheck.ps1

    .NOTES
    Version: 0.2
    Author: Razvan Ionescu
    Last Updated: March 2018

    Requires:
    Veeam Backup & Replication v9.5 Update 3

#>

# Load PS modules
Try {
  Add-PSSnapin -Name VeeamPSSnapin
}
catch {
  Write-Output "VeeamPSSnapin not found. Please install VBR Console on the machine running the script"
}

# Start function definitions
function ConnectVBR($config) {
  Disconnect-VBRServer -ErrorAction SilentlyContinue
  try {
    if ($config.Configuration.Username -eq "USERNAME") {
      $vbrPsCredentials = Get-Credential -Message "Please enter username and password for connecting to VBR server"
      Connect-VBRServer -Server $config.Configuration.Server -Credential $vbrPsCredentials
    }
    else {
      Connect-VBRServer -Server $config.Configuration.Server -User $config.Configuration.Username -Password $config.Configuration.Password
    }
  }
  catch {
      Write-Output "Failed to connect to VBR server"
      exit
  }
}

function checkVBRConfigJob($config) {
  $vbrConfigJob = Get-VBRConfigurationBackupJob
  if ($vbrConfigJob.Enabled -match $config.Configuration.GeneralConfiguration.ConfigurationBackup.Enabled) {
  	Write-Host -foregroundcolor yellow "VBR Configuration set to" $vbrConfigJob.Enabled
  } else {
  	Write-Host -foregroundcolor red "VBR Configuration set to" $vbrConfigJob.Enabled "expected" $config.Configuration.GeneralConfiguration.ConfigurationBackup.Enabled
  }
  if (($vbrConfigJob.Enabled -match "True") -And ($vbrConfigJob.EncryptionOptions.Enabled -match $config.Configuration.GeneralConfiguration.ConfigurationBackup.IsEncrypted)) {
  	Write-Host -foregroundcolor yellow "VBR Configuration encryption set to" $vbrConfigJob.EncryptionOptions.Enabled
  } else {
  	Write-Host -foregroundcolor red "VBR Configuration encryption set to" $vbrConfigJob.EncryptionOptions.Enabled "expected" $config.Configuration.GeneralConfiguration.ConfigurationBackup.IsEncrypted
  }
}


function checkBackupWindow($config, $allJobs, $csvFile) {
  # Check backup window
  $backupWindowArray = @('"JobName","NextRun"')

  if ($config.Configuration.BackupJobs.BackupWindow.Enabled -match "True") {
  	Write-Host -foreground white "...checking backup window"
  	Write-Host -foreground white "Backup window is " $config.Configuration.BackupJobs.BackupWindow.Start "to" $config.Configuration.BackupJobs.BackupWindow.Stop
  	Write-Host "... jobs scheduled to start outside backup window"
  	foreach ($job in $allJobs) {
  		if ($job.ScheduleOptions.NextRun)	{
  			$nextRunTime = [datetime]$job.ScheduleOptions.NextRun
  			$nextRunTime = $nextRunTime.ToShortTimeString()
  			$nextRunBWStart = (New-TimeSpan -Start $config.Configuration.BackupJobs.BackupWindow.Start -End $nextRunTime).TotalMinutes
  			$nextRunBWStop = (New-TimeSpan -Start $nextRunTime -End $config.Configuration.BackupJobs.BackupWindow.Stop).TotalMinutes

  			if ((New-TimeSpan -Start $config.Configuration.BackupJobs.BackupWindow.Start -End $nextRunTime).TotalMinutes -ge 0 -and (New-TimeSpan -Start $nextRunTime -End $config.Configuration.BackupJobs.BackupWindow.Stop).TotalMinutes -ge 0)	{
  				# Write-Host -foregroundcolor yellow  $job.Name $nextRunTime
  			} elseif (((New-TimeSpan -Start $config.Configuration.BackupJobs.BackupWindow.Start -End $nextRunTime).TotalMinutes -ge 0 -and (New-TimeSpan -Start $nextRunTime -End $config.Configuration.BackupJobs.BackupWindow.Stop).TotalMinutes -lt 0) -and ($config.Configuration.BackupJobs.BackupWindow.Stop -like "*AM*")) {

  				# Write-Host -foregroundcolor yellow  $job.Name $nextRunTime
  			} elseif (((New-TimeSpan -Start $config.Configuration.BackupJobs.BackupWindow.Start -End $nextRunTime).TotalMinutes -lt 0 -and (New-TimeSpan -Start $nextRunTime -End $config.Configuration.BackupJobs.BackupWindow.Stop).TotalMinutes -ge 0) -and ($config.Configuration.BackupJobs.BackupWindow.Start -like "*PM*")) {
  				# Write-Host -foregroundcolor yellow  $job.Name $nextRunTime
  			} else {
  				Write-Host -foregroundcolor red $job.Name $nextRunTime
  				$item = $job.Name + "," + $nextRunTime
  				$backupWindowArray += $item
  			}
  		}
  	}
  	$backupWindowArray | foreach { Add-Content -Path  $csvFile -Value $_ }
  }
}


function checkSOBR($config, $sobrList, $csvFileParent, $csvFileChild ) {
  $sobrArray = @('"SobrName","PolicyType","UsePerVMBackupFiles"')
  $sobrExtentArray = @('"SobrName","Name","MaxTaskCount","numCPU","memoryGB","TotalSizeGB","FreeSpaceGB","DataRateLimitMBps","OptimizeBlockAlign","Uncompress","OneBackupFilePerVm","IsAutoDetectAffinityProxies","IsRotatedDriveRepository","IsSanSnapshotOnly","HasBackupChainLengthLimitation","IsDedupStorage","SplitStoragesPerVm"')
  Write-Host ""
  if (!$sobrList) {
  	Write-Host -foreground white "...No SoBR found on" $config.Configuration.Server
  } else {
  	Write-Host "...checking SoBR "
  	Write-Host ""
  	foreach ($sobr in $sobrList) {
  		Write-Host -foreground white "SoBR: " $sobr.Name
  		Write-Host -foreground yellow "Policy type:" $sobr.PolicyType
  		<#
  		Write-Host -foreground yellow "per VM backup files:" $sobr.UsePerVMBackupFiles
  		#>
  		foreach ($extent in $sobr.Extent)	{
  			$numCpu = 0
  			Write-Host ""
  			Write-Host -foreground yellow "extent name: " $extent.Repository.Name
  			# Check parameters that should be False for SoBR
  			if ($extent.Repository.Options.CombinedDataRateLimit -gt 0)	{
  				Write-Host -foreground red " DataRateLimitMBps : " $extent.Repository.Options.CombinedDataRateLimit
  			}
  			if ($extent.Repository.IsRotatedDriveRepository -match "True") {
  				Write-Host -foreground red " IsRotatedDriveRepository: " $extent.Repository.IsRotatedDriveRepository
  			}
  			if ($extent.Repository.IsSanSnapshotOnly -match "True")	{
  				Write-Host -foreground red " IsSanSnapshotOnly: " $extent.Repository.IsSanSnapshotOnly
  			}
  			if ($extent.Repository.HasBackupChainLengthLimitation -match "True") {
  				Write-Host -foreground red " HasBackupChainLengthLimitation: " $extent.Repository.HasBackupChainLengthLimitation
  			}
  			if ($extent.Repository.IsDedupStorage -match "True") {
  				Write-Host -foreground red " IsDedupStorage: " $extent.Repository.IsDedupStorage
  			}
  			if ($extent.Repository.SplitStoragesPerVm -match "True") {
  				Write-Host -foreground red " SplitStoragesPerVm: " $extent.Repository.SplitStoragesPerVm
  			}
  			# Check configuration of the extent
  			Write-Host -foreground yellow " Max concurrent tasks: " $extent.Repository.Options.MaxTaskCount
  			<#
  			Write-Host -foreground yellow " Align backup file data blocks : " $extent.Repository.Options.OptimizeBlockAlign
  			Write-Host -foreground yellow " Decompress backup data: " $extent.Repository.Options.Uncompress
  			Write-Host -foreground yellow " User per-VM backup file : " $extent.Repository.Options.OneBackupFilePerVm
  			Write-Host -foreground yellow " Proxy affinity auto  : " $extent.Repository.Options.IsAutoDetectAffinityProxies
  			Write-Host ""
  			#>
  			# get server name where repo role is installed
  			$repoServer = Get-VBRServer | Where {$_.Id -match $extent.Repository.Info.HostId}

  			# get cpu and memory - windows repo only
  			try	{
  				Get-WmiObject Win32_Processor -ea stop -ComputerName $repoServer.Name -Property numberOfCores | Select-Object -Property numberOfCores| foreach-object {$numCpu += $_.numberOfCores }
  			}
  			catch {
  				Add-Content -Path  $errorLog -Value "WMI Error for $($repoServer.Name) : $($_.Exception.Message)"
  				$numCpu=-1
  			}
  			try	{
  				$memoryGB = Get-WmiObject CIM_PhysicalMemory -ComputerName $repoServer.Name  -ea stop | Measure-Object -Property capacity -sum | % {[math]::round(($_.sum / 1GB),2)}
  			}
  			catch	{
  				Add-Content -Path  $errorLog -Value "WMI Error for $($repoServer.Name) : $($_.Exception.Message)"
  				$memoryGB=-1
  			}
  			# create array item
  			#$sobrExtentArray = @('"SobrName","Name","MaxTaskCount","numCPU","memoryGB","TotalSizeGB","FreeSpaceGB","DataRateLimitMBps","OptimizeBlockAlign","Uncompress","OneBackupFilePerVm","IsAutoDetectAffinityProxies","IsRotatedDriveRepository","IsSanSnapshotOnly","HasBackupChainLengthLimitation","IsDedupStorage","SplitStoragesPerVm"')
  			$item = $sobr.Name + "," + $extent.Repository.Name + "," + $extent.Repository.Options.MaxTaskCount + "," + $numCpu + "," + $memoryGB + "," + [math]::Round(($extent.Repository.Info.CachedTotalSpace)/1GB,2) + "," + [math]::Round(($extent.Repository.Info.CachedFreeSpace)/1GB,2) + "," + $extent.Repository.Options.CombinedDataRateLimit + "," + $extent.Repository.Options.OptimizeBlockAlign + "," + $extent.Repository.Options.Uncompress + "," + $extent.Repository.Options.OneBackupFilePerVm + "," + $extent.Repository.Options.IsAutoDetectAffinityProxies + "," + $extent.Repository.IsRotatedDriveRepository + "," + $extent.Repository.IsSanSnapshotOnly + "," + $extent.Repository.HasBackupChainLengthLimitation + "," + $extent.Repository.IsDedupStorage + "," + $extent.Repository.SplitStoragesPerVm
  			$sobrExtentArray += $item
  		}
  		Write-Host ""
  		$sobrExtentArray | foreach { Add-Content -Path  $csvFileChild -Value $_ }
  		$sobrExtentArray = @()

  		$item = $sobr.Name + "," + $sobr.PolicyType + "," + $sobr.UsePerVMBackupFiles
  		$sobrArray += $item
  	}
  	$sobrArray | foreach { Add-Content -Path  $csvFileParent -Value $_ }
  }
}


function checkRepo($config, $sobrList, $csvFile) {

  $repoArray = @('"repoName","repoServerName","MaxTaskCount","numCPU","memoryGB","TotalSizeGB","FreeSpaceGB","DataRateLimitMBps","OptimizeBlockAlign","Uncompress","OneBackupFilePerVm","IsAutoDetectAffinityProxies","IsRotatedDriveRepository","IsSanSnapshotOnly","HasBackupChainLengthLimitation","IsDedupStorage","SplitStoragesPerVm"')

  Write-Host ""
  if (!$repoList) {
  Write-Host -foreground white "...No repository found on" $config.Configuration.Server
  } else {
  Write-Host "...checking Repositories "
  Write-Host ""
  foreach ($repo in $repoList) {
    Write-Host -foreground white "repository: " $repo.Name

    $numCpu = 0
    $memoryGB = 0
    $repoServerName = "N/A"
    #  deduplication appliances checks
    if ($repo.Type -match "HPStoreOnceIntegration") {
      if ($repo.Options.Uncompress -notmatch $config.Configuration.Repositories.HPStoreOnceIntegration.Uncompress) {
          Write-Host -foreground red "Uncompress: " $repo.Options.Uncompress "expected value: " $config.Configuration.Repositories.HPStoreOnceIntegration.Uncompress
        }
      if ($repo.Options.OneBackupFilePerVm -notmatch $config.Configuration.Repositories.HPStoreOnceIntegration.OneBackupFilePerVm) {
          Write-Host -foreground red "Per VM backup file : " $repo.Options.OneBackupFilePerVm "expected value: " $config.Configuration.Repositories.HPStoreOnceIntegration.OneBackupFilePerVm
        }
    } elseif ($repo.Type -match "DDBoost") {
      if ($repo.Options.Uncompress -notmatch $config.Configuration.Repositories.DDBoost.Uncompress) {
          Write-Host -foreground red "Uncompress: " $repo.Options.Uncompress "expected value: " $config.Configuration.Repositories.DDBoost.Uncompress
        }
      if ($repo.Options.OneBackupFilePerVm -notmatch $config.Configuration.Repositories.DDBoost.OneBackupFilePerVm) {
          Write-Host -foreground red "Per VM backup file : " $repo.Options.OneBackupFilePerVm "expected value: " $config.Configuration.Repositories.DDBoost.OneBackupFilePerVm
        }
    } elseif ($repo.Type -match "ExaGrid") {
      if ($repo.Options.Uncompress -notmatch $config.Configuration.Repositories.ExaGrid.Uncompress) {
          Write-Host -foreground red "Uncompress: " $repo.Options.Uncompress "expected value: " $config.Configuration.Repositories.ExaGrid.Uncompress
        }
      if ($repo.Options.OneBackupFilePerVm -notmatch $config.Configuration.Repositories.ExaGrid.OneBackupFilePerVm) {
          Write-Host -foreground red "Per VM backup file : " $repo.Options.OneBackupFilePerVm "expected value: " $config.Configuration.Repositories.ExaGrid.OneBackupFilePerVm
        }
      if ($repo.Options.MaxTaskCount -notmatch $config.Configuration.Repositories.ExaGrid.MaxTaskCount) {
          Write-Host -foreground red "MaxTaskCount : " $repo.Options.MaxTaskCount "expected value: " $config.Configuration.Repositories.ExaGrid.MaxTaskCount
        }
    } elseif ($repo.IsDedupStorage -match "True") {
      if ($repo.Options.Uncompress -match "False") {
        Write-Host -foreground red "Uncompress: " $repo.Options.Uncompress "expected value: True"
      }
    }

    if ($repo.Options.CombinedDataRateLimit -gt 0) {
      Write-Host -foreground red " DataRateLimitMBps : " $repo.Options.CombinedDataRateLimit
    }
    if ($repo.IsRotatedDriveRepository -match "True") {
      Write-Host -foreground red " IsRotatedDriveRepository: " $repo.IsRotatedDriveRepository
    }
    if ($repo.IsSanSnapshotOnly -match "True") {
      Write-Host -foreground red " IsSanSnapshotOnly: " $repo.IsSanSnapshotOnly
    }
    if ($repo.HasBackupChainLengthLimitation -match "True") {
      Write-Host -foreground red " HasBackupChainLengthLimitation: " $repo.HasBackupChainLengthLimitation
    }

    Write-Host -foreground yellow " Max concurrent tasks: " $repo.Options.MaxTaskCount
    <#
    Write-Host -foreground yellow " Align backup file data blocks : " $repo.Options.OptimizeBlockAlign
    Write-Host -foreground yellow " Decompress backup data: " $repo.Options.Uncompress
    Write-Host -foreground yellow " User per-VM backup file : " $repo.Options.OneBackupFilePerVm
    Write-Host -foreground yellow " Proxy affinity auto  : " $repo.Options.IsAutoDetectAffinityProxies
    #>
    Write-Host ""
    # get server name where repo role is installed
    $repoServer = Get-VBRServer | Where {$_.Id -match $repo.Info.HostId}
    if ($repoServer) {
      $repoServerName = $repoServer.Name
      # get cpu and memory - windows repo only
      try {
        Get-WmiObject Win32_Processor -ea stop -ComputerName $repoServer.Name -Property numberOfCores | Select-Object -Property numberOfCores| foreach-object {$numCpu += $_.numberOfCores }
      }
      catch {
        Add-Content -Path  $errorLog -Value "WMI Error for $($repoServer.Name) : $($_.Exception.Message)"
        $numCpu=-1
      }
      try {
        $memoryGB = Get-WmiObject CIM_PhysicalMemory -ComputerName $repoServer.Name  -ea stop | Measure-Object -Property capacity -sum | % {[math]::round(($_.sum / 1GB),2)}
      }
      catch {
        Add-Content -Path  $errorLog -Value "WMI Error for $($repoServer.Name) : $($_.Exception.Message)"
        $memoryGB=-1
      }
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
  $repoArray | foreach { Add-Content -Path  $csvFile -Value $_ }
  }
}

function checkProxyVi($config, $viProxyList, $csvFile) {
  $viProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","TransportMode","FailoverToNetwork","UseSsl","IsAutoDetectAffinityRepositories","IsAutoVddkMode","IsAutoDetectDisks"')
  if (!$viProxyList)  {
  	Write-Host -foreground white "...No VMware proxy found"
  	Add-Content -Path  $csvFile -Value "...No VMware proxy found"
  } else {
  	Write-Host "...checking VMware proxies"
  	Write-Host ""
  	foreach ($viProxy in $viProxyList) {
  		$numCpu = 0
  		Write-Host -foreground white "proxy: " $viProxy.Name
  		Write-Host -foreground yellow " MaxTasksCount: " $viProxy.Options.MaxTasksCount
  		if ($viProxy.IsDisabled -match "True") {
  			Write-Host -foreground red "Proxy is disabled"
  		}
  		if ($viProxy.Options.TransportMode -notmatch $config.Configuration.Proxies.ViProxy.TransportMode)	{
  			Write-Host -foreground red " TransportMode: " $viProxy.Options.TransportMode "expected " $config.Configuration.Proxies.ViProxy.TransportMode
  		}
  		if ($viProxy.Options.FailoverToNetwork -notmatch $config.Configuration.Proxies.ViProxy.FailoverToNetwork)	{
  			Write-Host -foreground red " FailoverToNetwork: " $viProxy.Options.FailoverToNetwork "expected " $config.Configuration.Proxies.ViProxy.FailoverToNetwork
  		}
  		if ($viProxy.Options.UseSsl -notmatch $config.Configuration.Proxies.ViProxy.UseSsl)	{
  			Write-Host -foreground red " UseSsl: " $viProxy.Options.UseSsl "expected " $config.Configuration.Proxies.ViProxy.UseSsl
  		}
  		if ($viProxy.Options.IsAutoDetectAffinityRepositories -notmatch $config.Configuration.Proxies.ViProxy.IsAutoDetectAffinityRepositories)	{
  			Write-Host -foreground red " IsAutoDetectAffinityRepositories: " $viProxy.Options.IsAutoDetectAffinityRepositories
  		}
  		if ($viProxy.Options.IsAutoVddkMode -notmatch $config.Configuration.Proxies.ViProxy.IsAutoVddkMode)	{
  			Write-Host -foreground red " IsAutoVddkMode: " $viProxy.Options.IsAutoVddkMode
  		}
  		if ($viProxy.Options.IsAutoDetectDisks -notmatch $config.Configuration.Proxies.ViProxy.IsAutoDetectDisks)	{
  			Write-Host -foreground red " IsAutoDetectDisks: " $viProxy.Options.IsAutoDetectDisks
  		}
  		Write-Host ""

  		# get server name where proxy role is installed
  		$viProxyServer = Get-VBRServer | Where {$_.Id -match $viProxy.Info.HostId}

  		try	{
  			Get-WmiObject Win32_Processor -ea stop -ComputerName $viProxyServer.Name -Property numberOfCores | Select-Object -Property numberOfCores| foreach-object {$numCpu += $_.numberOfCores }
  		}
  		catch	{
  			Add-Content -Path  $errorLog -Value "WMI Error for $($viProxyServer.Name) : $($_.Exception.Message)"
  			$numCpu=-1
  		}
  		try {
  			$memoryGB = Get-WmiObject CIM_PhysicalMemory -ComputerName $viProxyServer.Name  -ea stop | Measure-Object -Property capacity -sum | % {[math]::round(($_.sum / 1GB),2)}
  		}
  		catch	{
  			Add-Content -Path  $errorLog -Value "WMI Error for $($viProxyServer.Name) : $($_.Exception.Message)"
  			$memoryGB=-1
  		}
  		# create array item
  		# $viProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","TransportMode","FailoverToNetwork","UseSsl","IsAutoDetectAffinityRepositories","IsAutoVddkMode","IsAutoDetectDisks"')
  		$item = $viProxy.Name + "," + $viProxy.Options.MaxTasksCount + "," + $numCpu + "," + $memoryGB + "," + $viProxy.IsDisabled + "," + $viProxy.Options.TransportMode + "," + $viProxy.Options.FailoverToNetwork 			 + "," + $viProxy.Options.UseSsl + "," + $viProxy.Options.IsAutoDetectAffinityRepositories  + "," + $viProxy.Options.IsAutoVddkMode  + "," + $viProxy.Options.IsAutoDetectDisks
  		$viProxyArray += $item
  	}
  	$viProxyArray | foreach { Add-Content -Path $csvFile -Value $_ }
  }
}

function checkProxyHv($config, $hvProxyList, $csvFile) {
  $hvProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","Type","IsAutoDetectVolumes"')
  if (!$hvProxyList) {
  	Write-Host -foreground white "...No Hyper-V proxy found"
  	Add-Content -Path  $csvFile -Value "...No Hyper-V proxy found"
  } else {
  	Write-Host "...checking Hyper-V proxies"
  	Write-Host ""
  	foreach ($hvProxy in $hvProxyList) {
  		$numCpu = 0
  		Write-Host -foreground white "proxy: " $hvProxy.Name
  		Write-Host -foreground yellow " MaxTasksCount: " $hvProxy.MaxTasksCount
  		if ($hvProxy.IsDisabled -match "True") {
  			Write-Host -foreground red "Proxy is disabled"
  		}
  		if ($hvProxy.Type -notmatch $config.Configuration.Proxies.HvProxy.Type)	{
  			Write-Host -foreground red " ProxyType: " $hvProxy.Type "expected " $config.Configuration.Proxies.HvProxy.Type
  		}
  		if ($hvProxy.Options.IsAutoDetectVolumes -notmatch $config.Configuration.Proxies.HvProxy.IsAutoDetectVolumes)	{
  			Write-Host -foreground red " ProxyType: " $hvProxy.Options.IsAutoDetectVolumes "expected " $config.Configuration.Proxies.HvProxy.IsAutoDetectVolumes
  		}
  		Write-Host ""

  		# get server name where proxy role is installed
  		$hvProxyServer = Get-VBRServer | Where {$_.Id -match $hvProxy.HostId}
  		# get cpu and memory
  		try	{
  			Get-WmiObject Win32_Processor -ea stop -ComputerName $hvProxyServer.Name -Property numberOfCores | Select-Object -Property numberOfCores| foreach-object {$numCpu += $_.numberOfCores }
  		}
  		catch {
  			Add-Content -Path  $errorLog -Value "WMI Error for $($hvProxyServer.Name) : $($_.Exception.Message)"
  			$numCpu=-1
  		}
  		try	{
  			$memoryGB = Get-WmiObject CIM_PhysicalMemory -ComputerName $hvProxyServer.Name  -ea stop | Measure-Object -Property capacity -sum | % {[math]::round(($_.sum / 1GB),2)}
  		}
  		catch	{
  			Add-Content -Path  $errorLog -Value "WMI Error for $($hvProxyServer.Name) : $($_.Exception.Message)"
  			$memoryGB=-1
  		}
  		# create array item
  		# $hvProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","Type","IsAutoDetectVolumes"')
  		$item = $hvProxy.Name + "," + $hvProxy.MaxTasksCount + "," + $numCpu + "," + $memoryGB + "," + $hvProxy.IsDisabled + "," + $hvProxy.Type + "," + $hvProxy.Options.IsAutoDetectVolumes
  		$hvProxyArray += $item

  	}
  	$hvProxyArray | foreach { Add-Content -Path  $csvFile -Value $_ }
  }
}

function checkWANAcc($config, $wanAccList, $csvFile) {
  $wanAccArray = @('"Name","ServerName","numCPU","memoryGB"')
  if (!$wanAccList) {
  	Write-Host -foreground white "...No WAN accelerator found"
  	Add-Content -Path  $csvFile -Value "...No WAN accelerator found"
  } else {
  	Write-Host "...checking WAN accelerator"
  	Write-Host ""
  	foreach ($wanAcc in $wanAccList) {
  		$numCpu = 0
  		Write-Host -foreground white "WAN Accelerator: " $wanAcc.Name

  		Write-Host ""

  		# get server name where proxy role is installed
  		$wanAccServer = Get-VBRServer | Where {$_.Id -match $wanAcc.HostId}

  		try	{
  			Get-WmiObject Win32_Processor -ea stop -ComputerName $wanAccServer.Name -Property numberOfCores | Select-Object -Property numberOfCores| foreach-object {$numCpu += $_.numberOfCores }
  		}
  		catch	{
  			Add-Content -Path  $errorLog -Value "WMI Error for $($wanAccServer.Name) : $($_.Exception.Message)"
  			$numCpu=-1
  		}
  		try	{
  			$memoryGB = Get-WmiObject CIM_PhysicalMemory -ComputerName $wanAccServer.Name  -ea stop | Measure-Object -Property capacity -sum | % {[math]::round(($_.sum / 1GB),2)}
  		}
  		catch {
  			Add-Content -Path  $errorLog -Value "WMI Error for $($wanAccServer.Name) : $($_.Exception.Message)"
  			$memoryGB=-1
  		}
  		# create array item
  		# $wanAccArray = @('"Name","ServerName","numCPU","memoryGB"')
  		$item = $wanAccServer.Name + "," + $wanAccServer.Name + "," + $numCpu + "," + $memoryGB
  		$wanAccArray += $item
  	}
  	$wanAccArray | foreach { Add-Content -Path  $csvFile -Value $_ }
  }
}

function checkBackupJob($config, $allJobs, $csvFile) {
  $jobsArray = @('"Name","NumberOfVms","JobSizeGB"')
  foreach ($job in $allJobs) {
  	if ($job.JobType -notmatch "BackupSync"){
  		$totalVMs = 0
  		$jobSize = 0
  		$jvm = ""
  		$objects = $job.GetObjectsInJob()

  		foreach ($object in $objects)	{
  			$type = $object.GetObject().Type
  			if ($type -eq "VM")	{
  				$totalVMs++
  			} elseif ($type -eq "Host")	{
  				$jvm = Find-VBRViEntity -HostsAndClusters -Server (Get-VBRServer) | Where { $_.VmHostName -eq $object.Name }
  			} elseif ($type -eq "Directory") {
  				$jvm = Find-VBRViEntity -VMsAndTemplates -Server (Get-VBRServer) | Where { $_.VmFolderName -eq $object.Name }
  			} else {
  				Write-Host -foreground red "... skipping type " $type
  			}
  		}

  		foreach ($vm in $jvm) {
  			$totalVMs++
  		}
  		# VM number correction
  		$totalVMs--
  		# job size
  		$jobSize = [math]::round($job.Info.includedSize/1GB - $job.Info.excludedSize/1GB,2)
  		Write-Host $job.Name $totalVMs $jobSize"GB"
  		#$jobsArray = @('"Name","NumberOfVms","JobSizeGB"')
  		$item = $job.Name + "," + $totalVMs + "," + $jobSize
  		$jobsArray += $item
  	}
  }
  $jobsArray | foreach { Add-Content -Path  $csvFile -Value $_ }
}

function checkBackupCopyJob($config, $allJobs, $csvFile) {
  $copyJobsArray = @('"Name","JobSizeGB"')
  Write-Host ""
  Write-Host -foreground white "... calculating backup job size in GB "

  # check backup copy job sizes
  foreach ($job in $allJobs) {
  	$jobSize = 0
  	if ($job.JobType -match "BackupSync")	{
  		$jobSize = [math]::round($job.Info.includedSize/1GB - $job.Info.excludedSize/1GB,2)
  		Write-Host  $job.Name $jobSize"GB"
  		#$copyJobsArray = @('"Name","JobSizeGB"')
  		$item = $job.Name + "," + $jobSize
  		$copyJobsArray += $item
  	}
  }
  if ($copyJobsArray.Length -gt 1) {
  	$copyJobsArray | foreach { Add-Content -Path  $csvFile -Value $_ }
  } else {
  	Write-Host -foreground red "...no backup copy jobs are configured"
  }
}

# End function definitions

$configFileName = "config.xml"
$configFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\"+$configFileName
[xml]$configFileContent = Get-Content $configFile
$errorLog = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\hc_error.log"

# Connect backup server
Write-Host -foreground white "...connecting backup server"
ConnectVBR -config $configFileContent

# Check VBR configuration backup
Write-Host -foreground white "...checking VBR configuration status"
checkVBRConfigJob -config $configFileContent

# Get all jobs from VBR servers
$allJobs = Get-VBRJob
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\backupWindowFile.csv"
checkBackupWindow -config $configFileContent -allJobs $allJobs -csvFile $csvFile

# Check SOBR - PolicyType, MaxTaskCount, OneBackupFilePerVm, IsRotatedDriveRepository, HasBackupChainLengthLimitation, IsSanSnapshotOnly, IsDedupStorage, SplitStoragesPerVm
$sobrList =  Get-VBRBackupRepository -ScaleOut
$csvFileParent = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\SobrFile.csv"
$csvFileChild = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\SobrExtentFile.csv"
checkSOBR -config $configFileContent -sobrList $sobrList -csvFileParent $csvFileParent -csvFileChild $csvFileChild

# Check repositories
$repoList = Get-VBRBackupRepository
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\repoFile.csv"
checkRepo -config $configFileContent -sobrList $repoList -csvFile $csvFile

# Check proxy - VMware
$viProxyList = Get-VBRViProxy
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\viProxyFile.csv"
checkProxyVi -config $configFileContent -viProxyList $viProxyList -csvFile $csvFile

# Check proxy - Hyper-V
$hvProxyList = Get-VBRHvProxy
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\hvProxyFile.csv"
checkProxyHv -config $configFileContent -hvProxyList $hvProxyList -csvFile $csvFile

# Check WAN accelerator
$wanAccList = Get-VBRWANAccelerator
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\wanAccFile.csv"
checkWANAcc -config $configFileContent -wanAccList $wanAccList -csvFile $csvFile

# Check jobs
# Check number of VMs per job - no BCJ
# foreach ($job in Get-VBRBackup){ Write-Host $job.Name $job.vmCount } - looks at all backup files in the repository
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\jobsFile.csv"
checkBackupJob -config $configFileContent -allJobs $allJobs -csvFile $csvFile

# Check Copy Jobs number of VMs per job
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\copyJobsFile.csv"
checkBackupCopyJob -config $configFileContent -allJobs $allJobs -csvFile $csvFile
