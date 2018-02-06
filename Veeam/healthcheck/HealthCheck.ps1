Param (
    [string]$Configuration = "config.xml",
    [switch]$Touch
)


$configFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\"+$Configuration
[xml]$config = Get-Content $configFile

$errorLog = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\hc_error.log"

<#
Disconnect-VBRServer -ErrorAction SilentlyContinue
try
{
	if ($config.Configuration.Username -eq "USERNAME")
	{
		$vbrPsCredentials = Get-Credential -Message "Please enter username and password for connecting to VBR server"
		Connect-VBRServer -Server $config.Configuration.Server -Credential $vbrPsCredentials
	}
	else
	{
		Connect-VBRServer -Server $config.Configuration.Server -User $config.Configuration.Username -Password $config.Configuration.Password
	}
}
catch
{
    Write-Output "Failed to connect to VBR server"
    exit
}
#>

# Check VBR configuration backup
Write-Host -foreground white "...checking VBR configuration status"
$vbrConfigJob = Get-VBRConfigurationBackupJob
if ($vbrConfigJob.Enabled -match $config.Configuration.GeneralConfiguration.ConfigurationBackup.Enabled)
{
	Write-Host -foregroundcolor yellow "VBR Configuration set to" $vbrConfigJob.Enabled
} else
{
	Write-Host -foregroundcolor red "VBR Configuration set to" $vbrConfigJob.Enabled "expected" $config.Configuration.GeneralConfiguration.ConfigurationBackup.Enabled
}
if (($vbrConfigJob.Enabled -match "True") -And ($vbrConfigJob.EncryptionOptions.Enabled -match $config.Configuration.GeneralConfiguration.ConfigurationBackup.IsEncrypted))
{
	Write-Host -foregroundcolor yellow "VBR Configuration encryption set to" $vbrConfigJob.EncryptionOptions.Enabled
} else 
{
	Write-Host -foregroundcolor red "VBR Configuration encryption set to" $vbrConfigJob.EncryptionOptions.Enabled "expected" $config.Configuration.GeneralConfiguration.ConfigurationBackup.IsEncrypted
}
Write-Host ""

# Get all jobs from VBR servers
$allJobs = Get-VBRJob

# Check backup window
if ($config.Configuration.BackupJobs.BackupWindow.Enabled -match "True")
{
	Write-Host -foreground white "...checking backup window"
	Write-Host -foreground white "Backup window is " $config.Configuration.BackupJobs.BackupWindow.Start "to" $config.Configuration.BackupJobs.BackupWindow.Stop
	foreach ($job in $allJobs) 
	{
		if ($job.ScheduleOptions.NextRun)
		{
			$nextRunTime = [datetime]$job.ScheduleOptions.NextRun
			$nextRunTime = $nextRunTime.ToShortTimeString()
			if ((New-TimeSpan -Start $nextRunTime -End $config.Configuration.BackupJobs.BackupWindow.Start).TotalMinutes -gt 0 -and (New-TimeSpan -Start $nextRunTime -End $config.Configuration.BackupJobs.BackupWindow.Stop).TotalMinutes -lt 0)
			{
				Write-Host -foregroundcolor red  $job.Name $nextRunTime
			} <#else 
			{
				Write-Host -foregroundcolor yellow $job.Name $nextRunTime
			} #>
		}
	}
}

# Check SOBR - PolicyType, MaxTaskCount, OneBackupFilePerVm, IsRotatedDriveRepository, HasBackupChainLengthLimitation, IsSanSnapshotOnly, IsDedupStorage, SplitStoragesPerVm
$sobrArray = @('"SobrName","PolicyType","UsePerVMBackupFiles"')
$csvFileParent = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\SobrFile.csv"
		
$sobrExtentArray = @('"SobrName","Name","MaxTaskCount","numCPU","memoryGB","TotalSizeGB","FreeSpaceGB","OptimizeBlockAlign","Uncompress","OneBackupFilePerVm","IsAutoDetectAffinityProxies","IsRotatedDriveRepository","IsSanSnapshotOnly","HasBackupChainLengthLimitation","IsDedupStorage","SplitStoragesPerVm"')
$csvFileChild = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\SobrExtentFile.csv"

Write-Host ""
$sobrList = Get-VBRBackupRepository -ScaleOut
if (!$sobrList)
{
	Write-Host -foreground white "...No SoBR found on" $config.Configuration.Server
} else 
{
	Write-Host "...checking SoBR "
	Write-Host ""
	foreach ($sobr in $sobrList)
	{
		Write-Host -foreground white "SoBR: " $sobr.Name
		Write-Host -foreground yellow "Policy type:" $sobr.PolicyType 
		Write-Host -foreground yellow "per VM backup files:" $sobr.UsePerVMBackupFiles
		Write-Host ""
			
		foreach ($extent in $sobr.Extent)
		{
			$numCpu = 0
			Write-Host -foreground yellow "extent name: " $extent.Repository.Name
			# Check parameters that should be False for SoBR
			if ($extent.Repository.IsRotatedDriveRepository -match "True")
			{
				Write-Host -foreground red " IsRotatedDriveRepository: " $extent.Repository.IsRotatedDriveRepository
			} 
			if ($extent.Repository.IsSanSnapshotOnly -match "True")
			{
				Write-Host -foreground red " IsSanSnapshotOnly: " $extent.Repository.IsSanSnapshotOnly
			} 
			if ($extent.Repository.HasBackupChainLengthLimitation -match "True")
			{
				Write-Host -foreground red " HasBackupChainLengthLimitation: " $extent.Repository.HasBackupChainLengthLimitation
			} 
			if ($extent.Repository.IsDedupStorage -match "True")
			{
				Write-Host -foreground red " IsDedupStorage: " $extent.Repository.IsDedupStorage
			} 
			if ($extent.Repository.SplitStoragesPerVm -match "True")
			{
				Write-Host -foreground red " SplitStoragesPerVm: " $extent.Repository.SplitStoragesPerVm
			} 
			# Check configuration of the extent
			Write-Host -foreground yellow " Max concurrent tasks: " $extent.Repository.Options.MaxTaskCount
			Write-Host -foreground yellow " Align backup file data blocks : " $extent.Repository.Options.OptimizeBlockAlign
			Write-Host -foreground yellow " Decompress backup data: " $extent.Repository.Options.Uncompress
			Write-Host -foreground yellow " User per-VM backup file : " $extent.Repository.Options.OneBackupFilePerVm
			Write-Host -foreground yellow " Proxy affinity auto  : " $extent.Repository.Options.IsAutoDetectAffinityProxies
			Write-Host ""
		
			# get server name where repo role is installed
			$repoServer = Get-VBRServer | Where {$_.Id -match $extent.Repository.Info.HostId}
			
			# get cpu and memory - windows repo only
			try
			{
				Get-WmiObject Win32_Processor -ea stop -ComputerName $repoServer.Name -Property numberOfCores | Select-Object -Property numberOfCores| foreach-object {$numCpu += $_.numberOfCores }
			}
			catch
			{
				Add-Content -Path  $errorLog -Value "WMI Error for $($repoServer.Name) : $($_.Exception.Message)"
				$numCpu=-1
			}
			try
			{
				$memoryGB = Get-WmiObject CIM_PhysicalMemory -ComputerName $repoServer.Name  -ea stop | Measure-Object -Property capacity -sum | % {[math]::round(($_.sum / 1GB),2)}
			}
			catch
			{
				Add-Content -Path  $errorLog -Value "WMI Error for $($repoServer.Name) : $($_.Exception.Message)"
				$memoryGB=-1
			}			
			# create array item 
			#$sobrExtentArray = @('"SobrName","Name","MaxTaskCount","numCPU","memoryGB","TotalSizeGB","FreeSpaceGB","OptimizeBlockAlign","Uncompress","OneBackupFilePerVm","IsAutoDetectAffinityProxies","IsRotatedDriveRepository","IsSanSnapshotOnly","HasBackupChainLengthLimitation","IsDedupStorage","SplitStoragesPerVm"')
			$item = $sobr.Name + "," + $extent.Repository.Name + "," + $extent.Repository.Options.MaxTaskCount + "," + $numCpu + "," + $memoryGB + "," + [math]::Round(($extent.Repository.Info.CachedTotalSpace)/(1024*1024*1024),1) + "," + [math]::Round(($extent.Repository.Info.CachedFreeSpace)/(1024*1024*1024),1) + "," + $extent.Repository.Options.OptimizeBlockAlign + "," + $extent.Repository.Options.Uncompress + "," + $extent.Repository.Options.OneBackupFilePerVm + "," + $extent.Repository.Options.IsAutoDetectAffinityProxies + "," + $extent.Repository.IsRotatedDriveRepository + "," + $extent.Repository.IsSanSnapshotOnly + "," + $extent.Repository.HasBackupChainLengthLimitation + "," + $extent.Repository.IsDedupStorage + "," + $extent.Repository.SplitStoragesPerVm  
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

# Check repository

# Check proxy - VMware
$viProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","TransportMode","FailoverToNetwork","UseSsl","IsAutoDetectAffinityRepositories","IsAutoVddkMode","IsAutoDetectDisks"')
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\viProxyFile.csv"

$viProxyList = Get-VBRViProxy
if (!$viProxyList) 
{
	Write-Host -foreground white "...No VMware proxy found" 
	Add-Content -Path  $csvFile -Value "...No VMware proxy found" 
} else 
{
	Write-Host "...checking VMware proxies"
	Write-Host ""
	foreach ($viProxy in $viProxyList)
	{
		$numCpu = 0
		Write-Host -foreground white "proxy: " $viProxy.Name
		Write-Host -foreground yellow "MaxTasksCount: " $viProxy.Options.MaxTasksCount
		if ($viProxy.IsDisabled -match "True")
		{
			Write-Host -foreground red "Proxy is disabled"
		}
		if ($viProxy.Options.TransportMode -notmatch $config.Configuration.Proxies.ViProxy.TransportMode)
		{
			Write-Host -foreground red " TransportMode: " $viProxy.Options.TransportMode "expected " $config.Configuration.Proxies.ViProxy.TransportMode
		}
		if ($viProxy.Options.FailoverToNetwork -notmatch $config.Configuration.Proxies.ViProxy.FailoverToNetwork)
		{
			Write-Host -foreground red " FailoverToNetwork: " $viProxy.Options.FailoverToNetwork "expected " $config.Configuration.Proxies.ViProxy.FailoverToNetwork
		}	
		if ($viProxy.Options.UseSsl -notmatch $config.Configuration.Proxies.ViProxy.UseSsl)
		{
			Write-Host -foreground red " UseSsl: " $viProxy.Options.UseSsl "expected " $config.Configuration.Proxies.ViProxy.UseSsl
		}		
		if ($viProxy.Options.IsAutoDetectAffinityRepositories -notmatch $config.Configuration.Proxies.ViProxy.IsAutoDetectAffinityRepositories)
		{
			Write-Host -foreground red " IsAutoDetectAffinityRepositories: " $viProxy.Options.IsAutoDetectAffinityRepositories
		}
		if ($viProxy.Options.IsAutoVddkMode -notmatch $config.Configuration.Proxies.ViProxy.IsAutoVddkMode)
		{
			Write-Host -foreground red " IsAutoVddkMode: " $viProxy.Options.IsAutoVddkMode	
		}
		if ($viProxy.Options.IsAutoDetectDisks -notmatch $config.Configuration.Proxies.ViProxy.IsAutoDetectDisks)
		{
			Write-Host -foreground red " IsAutoDetectDisks: " $viProxy.Options.IsAutoDetectDisks
		}
		Write-Host ""
		
		# get server name where proxy role is installed
		$viProxyServer = Get-VBRServer | Where {$_.Id -match $viProxy.Info.HostId}

		try
		{
			Get-WmiObject Win32_Processor -ea stop -ComputerName $viProxyServer.Name -Property numberOfCores | Select-Object -Property numberOfCores| foreach-object {$numCpu += $_.numberOfCores }
		}
		catch
		{
			Add-Content -Path  $errorLog -Value "WMI Error for $($viProxyServer.Name) : $($_.Exception.Message)"
			$numCpu=-1
		}
		try
		{
			$memoryGB = Get-WmiObject CIM_PhysicalMemory -ComputerName $viProxyServer.Name  -ea stop | Measure-Object -Property capacity -sum | % {[math]::round(($_.sum / 1GB),2)}
		}
		catch
		{
			Add-Content -Path  $errorLog -Value "WMI Error for $($viProxyServer.Name) : $($_.Exception.Message)"
			$memoryGB=-1
		}
		# create array item 
		# $viProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","TransportMode","FailoverToNetwork","UseSsl","IsAutoDetectAffinityRepositories","IsAutoVddkMode","IsAutoDetectDisks"')
		$item = $viProxy.Name + "," + $viProxy.Options.MaxTasksCount + "," + $numCpu + "," + $memoryGB + "," + $viProxy.IsDisabled + "," + $viProxy.Options.TransportMode + "," + $viProxy.Options.FailoverToNetwork 			 + "," + $viProxy.Options.UseSsl + "," + $viProxy.Options.IsAutoDetectAffinityRepositories  + "," + $viProxy.Options.IsAutoVddkMode  + "," + $viProxy.Options.IsAutoDetectDisks 
		$viProxyArray += $item
	}
	$viProxyArray | foreach { Add-Content -Path  $csvFile -Value $_ } 
}


# Check proxy - Hyper-V
$hvProxyArray = @('"Name","MaxTasksCount","numCPU","memoryGB","IsDisabled","Type","IsAutoDetectVolumes"')
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\hvProxyFile.csv"

$hvProxyList = Get-VBRHvProxy
if (!$hvProxyList) 
{
	Write-Host -foreground white "...No Hyper-V proxy found" 
	Add-Content -Path  $csvFile -Value "...No Hyper-V proxy found" 
} else 
{
	Write-Host "...checking Hyper-V proxies"
	Write-Host ""
	foreach ($hvProxy in $hvProxyList)
	{
		$numCpu = 0
		Write-Host -foreground white "proxy: " $hvProxy.Name
		Write-Host -foreground yellow "MaxTasksCount: " $hvProxy.MaxTasksCount
		if ($hvProxy.IsDisabled -match "True")
		{
			Write-Host -foreground red "Proxy is disabled"
		}
		if ($hvProxy.Type -notmatch $config.Configuration.Proxies.HvProxy.Type)
		{
			Write-Host -foreground red " ProxyType: " $hvProxy.Type "expected " $config.Configuration.Proxies.HvProxy.Type
		}
		if ($hvProxy.Options.IsAutoDetectVolumes -notmatch $config.Configuration.Proxies.HvProxy.IsAutoDetectVolumes)
		{
			Write-Host -foreground red " ProxyType: " $hvProxy.Options.IsAutoDetectVolumes "expected " $config.Configuration.Proxies.HvProxy.IsAutoDetectVolumes
		}
		Write-Host ""
		
		# get server name where proxy role is installed
		$hvProxyServer = Get-VBRServer | Where {$_.Id -match $hvProxy.HostId}
		# get cpu and memory
		try
		{
			Get-WmiObject Win32_Processor -ea stop -ComputerName $hvProxyServer.Name -Property numberOfCores | Select-Object -Property numberOfCores| foreach-object {$numCpu += $_.numberOfCores }
		}
		catch
		{
			Add-Content -Path  $errorLog -Value "WMI Error for $($hvProxyServer.Name) : $($_.Exception.Message)"
			$numCpu=-1
		}
		try
		{
			$memoryGB = Get-WmiObject CIM_PhysicalMemory -ComputerName $hvProxyServer.Name  -ea stop | Measure-Object -Property capacity -sum | % {[math]::round(($_.sum / 1GB),2)}
		}
		catch
		{
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
