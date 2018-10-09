$storedBackups = Get-VBRBackup -Name "VMware - Backup of many VMs in Hot-add mode"
foreach ($job in $storedBackups) {
	$fullHash = @{}
	$incHash = @{}
	$fullBackupSize = 0
	$incBackupSize = 0
	$dataSize = 0

	$restorePoints = $job.GetAllStorages() | sort CreationTime -descending
	foreach ($rp in $restorePoints)	{
		if ($rp.IsFull -eq "True") {
			$fullBackupSize += [long]($rp.Stats.BackupSize/1GB)

			$rpSize = [long]($rp.Stats.BackupSize/1GB)
			$newHash = @{}
			$newHash.Add("rpSize", $rpSize)
			$newHash.Add("rpDate", $rp.CreationTimeUtc)

			$fullHash.Add($rp.Id,$newHash)

		} else {
			$incBackupSize += [long]($rp.Stats.BackupSize/1GB)

			$rpSize = [long]($rp.Stats.BackupSize/1GB)
			$newHash = @{}
			$newHash.Add("rpSize", $rpSize)
			$newHash.Add("rpDate", $rp.CreationTimeUtc)

			$incHash.Add($rp.Id,$newHash)

		}
	}

	Write-Host "Backup Job Name: " $job.Name
	Write-host "Number of Full RPs: " $fullHash.Count
	Write-host "Total Size of Full backup: " $fullBackupSize "GB"
	Write-host "Number of Full RPs: " $incHash.Count
	Write-host "Total Size of Full backup: " $incBackupSize "GB"

}

# $restorePoints = $backup.GetAllStorages() | sort CreationTime -descending



###############################################
################## test only ##################
###############################################
#
#
# $storedBackups = Get-VBRBackup -Name "Windows - Workstations backup policy - DEMO-WS-D0E0D6B"
# foreach ($backup in $storedBackups) {
# 	$incBackupSize = 0;	$rpSize = 0;	$hashes = @(); 	$vmNames = @()
#
# 	$restorePoints = $backup.GetAllStorages() | sort CreationTime -descending
#
# 	foreach ($r in $restorePoints) {
# 		$vmNames += $r.partialpath.Elements.Split(".")[0]
# 	}
# 	$vmNames = $vmNames | select -uniq
#
# 	foreach ($v in $vmNames) {
# 		foreach ($r in $restorePoints) {
# 			if ($r.PartialPath -like "$v*") {
# 				$rpSize = [long]($r.Stats.BackupSize)
# 				$hash = New-Object PSObject -property @{Id=$r.Id;ObjectId=$r.ObjectId;IsFull=$r.IsFull;CreationTimeUtc=$r.CreationTimeUtc;Size=$rpSize}
# 				Write-host $r.Id $r.ObjectId $r.IsFull
# 				$hashes += $hash
# 			}
# 		}
# 	}
# 	#$hashes | Sort-Object -Property CreationTimeUtc | Select-Object -Last 1 | Where {$_.IsFull -match "False" }
# 	$fullRPs = $hashes | Sort-Object -Property CreationTimeUtc | Select-Object | Where {$_.IsFull -match "True" }
# 	$fullRPs  | Sort-Object -Property CreationTimeUtc | Select-Object -Last 1
# }
# # foreach ($kvp in $incHash.GetEnumerator()) {Write-host $kvp.Key $kvp.Value.rpDate $kvp.Value.rpSize "GB"}
# #$storedBackups.JobId = f5a5286f-d177-4efd-b505-36e2b0405edc
# #$backupJob = Get-VBRJob | Select-Object | Where {$_.Id -match "f5a5286f-d177-4efd-b505-36e2b0405edc"}

# get last restore point for a particular VM
# $storedBackups = Get-VBRBackup -Name "Windows - Workstations backup policy - DEMO-WS-D0E0D6B"
# $storedBackups = Get-VBRBackup -Name "VMware - Backup of many VMs in Network mode"
