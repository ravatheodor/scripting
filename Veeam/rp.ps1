
<#
    .SYNOPSIS
    rp is is script that extracts last restore points for a job

    .DESCRIPTION

    rp looks for most recent incremental restore points
		and most recent full restore points of any VM in a job
		and it uses those values to calculate the total size of
		last incremental and last full for that job
		Does not process vCloud Director jobs, snapshot only jobs, cloud jobs

    .EXAMPLE
    .\rp.ps1

    .NOTES
    Version: 0.1
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

function CreateRPArray($v, $restorePoints) {
	$hashes = @()
	foreach ($r in $restorePoints) {
		if ($r.VmName -eq $v) {
			$rpSize = [long]($r.GetStorage().Stats.BackupSize)
			$hash = New-Object PSObject -property @{Vm=$v;Id=$r.Id;IsFull=$r.IsFull;CreationTimeUtc=$r.CreationTimeUtc;Size=$rpSize}
			$hashes += $hash
		}
	}
	return $hashes
}

function GetLastRP($v, $restorePoints, $type) {
	# $type can take values: LastInc, LastFull
	$hashes = @()
	$hashes = CreateRPArray -v $v -restorePoints $restorePoints
	if($type.ToLower() -match "lastinc") {
		# look for last incremental
		$lastRP = $hashes | Sort-Object -Property CreationTimeUtc | Select-Object -Last 1 | Where {$_.IsFull -match "False" }
		if (!$lastRP) {
			$lastRP = $hashes | Sort-Object -Property CreationTimeUtc | Select-Object -Last 2 | Where {$_.IsFull -match "False" }
		}
		return $lastRP
		# look for last full
	}	elseif($type.ToLower() -match "lastfull") {
			$hashes = $hashes | Sort-Object -Property CreationTimeUtc | Select-Object | Where {$_.IsFull -match "True" }
			$lastRP = $hashes | Sort-Object -Property CreationTimeUtc | Select-Object -Last 1
			return $lastRP
	} else {
		return $False
	}
}

# End function definitions

# connect to backup server

# [xml]$config='<?xml version="1.0" encoding="utf-8"?><Configuration Server="hq-vbr1.democenter.int" Username="USERNAME" Password="PASSWORD"></Configuration>'
# ConnectVBR -config $config

# get jobid for backup jobs - fitering out vCloud Director jobs;
$jobId=@()
$jobId = Get-VBRJob | Select -Property Name,Id,TargetType,BackupPlatform,ScheduleOptions | Where {$_.BackupPlatform -notmatch "EVcd"}
# get all backups
$storedBackups =  Get-VBRBackup
# search restore points only for existing backup jobs
foreach ($jId in $jobId) {
	if($jId.ScheduleOptions.NextRun) {
		#match backup job with backup on storage
		$backup = $storedBackups | Where {$_.JobId -match $jId.Id}
		if($backup) {
			Write-Host "...processing backups for:"$jId.Name
			$incBackupSize = 0
			$fullBackupSize = 0
			$rpSize = 0
			$hashesInc = @()
			$hashesFull =@()
			# get Restore points
			$restorePoints =  $backup | Get-VBRRestorePoint | sort CreationTimeUtc -descending
			$vmNames = @()
			# get VM name list
			foreach ($r in $restorePoints) {
				 $vmNames += $r.vmName
			}
			$vmNames = $vmNames | select -uniq
			# process incrementals
			foreach ($v in $vmNames) {
				$RP = GetLastRP -v $v -restorePoints $restorePoints -type "lastinc"
				if(!$RP) {
					break
				} else {
					$hashesInc += $RP
				}
			}
			# process fulls
			foreach ($v in $vmNames) {
				$RPfull = GetLastRP -v $v -restorePoints $restorePoints -type "lastfull"
				if(!$RPfull) {
					break
				 } else {
					$hashesFull += $RPfull
				 }
			}

			foreach ($kvp in $hashesInc.GetEnumerator()) {
				$rpSize = [math]::Round($kvp.Size/(1024*1024*1024),2)
				$incBackupSize += $rpSize
			}

			foreach ($kvp in $hashesFull.GetEnumerator()) {
				$rpSize = [math]::Round($kvp.Size/(1024*1024*1024),2)
				$fullBackupSize += $rpSize
			}

			$incBackupSize = [math]::Round($incBackupSize,2)
			$fullBackupSize = [math]::Round($fullBackupSize,2)
			Write-Host "  last incrementals size:" $incBackupSize"GB"
			Write-Host "  last fulls size:" $fullBackupSize"GB"
		}	else {
			Write-Host "...skipping:"$jId.Name
			Write-Host "  job target:"$jId.TargetType
		}
	}
}




foreach ($backup in Get-VBRBackup) {
  $vmNames = @()
  foreach ($rp in (Get-VBRRestorePoint -Backup $backup)) {
    $vmNames += $rp.vmName
  }
  $vmNames = $vmNames | select -uniq
  write-host $backup.Name -ForegroundColor yellow
  foreach ($vm in $vmNames) {
    Write-Host $vm "has" (get-VBRRestorePoint -Backup $backup -Name $vm).Count "restore points "
  }
}
