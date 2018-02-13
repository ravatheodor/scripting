
# Check number of VMs per job - the hard way

$jobsArray = @('"Name","NumberOfVms"')
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\jobsFile.csv"

Write-Host -foreground white "... counting VMs in backup and replica jobs "

foreach ($job in Get-VBRJob)
{
	if ($job.JobType -notmatch "BackupSync")
	{	
		$totalVMs = 0
		$jvm = ""
		$objects = $job.GetObjectsInJob()
		
		foreach ($object in $objects)
		{
			$type = $object.GetObject().Type
			if ($type -eq "VM")
			{
				$totalVMs++
			} elseif ($type -eq "Host")
			{
				$jvm = Find-VBRViEntity -HostsAndClusters -Server (Get-VBRServer) | Where { $_.VmHostName -eq $object.Name }
			} elseif ($type -eq "Directory")	
			{
				$jvm = Find-VBRViEntity -VMsAndTemplates -Server (Get-VBRServer) | Where { $_.VmFolderName -eq $object.Name }
			} else 
			{
				Write-Host -foreground red "... skipping type " $type
			}
		}

		foreach ($vm in $jvm) {
			$totalVMs++
		}
		# VM number correction
		$totalVMs--
		Write-Host  $job.Name  $totalVMs
		#$jobsArray = @('"Name","NumberOfVms"')
		$item = $job.Name + "," + $totalVMs
		$jobsArray += $item 
	}
	
}
$jobsArray | foreach { Add-Content -Path  $csvFile -Value $_ } 

# check backup job size
