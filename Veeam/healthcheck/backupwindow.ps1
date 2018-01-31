

$BackupWindowStart="10:00PM"
$BackupWindowStop="4:00AM"
Write-Host -foreground yellow "Backup window interval is" $BackupWindowStart "to" $BackupWindowStop

Get-VBRJob | ForEach-Object {
	if ($_.ScheduleOptions.NextRun) {
			$NextRunTime = [datetime]$_.ScheduleOptions.NextRun
			$NextRunTime = $NextRunTime.ToShortTimeString()
			if ((New-TimeSpan -Start $NextRunTime -End $BackupWindowStart).TotalMinutes -gt 0 -and (New-TimeSpan -Start $NextRunTime -End $BackupWindowStop).TotalMinutes -lt 0) {
				Write-Host -foregroundcolor red  $_.Name $NextRunTime} else {Write-Host $_.Name $NextRunTime
				} 
		}
}
