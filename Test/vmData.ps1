$vmData = @('"Name","NoDisks","UsedSpaceGB(noSwap)","UsedSpaceGB","ProvisionedSpaceGB"')
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\vmData.csv"

$totalUsedSpaceNoSwap = 0
$totalUsedSpace = 0
$totalNoDisks = 0

foreach ($v in get-vm)
{
	# for all VMs (on and off) comment out the if statement
	if ($v.PowerState -match "PoweredOn")
	{
		$vmResMemory = [math]::Round($v.ExtensionData.ResourceConfig.MemoryAllocation.Reservation/1024,2)
		$vmMem = [math]::Round($v.MemoryGB,2)
		$vmSwap = ($vmMem - $vmResMemory)
		$vmUsedSpace = [math]::Round($v.UsedSpaceGB,2)
		$vmUsedSpaceNoSwap = [math]::Round($v.UsedSpaceGB,2) - ($vmMem - $vmResMemory) # removing swap space from calculations
		$vmProvSpace = [math]::Round($v.ProvisionedSpaceGB,2) # swap space included
		$vmName = $v.Name
		$vmNoDisks = ($v | Get-HardDisk).count

		$item = $v.Name + "," + $vmNoDisks + "," + $vmUsedSpaceNoSwap + "," + $vmUsedSpace + "," + $vmProvSpace
		$vmData += $item

		$totalUsedSpaceNoSwap += $vmUsedSpaceNoSwap
		$totalUsedSpace += $vmUsedSpace
		$totalNoDisks += $vmNoDisks

	}

}
$item = $totalNoDisks.ToString() + "," + $totalUsedSpaceNoSwap.ToString() + "," + $totalUsedSpace.ToString()
$vmData += $item
$vmData | foreach { Add-Content -Path  $csvFile -Value $_ }
