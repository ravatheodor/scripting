<#
    .SYNOPSIS
    vmData is an information gathering script for VMs

    .DESCRIPTION

    vmData gathers VM sizing information from a VMware environment
    It outputs logs all findings to csv files.

    .EXAMPLE
    .\vmData.ps1 -on
		.\vmData.ps1 -all

    .NOTES
    Version: 0.2
    Author: Razvan Ionescu
    Last Updated: March 2018

    Requires:
    vCenter Server and PowerCLI

#>

param(
	[Parameter(Mandatory=$true)][string]$PowerState
)

function Test-Parameters {
	param(
		[Parameter(Mandatory=$true)][string]$PowerState
	)
	Process {
		if("on","all" -NotContains $powerState.ToLower()) {
			Throw "`"$($powerState)`" is not a valid state. Please enter `"on`" or `"all`"."
		}
	}
}

function GetVMData($v) {
	$vmResMemory = [math]::Round($v.ExtensionData.ResourceConfig.MemoryAllocation.Reservation/1024,2)
	$vmMem = [math]::Round($v.MemoryGB,2)
	$vmSwap = ($vmMem - $vmResMemory)
	$vmUsedSpace = [math]::Round($v.UsedSpaceGB,2)
	$vmUsedSpaceNoSwap = [math]::Round($v.UsedSpaceGB,2) - ($vmMem - $vmResMemory) # removing swap space from calculations
	$vmProvSpace = [math]::Round($v.ProvisionedSpaceGB,2) # swap space included
	$vmName = $v.Name
	$vmNoDisks = ($v | Get-HardDisk).count

	$hash = New-Object PSObject -property @{Vm=$v.Name;NoDisks=$vmNoDisks;UsedSpaceNoSwap=$vmUsedSpaceNoSwap;UsedSpace=$vmUsedSpace;ProvSpace=$vmProvSpace}
	return $hash

}

Test-Parameters -PowerState $PowerState

$vmData = @('"Name","NoDisks","UsedSpaceGB(noSwap)","UsedSpaceGB","ProvisionedSpaceGB"')
$csvFile = ($MyInvocation.MyCommand.Path | Split-Path -Parent)+"\vmData.csv"

$totalUsedSpaceNoSwap = 0
$totalUsedSpace = 0
$totalNoDisks = 0

foreach ($v in get-vm) {
	# for all VMs (on and off) comment out the if statement
	if ($PowerState.ToLower() -match "on" -and $v.PowerState -match "PoweredOn") {
		$hash = GetVMData -v $v
		$item = $hash.Vm + "," + $hash.NoDisks + "," + $hash.UsedSpaceNoSwap + "," + $hash.UsedSpace + "," + $hash.ProvSpace
		$vmData += $item

		$totalUsedSpaceNoSwap += $hash.UsedSpaceNoSwap
		$totalUsedSpace += $hash.UsedSpace
		$totalNoDisks += $hash.NoDisks

	} elseif ($PowerState.ToLower() -match "all") {
		$hash = GetVMData -v $v
		$item = $hash.Vm + "," + $hash.NoDisks + "," + $hash.UsedSpaceNoSwap + "," + $hash.UsedSpace + "," + $hash.ProvSpace
		$vmData += $item

		$totalUsedSpaceNoSwap += $hash.UsedSpaceNoSwap
		$totalUsedSpace += $hash.UsedSpace
		$totalNoDisks += $hash.NoDisks
	}

}
$item = $totalNoDisks.ToString() + "," + $totalUsedSpaceNoSwap.ToString() + "," + $totalUsedSpace.ToString()
$vmData += $item
$vmData | foreach { Add-Content -Path  $csvFile -Value $_ }
