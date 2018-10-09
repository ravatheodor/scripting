<#
    .SYNOPSIS
    custom report for snapshot only backups

    .DESCRIPTION


    .EXAMPLE


    .NOTES
    Version: 0.1
    Author: Razvan Ionescu
    Last Updated: April 2018

    Requires:
    Veeam Backup & Replication v9.5 Update 3

#>
# parameters
$volumeName = "demo_nfs"
$storageHost = "pdcstor12"

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

function checkBackupJob($config, $allJobs, $csvFile) {
  $jobsArray = @('"Name","NumberOfVms","JobSizeGB"')
  foreach ($job in $allJobs) {
  	if ($job.JobType -notmatch "BackupSync"){
      Write-Host " ### processing job:" $job.Name
  		$totalVMs = 0
  		$jobSize = 0
  		$jvm = ""
  		$objects = $job.GetObjectsInJob()
      $tagPathArray = @()
      $excludedVmArray = @()

  		foreach ($object in $objects)	{
        # $type = $object.GetObject().Type
        $type = $object.GetObject().ViType
        $platform = $object.GetObject().Platform.Platform
        if ($object.Type -eq "Include") {
    			if (($platform -eq "EHyperV" -and ($type -eq "VM" -or $type -eq "CSV")) -or ($platform -eq "EVmware" -and $type -eq "VirtualMachine"))	{
    				$totalVMs++
    			} elseif ($type -eq "Datastore") {
            $dsName = $object.Name
            $jvm = Find-VBRViEntity -DatastoresAndVMs -Server (Get-VBRServer) | Where { $_.Type -eq "VM" -and $_.Path -like "*$dsName*" }
          } elseif ($type -eq "Host")	{
    				$jvm = Find-VBRViEntity -HostsAndClusters -Server (Get-VBRServer) | Where { $_.VmHostName -eq $object.Name }
    			} elseif ($type -eq "Folder") {
    				$jvm = Find-VBRViEntity -VMsAndTemplates -Server (Get-VBRServer) | Where { $_.VmFolderName -eq $object.Name }
    			} else {
    				Write-Host -foreground red "... skipping type " $type
    			}
        } elseif ($object.Type -eq "Exclude") {
          #check exclusions by tags
          if ($type -eq "Tag") {
            $tagPathArray += $object.Location
          } elseif ($type -eq "VirtualMachine") {
            $excludedVmArray += $object.Name
          }
        } else {
          Write-Host -foreground red "... skipping Object type " $object.Type
        }
  		}

      foreach ($tagPath in $tagPathArray){
          Write-Host " >>> exclusion tag" $tagPath
          # $tagPath = (Find-VBRViEntity -Tags -name "Exclude from backups").Path
          $excludedVM = Find-VBRViEntity -Tags | where {$_.Type -eq "VM" -and $_.path -like "$tagPath*"}
          $excludedVmArray += $excludedVM.Name
      }
      #check for excluded VMs
  		foreach ($vm in $jvm) {
        if ($excludedVmArray -notcontains $vm.Name) {
    			$totalVMs++
          # Write-Host " " $vm.Name
        }
        else {
          Write-Host -foreground yellow " found excluded VM:" $vm.Name
        }
  		}
  		# VM number correction
      if (($platform -eq "EHyperV" -and $type -eq "VM") -or ($platform -eq "EVmware" -and $type -eq "VirtualMachine") )	{
  		    $totalVMs--
      }

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



$snap = Get-NetAppSnapshot
foreach ($s in $snap) {$s.Id}

$vols = Get-NetAppVolume
foreach ($v in $vols) {$v.Id}

$job = Get-VBRJob -Name "VMware - Backup from IBM Snapshot"
$job = Get-VBRJob -Name "VMware - Create IBM Snapshot"
$job = Get-VBRJob -Name "VMware - Backup in Hot-add mode"
$job = Get-VBRJob -Name "Hyper-V - Replication"

$job = Get-VBRJob -Name "VMware - Create Nimble Snapshot"
$job = Get-VBRJob -Name "VMware - Backup from HyperFlex Snapshot"

$job = Get-VBRJob -Name "VMware - Create NetApp Snapshot and send to SnapVault"
$objects = $job.GetObjectsInJob()
foreach ($object in $objects) {
  $object.Object.Info
  }

# $vol | Get-NetAppSnapshot | Where {$_.Name -like "VeeamSourceSnapshot*"} | Sort-Object -Property CreationTimeUtc | Select -last 1

$object.GetObject().ViType
$object.GetObject().Platform.Platform

$dsName = $object.Name
$jvm = Find-VBRViEntity -DatastoresAndVMs -Server (Get-VBRServer) | Where { $_.Path -like "*$dsName*" }

# EVmware EHyperV

$tagPath = (Find-VBRViEntity -Tags -name "Exclude from backups").Path
Find-VBRViEntity -Tags | where {$_.Type -eq "VM" -and $_.path -like "$tagPath*"} | select name


Find-VBRViEntity  -Server (get-vbrserver -Name vc1.democenter.int) -Tags -Name "Exclude from backups"


# ConnHostId : 25fb843d-92a3-45d4-836c-0531afe4df9b
# ConnHost   : Veeam.Backup.Core.Common.CHost
# Type       : Tag
# Reference  : urn:vmomi:InventoryServiceTag:7f87f11f-767a-4c86-824f-bffed8a4afe2:GLOBAL
# TagQsId    : urn:vmomi:InventoryServiceTag:7f87f11f-767a-4c86-824f-bffed8a4afe2:GLOBAL
# Id         : 25fb843d-92a3-45d4-836c-0531afe4df9b_urn:vmomi:InventoryServiceTag:7f87f11f-767a-4c86-824f-bffed8a4afe2:GLOBAL
# Name       : Exclude from backups
# Path       : vc1.democenter.int\Veeam Backup\Exclude from backups
#
#
