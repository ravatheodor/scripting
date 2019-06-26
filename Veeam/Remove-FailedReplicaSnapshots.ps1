<#
    .SYNOPSIS
    Remove-FailedReplicaSnapshots is a script  for fixing failed replica VMs

    .DESCRIPTION 
    Script checks for failed VMs in each replica job based on a specific failure reason.
    For each failed replica VM  it deletes all snapshots and remaps the disks if they are 
    still pointing at the delta files. 

    Script needs to be connected to both VBR and vCenter Server.

    Snapshots are processed sequentially

    Inputs:
    $vbrServer = VBR server hostname or IP
    $vcServer = vCenter Server hostname or IP
    $replicaSuffix = replica VM name suffix - utilized to create replica VM name
    $status = replication job status - default is "Failed"
    $reason = replication failure reason - it searchs for "Detected an invalid snapshot configuration." errors

    .EXAMPLE
    .\Remove-FailedReplicaSnapshots.ps1

    .NOTES
    Version: 0.0.2
    Author: Razvan Ionescu
    Last Updated: June 2019

    Requires:
    Veeam Backup & Replication v9.5 Update 4
#>

# Parameters
$vbrServer = "vbr1"
$vcServer = "vc1"
$status = "Failed"
$reason = "Detected an invalid snapshot configuration."
$replicaSuffix = "_replicabeta"

# Connect to servers
Add-PSSnapIn -Name VeeamPSSnapin
Connect-VBRServer -Server $vbrServer
Connect-VIServer -Server $vcServer

# Log file
$cmdPath = $MyInvocation.MyCommand.Path | Split-Path -Parent
$runTime = Get-Date -format MMddyyyy_hhmmss
$logFile = $cmdPath + "\fixreplica_" + $runTime + ".log"
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}

$vmList = @()
# get failed replica VM names 
$jobs = Get-VBRJob  | Where {$_.JobType -eq "Replica"}
#$jobs = Get-VBRJob  -Name "Replication Job - ORCL"
foreach($job in $jobs)
{
	$session = $job.FindLastSession()
	if(!$session){continue;}
	$tasks = $session.GetTaskSessions() # $tasks.Info.Reason
	$tasks | foreach { 
        if (($_.Status -eq $status) -and ($_.Info.Reason -match $reason)) {
            Write-Host "$($_.Name) :  $($_.Status)"
            Add-Content -Path  $logFile -Value "$($_.Name) :  $($_.Status)"
            $vmList += $_.Name
            }
        }
}
Write-Host "`r`n`r`nTotal VMs found: $($vmList.Length)"
Add-Content -Path  $logFile -Value "`r`n`r`nTotal VMs found: $($vmList.Length)"
$vmList | foreach {
    # replica suffix 
    $replicaName = $_ + $replicaSuffix
    # delete all snapshots for failed replica VM
    try {
        Write-Host "`r`nProcessing snapshots for $($replicaName)"
        Add-Content -Path  $logFile -Value "`r`nProcessing snapshots for $($replicaName)"
        $replica = Get-VM -Name $replicaName -ea Stop
        $replica | Get-Snapshot -ea Stop | Sort-Object -Property Created | Select -First 1 | Remove-Snapshot -RemoveChildren -Confirm:$false -ea Stop
    } catch {
        Write-Host "ERR: $($_.Exception.ItemName) : $($_.Exception.Message)"
        Add-Content -Path  $logFile -Value "ERR: $($_.Exception.ItemName) : $($_.Exception.Message)"
    }
    # reconfigure replica VM disk mapping
    try {
        $disk = $replica |  Get-HardDisk 
        $disk | foreach {
            $diskPath = $_.Filename
            if ($diskPath -Match "-0000") {
                $diskPath = $_.Filename
                Write-Host " WARN: disk mismatch: $($diskPath)"
                Add-Content -Path  $logFile -Value " WARN disk mismatch: $($diskPath)"
                $sourceDisk = $diskPath.substring(0,$diskPath.length-12) + ".vmdk"
                Write-Host " Reconfiguring VM to use: $($sourceDisk)"
                Add-Content -Path  $logFile -Value " Reconfiguring VM to use: $($sourceDisk)"
                $datastore = Get-Datastore -Id $_.ExtensionData.Backing.Datastore
                if (Get-HardDisk -Datastore $datastore.Name -DatastorePath $sourceDisk) {
                    Remove-HardDisk -HardDisk $_ -Confirm:$false -ea stop
                    $newDisk = New-HardDisk -VM $replica -DiskPath $sourceDisk -ea Stop
                    Write-Host " Attached: $($newDisk.Filename)"
                    Add-Content -Path  $logFile -Value " Attached: $($newDisk.Filename)"
                } else {
                    Write-Host "WARN Could not find $($sourceDisk) on $($datastore.Name) "
                    Add-Content -Path  $logFile -Value "WARN: Could not find $($sourceDisk) on $($datastore.Name) "
                }
            }
        }
    } catch {
        Write-Host "ERR: $($_.Exception.ItemName) : $($_.Exception.Message)"
        Add-Content -Path  $logFile -Value "ERR: $($_.Exception.ItemName) : $($_.Exception.Message)"
    }
 }
