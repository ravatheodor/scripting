# backup copy job - run scripts pre/post


### backup managed by agent
$rp = Get-VBRRestorePoint | Where {$_.VMName -like "demo-server-55c.veeam.lab"} | Sort-Object –Property CreationTime –Descending | Select -First 1
$server = Get-VBRServer -Type Windows -Name "srv2.democenter.int"
$disks =  Get-VBRFilesInRestorePoint -RestorePoint $rp
Start-VBRRestoreVirtualDisks -RestorePoint $rp -Server $server -Path "R:\Agent Restored Disks" -RestoreDiskType Vhdx -RunAsync

#Start-VBREpInstantRecovery -RestorePoint $rp -Server $server -Path "R:\HyperV\Volume\IVR"  -PowerUp $False

# backup copy job for server - first disable backup job
# 4/26/2018 5:41:33 PM Warning    Reason: Item [Backup Copy Job Windows AgentD2018-04-26T000000.vbk] is locked by running session Backup Copy Job Windows Agent [Backup Copy]
$rp = Get-VBRRestorePoint | Where {$_.VMName -like "demo-server-1b7.veeam.lab"} | Sort-Object –Property CreationTime –Descending | Select -First 1
$server = Get-VBRServer -Type Windows -Name "srv2.democenter.int"
Start-VBRRestoreVirtualDisks -RestorePoint $rp -Server $server -Path "R:\Agent Restored Disks" -RestoreDiskType Vmdk  -RunAsync

# tested 27-04-2018
$server = Get-VBRServer -Type HvServer -Name "srv2.democenter.int"
Start-VBREpInstantRecovery -RestorePoint $rp -Server $server -Path "R:\HyperV\Volume\IVR"  -PowerUp $False

$rp = Get-VBRRestorePoint | Where {$_.VMName -like "demo-server-55c.veeam.lab"} | Sort-Object –Property CreationTime –Descending | Select -First 1
Start-VBREpInstantRecovery -RestorePoint $rp -Server $server -Path "R:\HyperV\Volume\IVR1"  -PowerUp $False

Get-VBRInstantRecovery | foreach {Stop-VBRInstantRecovery -InstantRecovery $_ -RunAsync}

########
### Start-VBREpInstantRecovery -RestorePoint $rp -Server $server -Path "R:\HyperV\Volume\IVR"  -PowerUp $False
#4/26/2018 6:47:52 PM Error    Failed to start mount agents
#4/26/2018 6:47:52 PM Error    Failed to modify guest OS settings
#4/26/2018 6:47:53 PM Error    Reason: Unsupported type Microsoft Windows Server of the Hyper-V host srv2.democenter.int


# New-VM -Name Win10VM -MemoryStartupBytes 4GB -BootDevice VHD -VHDPath .\VMs\Win10.vhdx -Path .\VMData -Generation 2 -Switch ExternalSwitch

New-VM -Name "demo-server-1b7_restored" -MemoryStartupBytes 1GB  -BootDevice VHD -VHDPath "R:\Agent Restored Disks\demo-server-1b7.veeam.lab_Disk0.vhdx" -Path "R:\Agent Restored Disks\" -Generation 1 -Switch "InternalNATSwitch" -ComputerName "srv2.democenter.int"
Add-VMHardDiskDrive -VMName "demo-server-1b7_restored" -Path "R:\Agent Restored Disks\demo-server-1b7.veeam.lab_Disk1.vhdx" -ComputerName "srv2.democenter.int"
Start-VM "demo-server-1b7_restored" -ComputerName "srv2.democenter.int"

# Demo LAB
# DEMO-SERVER-D1D
#
 Get-VBRRestorePoint | Where {$_.VMName -like "demo-server-d1d.veeam.lab"} | Sort-Object –Property CreationTime –Descending | foreach {Write-Host $_.GetBackup().Name " " $_.CreationTime}

# tested 27-04-2018 - DEMO LAB
 $rp = Get-VBRBackup -Name "Windows - Backup Copy to ExaGrid" | Get-VBRRestorePoint | Where {$_.VMName -like "demo-server-d1d.veeam.lab"} | Sort-Object –Property CreationTime –Descending  | Select -First 1
 $server = Get-VBRServer -Type HvServer -Name  "hq-hvc3-1"
 Start-VBREpInstantRecovery -RestorePoint $rp -Server $server -Path "C:\ClusterStorage\Volume1\IVR"  -PowerUp $False



 # Linux VM 10.0.114.123
# IVR not supported
$rp = Get-VBRRestorePoint | Where {$_.VMName -like "10.0.114.123"} | Sort-Object –Property CreationTime –Descending | Select -First 1
$server = Get-VBRServer -Type HvServer -Name "srv2.democenter.int"
Start-VBREpInstantRecovery -RestorePoint $rp -Server $server -Path "R:\HyperV\Volume\IVR"  -PowerUp $False
# Start-VBREpInstantRecovery : Failed to process RestorePoint 5a4eaa84-4e41-45cb-801b-5603e5c88e44. Platform type ELinuxPhysical is not supported

# export disks
$server = Get-VBRServer -Type Windows -Name "srv2.democenter.int"
Start-VBRRestoreVirtualDisks -RestorePoint $rp -Server $server -Path "R:\Agent Restored Disks" -RestoreDiskType Vhdx  -RunAsync

# Set-Item WSMan:\localhost\Client\TrustedHosts -Value "srv2.democenter.int"
# Enable-WSManCredSSP -Role client -DelegateComputer "srv2.democenter.int"
# disk order is disk2, then disk1 - works for VMW, not on Hyper-v
New-VM -Name "demo-linux-betalab-1" -MemoryStartupBytes 1GB  -BootDevice VHD -VHDPath "R:\Agent Restored Disks\10.0.114.123_Disk0.vhdx" -Path "R:\Agent Restored Disks\" -Generation 1 -Switch "InternalNATSwitch" -ComputerName "srv2.democenter.int"
Add-VMHardDiskDrive -VMName "demo-linux-betalab-1" -Path "R:\Agent Restored Disks\10.0.114.123_Disk2.vhdx" -ComputerName "srv2.democenter.int"
Add-VMHardDiskDrive -VMName "demo-linux-betalab-1" -Path "R:\Agent Restored Disks\10.0.114.123_Disk1.vhdx" -ComputerName "srv2.democenter.int"
Start-VM "demo-linux-betalab-1" -ComputerName "srv2.democenter.int"






New-VM -Name $vmName -MemoryStartupBytes $memSize -BootDevice VHD -VHDPath $vhdPath1 -Path $path -Generation 1 -Switch $ -ComputerName $server
Add-VMHardDiskDrive -VMName $vmName -Path $vhdPath2 -ComputerName $server
Start-VM $vmName -ComputerName $server
