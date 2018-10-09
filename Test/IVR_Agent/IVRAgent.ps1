#Enable-PSRemoting
#Set-Item WSMan:\localhost\Client\TrustedHosts -Value "srv2.democenter.int"
#Enable-WSManCredSSP -Role client -DelegateComputer "srv2.democenter.int"

$privateSwName = "InternalNATSwitch" #Lab Isolated Network (HV Virtual Lab 1)
$hvHostName = "srv2.democenter.int" # 10.0.114.132
$phyServerName = "demo-server-1b7.veeam.lab" # VMW VM with VAW
$mountPath = "R:\HyperV\Volume\IVR" # "C:\HyperV\Volume\IVR"
#$hvVirtualLab = "HV Virtual Lab 1"

$server = Get-VBRServer -Type HvServer -Name $hvHostName
$rp = Get-VBRRestorePoint | Where {$_.VMName -like $phyServerName} | Sort-Object –Property CreationTime –Descending | Select -First 1
Start-VBREpInstantRecovery -RestorePoint $rp -Server $server -Path $mountPath  -PowerUp $True

#Get-VM -Name "demo-server-1b7.veeam.lab" -ComputerName "srv2.democenter.int"
#Get-VM  -ComputerName "hq-beta-hv2.veeam.lab"
Get-VMNetworkAdapter -VMName $phyServerName -ComputerName $hvHostName | Connect-VMNetworkAdapter -SwitchName $privateSwName
# tests
$tcpPort = 3389
Test-NetConnection -ComputerName $phyServerName -Port $tcpPort -InformationLevel "Detailed"
#Find-VSBHvVirtualLab -Server $server -Name $hvVirtualLab | Connect-VSBHvVirtualLab


$privateSwName = "Lab Isolated Network (HV Virtual Lab 1)" #Lab Isolated Network (HV Virtual Lab 1)
$hvHostName = "hq-beta-hv2" # 10.0.114.132
$phyServerName = "demo-server-1b7.veeam.lab" # VMW VM with VAW
$mountPath = "C:\HyperV\Volume\IVR" # "C:\HyperV\Volume\IVR"

# changed mount server for NTFS reporisotry to hq-vbr2
