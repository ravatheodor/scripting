$Password = ConvertTo-SecureString "PASS" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential "DOMAIN\USER", $Password


$regclass = Get-WmiObject -Namespace "root\default" -list "StdRegProv" -computername "hq-vbr2.democenter.int" -Credential $credential

$regkey = 2147483650
$key = "Software\Veeam\Veeam Backup and Replication\"
$value =  "CorePath"

$installPath = $regclass.GetStringValue($regkey,$key,$value).sValue
$drive = Split-Path -Path $installPath -Qualifier
$path =  Split-Path -Path $installPath -NoQualifier


Get-WmiObject Win32_Directory -Filter 'Drive="C:" and Path ="\Program Files\Veeam\Backup and Replication\Backup\"' -computername "hq-vbr2.democenter.int" -Credential $credential
Get-WmiObject Win32_Directory -Filter 'Drive="C:"' -computername "hq-vbr2.democenter.int" -Credential $credential



$dllFile = Get-WmiObject -computername "hq-vbr1.democenter.int" -Credential $credential -Query "SELECT * FROM CIM_DataFile Where Drive='C:' and Path='\\Program Files\\Veeam\\Backup and Replication\\Backup\\Packages\\' and fileName='\VeeamDeploymentDll' and Extension='dll'" 

Get-WmiObject -computername "hq-vbr1.democenter.int" -Credential $credential -Class cim_datafile -Filter "Drive='C:' and  Path='\\Program Files\\Veeam\\Backup and Replication\\Backup\\Packages\\' and fileName='VeeamDeploymentDll' and Extension='dll'"
