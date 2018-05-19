<#
    .SYNOPSIS
    add Linux computers to protection group

    .DESCRIPTION
    Adds computers to existing protection group using existing credentials or
    creates a new protection group, asks for credentials and adds computers
    to the new protection group

    variables:
    Name of the protection group (for new needs to be unique)
      $protectionGroupName = "Linux"
    array of computers to add (IP or FQDN)
      $newComputers = @("192.168.1.2","192.168.1.3")
    computer rescan hour (only daily implemented)
      $rescanTime = "17:30"

    .EXAMPLE
    .\ManagedVeeamAgentforLinux.ps1 -Method add
    .\ManagedVeeamAgentforLinux.ps1 -Method new

    .NOTES
    Version: 0.2
    Author: Razvan Ionescu
    Last Updated: May 2018

    Requires:
    Veeam Backup & Replication v9.5 Update 3

#>

param(
	[Parameter(Mandatory=$true)][string]$Method
)

$protectionGroupName = "CentOS laptops"
$newComputers = @("192.168.1.2","192.168.1.3","192.168.1.4")
$rescanPolicyType = "periodically" # other value: "periodically"; any other value defaults to "daily"
$rescanTime = "16:30"
$rescanPeriod = 12 # rescan period in hours for "periodically" - can be 1, 2, 3, 4, 6, 8, 12, 24
$rebootComputer = "true" # any other value will not set -RebootIfRequired flag

# Load PS modules
Try {
  Add-PSSnapin -Name VeeamPSSnapin
}
catch {
  Write-Output "VeeamPSSnapin not found. Please install VBR Console on the machine running the script"
}

# Test Method parameter - add to existing or create new protection group
function Test-Parameters {
	param(
		[Parameter(Mandatory=$true)][string]$Method
	)
	Process {
		if("add","new" -NotContains $Method.ToLower()) {
			Throw "`"$($Method)`" is not a valid method. Please enter `"add`" or `"new`"."
		}
	}
}


# Start function definitions
# add computers to existing protection ProtectionGroup - uses already existing credentials
function AddComputersToProtectionGroup($protectionGroupName,$newComputers) {
  $protectionGroup = Get-VBRProtectionGroup -Name $protectionGroupName
  $computerCreds = $protectionGroup.Container.CustomCredentials
  if ($computerCreds.Length -gt 1) {
      $creds = Get-VBRCredentials -Name $protectionGroup.Container.CustomCredentials.Credentials.Name[0] | Where {$_.Id -eq  $protectionGroup.Container.CustomCredentials.Credentials.Id[0]}
  } else {
      $creds = Get-VBRCredentials -Name $protectionGroup.Container.CustomCredentials.Credentials.Name | Where {$_.Id -eq  $protectionGroup.Container.CustomCredentials.Credentials.Id}
  }
  $newComputersCreds = $newComputers | ForEach { New-VBRIndividualComputerCustomCredentials -HostName $_ -Credentials $creds}
  $computerCreds += $newComputersCreds
  $updateContainer = Set-VBRIndividualComputerContainer -Container $protectionGroup.Container -CustomCredentials $computerCreds
  Set-VBRProtectionGroup -ProtectionGroup $protectionGroup -Container $updateContainer
}

# create ProtectionGroup, create new credentials and add computers
function NewProtectionGroup($protectionGroupName, $newComputers, $rescanTime, $rescanPolicyType, $rescanPeriod, $rebootComputer) {
  Write-Host -foreground yellow "Enter credentials for computers in protection group " $protectionGroupName
  $creds = Get-Credential
  $newCreds = Add-VBRCredentials -Credential $creds -Description "powershell added creds for $protectionGroupName" -Type Linux
  $newComputersCreds = $newComputers | ForEach { New-VBRIndividualComputerCustomCredentials -HostName $_ -Credentials $newCreds}
  $newContainer = New-VBRIndividualComputerContainer -CustomCredentials $newComputersCreds
	if ($rescanPolicyType -eq "daily") {
		$dailyOptions = New-VBRDailyOptions -Type Everyday -Period $rescanTime
		$scanSchedule = New-VBRProtectionGroupScheduleOptions -PolicyType Daily -DailyOptions  $dailyOptions
	} elseif ($rescanPolicyType -eq "periodically") {
		$periodicallyOptions = New-VBRPeriodicallyOptions -PeriodicallyKind Hours -FullPeriod $rescanPeriod
		$scanSchedule = New-VBRProtectionGroupScheduleOptions -PolicyType Periodically -PeriodicallyOptions  $periodicallyOptions
	} else {
		Write-host -foreground red "Uknown rescan policy type" $rescanPolicyType
		Write-host -foreground red "Using daily "
		$dailyOptions = New-VBRDailyOptions -Type Everyday -Period $rescanTime
		$scanSchedule = New-VBRProtectionGroupScheduleOptions -PolicyType Daily -DailyOptions  $dailyOptions
	}
	if ($rebootComputer -eq "true") {
		$deployment = New-VBRProtectionGroupDeploymentOptions -InstallAgent -UpgradeAutomatically	-RebootIfRequired
	} else {
		$deployment = New-VBRProtectionGroupDeploymentOptions -InstallAgent -UpgradeAutomatically
	}
  $protectionGroup = Add-VBRProtectionGroup -Name $protectionGroupName -Container $newContainer -ScheduleOptions $scanSchedule -DeploymentOptions $deployment
  # rescan and install
  Rescan-VBREntity -Entity $protectionGroup -Wait
  $computers = Get-VBRDiscoveredComputer -ProtectionGroup $protectionGroup
}


Test-Parameters -Method $Method

$pg = ""
if ($Method.ToLower() -like "add") {
  $pg = Get-VBRProtectionGroup -Name $protectionGroupName -ErrorAction SilentlyContinue
  if ($pg.length -eq 1) {
    AddComputersToProtectionGroup -protectionGroupName $protectionGroupName -newComputers $newComputers
  } else {
    Write-Host -foreground red "Protection group:" $protectionGroupName "does not exist. Make sure you enter the correct name."
  }
} else {
  if (Get-VBRProtectionGroup -Name $protectionGroupName -ErrorAction SilentlyContinue) {
    Write-Host -foreground red "Protection group:" $protectionGroupName "already exists. Use another name for protection group."
  } else {
    NewProtectionGroup -protectionGroupName $protectionGroupName -newComputers $newComputers -rescanTime $rescanTime -rescanPolicyType $rescanPolicyType -rescanPeriod $rescanPeriod -rebootComputer $rebootComputer
  }
}
