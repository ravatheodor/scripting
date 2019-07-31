<#
    .SYNOPSIS
    Creates vCenter Server role with given privileges

    .DESCRIPTION

    Create-NewRole takes as input a list of vCenter Server privileges
    and creates a vCenter Server role with those privileges.

    Provided lists are given for Veeam Backup server and for Veeam ONE. The
    list for backup server contains minimum requirered permissions for all
    functionality. 

    Datastore.Config privilege is required for VSAN environments only (restore)

    .EXAMPLE
    .\Create-NewRole.psq

    .NOTES
    Version: 1.0.0
    Author: Razvan Ionescu
    Last Updated: July 2019

    Requires:
    Veeam Backup & Replication v9.5 Update 3

#>

$role = "Veeam Backup Server role"
$rolePrivilegesFile = "veeam_vc_privileges.txt"
$vCenterServer = "your-vcenter-server-FQDN"
Connect-VIServer -server $vCenterServer
$roleIds = @()
Get-Content $rolePrivilegesFile | Foreach-Object{
    $roleIds += $_
}
New-VIRole -name $role -Privilege (Get-VIPrivilege -Server $vCenterServer -id $roleIds) -Server $vCenterServer

### Get existing privileges for a role ###
#$role = "Demo Service"
#Get-VIPrivilege -Role $role |  Select @{N="Role";E={$role.Name}},@{N="Privilege Name";E={$_.Name}},@{N="Privilege ID";E={$_.ID}}
