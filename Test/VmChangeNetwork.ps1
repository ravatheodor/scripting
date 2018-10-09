<#
    .SYNOPSIS


    .DESCRIPTION
    csv file format:
    vmName,srcPg,dstPg,reboot
    demo-server-1,vmnetwork-1,vmnetwork-2,true
    demo-server-1*,vmnetwork-1,vmnetwork-2,false

    may use wildcard in the name of the VM

    .EXAMPLE
    .\VmChangeNetwork.ps1 -csvVmList VmFile.csv

    .NOTES
    Version: 0.1
    Author: Razvan Ionescu
    Last Updated: March 2018

#>

param(
	[Parameter(Mandatory=$true)][string]$csvVmList
)

function VmChangeNetwork($vmName,$srcPg,$dstPg,$reboot){
  Write-Host "processing:" $vmName
  Write-Host "  src PG:" $srcPg "dst PG:" $dstPg "reboot required:" $reboot

  Try {
      $v = Get-VM | Where {$_.Name -like "$vmName"}
  }
  Catch {
    Write-Host $_.Exception.Message $_.Exception.ItemName
  }

  if ($v.Count -eq 1){
    $srcPgExist = $v  | Get-NetworkAdapter | Where {$_.NetworkName -eq $srcPg}
    if ($srcPgExist.Count -eq 1) {
      $v  | Get-NetworkAdapter | Where {$_.NetworkName -eq $srcPg} | Set-NetworkAdapter -NetworkName $dstPg -Confirm:$false
      if (($reboot.ToLower() -match "true") -and ($v.PowerState -match "PoweredOn")){
        Write-Host " rebooting VM"
        Restart-VM -VM $v -RunAsync -Confirm $False
      }
    } elseif ($srcPgExist.Count -eq 0) {
      Write-Host " no adapters connected to" $srcPg "found"
    } else {
      Write-Host " multiple adapters connected to" $srcPg "found"
    }


  } elseif ($v.Count -eq 0) {
    Write-Host " "$vmName "was not found"
  } else {
    Write-Host " "$v.Count "VMs found with name" $vmName
  }
  Write-Host ""
}

# load CSV file
Try {
  $vmList = Import-Csv $csvVmList
}
Catch {
  Write-Host " File is not accessible"
	exit
}

# process VMs
foreach ($vm in $vmList){
  VmChangeNetwork -vmName $vm.vmName -srcPg $vm.srcPg -dstPg $vm.dstPg -reboot $vm.reboot
}
