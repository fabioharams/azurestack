##
##  <copyright file="CreateVM.ps1" company="Microsoft">
##    Copyright (C) Microsoft. All rights reserved.
##  </copyright>
##
[CmdletBinding()]
param(
  [Hashtable]$Task
)

. $PSScriptRoot\NC\NetworkControllerRESTWrappers.ps1

ImportModuleWithoutError storage
ImportModuleWithoutError Hyper-V
$Settings = $Task.Parameters

### Create folder ###
if ($Settings.VMPath -ne $null) {
  $VMLocation = $Settings.VMPath + '\' + $Settings.Name
}
else {
  $VMLocation = (get-vmhost).VirtualMachinePath + '\' + $Settings.Name
}
Log "Creating VM folder $VMLocation"
del $VMLocation -force -Recurse -ErrorVariable Err -ErrorAction SilentlyContinue      
Log $err
New-Item -ItemType directory -Path $VMLocation -force  -ErrorVariable Err -ErrorAction SilentlyContinue      
Log $err
if (-not (Test-Path $VMLocation)) {
  Write-Error "$VMLocation cannot be created."
  return
}

### Create VM ####
Log "New VM"
$VM = New-VM -Name $Settings.Name -Path $VMLocation -MemoryStartupBytes 2GB -NoVHD -Generation 2

get-VMDvdDrive -VM $VM | Remove-VMDvdDrive
Set-VM -VM $VM -ProcessorCount $Settings.ProcessorCount 

### Nics ###
Get-VMNetworkAdapter -VM $VM | Remove-VMNetworkAdapter
foreach ($Nic in $Settings.Nics.Nic) {
  if ($Nic -eq $null) { break }
  Log "Add Nic [$($VM.Name)][$($Nic.Name)][$($Nic.vSwitch)]"
  $VMNetworkAdapter = Add-VMNetworkAdapter -VM $VM -Name $Nic.Name -SwitchName $Nic.vSwitch 
  if ($Nic.VLan -ne $null) {
    Log "Set VLAN [$($VM.Name)][$($Nic.Name)][$($Nic.VLan)]"
    Set-VMNetworkAdapterIsolation -VM $VM -VMNetworkAdapterName $Nic.Name -IsolationMode Vlan -DefaultIsolationID $Nic.VLan -AllowUntaggedTraffic $true
  }
}

### Hyper-V will assign a Mac address during VM fisrt startup. Mac address will be using in unattend.xml to config Nic
Log "Start VM[$($VM.Name)]"
Start-VM -VM $VM -ErrorVariable Err -ErrorAction SilentlyContinue      
Log $err
Stop-VM -VM $VM -Force
while ((Get-VMNetworkAdapter -Name ([array]($Settings.Nics.Nic))[0].Name -VM $VM).MacAddress -eq '000000000000') {
  sleep 5
  $VM = Get-VM $VM.Name
}

### Prepare Disk ####
$Disk1 = $null 
foreach ($vhd in $Settings.Disk) {
  $DiskPath = "$VMLocation\$([GUID]::NewGuid().ToString()).vhdx"
  if ($Disk1 -eq $null) {
    $Disk1 = $DiskPath
  }
  Log "Creating $($vhd.Base)"
  if ($vhd.Base -ne $null) {
    if ($vhd.Base -like '\\*' -or $vhd.Base -like '?:\*') {
      $vhdBase = $vhd.Base
    }
    else {
      $vhdBase = (get-vmhost).VirtualMachinePath + '\' + $vhd.Base
    }
    Log "Creating differencing vhdx $DiskPath  [$vhdBase]"
    if ($vhd.Size -ne $null) { New-VHD -Differencing -ParentPath $vhdBase -SizeBytes ([int]($vhd.Size)*1GB) -Path $DiskPath}
    else { New-VHD -Differencing -ParentPath $vhdBase -Path $DiskPath}
  }
  else {
    Log "New vhdx $DiskPath"
    if ($vhd.Size -eq $null) { $vhd.Size = '100' }
    New-VHD -Dynamic -SizeBytes ([int]($vhd.Size)*1GB) -Path $DiskPath
  }
  foreach ($Feature in $vhd.Features) {
    Log "Install Features $($Feature.Name) for $DiskPath"
    for ($i = 1 ; $i -le 3; $i++){
      try {
        Install-WindowsFeature $Feature.Name.Split(',') -Vhd $DiskPath -IncludeManagementTools
        break
      }
      catch {
        Log $_
        Log "HResult: $($_.Exception.HResult)"
        if ($i -lt 3 -and $_.Exception.Message -like '*0x800700b7*') {  #The specified image is currently being serviced by another DISM operation. Wait for the existing DISM operation to complete, and then try the operation again. -2146233088
          sleep 10
        }
        else {
          throw $_
        }
      }
    }
  }
  if ($vhd.file -ne $null) {
    sleep 5
    Log "Copy File to vhdx"
    $DL = MountVHD $DiskPath
    foreach ($File in $vhd.file) {
      $FromPath = $File.From
      $ToPath = "$DL\$($File.To)"
      if (-not [string]::IsNullOrEmpty($(Split-Path $ToPath))) {
        mkdir (Split-Path $ToPath) -ErrorVariable Err -ErrorAction SilentlyContinue
        Log $err
      }
      Log "Copy-Item $FromPath  $ToPath $($File.Option) -Force" 
      powershell -c "Copy-Item '$FromPath' '$ToPath' $($File.Option) -Force" 
    }
    Dismount-VHD -Path $DiskPath
  }
  Add-VMHardDiskDrive -VM $VM -Path $DiskPath
}

### Mount VHD ####
Log "Mounting VHD [$Disk1]..." 
$DL = MountVHD $Disk1
Log "Get volume [$DL]"

### Copy startup.ps1 & logon.ps1 ###
Log "Copying [$PSScriptRoot $DL\ startup.ps1 & logon.ps1]..."
robocopy $PSScriptRoot "$DL\" logon.ps1
robocopy $PSScriptRoot "$DL\" startup.ps1
robocopy /e $PSScriptRoot\..\Modules\AzureStackInstallerCommon "$DL\Program Files\WindowsPowerShell\Modules\AzureStackInstallerCommon"
robocopy /e $PSScriptRoot\..\Modules\AzureStackDSC "$DL\Program Files\WindowsPowerShell\Modules\AzureStackDSC"
if (-not (Test-Path $DL\Windows\Setup\Scripts)) {
  mkdir $DL\Windows\Setup\Scripts
}
$setupCompletePath = "$DL\Windows\Setup\Scripts\SetupComplete.cmd"
'Powershell.exe -c %SystemDrive%\startup.ps1 2>&1>>%SystemDrive%\startup.log' | Out-File -Encoding ascii -FilePath $setupCompletePath
$Settings.PostSetupCmd  | Out-File -Encoding ascii -FilePath $setupCompletePath -Append
'Powershell.exe -c %SystemDrive%\Logon.ps1 2>&1>>%SystemDrive%\Logon.log' | Out-File -Encoding ascii -FilePath $setupCompletePath -Append

if ($Settings.RegKeys -ne $null)
{
    $RegKeys = $Settings.RegKeys.Reg | foreach {
        @{
            Path = $_.Path
            Operation = $_.Operation
            Value = $_.Value
            Type = $_.Type
            Data = $_.Data
        }
    }
}
else
{
    $RegKeys = @()
}

### Internet Proxy ###
if (-not [string]::IsNullOrEmpty($Settings.ProxyServer))
{
    robocopy $PSScriptRoot "$DL\" SetInternetProxy.ps1
    "powershell.exe -c `"%SystemDrive%\SetInternetProxy.ps1 -ProxyServer $($Settings.ProxyServer) -ProxyExceptions '*.$($Settings.Domain.DomainName);<local>' `" 2>&1>>%SystemDrive%\SetInternetProxy.log" | Out-File -Encoding ascii -FilePath $setupCompletePath -Append
    
    $RegKeys += @{
            Path = "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
            Operation = "Add"
            Value = "ProxySettingsPerUser"
            Type = "REG_DWORD"
            Data = "0"
        }
}

### Set RegKey ###
[Hashtable]$LoadedReg = @{}
foreach ($RegKey in $RegKeys) {  
    $RegRoot = $($RegKey.Path.substring(0,$RegKey.Path.IndexOf('\')))
    if ($LoadedReg.Keys -notcontains $RegRoot) {
        $LoadedReg.Add($RegRoot,[GUID]::NewGuid().ToString())
        Log "reg load HKLM\$($LoadedReg.$RegRoot)_$RegRoot $DL\Windows\system32\config\$RegRoot"
        reg load "HKLM\$($LoadedReg.$RegRoot)_$RegRoot" "$DL\Windows\system32\config\$RegRoot"      
    }
$value =$null
$Type = $null
$Data = $null
if (-not [String]::IsNullOrEmpty($RegKey.Value)) { $Value = '/v ' + $RegKey.Value }
elseif ($RegKey.Operation -eq 'Add') { $Value = '/ve'}
if (-not [String]::IsNullOrEmpty($RegKey.Type)) { $Type = "/t $($RegKey.Type)" }
if (-not [String]::IsNullOrEmpty($RegKey.Data)) { $Data = "/d `"$($RegKey.Data)`"" }
Log "reg $($RegKey.Operation) `"HKLM\temp_$($RegKey.Path)`" /f $Value $Type $Data"
try {
    cmd /c "reg $($RegKey.Operation) `"HKLM\$($LoadedReg.$RegRoot)_$($RegKey.Path)`" /f $Value $Type $Data"
}
catch {
    Log $_
    Log $_.Exception.Message
}
}
try {
$LoadedReg.Keys | % {reg unload "HKLM\$($LoadedReg.$_)_$_"}
}
catch {
    Log $_
    Log $_.Exception.Message
}

### unattend XML ###
$UnattendXML = [xml](Get-Content $PSScriptRoot\Unattend.xml)
$oobeSystem = $UnattendXML.unattend.settings | ? {$_.pass -eq 'oobeSystem'}
$specialize = $UnattendXML.unattend.settings | ? {$_.pass -eq 'specialize'}

##specialize##
$Microsoft_Windows_Shell_Setup = $specialize.component | ? {$_.name -eq 'Microsoft-Windows-Shell-Setup'}
$Microsoft_Windows_TCPIP = $specialize.component | ? {$_.name -eq 'Microsoft-Windows-TCPIP'}
$Microsoft_Windows_DNS_Client = $specialize.component | ? {$_.name -eq 'Microsoft-Windows-DNS-Client'}

$Microsoft_Windows_Shell_Setup.ComputerName = $Settings.Name
Log "Microsoft_Windows_Shell_Setup.ComputerName : $($Microsoft_Windows_Shell_Setup.ComputerName)"

$IPInterfaces = $Microsoft_Windows_TCPIP.Interfaces
$IPInterface = $IPInterfaces.Interface
if ($IPInterfaces.ChildNodes.count -gt 0) { $IPInterfaces.RemoveAll() }
$DNSInterfaces = $Microsoft_Windows_DNS_Client.Interfaces
$DNSInterface = $DNSInterfaces.Interface
if ($DNSInterfaces.ChildNodes.count -gt 0) { $DNSInterfaces.RemoveAll() }
$Metric = 40
foreach ($Nic in $Settings.Nics.Nic) {
  if ($Nic -ne $null -and $Nic.DHCP -eq 'false') {
    $NewIPInterface = $IPInterface.Clone()
    $NewIPInterface.Ipv4Settings.DhcpEnabled = 'false'
    Log "NewIPInterface.Ipv4Settings.DhcpEnabled : $($NewIPInterface.Ipv4Settings.DhcpEnabled)"
    $NewIPInterface.Ipv4Settings.Metric = ($Metric++).ToString()
    Log "NewIPInterface.Ipv4Settings.Metric : $($NewIPInterface.Ipv4Settings.Metric)"
    $NewIPInterface.UnicastIpAddresses.IpAddress.'#text' = $Nic.IP
    Log "NewIPInterface.UnicastIpAddresses.IpAddress.'#text' : $($NewIPInterface.UnicastIpAddresses.IpAddress.'#text')"
    if($Nic.GW -ne $null)
    {
      $NewIPInterface.Routes.Route.NextHopAddress = $Nic.GW
      Log "NewIPInterface.Routes.Route.NextHopAddress : $($NewIPInterface.Routes.Route.NextHopAddress)"
      $NewIPInterface.Routes.Route.Metric = ($Metric++).ToString()
      Log "NewIPInterface.Routes.Route.Metric : $($NewIPInterface.Routes.Route.Metric)"
    }
    else {
      $NewIPInterface.RemoveChild($NewIPInterface.Routes)
    }
    $NewIPInterface.Identifier = (((Get-VMNetworkAdapter -Name $Nic.Name -VM $VM).MacAddress) -replace '..','-$0').substring(1)
    Log "NewIPInterface.Identifier : $($NewIPInterface.Identifier)"
    $IPInterfaces.AppendChild($NewIPInterface) > $null   
  }
  if ($Nic -ne $null -and $Nic.DNSList -ne $null) {
    $NewDNSInterface = $DNSInterface.Clone()
    $DNSServerSearchOrder = $NewDNSInterface.DNSServerSearchOrder
    $DNSIP = $DNSServerSearchOrder.IpAddress
    if ($DNSServerSearchOrder.ChildNodes.count -gt 0) { $DNSServerSearchOrder.RemoveAll() }
    for ($i=1; $i -le $Nic.DNSList.DNS.count; $i++) {
      $NewDNSIP = $DNSIP.Clone()
      $NewDNSIP.keyValue = [string]$i
      
      $NewDNSIP.'#text' = ([array]($Nic.DNSList.DNS))[$i-1]
      $DNSServerSearchOrder.AppendChild($NewDNSIP) > $null   
    }
    $NewDNSInterface.Identifier = (((Get-VMNetworkAdapter -Name $Nic.Name -VM $VM).MacAddress) -replace '..','-$0').substring(1)
    if ($Nic.DNSList.DisableDynamicUpdate -ne $null) {
      $NewDNSInterface.DisableDynamicUpdate = $Nic.DNSList.DisableDynamicUpdate
    }
    $DNSInterfaces.AppendChild($NewDNSInterface) > $null   
  }
}
if ($Microsoft_Windows_TCPIP.Interfaces -eq '') {
  $specialize.RemoveChild($Microsoft_Windows_TCPIP)
}
if ($Microsoft_Windows_DNS_Client.Interfaces -eq '') {
  $specialize.RemoveChild($Microsoft_Windows_DNS_Client)
}

##oobe##
$Microsoft_Windows_Shell_Setup = $oobeSystem.component | ? {$_.name -eq 'Microsoft-Windows-Shell-Setup'}

if ($Settings.AutoLogon.User -ne $null) {
  $Microsoft_Windows_Shell_Setup.AutoLogon.Username = $Settings.AutoLogon.User
  $Microsoft_Windows_Shell_Setup.AutoLogon.Domain = $Settings.AutoLogon.Domain
  $Microsoft_Windows_Shell_Setup.AutoLogon.Password.Value = ConvertTo-PlainTextString -SecureString  $Settings.AutoLogon.Password
}
else {
  $Microsoft_Windows_Shell_Setup.RemoveChild($Microsoft_Windows_Shell_Setup.AutoLogon)
}

$RandomAdminPassword = (New-Guid).ToString()
$Microsoft_Windows_Shell_Setup.UserAccounts.AdministratorPassword.Value = $RandomAdminPassword
$LocalAccounts = $Microsoft_Windows_Shell_Setup.UserAccounts.LocalAccounts
$LocalAccount = $LocalAccounts.LocalAccount
if ($LocalAccountsChildNodes.count -gt 0) { $LocalAccounts.RemoveAll() }
foreach ($Account in $Settings.LocalAccounts.Account) {
  if ($Account -ne $null) {
    $newLocalAccount = $LocalAccount.Clone()
    $newLocalAccount.Password.Value = ConvertTo-PlainTextString -SecureString  $Account.Password
    $newLocalAccount.Description = $Account.Name
    $newLocalAccount.DisplayName = $Account.Name
    $newLocalAccount.Name = $Account.Name
    $newLocalAccount.Group = $Account.Group
    $LocalAccounts.AppendChild($newLocalAccount) > $null   
  }
}
if ($Microsoft_Windows_Shell_Setup.UserAccounts.LocalAccounts -eq '') {
  $Microsoft_Windows_Shell_Setup.UserAccounts.RemoveChild($Microsoft_Windows_Shell_Setup.UserAccounts.LocalAccounts)
}

if (-not (Test-Path "$DL\Windows\Panther")){
  mkdir "$DL\Windows\Panther"
}
Log "Putting $DL\Windows\Panther\Unattend.xml"
$UnattendXML.Save("$DL\Windows\Panther\Unattend.xml")
$UnattendXML.Save("$VMLocation\Unattend.xml")

#Fix Boot Entries
Log "Fixing boot entries for $Disk1"

$EfiPartition = Get-Vhd -Path $Disk1 | Get-Disk | Get-Partition | where {$_.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"} #The type of EFI System Partition is always c12a7328-f81f-11d2-ba4b-00a0c93ec93b

function CallBcdEdit
{
    [CmdletBinding()] 
    param(
        [string]$Parameters
    )

    Log  "bcdedit $Parameters"
    Log (cmd /c "bcdedit $Parameters")
}

if ($EfiPartition -ne $null)
{
  for($i = 10; $i -gt 0; $i--)
  {
    try
    {
        $EfiPartition | Add-PartitionAccessPath -AssignDriveLetter -ErrorAction Stop
        $EfiPartition = $EfiPartition | Get-Partition -PartitionNumber $EfiPartition.PartitionNumber -ErrorAction Stop #EFI partition needs to be refreshed to get the drive letter
        $EfiDriveLetter = $EfiPartition.DriveLetter
    }
    catch
    {
        Log "Failed to assign drive letter to the EFI system partition of Disk $Disk1 due to error: $_"
        if ($i -gt 1)
        {
            Sleep 1
        }
    }
  }
 
  if (-not [string]::IsNullOrEmpty($EfiDriveLetter))
  {
      try
      { 
         $bcdPath = "$EfiDriveLetter`:\EFI\Microsoft\Boot\BCD"
         CallBcdEdit -Parameters "/store $bcdPath /set {default} device hd_partition=$DL"
         CallBcdEdit -Parameters "/store $bcdPath /set {default} osdevice hd_partition=$DL"
         CallBcdEdit -Parameters "/store $bcdPath /set {bootmgr} device hd_partition=$EfiDriveLetter`:"
      }
      finally
      {
         $EfiPartition | Remove-PartitionAccessPath -AccessPath "$EfiDriveLetter`:"
      }
  }
  else
  {
      Write-Error "Failed to assign drive letter to the EFI system partition of Disk $Disk1"
  }
}
else
{
  Write-Error "The EFI System Partition was not found in $Disk1"
}

### Unmount VHD ####
Log "Dismount-VHD $Disk1"
Dismount-VHD -Path $Disk1

### Allow nic pass VFP ###
set-PortProfileId -resourceID ([System.Guid]::Empty.tostring()) -VMName $VM.Name

### Add VM to Cluster
if ($Settings.HAVM -eq 'true') {
  Log "Adding VM[$($VM.Name)] to cluster"
  $ClusterRole = $VM | Add-ClusterVirtualMachineRole
  $ClusterRole | Get-ClusterResource | % {UpdateClusterResourceRetry $_}
}
### Start Vm ###
Set-VMFirmware -VMName $VM.Name -FirstBootDevice $(Get-VMHardDiskDrive -VMName $VM.Name | ? {$_.Path -eq $Disk1}) -EnableSecureBoot Off   #TODO: This is a workaround when host and VM not same build. May need to remove -EnableSecureBoot Off in offical ship
Log "Start VM[$($VM.Name)]"
for ($i = 0;(Get-VM -Name $VM.Name).State -ne 'Running' -and $i -lt 24;$i++)
{
  Start-VM -VM $VM -ErrorVariable Err -ErrorAction SilentlyContinue
  Log $err
  Log "Wait for VM to be ready, sleep 5 sec"
  sleep 5
}
if ((Get-VM -Name $VM.Name).State -ne 'Running') {
  Log "Fail to start VM [$($VM.Name)]"
  Write-Error "Fail to start VM [$($VM.Name)]"
}

$MachineIP = (([array]($Settings.Nics.Nic))[0].IP -replace '/.*$','')
Log "Password[$RandomAdminPassword]"
WaitMachineReboot $MachineIP -Credential (New-Object System.Management.Automation.PSCredential ("$($Settings.Name)\administrator", (ConvertTo-SecureString $RandomAdminPassword -AsPlainText -Force)))

Log "Checking disk and volume status"
$DiskInfo = @()
$DiskInfo += $Settings.Disk
RemotePS -ComputerName $MachineIP -UserName administrator -Password (ConvertTo-SecureString $RandomAdminPassword -AsPlainText -Force) `
  -Script { 
    param($DiskCount)
    $VerbosePreference=$Using:VerbosePreference
    $ErrorActionPreference = 'Stop'
    $Disks = @()
    $Disks += $(Get-Disk)
    $Volumes = @()
    $Volumes += $(Get-Volume)
    $RealDiskCount = $Disks.Count
    $VolumeCount = $Volumes.Count
    #We are assuming that each disk has one volume at least
    try {
      Get-disk | Get-Partition | Get-Volume | sort -Property SizeRemaining -Descending | % { Write-Verbose "[$($_.DriveLetter)] [$($_.FileSystemLabel)] [$($_.FileSystem)] [$($_.DriveType)] [$($_.HealthStatus)] [$($_.OperationalStatus)] [$($_.SizeRemaining)] [$($_.Size)]" } -Verbose} 
    catch {Write-Verbose "$_" -Verbose -ErrorAction Ignore}
    if($RealDiskCount -ne $DiskCount -or $VolumeCount -lt $DiskCount)
    {
        Write-Error "Failed to attach the disk. Expect Disk Count:$DiskCount, Real Disk Count: $RealDiskCount, Volume Count: $VolumeCount"
    }
  } `
  -Params ($DiskInfo.Count) -Retry 0

Log "Changing administrator password"
RemotePS -ComputerName $MachineIP -UserName administrator -Password (ConvertTo-SecureString $RandomAdminPassword -AsPlainText -Force) `
  -Script { 
    param($Password)
    $User = [adsi]"WinNT://$($env:COMPUTERNAME)/administrator,user"
    $User.SetPassword($(ConvertTo-PlainTextString -SecureString $Password))
  } `
  -Params ($Settings.LocalAccounts.AdministratorPassword)

# Domain Join
if ($Settings.Domain.DomainName -ne $null) {
  Log "Domain Join [$($Settings.Domain.DomainName)]"
  RemotePS -ComputerName $MachineIP -UserName administrator -Password $Settings.LocalAccounts.AdministratorPassword `
    -Script {
      param($DomainName,$DomainCredential)
      $ErrorActionPreference = 'Stop'
      Add-Computer -confirm:$false -DomainName $DomainName -Credential $DomainCredential
      "Rebooting" > C:\Status.txt
      shutdown /r /t 20
    } `
    -Params ($Settings.Domain.DomainName,(New-Object System.Management.Automation.PSCredential("$($Settings.Domain.DomainName)\$($Settings.Domain.User)", $Settings.Domain.Password)))
  WaitMachineReboot $MachineIP -Credential (New-Object System.Management.Automation.PSCredential ("$($Settings.Name)\administrator", $Settings.LocalAccounts.AdministratorPassword))
}

# Add VM to SG if Group been set
if (-not [String]::IsNullOrEmpty($Settings.Group) -and -not [String]::IsNullOrEmpty($Settings.Domain.DomainName)) {
  $DomainAdmin = New-Object System.Management.Automation.PSCredential ("$($Settings.Domain.DomainName)\$($Settings.Domain.User)", $Settings.Domain.Password)
  try {
    Log "Get Group [$($Settings.Group)]"
    $Group = Get-ADGroup $Settings.Group -Credential $DomainAdmin -ErrorVariable Err -ErrorAction SilentlyContinue
    Log $err
  }
  catch {
    Log "Group [$($Settings.Group)] not found"
    Log $_
    Log $_.Exception.Message
  }
  if ($Group -eq $null) {
    Log "New Group [$($Settings.Group)]"
    $Group = New-ADGroup $Settings.Group -Credential $DomainAdmin -GroupScope Global -GroupCategory Security -PassThru
  }
  Log "Add $($Settings.Name)$ to $($Settings.Group)"
  $Group | Add-ADGroupMember -Members "$($Settings.Name)$" -Credential $DomainAdmin
}
# SIG # Begin signature block
# MIIdvgYJKoZIhvcNAQcCoIIdrzCCHasCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU/XKH8QmUmt0THzScNPHtokB7
# GHagghhkMIIEwzCCA6ugAwIBAgITMwAAAIgVUlHPFzd7VQAAAAAAiDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTUxMDA3MTgxNDAx
# WhcNMTcwMTA3MTgxNDAxWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OjdBRkEtRTQxQy1FMTQyMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyBEjpkOcrwAm
# 9WRMNBv90OUqsqL7/17OvrhGMWgwAsx3sZD0cMoNxrlfHwNfCNopwH0z7EI3s5gQ
# Z4Pkrdl9GjQ9/FZ5uzV24xfhdq/u5T2zrCXC7rob9FfhBtyTI84B67SDynCN0G0W
# hJaBW2AFx0Dn2XhgYzpvvzk4NKZl1NYi0mHlHSjWfaqbeaKmVzp9JSfmeaW9lC6s
# IgqKo0FFZb49DYUVdfbJI9ECTyFEtUaLWGchkBwj9oz62u9Kg6sh3+UslWTY4XW+
# 7bBsN3zC430p0X7qLMwQf+0oX7liUDuszCp828HsDb4pu/RRyv+KOehVKx91UNcr
# Dc9Z7isNeQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFJQRxg5HoMTIdSZj1v3l1GjM
# 6KEMMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAHoudDDxFsg2z0Y+GhQ91SQW1rdmWBxJOI5OpoPzI7P7X2dU
# ouvkmQnysdipDYER0xxkCf5VAz+dDnSkUQeTn4woryjzXBe3g30lWh8IGMmGPWhq
# L1+dpjkxKbIk9spZRdVH0qGXbi8tqemmEYJUW07wn76C+wCZlbJnZF7W2+5g9MZs
# RT4MAxpQRw+8s1cflfmLC5a+upyNO3zBEY2gaBs1til9O7UaUD4OWE4zPuz79AJH
# 9cGBQo8GnD2uNFYqLZRx3T2X+AVt/sgIHoUSK06fqVMXn1RFSZT3jRL2w/tD5uef
# 4ta/wRmAStRMbrMWYnXAeCJTIbWuE2lboA3IEHIwggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TCCBhAwggP4
# oAMCAQICEzMAAABkR4SUhttBGTgAAAAAAGQwDQYJKoZIhvcNAQELBQAwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTAeFw0xNTEwMjgyMDMxNDZaFw0xNzAx
# MjgyMDMxNDZaMIGDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MQ0wCwYDVQQLEwRNT1BSMR4wHAYDVQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24w
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCTLtrY5j6Y2RsPZF9NqFhN
# FDv3eoT8PBExOu+JwkotQaVIXd0Snu+rZig01X0qVXtMTYrywPGy01IVi7azCLiL
# UAvdf/tqCaDcZwTE8d+8dRggQL54LJlW3e71Lt0+QvlaHzCuARSKsIK1UaDibWX+
# 9xgKjTBtTTqnxfM2Le5fLKCSALEcTOLL9/8kJX/Xj8Ddl27Oshe2xxxEpyTKfoHm
# 5jG5FtldPtFo7r7NSNCGLK7cDiHBwIrD7huTWRP2xjuAchiIU/urvzA+oHe9Uoi/
# etjosJOtoRuM1H6mEFAQvuHIHGT6hy77xEdmFsCEezavX7qFRGwCDy3gsA4boj4l
# AgMBAAGjggF/MIIBezAfBgNVHSUEGDAWBggrBgEFBQcDAwYKKwYBBAGCN0wIATAd
# BgNVHQ4EFgQUWFZxBPC9uzP1g2jM54BG91ev0iIwUQYDVR0RBEowSKRGMEQxDTAL
# BgNVBAsTBE1PUFIxMzAxBgNVBAUTKjMxNjQyKzQ5ZThjM2YzLTIzNTktNDdmNi1h
# M2JlLTZjOGM0NzUxYzRiNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzcitW2oynUC
# lTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEGCCsGAQUF
# BwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0MAwGA1Ud
# EwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAIjiDGRDHd1crow7hSS1nUDWvWas
# W1c12fToOsBFmRBN27SQ5Mt2UYEJ8LOTTfT1EuS9SCcUqm8t12uD1ManefzTJRtG
# ynYCiDKuUFT6A/mCAcWLs2MYSmPlsf4UOwzD0/KAuDwl6WCy8FW53DVKBS3rbmdj
# vDW+vCT5wN3nxO8DIlAUBbXMn7TJKAH2W7a/CDQ0p607Ivt3F7cqhEtrO1Rypehh
# bkKQj4y/ebwc56qWHJ8VNjE8HlhfJAk8pAliHzML1v3QlctPutozuZD3jKAO4WaV
# qJn5BJRHddW6l0SeCuZmBQHmNfXcz4+XZW/s88VTfGWjdSGPXC26k0LzV6mjEaEn
# S1G4t0RqMP90JnTEieJ6xFcIpILgcIvcEydLBVe0iiP9AXKYVjAPn6wBm69FKCQr
# IPWsMDsw9wQjaL8GHk4wCj0CmnixHQanTj2hKRc2G9GL9q7tAbo0kFNIFs0EYkbx
# Cn7lBOEqhBSTyaPS6CvjJZGwD0lNuapXDu72y4Hk4pgExQ3iEv/Ij5oVWwT8okie
# +fFLNcnVgeRrjkANgwoAyX58t0iqbefHqsg3RGSgMBu9MABcZ6FQKwih3Tj0DVPc
# gnJQle3c6xN3dZpuEgFcgJh/EyDXSdppZzJR4+Bbf5XA/Rcsq7g7X7xl4bJoNKLf
# cafOabJhpxfcFOowMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEw
# HhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBT
# aWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# q/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2Avw
# OMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eW
# WcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1
# eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le
# 2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+
# 0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2
# zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv
# 1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLn
# JN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31n
# gOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+Hgg
# WCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAG
# CSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZ
# BgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8E
# UzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEB
# BFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcw
# gZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwIC
# MDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBu
# AHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOS
# mUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQ
# VdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQ
# dION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive
# /DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrC
# xq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/
# E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ
# 7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANah
# Rr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3
# S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1W
# Tk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1t
# bWrJUnMTDXpQzTGCBMQwggTAAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcg
# UENBIDIwMTECEzMAAABkR4SUhttBGTgAAAAAAGQwCQYFKw4DAhoFAKCB2DAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAjBgkqhkiG9w0BCQQxFgQUN3JYcoFrewoSjB+6eE2KsUyWNo0weAYKKwYB
# BAGCNwIBDDFqMGigJoAkAFAATwBDAEkAbgBzAHQAYQBsAGwAZQByAFIAYQB3AF8A
# cABzoT6APGh0dHA6Ly9lZHdlYi9zaXRlcy9JU1NFbmdpbmVlcmluZy9FbmdGdW4v
# U2l0ZVBhZ2VzL0hvbWUuYXNweDANBgkqhkiG9w0BAQEFAASCAQAjnu/XoKw7msPb
# 0HJUZqlX/JNJHl2lOfAclkCdcn6mQ0GpWP8hM60s12SL/WJn0rCW2rN7BOvD3tFn
# 3JxEHm/8op1HT7i6dS59vRdT32ccaifP4DVaRlS65+YPZqDhMOwn8nd2ozHDNn5d
# ZB7CIESJB0BOZ3xS33NuuJTJrebRuebDRl3NI2uW1OoNJM4cfhzMJaCNY5oFPzVV
# LFHesS9ZCl3D1CZXmsaJUvulVqM+U5B1cyz82roiPAxkLghIODhvO+7NNRaRrWpj
# cJ+ce7GmXrD4ijMCJsZocSOos0hGl2X9ZceagtZ2c+88d2sIe64lxeelRm4edKo4
# sXZFW6HboYICKDCCAiQGCSqGSIb3DQEJBjGCAhUwggIRAgEBMIGOMHcxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQQITMwAAAIgVUlHPFzd7VQAAAAAAiDAJBgUrDgMCGgUA
# oF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYw
# MTI1MTgzOTIyWjAjBgkqhkiG9w0BCQQxFgQUp3UzqyxL53XaVvExRCHK5+2dk7Aw
# DQYJKoZIhvcNAQEFBQAEggEAvqbaJP8TGyjIu7FUI/gzvECoy6KX5xhNSTBeQ0ES
# L0bSup3fZ31xoQyumBmyvP7YR8YHzv72jHO6pzMyZCQnrUZoC5IaKc/TCPvb2/fw
# 2CF2ks2try42cM6cs7JDiTtb+i1D9agkSrSMEP0VK3Cq1r8YCilcHhdPlN03ebE/
# Ea67zgMdgCATd8V4cNlJTyh59q6yzTgE7MEyq6IUardhNWxJ5xrCKWAeYzTyLx+z
# u297dALdhht4FFSjjLMgiZ8CSH5wCiU7XUrtmRr0o69K8BT9aTCwwIc8vBeY7601
# yfw3s4DibwS0SHuiHybB6CdytHYKkJJJoFKbYXPy5HYbAQ==
# SIG # End signature block
