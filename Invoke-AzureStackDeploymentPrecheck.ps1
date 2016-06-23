##
##  <copyright file="Invoke-AzureStackDeploymentPrecheck.ps1" company="Microsoft">
##    Copyright (C) Microsoft. All rights reserved.
##  </copyright>
##

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][String] $PackagePath,
    [Parameter(Mandatory = $true)][String] $OSVHD,
    [Parameter(Mandatory = $true)][String[]] $OtherVHDs
)

# Define consts
$PocRootKey = "HKLM:\SOFTWARE\Microsoft\AzureStack\Installer"
$DeployAzureStackFileName = "DeployAzureStack.ps1"

function CheckAdministratorPriviledge {
    Write-Verbose "Check for Administrator priviledge."

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        throw "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
        break
    }
}

function CheckInternetAccess {
    Write-Verbose "Check Internet access."

    # Test AAD http connection.
    try {
        $resp = Invoke-WebRequest -Uri "https://login.windows.net" -UseBasicParsing
        if ($resp.StatusCode -ne 200) {
            throw "Failed to connect to AAD endpoint https://login.windows.net"
        }
        Write-Verbose "Check Internet access succeeded."
    }
    catch {
        Write-Verbose $_.Exception.Message
        throw "Failed to connect to AAD endpoint 'https://login.windows.net'."
    }
}

function CheckDisks {
    Write-Verbose "Check physical disks for storage pool."

    Write-Verbose "Check whether this check item has passed before. Only need to do it once."

    $diskCheckPassedPropertyName = "DiskCheckPassed"
    $property = Get-ItemProperty -LiteralPath $PocRootKey
    if ($property.DiskCheckPassed -eq 1) {
        Write-Verbose "Disks check already passed."
        return
    }

    # Make sure at least 3 physical disks with the same bus type (RAID/SAS/SATA) exist
    # TODO Logic here need to change since some disk which is CanPool but can be only used locally. Like the disk which already have local volume but still have free space.
    
    Write-Verbose (Get-PhysicalDisk | Format-Table -Property @("FriendlyName", "SerialNumber", "CanPool", "BusType", "OperationalStatus", "HealthStatus", "Usage", "Size") | Out-String)
    $physicalDisks = Get-PhysicalDisk | Where-Object { $_.CanPool -eq $true -and ($_.BusType -eq 'RAID' -or $_.BusType -eq 'SAS' -or $_.BusType -eq 'SATA') }
    Write-Verbose ($physicalDisks | Format-Table -Property @("FriendlyName", "SerialNumber", "CanPool", "BusType", "OperationalStatus", "HealthStatus", "Usage", "Size") | Out-String)

    $selectedDisks = $physicalDisks | Group-Object -Property BusType | Sort-Object -Property Count -Descending | Select-Object -First 1

    if ($selectedDisks.Count -lt 3) {
        throw "Check disks failed. At least 3 disks of the same bus type (RAID/SAS/SATA) and with CanPool attribute equals true are required."
    }    

    Write-Verbose "Check free space in disks."
    Write-Verbose (Get-Disk | Get-Partition | Get-Volume | Sort-Object -Property SizeRemaining -Descending | Out-String)
    $volumes = (Get-disk | ? {$_.BusType -ne 'File Backed Virtual' -or $_.IsBoot} | Get-Partition | Get-Volume |`
         ? {-not [String]::IsNullOrEmpty($_.DriveLetter)} | sort -Property SizeRemaining -Descending)
    if (!$volumes -or $volumes.Count -le 0) {
        Write-Host "Check disk free space failed because of no volumes is available."
    }
    if ($volumes[0].SizeRemaining -lt 50 * 1024 * 1024 * 1024) {
        throw "Check disk free space failed. At least 50GB free space should be available in one of disk volumes."
    }

    # Block existing storage pool
    $pools = [Array](Get-StoragePool -IsPrimordial $False -ErrorAction Ignore)
    if ($pools.Count -ne 0) {
        Write-Verbose "Existing storage pools founded."
        Write-Verbose ($pools | Format-Table | Out-String)
        throw "Check disks failed because existing storage pools founded. Please remove existing storage pools and try again."
    }

    New-ItemProperty -LiteralPath $PocRootKey -Name $diskCheckPassedPropertyName -PropertyType DWord -Value 1 -Force
}

function CheckRam {
    Write-Verbose "Check RAM."
    
    $mem = Get-WmiObject -Class Win32_ComputerSystem
    $totalMemoryInGB = [Math]::Round($mem.TotalPhysicalMemory / (1024 * 1024 * 1024))
    if ($totalMemoryInGB -lt 6) {
        throw "Check system memory requirement failed. At least 6GB physical memory is required."
    }
}

function CheckVhds {
    [CmdletBinding()]
    Param(
        [string]
        [Parameter(Mandatory = $true)]
        $PackagePath
    )

    Write-Verbose "Check Files existence. PackagePath: $PackagePath"
    $OtherVHDs + ($DeployAzureStackFileName,$OSVHD) | ? { -not (Test-Path ([System.IO.Path]::Combine($PackagePath, $_)))} | % { throw "Cannot find $_ in $PackagePath" }
}

function CheckHyperVSupport {
    Write-Verbose "Check Hyper-V support on the host."

    $feature = Get-WindowsFeature -Name "Hyper-V"
    if ($feature.InstallState -ne "Installed") {
        $cpu = Get-WmiObject -Class WIN32_PROCESSOR
        if (!$cpu.VirtualizationFirmwareEnabled) {
            throw "Hyper-V is not supported on this host. Hardware virtualization is required for Hyper-V."
        }
    }
}

function CheckOSVersion {
    [CmdletBinding()]
    Param(
        [string]
        [Parameter(Mandatory = $true)]
        $PackagePath
    )

    # Check Host OS version first, otherwist DISM will failed to get VHD OS version
    Write-Verbose "Check Host OS version"
    $hostOS = Get-WmiObject win32_operatingsystem
    Write-Verbose ("Host OS version: {0}, SKU: {1}" -f $hostOS.Version, $hostOS.OperatingSystemSKU)
    $hostOSVersion = [Version]::Parse($hostOS.Version)
    
    #TODO: Update the least required OS version
    $server2016OSVersion = [Version]::Parse("10.0.10586")
    $serverDataCenterSku = 8 # Server Datacenter
    $serverDataCenterEvalSku = 80 # Server Datacenter EVal
 
    if ($hostOSVersion -lt $server2016OSVersion -or ($hostOS.OperatingSystemSKU -ne $serverDataCenterSku -and $hostOS.OperatingSystemSKU -ne $serverDataCenterEvalSku)) {
        throw "The host OS should be Windows Server 2016 Datacenter."
    }
}

function CheckDomainJoinStatus {
    Write-Verbose "Check domain join status"
    Write-Verbose "Check whether this check item has passed before. Only need to do it once."

    $domainJoinStatusCheckPassedPropertyName = "DomainJoinStatusCheckPassed"
    $property = Get-ItemProperty -LiteralPath $PocRootKey
    if ($property.DomainJoinStatusCheckPassed -eq 1) {
        Write-Verbose "Domain join status check already passed."
        return
    }

    $sysInfo = Get-WmiObject -Class Win32_ComputerSystem
    if ($sysInfo.PartOfDomain) {
        throw "The host must not be domain joined. Please leave the domain and try again."
    }

    New-ItemProperty -LiteralPath $PocRootKey -Name $domainJoinStatusCheckPassedPropertyName -PropertyType DWord -Value 1 -Force
}

function CheckVMSwitch {
    $vmSwitchCheckPassedPropertyName = "VMSwitchCheckPassed"
    $property = Get-ItemProperty -LiteralPath $PocRootKey
    if ($property.VMSwitchCheckPassed -eq 1) {
        Write-Verbose "Virtual Switch check already passed."
        return
    }

    if (([array](Get-NetAdapter | ? {$_.Status -eq 'Up'})).Count -ne 1) {
        throw "Multiple NICs, virtual switches or NIC teaming are not allowed. Please only keep one physical NIC enabled and remove virtual switches or NIC teaming."
    }

    New-ItemProperty -LiteralPath $PocRootKey -Name $vmSwitchCheckPassedPropertyName -PropertyType DWord -Value 1 -Force
}

function CheckServerName {
  if ($Env:COMPUTERNAME -eq 'AzureStack') {
    throw "Server name cannot be ""AzureStack"" since it conflicts with the domain name."
  }
}

$ErrorActionPreference = 'Stop'

Write-Host "There are several prerequisites checks to verify that your machine meets all the minimum requirements for deploying Microsoft Azure Stack POC."

Write-Verbose "Invoke-AzureStackDeploymentPrecheck started."

if (-not (Test-Path $PocRootKey)) {
    New-Item -Path $PocRootKey -Force | Out-Null
}

$checks = {CheckAdministratorPriviledge}, `
            {CheckDomainJoinStatus}, `
            {CheckInternetAccess}, `
            {CheckDisks}, `
            {CheckRam}, `
            {CheckHyperVSupport}, `
            {CheckVhds -PackagePath $PackagePath}, `
            {CheckOSVersion -PackagePath $PackagePath}, `
            {CheckVMSwitch}, `
            {CheckServerName}

$PreCheckProgressMessage = "Running Prerequisites Check"

for($i=0; $i -lt $checks.Length; $i++)
{
     Write-Progress -Activity $PreCheckProgressMessage -PercentComplete ($i * 100 / $checks.Length)
     Invoke-Command -ScriptBlock $checks[$i] -NoNewScope
}

Write-Progress -Activity $PreCheckProgressMessage -Completed

Write-Host "All of the prerequisite checks passed."


Write-Verbose "Invoke-AzureStackDeploymentPrecheck finished."

# SIG # Begin signature block
# MIIdvgYJKoZIhvcNAQcCoIIdrzCCHasCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUquJNtDIy4uF462KXI9kZESGc
# 6xygghhkMIIEwzCCA6ugAwIBAgITMwAAAIz/8uUYHhYhIgAAAAAAjDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTUxMDA3MTgxNDAz
# WhcNMTcwMTA3MTgxNDAzWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OjU4NDctRjc2MS00RjcwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4W+LEnfuZm/G
# IvSqVPm++Ck9A/SF27VL7uz2UVwcplyRlFzPcVu5oLD4/hnjqwR28E3X7Fz1SHwD
# XpaRyCFCi3rXEZDJIYq3AxZYINPoc9D75eLpbjxdjslrZjOEZKT3YCzZB/gHX/v6
# ubvwP+oiDSsYV0t/GuWLkMtT49ngakuI6j0bamkAD/WOPB9aBa+KekFwpMn7H+/j
# LP2S7y1fiGErxBwI1qmbBR/g7N4Aka4LOzkxOKVFWNdOWAhvChKomkpiWPyhb9bY
# 4+CqcpYvCHyq1V8siMzd0bUZYzibnYL5aHoMWKVgxZRqZKTvRcr5s1NQtHkucERK
# 4CkAb4MhqQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFOZJqXDBCcJz5PLcr2XHyiAb
# YqdkMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAIsRhQk0uISBb0rdX57b2fsvYaNCa9h9SUn6vl26eMAiWEoI
# wDOTALzioSHJPwLKx3CV+pBnDy8MTIKEjacHJhMJ/m8b5PFDopM53NbkVE3NgqjF
# id4O1YH5mFjJDCi0M2udQL9sYsIn5wC6+mxlz15jnc72kCc34cU+1HgOU6UPGURM
# XZzE67qms2NgE+FIPMNbHw7PfI8PSHZz/W9Y+oyCsyJlggc4lMCK97AKo6weBMNH
# Zh8KqwLxb6CDM/UuYAs0UvflmvpbITPlCssYJtdzM+hF6NdMvIkUw0BGtqsIZUZK
# q2sOk0RYOYL4BYDWTBPhPWpKpDKFYUKpgrkP94kwggYHMIID76ADAgECAgphFmg0
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
# NwIBFTAjBgkqhkiG9w0BCQQxFgQU+K6mTKcrzAEMP7BWaPlCRZFzptkweAYKKwYB
# BAGCNwIBDDFqMGigJoAkAFAATwBDAEkAbgBzAHQAYQBsAGwAZQByAFIAYQB3AF8A
# cABzoT6APGh0dHA6Ly9lZHdlYi9zaXRlcy9JU1NFbmdpbmVlcmluZy9FbmdGdW4v
# U2l0ZVBhZ2VzL0hvbWUuYXNweDANBgkqhkiG9w0BAQEFAASCAQCSYncmWoqNOe4P
# KfnIg9rMsKwOPsm08KF5NWhpo7cxEfB8jo0edD1yY+7+4+o8hr9mnG1n8bs2g3of
# hp1bEP9aVUVrwCa+JTLHSPxH0P44vLyi9HyAY08SHZ+xAFwaFdqyRX91CXlCGf2Y
# r1WFy9rl/yXaZ9rMPIrYIxLbNYTwJDtVCMez3USTtdWbDsyJ3NIyzZaVIQpBS4UL
# CVhPtHOFMOkf5i1FReeRR9lNJcdPUMOKQw2Z8pAihg9tEgl86GH4due5WrFjocfz
# 1dmAEq/t2YMn2bIoT6KCCfSwFqjENNL66Lpgew/W/1F0etsV6Cn8xG2KewK4whRg
# N3mLR7CxoYICKDCCAiQGCSqGSIb3DQEJBjGCAhUwggIRAgEBMIGOMHcxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQQITMwAAAIz/8uUYHhYhIgAAAAAAjDAJBgUrDgMCGgUA
# oF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYw
# MTI1MTgzOTE5WjAjBgkqhkiG9w0BCQQxFgQUFg5QA+xkKtm7SLUEDIJti8S5Bngw
# DQYJKoZIhvcNAQEFBQAEggEAvWHNy3HbGIRU2dr6y+UDnoShTtVkVMXLEzBy4po3
# cNFbHJf6MUC/0pSBMCzwAZGfN44v1lO18ZcUimzl8Fd8aQhrB18q2wFenqu9lXjZ
# b3TVfrFTI7t9pOHmfuIDhwDb/Y3Kng/mWO0Ca1F3XfN3Niz4J4s4Ea+8AktZcQZT
# uBcTReSeHJxetWkRh8pzW9RA1GOjrObehqV8AFJoA2ZpOrUvKipvNo1AkoDnp1SE
# pjV1i3bpkarPVO2t5FdxVaPOdTXtQ/tVZQ5bPTH3PtnaJKhm5Naq39+nqy11nJxb
# Z9XD+/KNtr5hJodRXWOkskYyeRXgmAuFdR/aPfmK0cuqSw==
# SIG # End signature block
