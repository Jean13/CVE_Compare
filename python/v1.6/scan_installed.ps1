$ErrorActionPreference = "Continue"

$arch = Get-WmiObject -class win32_operatingsystem | select -expand OSArchitecture

# First try with Windows 64-bit
if ($arch -eq "64-bit")
{
  # Get installed packages information (Windows 64-bit)
  $a = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
  $b = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
  $c = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
  $registries = $a + $b + $c
}

# Else, try Windows 32-bit
else
{
  # Get installed packages information (Windows 32-bit)
  $a = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
  $b = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
  $registries = $a + $b
}


# Parse information to neat table
$registries | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize

# Save information to CSV file
$registries | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv installed.txt


# Timestamp file
$filename = "installed_windows.txt"
$newFileName = [DateTime]::Now.ToString("yyyy") + "_" + $filename
Move-Item -LiteralPath $filename -Destination $newFileName
Remove-Item $filename


# Get the Windows version details
$ver = Get-WmiObject -class win32_operatingsystem | select Caption,ServicePackMajorVersion,OSArchitecture
#Add-Content -Path $newFileName -Value $h
#Add-Content -Path $newFileName -Value $ver
$dev_file = "device_data.txt"
$ver >> $dev_file

# Get the device details
$mod_man = wmic computersystem get model","manufacturer
$device_ver = wmic csproduct get vendor","version
$mod_man >> $dev_file
$device_ver >> $dev_file

# Operating System. Temp file.
$os_file = "windows_ver.txt"
$os = Get-WmiObject -class win32_operatingsystem | select Caption
$os >> $os_file

# Vendor and version information for the database. Temp file.
$vv_file = "vendor_version.txt"
$vv = $device_ver | select-object -skip 2
$vv | Out-File $vv_file -encoding Utf8

# Get list of installed KB's
wmic qfe get HotFixID","InstalledOn
$get_kb = wmic qfe get HotFixID | findstr /r /v "^$"
$kb_file = "kb_list.txt"
$get_kb | Out-File $kb_file -encoding Utf8
