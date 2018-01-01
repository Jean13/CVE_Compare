$ErrorActionPreference = "Continue"

$arch = Get-WmiObject -class win32_operatingsystem | select -expand OSArchitecture

# First try with Windows 64-bit
if ($arch -eq "64-bit")
{
  # Get installed packages information (Windows 64-bit)
  $a = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
  $b = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
  $c = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
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
$filename = "installed.txt"
$newFileName = [DateTime]::Now.ToString("yyyy") + "_" + $filename
Move-Item -LiteralPath $filename -Destination $newFileName
Remove-Item $filename


# Get the Windows version details
$ver = Get-WmiObject -class win32_operatingsystem | select Caption,ServicePackMajorVersion,OSArchitecture
#Add-Content -Path $newFileName -Value $h
#Add-Content -Path $newFileName -Value $ver
$ver_file = "windows_version.txt"
$ver >> $ver_file


# Get list of installed KB's
wmic qfe get HotFixID","InstalledOn
$get_kb = wmic qfe get HotFixID
$kb_file = "kb_list.txt"
$get_kb >> $kb_file
