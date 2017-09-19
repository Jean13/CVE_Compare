$ErrorActionPreference = "Continue"

# First try with Windows 64-bit
if ([Environment]::Is64BitOperatingSystem)
{
  # Get installed packages information (Windows 64-bit)
  $a = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
  $b = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
  $c = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
  $registries = $a, $b, $c
}

# Else, try Windows 32-bit
else
{
  # Get installed packages information (Windows 32-bit)
  $a = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
  $b = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
  $registries = $a, $b
}


Foreach ($i in $registries)
{
  # Parse information to neat table
  $i | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize

  # Save information to CSV file
  $i | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Csv -NoTypeInformation | Out-File -Append -FilePath "installed.txt"
}


# Timestamp file
$filename = "installed.txt"
$newFileName = [DateTime]::Now.ToString("yyyy") + "_" + $filename
Move-Item -LiteralPath $filename -Destination $newFileName
Remove-Item $filename
