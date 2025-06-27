# Function to add registry keys
function Add-RegistryKeys {
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force
    }
    Set-ItemProperty -Path $registryPath -Name "ProductVersion" -Value "Windows 11"
    Set-ItemProperty -Path $registryPath -Name "TargetReleaseVersion" -Type DWord -Value 1
    Set-ItemProperty -Path $registryPath -Name "TargetReleaseVersionInfo" -Value "23H2"
}
# Function to remove registry keys
function Remove-RegistryKeys {
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (Test-Path $registryPath) {
        Remove-ItemProperty -Path $registryPath -Name "ProductVersion" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $registryPath -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $registryPath -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
    }
}
# Function to ensure PSWindowsUpdate is installed and import the module
function Ensure-PSWindowsUpdate {
    if (!(Get-InstalledModule PSWindowsUpdate -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module PowershellGet -Force
        Install-Module PSWindowsUpdate -Force
    }
    Import-Module PSWindowsUpdate -Force
}
# Function to initiate Windows updates
function Install-WindowsUpdates {
    Get-WindowsUpdate -NotTitle "Preview" -AcceptAll -Install -IgnoreReboot -MicrosoftUpdate -ForceInstall
}
# Function to create a scheduled task to remove registry keys on next boot
function Create-RemoveRegTask {
    $scriptPath = $PSScriptRoot + "\RemoveRegistryKeys.ps1"
    $taskName = "RemoveWindowsUpdateRegistryKeys"
    # Create the script to remove registry keys
    @"
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ProductVersion' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersion' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersionInfo' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName '$taskName' -Confirm:$false
"@ | Out-File -FilePath $scriptPath -Encoding UTF8
    # Create the scheduled task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -Description "Remove Windows Update registry keys on next boot" -RunLevel Highest -Force
}
# Main script logic
try {
    # Add registry keys
    Add-RegistryKeys
    # Ensure PSWindowsUpdate is installed and imported
    Ensure-PSWindowsUpdate
    # Install Windows updates
    Install-WindowsUpdates
}
finally {
    # Create a scheduled task to remove registry keys on next boot
    Create-RemoveRegTask
}
