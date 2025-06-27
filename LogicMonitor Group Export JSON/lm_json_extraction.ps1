# Import the LogicMonitor module
Import-Module LogicMonitor

# Account details
$Account = "accountidhere"
$AccessId = "accessidhere"
$AccessKey = "accesskeyhere"

# Authenticate
Connect-LMAccount -Account $Account -AccessId $AccessId -AccessKey $AccessKey

# Retrieve device group information
$DeviceGroupId = 2690 # Ensure this matches the desired device group ID
$DeviceGroup = Get-LMDeviceGroup -Id $DeviceGroupId

# Define the output file path
$OutputFilePath = "C:\Temp\DeviceGroup.json"

# Output the device group information to a JSON file
$DeviceGroup | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFilePath -Encoding utf8

Write-Host "Device group information saved to $OutputFilePath"
