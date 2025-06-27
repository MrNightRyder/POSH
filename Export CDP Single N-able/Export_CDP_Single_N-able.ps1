########## VARIABLES BEGIN ##########
$ServerFQDN = "server.address.here"
$CDPName = "cdp_name"
$JWT = "jwthere"
$SleepSeconds  = 0                         # set to 0 for fastest speed
$EnableDebug   = $true                     # turn off debug logs by setting $false
$LogFilePath   = "C:\Temp\cdp_rmmlog.txt"
$ExcelPath     = "C:\Temp\FilteredVeeamDevices_rmm.xlsx"
########## VARIABLES END ##########

# Ensure log/log folder exists
if (-not (Test-Path (Split-Path $LogFilePath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogFilePath) -Force
}
"" | Out-File -FilePath $LogFilePath -Encoding utf8  # clean log at start

# Logging functions
function Log-Info($msg) {
    $time = Get-Date -Format u
    Write-Host "[$time] $msg"
    "$time $msg" | Out-File -FilePath $LogFilePath -Encoding utf8 -Append
}
function Log-Debug($msg) {
    if ($EnableDebug) { Log-Info "[DEBUG] $msg" }
}

# Load modules or install
if (-not (Get-Module -ListAvailable -Name "ps-ncentral")) {
    Install-Module ps-ncentral -Force -Scope CurrentUser
}
Import-Module ps-ncentral

if (-not (Get-Module -ListAvailable -Name "ImportExcel")) {
    Install-Module -Name ImportExcel -Force -Scope CurrentUser
}
Import-Module ImportExcel

# Connect to NCentral API
Log-Info "Connecting to NCentral..."
try {
    New-NCentralConnection -ServerFQDN $ServerFQDN -jwt $JWT
    Log-Info "NCentral connection established."
} catch {
    Log-Info "ERROR: Failed to connect to NCentral: $($_.Exception.Message)"
    exit 1
}

# Get all non-SO customers (id >= 100)
try {
    $allCustomers = Get-NCCustomerList | Where-Object { $_.customerid -ge 100 }
    Log-Info "Found $($allCustomers.Count) customers to process."
} catch {
    Log-Info "ERROR: Could not get customer list: $($_.Exception.Message)"
    exit 1
}

$AllDevicesFiltered = @()
$PropertyNameDetected = $null

foreach ($cust in $allCustomers) {
    Log-Info "Processing customer $($cust.customername) [ID $($cust.customerid)]..."
    try {
        $deviceIDs = Get-NCDeviceList -CustomerIDs $cust.customerid | Select-Object -ExpandProperty deviceid -Unique
        Log-Info "`tFound $($deviceIDs.Count) devices."
        if ($deviceIDs.Count -eq 0) { Log-Info "`tNo devices, skipping."; continue }

        $devices = Get-NCDeviceInfo -DeviceIDs $deviceIDs | Select-Object deviceid, deviceclass, longname, customername
        $CDPInfoRaw = Get-NCDevicePropertyList -DeviceIDs $deviceIDs 

        # On first device, auto-detect CDP property name if needed
        if (-not $PropertyNameDetected) {
            $CDPColumns = $CDPInfoRaw | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
            # Find closest match to $CDPName (case-insensitive, removes spaces)
            $target = $CDPName -replace '\s',''
            $match = $CDPColumns | Where-Object { ($_ -replace '\s','').ToLower() -eq $target.ToLower() }
            if ($match.Count -eq 1) {
                $PropertyNameDetected = $match
                Log-Info "`tDetected property name: '$PropertyNameDetected'"
            } else {
                Log-Info "`tWARNING: Could not auto-detect '$CDPName'. CDP columns: $($CDPColumns -join ', ')"
                # Fall back to specified name anyway
                $PropertyNameDetected = $CDPName
            }
        }

        $CDPInfo = $CDPInfoRaw | Select-Object deviceid, $PropertyNameDetected

        # Store expanded objects with parsed fields
        $expandedDevices = @()
        foreach ($device in $devices) {
            $infoRow = $CDPInfo | Where-Object { $_.deviceid -eq $device.deviceid }
            $val = $null
            if ($infoRow -and $infoRow.PSObject.Properties[$PropertyNameDetected]) {
                $val = $infoRow.$PropertyNameDetected
            }
            Log-Debug "Device $($device.deviceid) $($device.longname): $PropertyNameDetected = [$val]"
            # Add parsed fields as properties
            $fields = @{}
            if (-not [string]::IsNullOrWhiteSpace($val)) {
                foreach ($pair in $val -split '\|') {
                    if ($pair -match '([^=]+)=(.*)') {
                        $fields[$matches[1].Trim()] = $matches[2].Trim()
                    }
                }
            }
            $full = $device | Select-Object *
            foreach ($key in $fields.Keys) {
                $full | Add-Member -MemberType NoteProperty -Name $key -Value $fields[$key] -Force
            }
            $expandedDevices += $full
        }

        # Filter by UsedInstancesNumber > 0
        $devicesFiltered = $expandedDevices | Where-Object {
            $_.UsedInstancesNumber -as [int] -and ([int]$_.UsedInstancesNumber -gt 0)
        }
        Log-Info "`t$($devicesFiltered.Count) devices meeting UsedInstancesNumber -gt 0 found."
        $AllDevicesFiltered += $devicesFiltered
    }
    catch {
        Log-Info "`tERROR processing customer $($cust.customername): $($_.Exception.Message)"
    }
    if ($SleepSeconds -gt 0) {
        Log-Info "`tSleeping $SleepSeconds seconds before next customer..."
        Start-Sleep -Seconds $SleepSeconds
    }
}

Log-Info "All customers processed. Final device count: $($AllDevicesFiltered.Count). Exporting to Excel..."

if ($AllDevicesFiltered.Count -gt 0) {
    $AllDevicesFiltered | Export-Excel -Path $ExcelPath -AutoSize -FreezeTopRowFirstColumn -AutoFilter -BoldTopRow -WorksheetName "$CDPName" -Show
    Log-Info "Excel export complete: $ExcelPath"
} else {
    Log-Info "No devices matched filter. Nothing exported."
}

Log-Info "Done!"
