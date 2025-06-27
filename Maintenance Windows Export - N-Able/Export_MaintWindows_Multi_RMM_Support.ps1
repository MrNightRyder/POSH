########## VARIABLES BEGIN ##########
$RMMs = @(
    @{ ServerFQDN="rmm.server.here"; JWT="jwthere" }, # JWT1
    @{ ServerFQDN="rmm.server.here"; JWT="jwthere2" }, # JWT2
    @{ ServerFQDN="rmm.server.here"; JWT="jwthere3" }, # JWT3
    @{ ServerFQDN="rmm.server.here"; JWT="jwthere4" }  # JWT4
)
$SleepSeconds  = 2
$EnableDebug   = $true
$LogFilePath   = "C:\Temp\maintenance_log.txt"
$ExcelPath     = "C:\Temp\DeviceMaintenanceWindows.xlsx"

########## CUSTOMER TARGETING ##########
# To process ALL customers, leave both variables blank/null.
# To filter by name, set $TargetCustomerName = "Your Customer Name"
# To filter by ID,   set $TargetCustomerId   = 12345
$TargetCustomerName = "$null"     # Example: "Acme Corporation"
$TargetCustomerId   = $null  # Example: 12345

########## LOGGING ##########
if (-not (Test-Path (Split-Path $LogFilePath))) { New-Item -ItemType Directory -Path (Split-Path $LogFilePath) -Force }
"" | Out-File -FilePath $LogFilePath -Encoding utf8

function Log-Info ($msg) {
    $time = Get-Date -Format u
    Write-Host "[$time] $msg"
    "$time $msg" | Out-File -FilePath $LogFilePath -Encoding utf8 -Append
}
function Log-Debug ($msg) { if ($EnableDebug) { Log-Info "[DEBUG] $msg" } }

########## MODULES ##########
if (-not (Get-Module -ListAvailable -Name "ps-ncentral")) { Install-Module ps-ncentral -Force -Scope CurrentUser }
Import-Module ps-ncentral
if (-not (Get-Module -ListAvailable -Name "ImportExcel")) { Install-Module -Name ImportExcel -Force -Scope CurrentUser }
Import-Module ImportExcel

########## GET SHORT-LIVED ACCESS TOKEN ##########
function Get-AccessToken ($ServerFQDN, $UiJWT) {
    $url = "https://$ServerFQDN/api/auth/authenticate"
    $headers = @{ "Authorization" = "Bearer $UiJWT"; "accept" = "*/*" }
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -ErrorAction Stop
        return $resp.tokens.access.token
    } catch {
        Log-Info "[AUTH ERROR] $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $body = (New-Object IO.StreamReader $_.Exception.Response.GetResponseStream()).ReadToEnd()
            Log-Info "[AUTH ERROR BODY] $body"
        }
        throw
    }
}

########## MAINTENANCE WINDOWS ##########
function Get-DeviceMaintenanceWindows ($ServerFQDN, $AccessToken, $DeviceId) {
    $url = "https://$ServerFQDN/api/devices/$DeviceId/maintenance-windows"
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "accept" = "*/*"
    }
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method GET -ErrorAction Stop
        return $resp.data
    } catch {
        Log-Info "[MW WARN] For ${ServerFQDN} Device ${DeviceId}: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $body = (New-Object IO.StreamReader $_.Exception.Response.GetResponseStream()).ReadToEnd()
            Log-Info "[MW RESPONSE BODY] $body"
        }
        return $null
    }
}

########## MAIN ROUTINE ##########
$DevicesPerRMM = @{}

foreach ($RMM in $RMMs) {
    $ServerFQDN = $RMM.ServerFQDN
    $UiJWT = $RMM.JWT
    Log-Info "`nConnecting to NCentral $ServerFQDN..."

    # New NCentralConnection - this is for PowerShell module calls
    try {
        New-NCentralConnection -ServerFQDN $ServerFQDN -jwt $UiJWT
        Log-Info "NCentral connection established."
    } catch {
        Log-Info "ERROR: Failed to connect to ${ServerFQDN}: $($_.Exception.Message)"
        continue
    }

    # Get a short-lived Bearer access token for the REST API
    try {
        $accessToken = Get-AccessToken $ServerFQDN $UiJWT
        Log-Info "Short-lived REST access token acquired for $ServerFQDN."
    } catch {
        Log-Info "ERROR: Could not get REST access token for ${ServerFQDN}. Skipping."
        continue
    }

    try {
        $allCustomers = Get-NCCustomerList | Where-Object { $_.customerid -ge 100 }

        # === CUSTOMER FILTERING LOGIC ===
        if ($TargetCustomerName) {
            $allCustomers = $allCustomers | Where-Object { $_.customername -eq $TargetCustomerName }
            Log-Info "Filtering for customer name '$TargetCustomerName'."
        }
        elseif ($TargetCustomerId) {
            $allCustomers = $allCustomers | Where-Object { $_.customerid -eq $TargetCustomerId }
            Log-Info "Filtering for customer ID '$TargetCustomerId'."
        }
        else {
            Log-Info "Processing ALL customers."
        }

        if ($allCustomers.Count -eq 0) {
            Log-Info "No matching customers found. Skipping server."
            continue
        }

        Log-Info "Found $($allCustomers.Count) customers to process."
    } catch {
        Log-Info "ERROR: Could not get customer list from ${ServerFQDN}: $($_.Exception.Message)"
        continue
    }

    foreach ($cust in $allCustomers) {
        Log-Info "Processing customer $($cust.customername) [ID $($cust.customerid)] in ${ServerFQDN}..."
        try {
            $deviceIDs = Get-NCDeviceList -CustomerIDs $cust.customerid | Select-Object -ExpandProperty deviceid -Unique
            Log-Info "`tFound $($deviceIDs.Count) devices."
            if ($deviceIDs.Count -eq 0) { Log-Info "`tNo devices, skipping."; continue }

            $devices = Get-NCDeviceInfo -DeviceIDs $deviceIDs | Select-Object deviceid, deviceclass, longname, customername

            $deviceResults = @()
            foreach ($device in $devices) {
                $full = $device | Select-Object *
                $full | Add-Member -MemberType NoteProperty -Name "RMMServer" -Value $ServerFQDN -Force

                $mwData = Get-DeviceMaintenanceWindows $ServerFQDN $accessToken $device.deviceid
                if ($mwData) {
                    if ($mwData.Count -gt 0) {
                        $firstMW = $mwData | Select-Object -First 1
                        $full | Add-Member -MemberType NoteProperty -Name "MaintenanceWindowName" -Value $firstMW.name -Force
                        $full | Add-Member -MemberType NoteProperty -Name "MaintenanceWindowSchedule" -Value $firstMW.schedule -Force
                        $full | Add-Member -MemberType NoteProperty -Name "AllMaintenanceWindows" -Value ( ($mwData | ForEach-Object { $_.name }) -join '; ' ) -Force
                    } else {
                        $full | Add-Member -MemberType NoteProperty -Name "MaintenanceWindowName" -Value "" -Force
                        $full | Add-Member -MemberType NoteProperty -Name "MaintenanceWindowSchedule" -Value "" -Force
                        $full | Add-Member -MemberType NoteProperty -Name "AllMaintenanceWindows" -Value "" -Force
                    }
                } else {
                    $full | Add-Member -MemberType NoteProperty -Name "MaintenanceWindowName" -Value "N/A" -Force
                    $full | Add-Member -MemberType NoteProperty -Name "MaintenanceWindowSchedule" -Value "N/A" -Force
                    $full | Add-Member -MemberType NoteProperty -Name "AllMaintenanceWindows" -Value "N/A" -Force
                }

                $deviceResults += $full
            }

            Log-Info "`t$($deviceResults.Count) devices processed."
            if (-not $DevicesPerRMM.ContainsKey($ServerFQDN)) { $DevicesPerRMM[$ServerFQDN] = @() }
            $DevicesPerRMM[$ServerFQDN] += $deviceResults
        }
        catch {
            Log-Info "`tERROR processing customer $($cust.customername) in ${ServerFQDN}: $($_.Exception.Message)"
        }
        if ($SleepSeconds -gt 0) {
            Log-Info "`tSleeping $SleepSeconds seconds before next customer..."
            Start-Sleep -Seconds $SleepSeconds
        }
    }
}

Log-Info ""
Log-Info "All servers processed. Exporting Excel with one worksheet per RMM..."

if ($DevicesPerRMM.Values | Where-Object { $_.Count -gt 0 }) {
    Remove-Item -Path $ExcelPath -ErrorAction SilentlyContinue # Clean old excel
    $first = $true
    foreach ($kv in $DevicesPerRMM.GetEnumerator()) {
        $rmmServer = $kv.Key
        $items = $kv.Value
        if ($items.Count -eq 0) { continue }
        Log-Info "Exporting $($items.Count) devices from $rmmServer as worksheet..."
        $wsName = ($rmmServer -replace "\..*$","") -replace '[^\w]','_'  # worksheet names can't have dots
        $params = @{
            Path = $ExcelPath
            WorksheetName = $wsName
            AutoSize = $true
            FreezeTopRowFirstColumn = $true
            AutoFilter = $true
            BoldTopRow = $true
            Title = "Maintenance Windows Export ($rmmServer)"
        }
        if ($first) {
            $params.Add("Show",$true)
            $first = $false
            $items | Export-Excel @params
        } else {
            $params.Remove("Show")
            $items | Export-Excel @params -Append
        }
    }
    Log-Info "Excel export complete: $ExcelPath"
} else {
    Log-Info "No devices found. Nothing exported."
}

Log-Info "Done!"
