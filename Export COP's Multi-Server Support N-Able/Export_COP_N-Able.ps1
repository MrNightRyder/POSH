########## VARIABLES BEGIN ##########
$RMMs = @(
    @{ ServerFQDN="insert.rmm.here"; JWT="jwt1" },
    @{ ServerFQDN="insert.rmm.here"; JWT="jwt2" },
    @{ ServerFQDN="insert.rmm.here"; JWT="jwt3" },
    @{ ServerFQDN="insert.rmm.here"; JWT="jwt4" }
)
# -- COPs you want to export (add here to show in excel!) --
$COPNames = @(
    "COP_Name_1",
    "COP_Name_2",
    "COP_Name_3",
    "COP_Name_4",
    "COP_Name_5",
    "COP_Name_6",
    "COP_Name_7",
    "COP_Name_8"
)
$PrimaryCOPName = "Adlumin Tenant ID"  # Used for inclusion (must not be blank to export row)
$EnableDebug = $true
$LogFilePath = "C:\Temp\Security_Stack_log.txt"
$ExcelPath   = "C:\Temp\Security_Stack.xlsx"
########## VARIABLES END ##########

# Ensure log folder exists
if (-not (Test-Path (Split-Path $LogFilePath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogFilePath) -Force | Out-Null
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

# Module loading
if (-not (Get-Module -ListAvailable -Name "ps-ncentral")) {
    Install-Module ps-ncentral -Force -Scope CurrentUser
}
Import-Module ps-ncentral

if (-not (Get-Module -ListAvailable -Name "ImportExcel")) {
    Install-Module -Name ImportExcel -Force -Scope CurrentUser
}
Import-Module ImportExcel

$ResultsPerRMM = @{}

foreach ($RMM in $RMMs) {
    $ServerFQDN = $RMM.ServerFQDN
    $JWT = $RMM.JWT
    Log-Info ""
    Log-Info "Connecting to NCentral $ServerFQDN..."

    try {
        New-NCentralConnection -ServerFQDN $ServerFQDN -jwt $JWT
        Log-Info "NCentral connection established."
    } catch {
        Log-Info "ERROR: Failed to connect to ${ServerFQDN}: $($_.Exception.Message)"
        continue
    }

    try {
        $allCustomers = Get-NCCustomerList | Where-Object { $_.customerid -ge 100 }
        Log-Info "Found $($allCustomers.Count) customers to process."
    } catch {
        Log-Info "ERROR: Could not get customer list from ${ServerFQDN}: $($_.Exception.Message)"
        continue
    }

    # Build lookup: customer ID -> name (to later resolve ParentName)
    $customerIdToName = @{}
    foreach ($cc in $allCustomers) { $customerIdToName[$cc.customerid] = $cc.customername }

    $customerResults = @()
    foreach ($cust in $allCustomers) {
        # Only include customers with parentid 50
        if ($cust.parentid -ne 50) { continue }
        Log-Info "Processing customer: $($cust.customername) [ID $($cust.customerid)] (Type: $($cust.customertype), ParentID: $($cust.parentid)) in ${ServerFQDN}..."
        try {
            $props = Get-NCCustomerPropertyList -CustomerIDs $cust.customerid
            # Must have Primary COP set (non-null, non-empty, non-blank)
            $primaryCOPval = $null
            $COPVals = @{}
            foreach ($cop in $COPNames) {
                $COPVals[$cop] = if ($props.PSObject.Properties.Match($cop)) { $props.$cop } else { $null }
            }
            $primaryCOPval = $COPVals[$PrimaryCOPName]
            if (-not [string]::IsNullOrWhiteSpace($primaryCOPval)) {
                $parentName = if ($cust.parentid -and $customerIdToName.ContainsKey($cust.parentid)) { $customerIdToName[$cust.parentid] } else { $null }
                $objProps = [ordered]@{
                    CustomerName = $cust.customername
                    CustomerID   = $cust.customerid
                    CustomerType = $cust.customertype
                    ParentID     = $cust.parentid
                    ParentName   = $parentName
                    RMMServer    = $ServerFQDN
                }
                foreach ($cop in $COPNames) {
                    $objProps[$cop] = $COPVals[$cop]
                }
                $customerResults += New-Object PSObject -Property $objProps
            }
        } catch {
            Log-Info "`tERROR for $($cust.customername): $($_.Exception.Message)"
        }
    }

    $ResultsPerRMM[$ServerFQDN] = $customerResults
}

Log-Info ""
Log-Info "All servers processed. Exporting Excel with one worksheet per RMM..."

if ($ResultsPerRMM.Values | Where-Object { $_.Count -gt 0 }) {
    Remove-Item -Path $ExcelPath -ErrorAction SilentlyContinue # Clean old excel
    $first = $true
    foreach ($kv in $ResultsPerRMM.GetEnumerator()) {
        $rmmServer = $kv.Key
        $items = $kv.Value | Sort-Object CustomerName
        if ($items.Count -eq 0) { continue }
        Log-Info "Exporting $($items.Count) customers from $rmmServer as worksheet..."
        $wsName = ($rmmServer -replace "\..*$","") -replace '[^\w]','_'  # worksheet names can't have dots
        $params = @{
            Path = $ExcelPath
            WorksheetName = $wsName
            AutoSize = $true
            FreezeTopRowFirstColumn = $true
            AutoFilter = $true
            BoldTopRow = $true
            Title = "$PrimaryCOPName Export ($rmmServer)"
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
    Log-Info "No customers found. Nothing exported."
}

Log-Info "Done!"
