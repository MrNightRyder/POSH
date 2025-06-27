# Enable debugging output
$DebugPreference = "Continue"

# Configuration
$serverAddress = 'rmmserv.url.listed.here'
$authToken = 'jwttokenhere'
$customerId = '50'
$csvFilePath = "C:\Temp\list.csv"
$baseUrl = "https://$serverAddress"
$throttleDelaySeconds = 0
$retryCount = 1
$retryDelaySeconds = 2

# Function to get Bearer token
function Get-BearerToken {
    param (
        [string]$baseUrl,
        [string]$authToken
    )

    $authUrl = "$baseUrl/api/auth/authenticate"
    $headers = @{
        "Authorization" = "Bearer $authToken"
        "accept" = "*/*"
    }

    try {
        $response = Invoke-RestMethod -Uri $authUrl -Method Post -Headers $headers
        return $response.tokens.access.token
    } catch {
        Write-Output "Failed to obtain Bearer token: $($_.Exception.Message)"
        exit 1
    }
}

# Function to add a site with enhanced debugging
function Add-Site {
    param (
        [string]$apiUrl,
        [string]$accessToken,
        [string]$siteName,
        [string]$contactFirstName,
        [string]$contactLastName,
        [string]$externalId,
        [string]$phone,
        [string]$contactTitle,
        [string]$contactEmail,
        [string]$contactPhone,
        [string]$contactPhoneExt,
        [string]$contactDepartment,
        [string]$street1,
        [string]$street2,
        [string]$city,
        [string]$stateProv,
        [string]$country,
        [string]$postalCode
    )

    # Check and set default values for required fields
    if (-not $siteName) { $siteName = "Unknown Site" }
    if (-not $contactFirstName) { $contactFirstName = "First" }
    if (-not $contactLastName) { $contactLastName = "Last" }

    Write-Debug "Preparing to add site: $siteName"

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
        "accept"        = "application/json"
    }

    $payload = @{
        siteName         = $siteName
        contactFirstName = $contactFirstName
        contactLastName  = $contactLastName
        licenseType      = "Professional"
        externalId       = $externalId
        phone            = $phone
        contactTitle     = $contactTitle
        contactEmail     = $contactEmail
        contactPhone     = $contactPhone
        contactPhoneExt  = $contactPhoneExt
        contactDepartment= $contactDepartment
        street1          = $street1
        street2          = $street2
        city             = $city
        stateProv        = $stateProv
        country          = $country
        postalCode       = $postalCode
    } | ConvertTo-Json -Depth 3

    Write-Debug "JSON Payload: $payload"

    for ($i = 0; $i -le $retryCount; $i++) {
        try {
            $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $payload
            Write-Output "Successfully added site: $siteName"
            return  # Exit the function if the request is successful
        } catch {
            Write-Output "Failed to add site: $siteName (Attempt $($i + 1))"
            Write-Output "Error: $($_.Exception.Message)"
            if ($_.Exception.Response -ne $null) {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $errorResponse = $reader.ReadToEnd()
                Write-Output "Server Response: $errorResponse"
            }
            if ($i -lt $retryCount) {
                Write-Output "Retrying in $retryDelaySeconds seconds..."
                Start-Sleep -Seconds $retryDelaySeconds
            }
        }
    }
}

# Obtain Bearer token
$accessToken = Get-BearerToken -baseUrl $baseUrl -authToken $authToken

# Import sites from CSV file
$sites = Import-Csv -Path $csvFilePath

# Add each site with throttling and retry logic
foreach ($site in $sites) {
    $apiUrl = "$baseUrl/api/customers/$customerId/sites"
    Add-Site -apiUrl $apiUrl -accessToken $accessToken -siteName $site.siteName -contactFirstName $site.contactFirstName -contactLastName $site.contactLastName -externalId $site.externalId -phone $site.phone -contactTitle $site.contactTitle -contactEmail $site.contactEmail -contactPhone $site.contactPhone -contactPhoneExt $site.contactPhoneExt -contactDepartment $site.contactDepartment -street1 $site.street1 -street2 $site.street2 -city $site.city -stateProv $site.stateProv -country $site.country -postalCode $site.postalCode
    Start-Sleep -Seconds $throttleDelaySeconds
}
