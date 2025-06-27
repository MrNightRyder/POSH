########## VARIABLES BEGIN ##########
$ServerFQDN = "rmm.address.here"
$CDPName = "Nameofcdphere"
$JWT = "jwttokenhere"
########## VARIABLES END ##########

# Install necesairy modules
If (Get-Module -ListAvailable -Name "ps-ncentral") { 
    Import-module ps-ncentral
}
Else { 
    Install-Module ps-ncentral -Force
    Import-Module ps-ncentral
}

# Make connection
New-NCentralConnection -ServerFQDN $ServerFQDN -jwt $JWT

$customers = Get-NCCustomerList
$customer = $customers | Select-Object customerid, customername, parentid | Out-GridView -PassThru -Title "Select Customer(s)"
$deviceids = Get-NCDeviceList -CustomerIDs $customer.customerid | Select-Object deviceid -Unique
$devices = Get-NCDeviceInfo -DeviceIDs $deviceids | Where-Object { $_.customerid -in $($customer.customerid) } | select-object deviceid, deviceclass, longname, customername
$CDPInfo = Get-NCDevicePropertyList -DeviceIDs $devices.deviceid | Select-Object deviceid, "$CDPName"

foreach ($device in $devices) {
    $device | Add-Member -MemberType NoteProperty -Name "$CDPName" -Value ($CDPInfo | Where-Object { $_.deviceid -eq $device.deviceid })."$CDPName"
}

# output to excel, but you can do also csv or screen
$devices | Export-Excel -AutoSize -FreezeTopRowFirstColumn -AutoFilter -BoldTopRow -WorksheetName "$CDPName" -show
