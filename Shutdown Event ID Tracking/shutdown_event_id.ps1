# Define the event IDs to search for
$EventIDs = @(41, 1074, 6008)

# Calculate the start time for the last 24 hours
$StartTime = (Get-Date).AddDays(-1)

# Get the relevant events from the System log for the last 24 hours
$Events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=$EventIDs; StartTime=$StartTime} -ErrorAction SilentlyContinue

# Check if events were found
if ($Events) {
    # Format and output the event details to the console
    $Events | ForEach-Object {
        $output = "Time: $($_.TimeCreated)`nEvent ID: $($_.Id)`nMessage: $($_.Message)`nUser: $($_.UserId)`nMachine: $($_.MachineName)`n"
        Write-Output $output
    }
} else {
    Write-Output "No matching events found in the last 24 hours."
}
