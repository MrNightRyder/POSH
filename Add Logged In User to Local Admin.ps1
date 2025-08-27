# ImmyBot Compatible Azure AD User Detection and Local Admin Assignment
$VerbosePreference = 'Continue'

$Group = "Administrators"
$Method = "set"
$IsCompliant = $false

Write-Verbose "=== Universal Azure AD User Detection and Local Admin Assignment ==="

# Check if running in ImmyBot environment
$IsImmyBot = $null -ne (Get-Command "Invoke-ImmyCommand" -ErrorAction SilentlyContinue)
Write-Verbose "Running in ImmyBot: $IsImmyBot"

# Function to execute commands (ImmyBot aware) with proper parameter passing
function Invoke-UniversalCommand {
    param(
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )
    
    if ($IsImmyBot) {
        if ($ArgumentList -and $ArgumentList.Count -gt 0) {
            return Invoke-ImmyCommand -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        } else {
            return Invoke-ImmyCommand -ScriptBlock $ScriptBlock
        }
    } else {
        if ($ArgumentList -and $ArgumentList.Count -gt 0) {
            return & $ScriptBlock @ArgumentList
        } else {
            return & $ScriptBlock
        }
    }
}

# Function to check if running as administrator (standalone only)
function Test-IsAdmin {
    if ($IsImmyBot) { 
        return $true 
    }
    
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to check Azure AD join status
function Test-AzureADJoinStatus {
    Write-Verbose "Checking Azure AD join status..."
    
    return Invoke-UniversalCommand {
        $azureInfo = @{
            IsAzureADJoined = $false
            IsHybridJoined = $false
            TenantId = $null
            JoinType = "None"
        }
        
        try {
            $dsregResult = dsregcmd /status 2>$null
            
            if ($dsregResult) {
                $azureJoinedLine = $dsregResult | Where-Object { $_ -match "AzureAdJoined\s*:\s*YES" }
                $hybridJoinedLine = $dsregResult | Where-Object { $_ -match "DomainJoined\s*:\s*YES" }
                $tenantIdLine = $dsregResult | Where-Object { $_ -match "TenantId\s*:\s*(.+)" }
                
                if ($azureJoinedLine) {
                    $azureInfo.IsAzureADJoined = $true
                }
                
                if ($hybridJoinedLine) {
                    $azureInfo.IsHybridJoined = $true
                }
                
                if ($tenantIdLine) {
                    $parts = $tenantIdLine -split ":"
                    if ($parts.Length -gt 1) {
                        $azureInfo.TenantId = $parts[-1].Trim()
                    }
                }
                
                # Set join type
                if ($azureInfo.IsAzureADJoined -and $azureInfo.IsHybridJoined) {
                    $azureInfo.JoinType = "Hybrid"
                } elseif ($azureInfo.IsAzureADJoined) {
                    $azureInfo.JoinType = "Azure AD Only"
                } elseif ($azureInfo.IsHybridJoined) {
                    $azureInfo.JoinType = "Domain Only"
                }
            }
        } catch {
            Write-Verbose "dsregcmd failed: $($_.Exception.Message)"
        }
        
        return $azureInfo
    }
}

# Function to get the actual logged-in user with comprehensive detection
function Get-CurrentUser {
    Write-Verbose "Auto-detecting current user with comprehensive methods..."
    
    # Method 1: ImmyBot Person context (most reliable in ImmyBot)
    if ($IsImmyBot) {
        if ($ImmyBot.Person.Email) {
            Write-Verbose "Found user from ImmyBot.Person.Email: $($ImmyBot.Person.Email)"
            return $ImmyBot.Person.Email
        }
    }
    
    # Method 2: Comprehensive user detection
    $userResult = Invoke-UniversalCommand {
        $foundUser = $null
        $detectionMethod = ""
        
        Write-Verbose "Starting comprehensive user detection..."
        
        # Method 2A: Win32_ComputerSystem (most reliable for current logged-in user)
        try {
            $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
            $loggedInUser = $computerSystem.UserName
            if ($loggedInUser -and $loggedInUser -notlike "*SYSTEM*" -and $loggedInUser -notlike "*SERVICE*") {
                $foundUser = $loggedInUser
                $detectionMethod = "Win32_ComputerSystem"
                Write-Verbose "✅ Method 2A Success - Win32_ComputerSystem: $foundUser"
            } else {
                Write-Verbose "❌ Method 2A - Win32_ComputerSystem returned system account: $loggedInUser"
            }
        } catch {
            Write-Verbose "❌ Method 2A Failed - Win32_ComputerSystem: $($_.Exception.Message)"
        }
        
        # Method 2B: Query active console session user
        if (-not $foundUser) {
            try {
                Write-Verbose "Trying quser command for console session..."
                $quserOutput = quser 2>$null
                if ($quserOutput) {
                    foreach ($line in $quserOutput) {
                        Write-Verbose "quser line: $line"
                        # Look for active console session (marked with > or console)
                        if ($line -match '^\s*>?(\w+)\s+(console|\d+)\s+Active' -or $line -match '^\s*(\w+)\s+console\s+Active') {
                            $sessionUser = $matches[1].Trim()
                            if ($sessionUser -and $sessionUser -ne "USERNAME" -and $sessionUser -notlike "*SYSTEM*") {
                                # Try to get domain info for this user
                                $domain = $env:USERDOMAIN
                                if ($domain -and $domain -ne $env:COMPUTERNAME) {
                                    $foundUser = "$domain\$sessionUser"
                                } else {
                                    $foundUser = $sessionUser
                                }
                                $detectionMethod = "quser-console"
                                Write-Verbose "✅ Method 2B Success - quser console: $foundUser"
                                break
                            }
                        }
                    }
                }
                if (-not $foundUser) {
                    Write-Verbose "❌ Method 2B - quser did not find active console user"
                }
            } catch {
                Write-Verbose "❌ Method 2B Failed - quser: $($_.Exception.Message)"
            }
        }
        
        # Method 2C: Get owner of explorer.exe process (user's desktop process)
        if (-not $foundUser) {
            try {
                Write-Verbose "Trying explorer.exe process owner detection..."
                $explorerProcesses = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop
                foreach ($process in $explorerProcesses) {
                    $owner = $process.GetOwner()
                    if ($owner -and $owner.User -and $owner.User -notlike "*SYSTEM*") {
                        if ($owner.Domain -and $owner.Domain -ne $env:COMPUTERNAME) {
                            $foundUser = "$($owner.Domain)\$($owner.User)"
                        } else {
                            $foundUser = $owner.User
                        }
                        $detectionMethod = "explorer-process-owner"
                        Write-Verbose "✅ Method 2C Success - explorer.exe owner: $foundUser"
                        break
                    }
                }
                if (-not $foundUser) {
                    Write-Verbose "❌ Method 2C - No valid explorer.exe process owner found"
                }
            } catch {
                Write-Verbose "❌ Method 2C Failed - explorer.exe owner: $($_.Exception.Message)"
            }
        }
        
        # Method 2D: Win32_LogonSession and Win32_LoggedOnUser (interactive sessions only)
        if (-not $foundUser) {
            try {
                Write-Verbose "Trying Win32_LoggedOnUser for interactive sessions..."
                $logonSessions = Get-WmiObject -Class Win32_LogonSession -Filter "LogonType=2" -ErrorAction Stop  # Interactive logon
                foreach ($session in $logonSessions) {
                    $loggedOnUsers = Get-WmiObject -Class Win32_LoggedOnUser -ErrorAction Stop
                    foreach ($loggedUser in $loggedOnUsers) {
                        if ($loggedUser.Dependent -match "LogonId=`"$($session.LogonId)`"") {
                            $antecedent = $loggedUser.Antecedent
                            if ($antecedent -match 'Domain="(.+)",Name="(.+)"') {
                                $domain = $matches[1]
                                $username = $matches[2]
                                
                                if ($username -notlike "*$*" -and $username -ne "SYSTEM" -and $username -ne "LOCAL SERVICE" -and $username -ne "NETWORK SERVICE") {
                                    if ($domain -ne $env:COMPUTERNAME) {
                                        $foundUser = "$domain\$username"
                                    } else {
                                        $foundUser = $username
                                    }
                                    $detectionMethod = "interactive-logon-session"
                                    Write-Verbose "✅ Method 2D Success - Interactive session: $foundUser"
                                    break
                                }
                            }
                        }
                    }
                    if ($foundUser) { break }
                }
                if (-not $foundUser) {
                    Write-Verbose "❌ Method 2D - No interactive logon sessions found"
                }
            } catch {
                Write-Verbose "❌ Method 2D Failed - Interactive sessions: $($_.Exception.Message)"
            }
        }
        
        # Method 2E: Registry-based detection (current user profile)
        if (-not $foundUser) {
            try {
                Write-Verbose "Trying registry-based user detection..."
                $profileList = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction Stop
                foreach ($profile in $profileList) {
                    $profilePath = Get-ItemProperty -Path $profile.PSPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue
                    if ($profilePath -and $profilePath.ProfileImagePath -like "*Users\*") {
                        $userFolder = Split-Path -Leaf $profilePath.ProfileImagePath
                        if ($userFolder -ne "Public" -and $userFolder -ne "Default" -and $userFolder -notlike "*SYSTEM*") {
                            # Check if this profile is currently loaded
                            $sid = Split-Path -Leaf $profile.PSPath
                            $loadedProfile = Get-ItemProperty -Path "HKU:\$sid" -ErrorAction SilentlyContinue
                            if ($loadedProfile) {
                                $foundUser = $userFolder
                                $detectionMethod = "registry-loaded-profile"
                                Write-Verbose "✅ Method 2E Success - Loaded registry profile: $foundUser"
                                break
                            }
                        }
                    }
                }
                if (-not $foundUser) {
                    Write-Verbose "❌ Method 2E - No loaded user profiles found in registry"
                }
            } catch {
                Write-Verbose "❌ Method 2E Failed - Registry detection: $($_.Exception.Message)"
            }
        }
        
        # Convert to email format if we have domain info (better hybrid join handling)
        if ($foundUser -and $foundUser -notlike "*@*" -and $foundUser -like "*\*") {
            try {
                $userParts = $foundUser -split '\\'
                $domain = $userParts[0]
                $username = $userParts[1]
                
                # For hybrid joined machines, try to get the proper email format
                $dnsDomain = $env:USERDNSDOMAIN
                if ($dnsDomain) {
                    $emailFormat = "$username@$dnsDomain"
                    Write-Verbose "Converted to email format for hybrid join: $emailFormat"
                    return @{
                        User = $emailFormat
                        OriginalFormat = $foundUser
                        Method = $detectionMethod
                        IsHybridFormat = $true
                    }
                } else {
                    # Keep original domain\user format if no DNS domain
                    Write-Verbose "Keeping domain\user format (no DNS domain): $foundUser"
                    return @{
                        User = $foundUser
                        OriginalFormat = $foundUser
                        Method = $detectionMethod
                        IsHybridFormat = $false
                    }
                }
            } catch {
                Write-Verbose "Could not process domain\user format: $($_.Exception.Message)"
            }
        }
        
        if ($foundUser) {
            return @{
                User = $foundUser
                OriginalFormat = $foundUser
                Method = $detectionMethod
                IsHybridFormat = $false
            }
        }
        
        return $null
    }
    
    # Validate and return result
    if ($userResult -and $userResult.User -and $userResult.User -notlike "*SYSTEM*" -and $userResult.User -notlike "*SERVICE*") {
        Write-Verbose "✅ Final user detection successful: $($userResult.User) (Method: $($userResult.Method), IsHybrid: $($userResult.IsHybridFormat))"
        return $userResult.User
    }
    
    # Method 3: ImmyBot fallback
    if ($IsImmyBot) {
        if ($ImmyBot.Computer.PrimaryUser.Email) {
            Write-Verbose "Using ImmyBot.Computer.PrimaryUser.Email fallback: $($ImmyBot.Computer.PrimaryUser.Email)"
            return $ImmyBot.Computer.PrimaryUser.Email
        }
    }
    
    # Last resort: Show diagnostic info and fail
    Write-Verbose "=== DIAGNOSTIC INFORMATION ==="
    Invoke-UniversalCommand {
        Write-Verbose "Computer Name: $env:COMPUTERNAME"
        Write-Verbose "Current Process User: $env:USERNAME"
        Write-Verbose "User Domain: $env:USERDOMAIN"
        Write-Verbose "DNS Domain: $env:USERDNSDOMAIN"
        
        try {
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            Write-Verbose "Process Identity: $($identity.Name)"
        } catch { }
        
        try {
            $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
            Write-Verbose "Win32_ComputerSystem.UserName: $($computerSystem.UserName)"
        } catch { }
    }
    
    throw "Could not determine actual logged-in user after trying all methods"
}

# Function to add user to local administrators
function Add-UserToLocalAdmins {
    param([string]$UserIdentifier)
    
    return Invoke-UniversalCommand {
        param($User)
        
        Write-Verbose "Attempting to add user '$User' to local administrators..."
        
        try {
            # Get admin group by SID
            $adminGroups = Get-LocalGroup | Where-Object { $_.SID -eq "S-1-5-32-544" }
            
            if (-not $adminGroups -or $adminGroups.Count -eq 0) {
                throw "Could not find local Administrators group"
            }
            
            $adminGroup = $adminGroups[0]
            Write-Verbose "Found administrators group: $($adminGroup.Name)"
            
            # Check current membership
            Write-Verbose "Checking current group membership..."
            $members = @()
            try {
                $allMembers = Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction SilentlyContinue
                if ($allMembers) {
                    $members = @($allMembers)
                }
            } catch {
                Write-Verbose "Error getting group members: $($_.Exception.Message)"
            }
            
            # Check if already member
            $isAlreadyMember = $false
            if ($members.Count -gt 0) {
                foreach ($member in $members) {
                    if ($member -and $member.Name) {
                        $memberName = $member.Name
                        if ($memberName -eq $User) {
                            $isAlreadyMember = $true
                            break
                        }
                        
                        # Check username part
                        $userParts = $User -split '\\'
                        $usernamePart = $userParts[-1]
                        if ($memberName -like "*$usernamePart*") {
                            $isAlreadyMember = $true
                            break
                        }
                        
                        # Check email part
                        $emailParts = $User -split '@'
                        $emailUserPart = $emailParts[0]
                        if ($memberName -like "*$emailUserPart*") {
                            $isAlreadyMember = $true
                            break
                        }
                    }
                }
            }
            
            if ($isAlreadyMember) {
                Write-Host "User '$User' is already in local administrators" -ForegroundColor Green
                return $true
            }
            
            Write-Verbose "User is not currently in administrators group. Adding..."
            
            # Create list of formats to try
            $userFormats = @($User)
            
            # Add variations based on format
            if ($User -match '^(.+)\\(.+)$') {
                $domain = $matches[1]
                $username = $matches[2]
                
                $userFormats += $username
                $userFormats += "$env:COMPUTERNAME\$username"
                
                # Try SID resolution
                try {
                    $ntAccount = New-Object System.Security.Principal.NTAccount($User)
                    $userSID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    $userFormats += $userSID
                    Write-Verbose "Found SID for user: $userSID"
                } catch {
                    Write-Verbose "Could not resolve SID for $User"
                }
            }
            
            if ($User -like "*@*") {
                $emailParts = $User -split '@'
                $username = $emailParts[0]
                $userFormats += $username
                $userFormats += "$env:COMPUTERNAME\$username"
            }
            
            # Remove duplicates
            $uniqueFormats = @()
            foreach ($format in $userFormats) {
                if ($uniqueFormats -notcontains $format) {
                    $uniqueFormats += $format
                }
            }
            
            Write-Verbose "Will try these user formats: $($uniqueFormats -join ', ')"
            
            # Try each format
            $added = $false
            $lastError = $null
            
            foreach ($userFormat in $uniqueFormats) {
                try {
                    Write-Verbose "Trying to add user format: $userFormat"
                    Add-LocalGroupMember -Group $adminGroup.Name -Member $userFormat -ErrorAction Stop
                    Write-Host "Successfully added '$userFormat' to local administrators" -ForegroundColor Green
                    $added = $true
                    break
                } catch {
                    $lastError = $_.Exception.Message
                    Write-Verbose "Failed with format '$userFormat': $lastError"
                    continue
                }
            }
            
            if (-not $added) {
                throw "Failed to add user with any format. Last error: $lastError"
            }
            
            return $true
            
        } catch {
            Write-Error "Failed to add user to administrators: $($_.Exception.Message)"
            return $false
        }
    } -ArgumentList $UserIdentifier
}

# Main execution
try {
    # Check admin privileges for standalone mode
    if (-not $IsImmyBot -and -not (Test-IsAdmin)) {
        Write-Error "This script must be run as Administrator when not in ImmyBot"
        $IsCompliant = $false
        return $IsCompliant
    }
    
    Write-Host "Running with appropriate privileges" -ForegroundColor Green
    
    # Check Azure AD status first to inform user detection
    Write-Host ""
    Write-Host "--- Azure AD Join Status ---" -ForegroundColor Yellow
    $azureStatus = Test-AzureADJoinStatus
    
    $azureJoinColor = if($azureStatus.IsAzureADJoined){"Green"}else{"Red"}
    $hybridJoinColor = if($azureStatus.IsHybridJoined){"Green"}else{"Red"}
    
    Write-Host "Azure AD Joined: $($azureStatus.IsAzureADJoined)" -ForegroundColor $azureJoinColor
    Write-Host "Hybrid Joined: $($azureStatus.IsHybridJoined)" -ForegroundColor $hybridJoinColor
    Write-Host "Join Type: $($azureStatus.JoinType)" -ForegroundColor Cyan
    
    if ($azureStatus.TenantId) {
        Write-Host "Tenant ID: $($azureStatus.TenantId)" -ForegroundColor Gray
    }
    
    # Update join status based on findings - this machine appears to be hybrid joined
    if ($azureStatus.IsAzureADJoined -and -not $azureStatus.IsHybridJoined) {
        # Double-check for hybrid join signs
        $hasOnPremDomain = Invoke-UniversalCommand { 
            $domain = $env:USERDOMAIN
            $dnsDomain = $env:USERDNSDOMAIN
            return ($domain -and $domain -ne $env:COMPUTERNAME -and $dnsDomain)
        }
        
        if ($hasOnPremDomain) {
            Write-Host "NOTE: Detected on-premises domain indicators - this appears to be Hybrid Joined" -ForegroundColor Yellow
            $azureStatus.IsHybridJoined = $true
            $azureStatus.JoinType = "Hybrid (detected)"
        }
    }
    
    # Get current user
    Write-Host ""
    Write-Host "--- User Detection ---" -ForegroundColor Yellow
    $targetUser = Get-CurrentUser
    
    if (-not $targetUser) {
        throw "Failed to detect current user"
    }
    
    Write-Host "Target User: $targetUser" -ForegroundColor Green
    Write-Host "User Format: $(if($targetUser -like '*@*'){'Email'}elseif($targetUser -like '*\*'){'Domain\User'}else{'Local'})" -ForegroundColor Cyan
    
    # Add to local admins with explicit parameter validation
    Write-Host ""
    Write-Host "--- Adding to Local Administrators ---" -ForegroundColor Yellow
    
    if ([string]::IsNullOrWhiteSpace($targetUser)) {
        throw "Target user is null or empty - cannot add to administrators"
    }
    
    Write-Host "Adding user: '$targetUser'" -ForegroundColor Cyan
    $success = Add-UserToLocalAdmins -UserIdentifier $targetUser
    
    if ($success) {
        Write-Host ""
        Write-Host "SUCCESS: User added to local administrators!" -ForegroundColor Green
        Write-Host "Note: User may need to log off/on for changes to take effect." -ForegroundColor Cyan
        $IsCompliant = $true
    } else {
        Write-Host ""
        Write-Host "FAILED: Could not add user to local administrators" -ForegroundColor Red
        $IsCompliant = $false
    }
    
} catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    $IsCompliant = $false
}

# Output final status
Write-Host ""
Write-Host "--- Final Status ---" -ForegroundColor Magenta
$statusColor = if($IsCompliant){"Green"}else{"Red"}
Write-Host "Compliance Status: $IsCompliant" -ForegroundColor $statusColor

return $IsCompliant
