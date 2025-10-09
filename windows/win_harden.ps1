#User Accounts
function check_user_accounts {
    Write-Host "Checking user accounts and permissions..."
    
    $users = Get-LocalUser
    
   

    # Check administrator accounts
    $adminUsers = Get-LocalGroupMember -Group "Administrators"
    Write-Host "Administrator accounts:"
    $adminUsers | ForEach-Object { Write-Host " - $($_.Name)" }

    # Check guest account status
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guestAccount) {
        if ($guestAccount.Enabled) {
            Write-Host "WARNING: Guest account is enabled."
            $confirm = Read-Host "Do you want to disable the Guest account? (Y/N)"
            if ($confirm -eq "Y") {
                Disable-LocalUser -Name "Guest"
                Write-Host "Guest account has been disabled."
            } else {
                Write-Host "Guest account remains enabled."
            }
        } else {
            Write-Host "Guest account is properly disabled."
        }
    }

    # Check guest group permissions
    $guestGroup = Get-LocalGroup -Name "Guests" -ErrorAction SilentlyContinue
    if ($guestGroup) {
        $guestMembers = Get-LocalGroupMember -Group "Guests" -ErrorAction SilentlyContinue
        if ($guestMembers) {
            Write-Host "WARNING: Users found in Guests group:"
            $guestMembers | ForEach-Object { Write-Host " - $($_.Name)" }
        } else {
            Write-Host "No users found in Guests group - Good."
        }
    }
}



            $confirm = Read-Host "Do you want to enable the firewall profile '$($profile.Name)'? (Y/N)"
            if ($confirm -eq "Y") {
                Set-NetFirewallProfile -Profile $profile.Name -Enabled True
                Write-Host "Firewall profile '$($profile.Name)' enabled."
            } else {
                Write-Host "Skipped enabling firewall profile '$($profile.Name)'."
            }
function firewall_status {
    $firewallStatus = Get-NetFirewallProfile | Select-Object Name, Enabled
    foreach ($fwProfile in $firewallStatus) {
        if (-not $fwProfile.Enabled) {
            Write-Host "Firewall profile '$($fwProfile.Name)' is disabled. Enabling now..."
            Set-NetFirewallProfile -Profile $fwProfile.Name -Enabled True
        } else {
            Write-Host "Firewall profile '$($fwProfile.Name)' is already enabled."
        }
    }
}
function windows_update {
    Write-Host "Checking for Windows updates..."
    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Host "PSWindowsUpdate module not found. Installing now..."
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
        }
        Import-Module PSWindowsUpdate
        Install-WindowsUpdate -AcceptAll -AutoReboot
        Write-Host "Windows updates installed successfully."
    } catch {
        Write-Host "Error installing Windows updates: $_"
    }
}
function antivirus_check {
    Write-Host "Checking for antivirus software..."
    try {
        $antivirus = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
        if ($antivirus) {
            Write-Host "Antivirus software is installed: $($antivirus.displayName)"
        } else {
            Write-Host "No antivirus software found. Please install an antivirus solution."
        }
    } catch {
        Write-Host "Unable to query antivirus status. The SecurityCenter2 namespace may not be available on this system."
    }
}


########################################################################
# Execute Functions
########################################################################

# Main Function
function main {
    Write-Host "Starting Windows Hardening Script..."
    
    #Calling Functions
    firewall_status
    antivirus_check
    check_user_accounts
    
    Write-Host "Windows Hardening Script completed."
}

main