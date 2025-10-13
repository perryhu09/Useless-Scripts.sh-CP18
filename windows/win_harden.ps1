function manageLocalGroups {
    Clear-Host
    Get-LocalGroup

    $group = Read-Host "What group would you like to check?"
    Get-LocalGroupMember -Group $group

    do {
        $answer = Read-Host "Is there a user you would like to add or remove? [add/remove/back]"
        
        switch ($answer.ToLower()) {
            "add" {
                $userAdd = Read-Host "Please enter the user you would like to add"
                Add-LocalGroupMember -Group $group -Member $userAdd
                Write-Host "$userAdd has been added to $group"
            }
            "remove" {
                $userRem = Read-Host "Please enter the user you would like to remove"
                Remove-LocalGroupMember -Group $group -Member $userRem
                Write-Host "$userRem has been removed from $group"
            }
            "back" {
                return
            }
        }

        $checkAgain = Read-Host "Would you like to check again? [y/n]"
    } while ($checkAgain.ToLower() -eq 'y')
}


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

function disable_remote_services {
    Write-Host "Disabling common remote services (Telnet, SSH, RDP, WinRM, Remote Registry, Remote Access)..."

    # Services to disable: key = service short name, value = friendly name
    $servicesToDisable = @{
        'TlntSvr'        = 'Telnet Server'
        'sshd'           = 'OpenSSH Server'
        'TermService'    = 'Remote Desktop Services (TermService)'
        'WinRM'          = 'Windows Remote Management (WinRM)'
        'RemoteRegistry' = 'Remote Registry'
        'RemoteAccess'   = 'Routing and Remote Access'
        'RasMan'         = 'Remote Access Connection Manager'
    }

    foreach ($svcName in $servicesToDisable.Keys) {
        $friendly = $servicesToDisable[$svcName]
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                if ($svc.Status -ne 'Stopped') {
                    Write-Host "Stopping $friendly ($svcName)..."
                    Stop-Service -Name $svcName -Force -ErrorAction Stop
                }
                Write-Host "Setting $friendly ($svcName) startup type to Disabled..."
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
                Write-Host "$friendly ($svcName) is now disabled."
            } catch {
    Write-Host "Warning: could not modify service $svcName : $($_.Exception.Message)"
}

        } else {
            Write-Host "$friendly ($svcName) not present on this system."
        }
    }

    # As an extra precaution, disable Remote Desktop connections via registry
    try {
        $rdpRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        if (Test-Path $rdpRegPath) {
            $current = Get-ItemProperty -Path $rdpRegPath -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
            if ($null -eq $current -or $current.fDenyTSConnections -ne 1) {
                Write-Host "Disabling Remote Desktop connections via registry (fDenyTSConnections = 1)..."
                Set-ItemProperty -Path $rdpRegPath -Name 'fDenyTSConnections' -Value 1 -ErrorAction Stop
                Write-Host "Remote Desktop (RDP) connections disabled via registry."
            } else {
                Write-Host "Remote Desktop (RDP) already disabled in registry."
            }
        }
    } catch {
        Write-Host "Warning: Unable to modify RDP registry setting: $_"
    }
}
function disable_additional_services {
    Write-Host "Disabling additional vulnerable services..."

    $servicesToDisable = @(
        'TapiSrv',
        'TlntSvr',
        'ftpsvc',
        'SNMP',
        'SessionEnv',
        'TermService',
        'UmRdpService',
        'SharedAccess',
        'remoteRegistry',
        'SSDPSRV',
        'W3SVC',
        'SNMPTRAP',
        'remoteAccess',
        'RpcSs',
        'HomeGroupProvider',
        'HomeGroupListener'
    )

    foreach ($service in $servicesToDisable) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                if ($svc.Status -ne 'Stopped') {
                    Stop-Service -Name $service -Force -ErrorAction Stop
                    Write-Host "Stopped service: $service"
                }
                Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                Write-Host "Disabled service: $service"
            } catch {
                Write-Host "Warning: Could not modify service $service : $($_.Exception.Message)"
            }
        } else {
            Write-Host "Service $service not found on this system."
        }
    }
}
function checkUAC {
    Write-Host "Checking UAC settings for maximum security..."
    $uacRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $maxUAC = @{
        'EnableLUA' = 1
        'ConsentPromptBehaviorAdmin' = 2
        'PromptOnSecureDesktop' = 1
    }
    $allGood = $true
    foreach ($key in $maxUAC.Keys) {
        $value = Get-ItemProperty -Path $uacRegPath -Name $key -ErrorAction SilentlyContinue
        if ($null -eq $value -or $value.$key -ne $maxUAC[$key]) {
            Write-Host "UAC setting '$key' is not at maximum. Setting to $($maxUAC[$key])..."
            Set-ItemProperty -Path $uacRegPath -Name $key -Value $maxUAC[$key] -ErrorAction SilentlyContinue
            $allGood = $false
        }
    }
    if ($allGood) {
        Write-Host "All UAC settings are at maximum security."
    } else {
        Write-Host "UAC settings have been updated to maximum security."
    }
}
function secure_registry_settings {
    Write-Host "Configuring secure registry settings..."

    # Restrict CD ROM drive
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateCDRoms" -Value 1 -Type DWord

    # Disable Automatic Admin logon
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -Type DWord

    # Set logon message
    $body = Read-Host "Please enter logon text"
    Set-ItemProperty -Path "HKLM:\SYSTEM\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value $body
    
    $subject = Read-Host "Please enter the title of the message"
    Set-ItemProperty -Path "HKLM:\SYSTEM\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Value $subject

    # Configure security settings
    $registrySettings = @{
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" = @{
            "ClearPageFileAtShutdown" = 1
        }
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{
            "AllocateFloppies" = 1
        }
        "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" = @{
            "AddPrinterDrivers" = 1
        }
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" = @{
            "LimitBlankPasswordUse" = 1
            "auditbaseobjects" = 1
            "fullprivilegeauditing" = 1
            "disabledomaincreds" = 1
            "everyoneincludesanonymous" = 0
            "restrictanonymous" = 1
            "restrictanonymoussam" = 1
            "UseMachineId" = 0
        }
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
            "dontdisplaylastusername" = 1
            "EnableInstallerDetection" = 1
            "undockwithoutlogon" = 0
            "DisableCAD" = 0
        }
        "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" = @{
            "MaximumPasswordAge" = 15
            "DisablePasswordChange" = 1
            "RequireStrongKey" = 1
            "RequireSignOrSeal" = 1
            "SignSecureChannel" = 1
            "SealSecureChannel" = 1
        }
        "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" = @{
            "autodisconnect" = 45
            "enablesecuritysignature" = 0
            "requiresecuritysignature" = 0
            "NullSessionPipes" = ""
            "NullSessionShares" = ""
        }
        "HKLM:\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" = @{
            "EnablePlainTextPassword" = 0
        }
    }

    foreach ($path in $registrySettings.Keys) {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        
        foreach ($name in $registrySettings[$path].Keys) {
            try {
                Set-ItemProperty -Path $path -Name $name -Value $registrySettings[$path][$name] -Type DWord -ErrorAction Stop
                Write-Host "Successfully set $name in $path"
            }
            catch {
                Write-Host "Error setting $name in $path : $_"
            }
        }
    }
}

########################################################################
# Execute Functions
########################################################################

# Main Function
function main {
    Write-Host "Starting Windows Hardening Script..."
    
    #Calling Functions
    manageLocalGroups
    firewall_status
    antivirus_check
    check_user_accounts
    windows_update
    disable_remote_services
    checkUAC
    disable_additional_services
    secure_registry_settings
   
    Write-Host "Windows Hardening Script completed."
}

main