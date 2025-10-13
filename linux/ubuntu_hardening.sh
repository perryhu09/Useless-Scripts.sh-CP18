 #!/usr/bin/env bash

#===============================================
# Configuration && Setup
#===============================================
# MANUALLY enter based on README for each image

# Authorized Users
AUTHORIZED_USERS=()

# Users with admin/sudo privileges
ADMIN_USERS=()

# System accounts that should remain disabled (???? <- CHECK THIS)
SYSTEM_ACCOUNTS=()

#===============================================
# Utility Functions
#===============================================
# Set up log  directory and file
LOG_FILE="$HOME/Desktop/hardening.log"

# Logging Function
log_action() {
	local timestamp="[$(date '+%Y-%m-%d %H:%M:%S')]"
	local message="$timestamp $1"

	echo "$message"
	echo "$message" >> "$LOG_FILE" 2>/dev/null
}

backup_file() {
	if  [ -f "$1" ]; then
		cp "$1" "$1.bak.$(date +%s)"
		log_action "Backed up $1"
	fi
}

#===============================================
# System Updates
#===============================================

update_system() {
	log_action "=== UPDATING SYSTEM PACKAGES ==="

	apt update -y -qq &>/dev/null
	log_action "Updated package lists"

	apt full-upgrade -y -qq &>/dev/null
	log_action "Performed full system upgrade"

	apt autoremove -y -qq &>/dev/null
	log_action "Removed unnecessary packages"

	apt autoclean -y -qq &>/dev/null
	log_action "Cleaned package cache"
}

configure_automatic_updates() {
	log_action "=== CONFIGURING AUTOMATIC UPDATES ==="

	# Install unattended updates
	if ! dpkg -l | grep -q unattended-upgrades; then
		apt install -y unattended-upgrades apt-listchanges &>/dev/null
		log_action "Installed unattended-upgrades"
	fi

	# Enable automatic updates
	echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections &>/dev/null
	dpkg-reconfigure -f noninteractive unattended-upgrades &>/dev/nul
	log_action "Enabled unattended-upgrades"

	backup_file /etc/apt/apt.conf.d/20auto-upgrades

	cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
	log_action "Configured daily automatic updates"
}

#===============================================
# Users && Groups
#===============================================

remove_unauthorized_users() {
	log_action "=== CHECKING FOR UNAUTHORIZED USERS ==="

	CURRENT_USERS=$(awk -F: '($3 >=1000 || $3 == 0) && $1 != "nobody" {print $1}' /etc/passwd)	
	for user in $CURRENT_USERS; do
		# Skip root
		if [ "$user" = "root" ]; then
			continue
		fi

		if [[ ! "${AUTHORIZED_USERS[@]}" =~ "${user}" ]]; then
			log_action "FOUND UNAUTHORIZED USER: $user - Removing ..."
			userdel --remove-home "$user" 2>/dev/null
			if [ $? -eq 0 ]; then
				log_action "Successfully removed user: $user"
			else
				log_action "Failed to remove user: $user (CHECK MANUALLY)"
			fi
		fi
	done
}

fix_admin_group() {
	log_action "=== FIXING SUDO GROUP MEMBERSHIP ==="

	# ADMIN - older ubuntu versions used admin group, included for compatability

	SUDO_MEMBERS=$(getent group sudo | cut -d: -f4 | tr ',' ' ')
	ADMIN_MEMBERS=$(getent group admin 2>/dev/null | cut -d: -f4 | tr ',' ' ')

	# Remove unauthorized users from sudo group
	for user in $SUDO_MEMBERS; do
		if [[ ! "$ADMIN_USERS[@]" =~ "${user}" ]]; then
			log_action "Removing $user from sudo group"
			sudo deluser "$user" sudo &>/dev/null
		fi
	done

	# Check if admin group exists (then remove)
	if getent group admin > /dev/null 2>&1; then
		for user in $ADMIN_MEMBERS; do
			if [[ ! "$ADMIN_USERS[@]" =~ "${user}" ]]; then
				log_action "Removing $user from admin group"
				sudo deluser "$user" admin &>/dev/null
			fi
		done
	fi

	# Add authorized admin users to sudo group
	for user in "${ADMIN_USERS[@]}"; do
		if id "$user" &>/dev/null; then
			usermod -aG sudo "$user" &>/dev/null
			log_action "Added $user to sudo group"
		fi
	done
}

check_uid_zero() {
	log_action "=== CHECKING FOR UNAUTHORIZED UID 0 ACCOUNTS ==="

	UID_ZERO=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)

	if [ -n "$UID_ZERO" ]; then
		for user in $UID_ZERO; do
			log_action "WARNING: Found UID 0 account: $user - Removing..."
			deluser --remove-home "$user" 2>/dev/null
		done
	else
		log_action "No unauthorized UID 0 accounts found"
	fi
}
	
# set shell to nologin for system accounts
lock_system_accounts() {
	# TODO: Implement
	log_action "=== LOCKING SYSTEM ACCOUNTS ==="
	log_action "Not yet implemented"
} 

disable_guest() {
	log_action "=== DISABLING GUEST ACCOUNT ==="
	
	# LightDM for Ubuntu 17.04 and prior
	if [ -f /etc/lightdm/lightdm.conf ]; then
		backup_file /etc/lightdm/lightdm.conf

		if ! grep -q "allow-guest=false" /etc/lightdm/lightdm.conf; then # if its not there then...
			echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
			log_action "Disabled guest account in lightdm.conf"
		fi
	fi

	# GDM3 Display Manager
	for gdm_conf in /etc/gdm3/custom.conf /etc/gdm/custom.conf; do
		if [ -f "$gdm_conf" ]; then
			backup_file "$gdm_conf"

			local dm_name="GDM3"
			[[ "$gdm_conf" == *"/gdm/"* ]] && dm_name="GDM"

			# Disable timed login
			if [[ "$gdm_conf" == *"/gdm3/"* ]]; then
				if grep -q "^TimedLoginEnable.*=.*true" "$gdm_conf"; then
					sed -i 's/^\(TimedLoginEnable.*=.*\)true/\1false/' "$gdm_conf"
					log_action "Disabled timed login in ${dm_name} (replaced true w/ false)"
				elif ! grep -q "^TimedLoginEnable.*=.*false" "$gdm_conf"; then
					if grep -q "^\[security\]" "$gdm_conf"; then
						sed -i '/^\[security\]/a TimedLoginEnable=false' "$gdm_conf"
					else
						echo -e "\n[security]\n TimedLoginEnable=false" >> "$gdm_conf"
					fi
					log_action "Disabled timed login in ${dm_name} (added new setting)"
				fi
			fi

			# Disable automatic login
			if grep -q "^AutomaticLoginEnable.*=.+true" "$gdm_conf"; then
				sed -i 's/^\(AutomaticLoginEnable.*=.*\)true/\1false/' "$gdm_conf"
				log_action "Disabled automatic log in ${dm_name} (replaced true with false)"
			elif ! grep -q "^AutomaticLoginEnable.*=.*false" "$gdm_conf"; then
				if grep -q "^\[security\]" "$gdm_conf"; then
					sed -i '/^\[daemon\]/a AutomaticLoginEnable=false' "$gdm_conf"
				else
					echo -e "\n[daemon]\n AutomaticLoginEnable=false" >> "$gdm_conf"
				fi
				log_action "Disabled automatic login in ${dm_name} (added new setting)"
			fi
		fi
	done
	# sudo systemctl restart gdm3
	# REQUIRES SYSTEM RESTART AT THE END
}

set_all_user_passwords() {
	log_action "=== SETTING ALL USER PASSWORDS ==="

	REGULAR_USERS=$(awk -F: '($3 >= 1000) && ($1 != "nobody") {print $1}' /etc/passwd)

	for user in $REGULAR_USERS; do
		echo "$user:Cyb3rPatr!0t" | chpasswd
		log_action "Set password for user: $user"
	done

	log_action "All user passwords set to: Cyb3rPatr!0t"
}

#===============================================
# Password Policies 
#===============================================

# remove nullok in /etc/pam.d/common-auth to disallow empty pwds
disallow_empty_passwords() {
	log_action "=== DISALLOWING EMPTY PASSWORDS ==="
	backup_file /etc/pam.d/common-auth

	if grep -q "nullok" /etc/pam.d/common-auth; then
		sed -i 's/nullok//g' /etc/pam.d/common-auth
		log_action "Removed nullok from common-auth"
	else
		log_action "No nullok found in common-auth"
	fi

	log_action "Disallowed empty user passwords"
}

configure_pam() {
	log_action "=== CONFIGURING PAM PASSWORD COMPLEXITY ==="

	if ! dpkg -l | grep -q libpam-pwquality; then
		log_action "Installing libpam-pwquality ..."
		apt install -y libpam-pwquality &>/dev/null
	fi

	backup_file /etc/pam.d/common-password

	# minimim pwd len, limits consecutive repeated chars, require uppercase, lowercase, digit, special char
	# at least 3 chars diff from old password, can't contain username, and apply to root too
	sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 maxrepeat=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=3 reject_username enforce_for_root' /etc/pam.d/common-password &>/dev/null

	log_action "Configured password complexity requirements"

	# remember last 5 passwords so user can't use any last 5 old passwords
	if ! grep -q "remember=5" /etc/pam.d/common-password; then
		sed -i '/pam_unix.so/ s/$/ remember=5/' /etc/pam.d/common-password &>/dev/null
		log_action "Configured password history (remember=5)"
	fi

	backup_file /etc/pam.d/common-auth

	if ! grep -q "pam_tally2" /etc/pam.d/common-auth; then
		sed -i '1i auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=1800' /etc/pam.d/common-auth &>/dev/null
		log_action "Configured account lockout (5 attempts, 30 min lockout)"
	fi
}

set_password_aging() {
	log_action "=== CONFIGURE PASSWORD AGING POLICIES ==="

	backup_file /etc/login.defs
	
	# max password age
	if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
		sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   14/' /etc/login.defs &>/dev/null
	else
		echo "PASS_MAX_DAYS   14" >> /etc/login.defs
	fi

	# min password age
	if grep -q "^PASS_MIN_DAYS" /etc/login.defs; then
		sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   5/' /etc/login.defs &>/dev/null
	else
		echo "PASS_MIN_DAYS   5" >> /etc/login.defs
	fi

	# pwd expiration warning
	if grep -q "^PASS_WARN_DAYS" /etc/login.defs; then
		sed -i 's/^PASS_WARN_DAYS.*/PASS_WARN_DAYS   7/' /etc/login.defs &>/dev/null
	else
		echo "PASS_WARN_DAYS   7" >> /etc/login.defs
	fi

	log_action "Set password aging: max=14 days, min=5 days, warn=7 days"
	
	CURRENT_USERS=$(awk -F: '($3 >=1000 || $3 == 0) && $1 != "nobody" {print $1}' /etc/passwd)	
	
	for user in $CURRENT_USERS; do
		if [[ " ${AUTHORIZED_USERS[@]} " =~ " ${user} " ]]; then
			chage -M 14 -m 5 -W 7 "$user" &>/dev/null
			log_action "Applied aging policy to user: $user"
		fi
	done
}

#===============================================
# File Permissions
#===============================================

secure_file_permissions() {
	log_action "=== SECURING FILE PERMISSIONS ==="

	# Password & Authentication Files
	[ -f /etc/passwd ] && chmod 644 /etc/passwd && chown root:root /etc/passwd &>/dev/null
	[ -f /etc/shadow ] && chmod 640 /etc/shadow && chown root:shadow /etc/shadow &>/dev/null
	[ -f /etc/group ] && chmod 644 /etc/group && chown root:root /etc/group &>/dev/null
	[ -f /etc/gshadow ] && chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow &>/dev/null
	[ -f /etc/security/opasswd ] && chmod 600 /etc/security/opasswd && chown root:root /etc/security/opasswd &>/dev/null

	log_action "Secured password/auth files"

	# Boot files (GRUB)
	for grub_cfg in /boot/grub/grub.cfg /boot/grub/grub.conf /boot/grub2/grub.cfg; do
		if [ -f "$grub_cfg" ]; then
			chmod 600 "$grub_cfg" &>/dev/null
			chown root:root "$grub_cfg" &>/dev/null
			log_action "Secured $grub_cfg"
		fi
	done

	# SSH Configuration
	[ -f /etc/ssh/sshd_config ] && chmod 600 /etc/ssh/sshd_config &>/dev/null && chown root:root /etc/ssh/sshd_config
	[ -d /etc/ssh ] && chmod 755 /etc/ssh && chown root:root /etc/ssh
	log_action "Secured SSH configuration"

	# Sudoers
	[ -f /etc/sudoers ] && chmod 440 /etc/sudoers && chown root:root /etc/sudoers
	if [ -d /etc/sudoers.d ]; then
		chmod 755 /etc/sudoers.d
		find /etc/sudoers.d -type f -exec chmod 440 {} \; &>/dev/null
		find /etc/sudoers.d -type f -exec chown root:root {} \; &>/dev/null
		log_action "Secured /etc/sudoers and /etc/sudoers.d/*"
	fi

	# Cron files
	[ -f /etc/crontab ] && chmod 600 /etc/crontab && chown root:root /etc/crontab
	[ -d /etc/cron.d ] && find /etc/cron.d -type f -exec chmod 600 {} \;
	[ -d /var/spool/cron/crontabs ] && chmod 700 /var/spool/cron/crontabs
	log_action "Secured cron configurations"

	[ -d /root ] && chmod 700 /root && chown root:root /root
	log_action "Secured /root directory"

	# SSL private keys
	[ -d /etc/ssl/private ] && chmod 710 /etc/ssl/private && chown root:ssl-cert /etc/ssl/private
	log_action "Secured SSL private key directory"

	log_action "File perms hardening complete"
}

find_world_writable_files() {
	log_action "=== CHECKING FOR WORLD-WRITABLE FILES ==="
	# meaning anyone can modify which is sec risk

	WRITABLE=$(find / -path /proc -prune -o -path /sys -prune -o -type f -perm -0002 -print 2>/dev/null)	

	if [ -n "$WRITABLE" ]; then
		log_action "WARNING: Found world-writable files:"
		echo "$WRITABLE" | while read file; do
			log_action " - $file"
			# chmod o-w "$file"
			# ^ optional to remove world write 
		done
	else
		log_action "No suspicious world-writable files found"
	fi
}

check_suid_sgid() {
	log_action "=== CHECKING SUID/SGID BINARIES ==="
	
	# list of legit SUID bins (ADJUST)
	LEGIT_SUID=(
		"/bin/su"		
		"/bin/sudo"		
		"/usr/bin/sudo"		
		"/bin/mount"		
		"/bin/umount"		
		"/usr/bin/passwd"		
		"/usr/bin/gpasswd"		
		"/usr/bin/newgrp"		
		"/usr/bin/chfn"		
	)

	find / -path /proc -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | while read file; do
		if [[ ! " ${LEGIT_SUID[@]} " =~ " ${file} " ]]; then
			log_action "SUSPICIOUS SUID/SGID: $file"
			# Optional to remove SUID bit
			# chmod u-s "$file"
		fi
	done
}

find_orphaned_files() {
	log_action "=== CHECKING FOR ORPHANED FILES ==="

	find / -path /proc -prune -o -nouser -o -nogroup -print 2>/dev/null | while read file; do
		log_action "ORPHANED FILE: $file"
	done
}


#===============================================
# Network Security
#===============================================

# REQUIRES OpenSSH Sever Service to be installed (should be by default)
harden_ssh() {
	log_action "=== HARDENING SSH CONFIGURATION ==="

	backup_file /etc/ssh/sshd_config

	# Helper fn
	set_ssh_config() {
		local setting="$1"
		local value="$2"
		sed -i "/^#*${setting}/d" /etc/ssh/sshd_config
		echo "${setting} ${value}" >> /etc/ssh/sshd_config
		log_action "Set ${setting} ${value}"
	}

	set_ssh_config "Protocol" "2"
	set_ssh_config "PermitRootLogin" "no"
	set_ssh_config "PasswordAuthentication" "yes"
	set_ssh_config "PermitEmptyPasswords" "no"
	set_ssh_config "ChallengeResponseAuthentication" "no"
	set_ssh_config "UsePAM" "yes"
	set_ssh_config "LogLevel" "VERBOSE"
	set_ssh_config "X11Forwarding" "no"
	set_ssh_config "MaxAuthTries" "4"
	set_ssh_config "IgnoreRhosts" "yes"
	set_ssh_config "HostbasedAuthentication" "no"
	set_ssh_config "LoginGraceTime" "60"
	set_ssh_config "ClientAliveinterval" "300"
	set_ssh_config "ClientAliveCountMax" "2"
	set_ssh_config "AllowTcpForwarding" "no" # prevent SSH tunneling
	set_ssh_config "AllowAgentForwarding" "no"
	set_ssh_config "PermitTunnel" "no"
	set_ssh_config "StrictModes" "yes"
	set_ssh_config "PermitUserEnvironment" "no"
	set_ssh_config "GSSAPIAuthentication" "no" # Kerberos

	log_action "SSH Hardening complete (reboot required)"
}

enable_tcp_syncookies() {
	log_action "=== ENABLING IPv4 TCP SYN COOKIES ==="

	backup_file /etc/sysctl.conf

	if grep -q "^.*net.ipv4.tcp_syncookies" /etc/sysctl.conf; then
		sed -i 's/^#.*net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf
		log_action "Uncommented and enable TCP SYN cookies"
	elif grep -q "^net.ipv4.tcp_syncookies" /etc/sysctl.conf; then
		sed -i 's/^.*net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf
		log_action "Enabled TCP SYN cookies"
	else
		echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
		log_action "Enabled TCP SYN cookies (added new setting)"
	fi

	log_action "Applied TCP SYN cookies to running system (reboot required)"
}

harden_kernel_sysctl() {
	log_action "=== HARDENING KERNEL ==="

	backup_file /etc/sysctl.conf
	backup_file /etc/sysctl.d/99-hardening.conf
	
}

#===============================================
# Firewall
#===============================================

enable_ufw() {
	log_action "=== ENABLING UNCOMPLICATED FIREWALL (UFW)==="
	
	if ufw status | grep -q "inactive" ; then
		ufw --force enable
		log_action "UFW has been enabled"
	fi
}

configure_firewall() {
	log_action "=== CONFIGURING UFW FIREWALL ==="

	# Remove iptables-persistent
	if dpkg -l | grep -q iptables-persistent; then
		apt purge -y iptables-persistent
		log_action "Removed iptables-persistent"
	fi

	ufw --force reset
	log_action "Reset UFW to defaults"

	# Loopback rules
	ufw allow in on lo
	ufw allow out on lo
	ufw deny in from 127.0.0.0/8
	ufw deny in from ::1
	log_action "Configured loopback rules"

	# Default policies
	ufw default deny incoming
	ufw default allow outgoing
	ufw default deny routed
	log_action "Set default policies"

	# ADD SERVICE SPECIFIC RULES BASED ON README
	# ie: allow http, https, mysql, ssh, etc
	# sudo ufw allow ssh
	# sudo ufw reload
	# sudo systemctl enable ssh
	# sudo systemctl start ssh

	
	log_action "Firewall configuration complete"	
}

#===============================================
# Packages, Services, & Files
#===============================================

disable_unnecessary_services() {
	log_action "=== DISABLING UNNECESSARY SERVICES ==="

	local BLACKLIST_FILE="${1:-}"

	# If no file provided, skip this function
	if [[ -z "$BLACKLIST_FILE" ]]; then
		log_action "WARNING: No service blacklist file provided"
		log_action "Usage: disable_unnecessary_services <blacklist_file>"
		log_action "Skipping service disabling..."
		return 0
	fi

	# Check if file exists
	if [[ ! -f "$BLACKLIST_FILE" ]]; then
		log_action "ERROR: Service blacklist file not found: $BLACKLIST_FILE"
		return 1
	fi

	log_action "Reading prohibited services from: $BLACKLIST_FILE"

	# Read services from file (one per line, ignore comments and empty lines)
	local service_count=0
	local disabled_count=0

	while IFS= read -r service || [[ -n "$service" ]]; do
		# Skip empty lines and comments
		[[ -z "$service" || "$service" =~ ^[[:space:]]*# ]] && continue

		# Clean up whitespace
		service=$(echo "$service" | xargs)
		[[ -z "$service" ]] && continue

		((service_count++))

		# Check if service exists
		if systemctl list-unit-files | grep -q "^${service}.service"; then
			if systemctl is-active --quiet "$service"; then
				log_action "Stopping and disabling: $service"
				systemctl stop "$service" &>/dev/null
				systemctl disable "$service" &>/dev/null
				((disabled_count++))
				log_action "Stopped and disabled: $service"
			elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
				log_action "Disabling: $service"
				systemctl disable "$service" &>/dev/null
				((disabled_count++))
				log_action "Disabled: $service"
			else
				log_action "Service $service is already disabled"
			fi
		else
			log_action "Service $service not found on system (skipping)"
		fi
	done < "$BLACKLIST_FILE"

	log_action "Processed $service_count services, disabled $disabled_count"
}

audit_running_services() {
	log_action "=== AUDITING RUNNING SERVICES ==="

	systemctl list-units --type=service --state=running --no-pager | grep "loaded active running" | awk '{print $1}' | while read service; do
		log_action "RUNNING: $service"
	done

	log_action "Perform manual review of log for services that shouldn't be running"
}

remove_unauthorized_software() {
	log_action "=== REMOVING UNAUTHORIZED SOFTWARE ==="

	local BLACKLIST_FILE="${1:-}"

	# If no file provided, skip this function
	if [[ -z "$BLACKLIST_FILE" ]]; then
		log_action "WARNING: No package blacklist file provided"
		log_action "Usage: remove_unauthorized_software <blacklist_file>"
		log_action "Skipping software removal..."
		return 0
	fi

	# Check if file exists
	if [[ ! -f "$BLACKLIST_FILE" ]]; then
		log_action "ERROR: Package blacklist file not found: $BLACKLIST_FILE"
		return 1
	fi

	log_action "Reading prohibited packages from: $BLACKLIST_FILE"

	# Read packages from file (one per line, ignore comments and empty lines)
	local package_count=0
	local removed_count=0

	while IFS= read -r package || [[ -n "$package" ]]; do
		# Skip empty lines and comments
		[[ -z "$package" || "$package" =~ ^[[:space:]]*# ]] && continue

		# Clean up whitespace
		package=$(echo "$package" | xargs)
		[[ -z "$package" ]] && continue

		((package_count++))

		# Check if package is installed
		if dpkg -l 2>/dev/null | grep -q "^ii  $package "; then
			log_action "Removing package: $package"
			if apt purge -y "$package" &>/dev/null; then
				((removed_count++))
				log_action "Successfully removed: $package"
			else
				log_action "Failed to remove: $package"
			fi
		else
			log_action "Package $package not installed (skipping)"
		fi
	done < "$BLACKLIST_FILE"

	# Clean up dependencies
	log_action "Cleaning up orphaned dependencies..."
	apt autoremove -y &>/dev/null

	log_action "Processed $package_count packages, removed $removed_count"
}

# Implement another function for auditing installed packages?

remove_prohibited_media() {
	log_action "=== SCANNING FOR PROHIBITED MEDIA FILES ==="

	MEDIA_EXTENSIONS=(
		"*.mp3"	
		"*.mp4"	
		"*.avi"	
		"*.mkv"	
		"*.mov"	
		"*.flv"	
		"*.wmv"	
		"*.wav"	
		"*.flag"	
		"*.ogg"	
		"*.m4a"	
		"*.aac"	
	)
	
	for ext in "${MEDIA_EXTENSIONS[@]}"; do
		find /home -type f -name "$ext" 2>/dev/null | while read file; do
			log_action "PROHIBITED MEDIA: $file"
			rm -f "$file"
		done
	done

	log_action "Removed prohibited media"
}

#===============================================
# Cronjobs
#===============================================

secure_cron_system() {
	log_action "=== SECURING CRON SYSTEM ==="

	# Check current user's crontab
	if crontab -l &>/dev/null; then
		log_action "Current user has crontab entries (logged to file)"
		crontab -l >> "$LOG_FILE" 2>&1
	else
		log_action "No crontab for current user"
	fi

	# Scan system cron directories
	log_action "Scanning system cron directories..."
	for file in /etc/crontab /etc/cron.*/* /var/spool/cron/crontabs/*; do
		if [ -e "$file" ]; then
			log_action "Found cron file: $file"
			cat "$file" >> "$LOG_FILE" 2>&1
		fi
	done

	# Check init files
	log_action "Checking init files..."
	for init_file in /etc/init/*.conf /etc/init.d/*; do
		if [ -e "$init_file" ]; then
			log_action "Found init file: $init_file"
		fi
	done

	# Clear /etc/rc.local (startup script)
	log_action "Clearing /etc/rc.local..."
	backup_file "/etc/rc.local"
	echo "exit 0" > /etc/rc.local 2>/dev/null
	chmod +x /etc/rc.local &>/dev/null
	log_action "/etc/rc.local reset to 'exit 0'"

	# List all user crontabs
	log_action "Listing all user crontabs..."
	while IFS=: read -r user _; do
		if crontab -u "$user" -l &>/dev/null; then
			log_action "Crontab for $user (logged to file)"
			crontab -u "$user" -l >> "$LOG_FILE" 2>&1
		fi
	done < /etc/passwd

	# Deny all users from using cron (restrictive approach)
	log_action "Denying all users from using cron..."
	backup_file "/etc/cron.deny"
	echo "ALL" >> /etc/cron.deny 2>/dev/null
	log_action "Appended 'ALL' to /etc/cron.deny"

	log_action "Cron security lockdown completed"
}

#===============================================
# Antivirus
#===============================================

run_rootkit_scans() {
	log_action "=== RUNNING ROOTKIT SCANS ==="

	local RK_LOG="/var/log/rkhunter.log"
	local CRK_LOG="/var/log/chkrootkit.log"

	# Update package lists
	log_action "Updating package lists for rootkit scanner installation..."
	apt update -y -qq &>/dev/null

	# Install or reinstall rkhunter
	if ! dpkg -s rkhunter &>/dev/null; then
		log_action "Installing rkhunter..."
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rkhunter &>/dev/null
		log_action "rkhunter installed successfully"
	else
		log_action "Reinstalling rkhunter for clean baseline..."
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --reinstall rkhunter &>/dev/null
		log_action "rkhunter reinstalled successfully"
	fi

	# Install or reinstall chkrootkit
	if ! dpkg -s chkrootkit &>/dev/null; then
		log_action "Installing chkrootkit..."
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq chkrootkit &>/dev/null
		log_action "chkrootkit installed successfully"
	else
		log_action "Reinstalling chkrootkit for clean baseline..."
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --reinstall chkrootkit &>/dev/null
		log_action "chkrootkit reinstalled successfully"
	fi

	# Configure rkhunter
	if [ -f /etc/rkhunter.conf ]; then
		backup_file /etc/rkhunter.conf
		log_action "Configuring rkhunter..."
		# Prefer mirror updates and quiet web fetches
		sed -i 's/^[#[:space:]]*UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf 2>/dev/null || true
		sed -i 's/^[#[:space:]]*MIRRORS_MODE=.*/MIRRORS_MODE=1/' /etc/rkhunter.conf 2>/dev/null || true
		sed -i 's|^[#[:space:]]*WEB_CMD=.*|WEB_CMD="wget -q"|' /etc/rkhunter.conf 2>/dev/null || true
		log_action "rkhunter configuration updated"
	fi

	# Update rkhunter database
	log_action "Updating rkhunter signatures database..."
	rkhunter --update &>> "$RK_LOG" || true

	# Build baseline file property database
	log_action "Building rkhunter file property baseline..."
	rkhunter --propupd &>> "$RK_LOG" || true

	# Run rkhunter scan
	log_action "Starting rkhunter system scan (this may take several minutes)..."
	rkhunter --check --sk --nocolors --noappend-log &>> "$RK_LOG" || true
	log_action "rkhunter scan completed. Full log: $RK_LOG"

	# Run chkrootkit scan
	log_action "Starting chkrootkit system scan..."
	chkrootkit -q > "$CRK_LOG" 2>&1 || true
	log_action "chkrootkit scan completed. Full log: $CRK_LOG"

	# Append scan results to main log
	{
		echo "========== rkhunter Results (last 50 lines) =========="
		tail -n 50 "$RK_LOG" 2>/dev/null || echo "No rkhunter log found"
	} >> "$LOG_FILE" 2>/dev/null

	{
		echo "========== chkrootkit Results (last 50 lines) =========="
		tail -n 50 "$CRK_LOG" 2>/dev/null || echo "No chkrootkit log found"
	} >> "$LOG_FILE" 2>/dev/null

	# Basic alerting based on common warning patterns
	log_action "Analyzing scan results for suspicious findings..."
	local RK_ALERTS CRK_ALERTS
	RK_ALERTS=$(grep -Ei "Warning|suspect|infected|rootkit" "$RK_LOG" 2>/dev/null | wc -l)
	CRK_ALERTS=$(grep -Ei "INFECTED|Vulnerable|Warning" "$CRK_LOG" 2>/dev/null | wc -l)

	if [ "${RK_ALERTS:-0}" -gt 0 ] || [ "${CRK_ALERTS:-0}" -gt 0 ]; then
		log_action "ALERT: Potential security issues detected by rootkit scanners"
		log_action "ALERT: rkhunter warnings: ${RK_ALERTS}, chkrootkit warnings: ${CRK_ALERTS}"
		log_action "ALERT: Review full logs at $RK_LOG and $CRK_LOG"
	else
		log_action "No obvious rootkit indicators found in scans"
	fi

	log_action "Rootkit scanning complete"
}

#==============================================
# Auditd
#==============================================

harden_auditd() {
	log_action "=== HARDENING AUDITD (SYSTEM AUDITING) ==="

	# Install auditd
	if ! command -v auditctl &>/dev/null; then
		log_action "Installing auditd and plugins..."
		apt-get update -qq &>/dev/null
		apt-get install -y -qq auditd audispd-plugins &>/dev/null
		log_action "auditd installed successfully"
	else
		log_action "auditd already installed"
	fi

	# Enable auditd at runtime
	log_action "Enabling auditd in current session..."
	auditctl -e 1 &>/dev/null
	log_action "auditd enabled (auditctl -e 1)"

	# Set GRUB to persist audit=1 across reboot
	if [ -f /etc/default/grub ] && grep -q 'GRUB_CMDLINE_LINUX=' /etc/default/grub; then
		backup_file "/etc/default/grub"

		# Check if audit=1 is already present
		if ! grep -q 'audit=1' /etc/default/grub; then
			log_action "Adding audit=1 to GRUB kernel parameters..."
			sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="audit=1 /' /etc/default/grub &>/dev/null
			update-grub &>/dev/null
			log_action "GRUB updated to enable persistent audit logging"
		else
			log_action "GRUB already configured with audit=1"
		fi
	fi

	# Backup and update auditd.conf
	backup_file "/etc/audit/auditd.conf"
	log_action "Configuring auditd.conf with hardened settings..."

	cat > /etc/audit/auditd.conf << 'EOF'
# CyberPatriot auditd configuration
log_file = /var/log/audit/audit.log
log_format = RAW
flush = INCREMENTAL
freq = 50
num_logs = 10
max_log_file = 20
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
EOF
	log_action "auditd.conf configured successfully"

	# Create hardened audit rules
	local RULE_FILE="/etc/audit/rules.d/hardening.rules"
	log_action "Creating hardened audit rules in $RULE_FILE..."
	backup_file "$RULE_FILE"

	cat > "$RULE_FILE" << 'EOF'
# CyberPatriot Audit Rules - Monitor security-critical events

# Permission changes
-w /bin/chmod -p x -k perm_mod
-w /bin/chown -p x -k perm_mod

# Password changes
-w /usr/bin/passwd -p x -k passwd_change
-w /etc/shadow -p wa -k shadow_access
-w /etc/passwd -p wa -k passwd_access

# Sudo usage
-w /usr/bin/sudo -p x -k sudo_usage

# All program executions (comprehensive but may be noisy)
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log

# Login monitoring
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k failed_logins
-w /var/log/faillog -p wa -k login_failures

# Privilege escalation attempts
-a always,exit -F arch=b64 -S setuid,setgid -k priv_esc
-a always,exit -F arch=b32 -S setuid,setgid -k priv_esc
EOF
	log_action "Audit rules created successfully"

	# Load audit rules and restart auditd
	log_action "Loading audit rules and restarting auditd..."
	augenrules --load &>/dev/null
	systemctl restart auditd &>/dev/null
	log_action "auditd restarted with new rules"

	# Verify auditd is running
	if systemctl is-active --quiet auditd; then
		log_action "auditd is running and monitoring system events"
	else
		log_action "WARNING: auditd may not be running correctly"
	fi

	log_action "auditd hardening complete"
}

#===============================================
# Lynis
#===============================================
audit_with_lynis() {
	log_action "=== RUNNING LYNIS SECURITY AUDIT ==="

	# Change to /usr/local for installation
	if ! cd /usr/local 2>/dev/null; then
		log_action "ERROR: Failed to change directory to /usr/local"
		return 1
	fi

	# Clone Lynis repository
	log_action "Cloning Lynis repository from GitHub..."
	if git clone https://github.com/CISOfy/lynis &>/dev/null; then
		log_action "Lynis repository cloned successfully"
	else
		log_action "ERROR: Failed to clone Lynis repository"
		log_action "Checking if Lynis already exists..."
		if [ -d /usr/local/lynis ]; then
			log_action "Lynis directory already exists, proceeding..."
		else
			return 1
		fi
	fi

	# Set secure ownership (root:root)
	log_action "Setting ownership to root:root for security..."
	chown -R 0:0 /usr/local/lynis &>/dev/null
	log_action "Ownership configured securely"

	# Change to Lynis directory
	if ! cd /usr/local/lynis 2>/dev/null; then
		log_action "ERROR: Failed to enter /usr/local/lynis directory"
		return 1
	fi

	# Run full system audit
	log_action "Running Lynis system audit (this will take several minutes)..."
	./lynis audit system &>/dev/null
	log_action "Lynis audit completed"

	# Extract and log warnings/suggestions
	log_action "Extracting security recommendations from Lynis report..."
	if [ -f /var/log/lynis-report.dat ]; then
		log_action "========== Lynis Warnings =========="
		grep 'warning\[\]=' /var/log/lynis-report.dat 2>/dev/null | sed 's/warning\[\]=//g' >> "$LOG_FILE"

		log_action "========== Lynis Suggestions =========="
		grep 'suggestion\[\]=' /var/log/lynis-report.dat 2>/dev/null | sed 's/suggestion\[\]=//g' >> "$LOG_FILE"

		# Count findings
		local warnings=$(grep -c 'warning\[\]=' /var/log/lynis-report.dat 2>/dev/null || echo "0")
		local suggestions=$(grep -c 'suggestion\[\]=' /var/log/lynis-report.dat 2>/dev/null || echo "0")

		log_action "Lynis found $warnings warnings and $suggestions suggestions"
		log_action "Full report available at: /var/log/lynis-report.dat"
	else
		log_action "WARNING: Lynis report not found at /var/log/lynis-report.dat"
	fi

	log_action "Lynis security audit completed"
}

#===============================================
# MAIN EXECUTION
#===============================================
main() {
	if [ "$EUID" -ne 0 ]; then
		echo "ERR: Script must be run as root"
		exit 1
	fi

	log_action "======================================"
	log_action "STARTING UBUNTU HARDENING SCRIPT"
	log_action "======================================"
	log_action "Timestamp: $(date)"
	log_action ""

	# 1. SYSTEM UPDATES (Do this first for security patches)
	log_action "[ PHASE 1: SYSTEM UPDATES ]"
	update_system
	configure_automatic_updates
	log_action ""

	# 2. USER MANAGEMENT
	log_action "[ PHASE 2: USER & GROUP MANAGEMENT ]"
	remove_unauthorized_users
	fix_admin_group
	check_uid_zero
	disable_guest
	set_all_user_passwords
	log_action ""

	# 3. PASSWORD POLICIES
	log_action "[ PHASE 3: PASSWORD POLICIES ]"
	disallow_empty_passwords
	configure_pam
	set_password_aging
	log_action ""

	# 4. FILE PERMISSIONS & AUDITING
	log_action "[ PHASE 4: FILE PERMISSIONS & SECURITY ]"
	secure_file_permissions
	find_world_writable_files
	check_suid_sgid
	find_orphaned_files
	log_action ""

	# 5. NETWORK SECURITY
	log_action "[ PHASE 5: NETWORK SECURITY ]"
	harden_ssh
	harden_kernel_sysctl
	log_action ""

	# 6. FIREWALL CONFIGURATION
	log_action "[ PHASE 6: FIREWALL ]"
	enable_ufw
	configure_firewall
	log_action ""

	# 7. SERVICE MANAGEMENT
	log_action "[ PHASE 7: SERVICE MANAGEMENT ]"
	disable_unnecessary_services "./service_blacklist.txt"
	audit_running_services
	log_action ""

	# 8. PACKAGE AUDITING & REMOVAL
	log_action "[ PHASE 8: SOFTWARE AUDITING ]"
	remove_unauthorized_software "./package_blacklist.txt"
	remove_prohibited_media
	log_action ""

	# 9. CRON SECURITY
	log_action "[ PHASE 9: CRON SECURITY ]"
	secure_cron_system
	log_action ""

	# 10. SYSTEM AUDITING
	log_action "[ PHASE 10: SYSTEM AUDITING ]"
	harden_auditd
	log_action ""

	# 11. ANTIVIRUS & ROOTKIT DETECTION
	log_action "[ PHASE 11: MALWARE DETECTION ]"
	run_rootkit_scans
	log_action ""

	# 12. COMPREHENSIVE SECURITY AUDIT
	log_action "[ PHASE 12: LYNIS AUDIT ]"
	audit_with_lynis
	log_action ""
	
	log_action "======================================"
	log_action "HARDENING COMPLETE"
	log_action "======================================"
	log_action "IMPORTANT: Review the log at $LOG_FILE"
	log_action "IMPORTANT: Reboot system to apply all changes"
	log_action "Run: sudo reboot"
	log_action ""
	log_action "Completion time: $(date)"
}

main
