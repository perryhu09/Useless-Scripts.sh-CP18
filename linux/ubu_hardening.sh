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
			sudo deluser "$user" sudo
		fi
	done

	# Check if admin group exists (then remove)
	if getent group admin > /dev/null 2>&1; then
		for user in $ADMIN_MEMBERS; do
			if [[ ! "$ADMIN_USERS[@]" =~ "${user}" ]]; then
				log_action "Removing $user from admin group"
				sudo deluser "$user" admin
			fi
		done
	fi

	# Add authorized admin users to sudo group
	for user in "${ADMIN_USERS[@]}"; do
		if id "$user" &>/dev/null; then
			usermod -aG sudo "$user"	
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
	# Implement
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
	sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 maxrepeat=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=3 reject_username enforce_for_root' /etc/pam.d/common-password

	log_action "Configured password complexity requirements"

	# remember last 5 passwords so user can't use any last 5 old passwords
	if ! grep -q "remember=5" /etc/pam.d/common-password; then
		sed -i '/pam_unix.so/ s/$/ remember=5/' /etc/pam.d/common-password
		log_action "Configured password history (remember=5)"
	fi

	backup_file /etc/pam.d/common-auth

	if ! grep -q "pam_tally2" /etc/pam.d/common-auth; then
		sed -i '1i auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=1800' /etc/pam.d/common-auth
		log_action "Configured account lockout (5 attempts, 30 min lockout)"
	fi
}

set_password_aging() {
	log_action "=== CONFIGURE PASSWORD AGING POLICIES ==="

	backup_file /etc/login.defs
	
	# max password age
	if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
		sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   14/' /etc/login.defs
	else
		echo "PASS_MAX_DAYS   14" >> /etc/login.defs
	fi

	# min password age
	if grep -q "^PASS_MIN_DAYS" /etc/login.defs; then
		sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   5/' /etc/login.defs
	else
		echo "PASS_MIN_DAYS   5" >> /etc/login.defs
	fi

	# pwd expiration warning
	if grep -q "^PASS_WARN_DAYS" /etc/login.defs; then
		sed -i 's/^PASS_WARN_DAYS.*/PASS_WARN_DAYS   7/' /etc/login.defs
	else
		echo "PASS_WARN_DAYS   7" >> /etc/login.defs
	fi

	log_action "Set password aging: max=14 days, min=5 days, warn=7 days"
	
	CURRENT_USERS=$(awk -F: '($3 >=1000 || $3 == 0) && $1 != "nobody" {print $1}' /etc/passwd)	
	
	for user in $CURRENT_USERS; do
		if [[ " ${AUTHORIZED_USERS[@]} " =~ " ${user} " ]]; then
			chage -M 14 -m 5 -W 7 "$user"
			log_action "Applied aging policy to user: $user"
		fi
	done
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

#===============================================
# Network Security
#===============================================

harden_ssh() {
	log_action "=== DISABLING SSH ROOT LOGIN ==="

	backup_file /etc/ssh/sshd_config

	# Disable root login via SSH
	if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
		sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
		log_action "Set PermitRootLogin to no"
	else
		echo "PermitRootLogin no" >> /etc/ssh/sshd_config
		log_action "Added PermitRootLogin no"
	fi

	log_action "SSH root login disabled"

	# ENABLE password authentication
	if grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
		sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
	else
		echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
	fi

	log_action "Enabled SSH password authentication"

	if grep -q "^PermitEmptyPasswords" /etc/ssh/sshd_config; then
		sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
	else
		echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
	fi
	log_action "Disabled empty passwords for SSH"

	log_action "SSH Hardening complete (requires reboot)"
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

#===============================================
# MAIN EXECUTION
#===============================================
main() {
	if [ "$EUID" -ne 0 ]; then
		echo "ERR: Script must be run as root"
		exit 1
	fi

	log_action "======================================"
	log_action "HARDENING COMPLETE"
	log_action "======================================"
	log_action "IMPORTANT: Reboot system to apply all changes"
	log_action "Run: sudo reboot"
}

main
