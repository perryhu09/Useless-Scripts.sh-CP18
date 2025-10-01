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
	echo "$messgae" >> "$LOG_FILE" 2>/dev/null
}

backup_file() {
	if  [-f "$1" ]; then
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

		if [[ !"${AUTHORIZED_USERS[@]}" =~ "${user}" ]]; then
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
	ADMIN_MEMBERS=$(getent group admink 2>/dev/null | cut -d: -f4 | tr ',' ' ')

	# Remove unauthorized users from sudo group
	for user in $SUDO_MEMBERS; do
		if [[! "$ADMIN_USERS[@]" =~ "${user}" ]]; then
			log_action "Removing $user from sudo group"
			sudo deluser "$user" sudo
		fi
	done

	# Check if admin group exists (then remove)
	if getent group admin > /dev/null 2>&1; then
		for user in $ADMIN_MEMBERS; do
			if [[! "$ADMIN_USERS[@]" =~ "${user}" ]]; then
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

	if [ -n "$USER_ZERO" ]; then
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
		# ^^^ what is this implementation??? what if allow-guest=true?
	fi

	# continue here
}

#===============================================
# Password Policies 
#===============================================

# remove nullok in /etc/pam.d/common-auth to disallow empty pwds
check_empty_passwords() {}


#===============================================
# MAIN EXECUTION
#===============================================
main() {
	if [ "$EUID" -ne 0 ]; then
		echo "ERR: Script must be run as root"
		exit 1
	fi
}

main
