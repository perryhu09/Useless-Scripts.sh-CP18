# Updates
- [ ] Update package lists
- [ ] Perform full system upgrade
- [ ] Remove unnecssary packages
- [ ] Configure automatic updates

# Users/Group Accounts
- [ ] Remove unauthorized users
- [ ] Fix admin group
- [ ] Check users with UID zero
- [ ] Lock system accounts (???)
- [ ] Disable guest
- [ ] Set all user passwords to "Cyb3rPatr!0t"

# Password Policy
- [ ] Disallow empty passwords
- [ ] Configure PAM
- [ ] Set password aging policy

# File Permissions
- [ ] Secure file permissions
- [ ] Find world writable files (remove them???)
- [ ] Check for SUID and SGID files
- [ ] Find orphaned files (remove them???)

# Network Security
- [ ] Harden ssh configurations
- [ ] Enable tcp synncookies
- [ ] Harden kernel sysctl

# Firewall
- [ ] Remove iptables-persistent
- [ ] Reset ufw
- [ ] Loopback rules
- [ ] Set to default policies
- [ ] TODO: allow specific rules based on Readme (allow ssh, http, , etc)

# Prohibited Files/Services/Packages
- [ ] Loop through bad services and disable
- [ ] Delete games, hacking tools, media p2p
- [ ] Remove bad media extensions

# misc
- [ ] disable cron job to be made from user
- [ ] hardening Auditd 
- [ ] Backdoor access
- [ ] Antivirus implementation
- [ ] run antivirus, logs are "/var/log/rkhunter.log", "/var/log/chkrootkit.log"
- [ ] Lynis - stores logs in  "/var/log/lynis-report.dat"
