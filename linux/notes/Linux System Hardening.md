#cybersec #linux 
## LUKS (Linux Unified Key Setup)
- Standard for Linux disk encryption
- Encrypts partitions to protect data at rest

 LUKS Partition Header (phdr)
- UUID
- Cipher & mode
- Key length
- Active key slots info
Key Material (KM1..KM8)
- Each slot: master key encrypted with user password (multiple users share a device)
- Allows multiple passwords to unlock same volume
 Bulk Data 
- Actual files, encrypted with master key

```
enc_data = encrypt(cipher_name, cipher_mode, key, original, original_length)
key = PBKDF2(password, salt, iteration_count, derived_key_length)
```

```
# Install cryptsetup
sudo apt install cryptsetup

# Check partitions
lsblk

# Initialize LUKS encryption
sudo cryptsetup -y -v luksFormat /dev/sdb1

# Open encrypted partition
sudo cryptsetup luksOpen /dev/sdb1 secureDisk

# Format & mount
sudo mkfs.ext4 /dev/mapper/secureDisk
sudo mount /dev/mapper/secureDisk /mnt
```
## Firewall
- decides which packets can enter and leave a system
- **host based firewall** - restricts packets to and from a single host
	- decides what packets can enter
	- decides what packets can leave

- Stateless firewall - can inspect fields in IP and TCP/UDP headers but doesn't maintain info about on going TCP connections
- Stateful firewall - keep track of ongoing connections and restrict packets based on specific fields in IP and TCP/UDP headers based on if packet is part of on going connection.

IP header fields in firewall rules:
- Source IP Address
- Destination IP Address
TCP/UDP header fields for firewall rules:
- Source TCP/UDP port
- Destination TCP/UDP port
### Netfilter
- iptables chain (rules)
- ie: allow access to SSH on remote server, this requires accepting incoming and outgoing packets to TCP port 22:
	- `iptables -A INPUT -p tcp --dport 22 -j ACCEPT`
	- dport = destination port 
	- `iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT`
	- sport = source port 
- if you want allow traffic to local ssh server and block everything else, add two more rules to set default behavior of firewall
	- `iptables -A INPUT -j DROP`: block all incoming traffic not allowed in prev rules
	- `iptables -A OUTPUT -j DROP`: block all outgoing traffic not allowed in prev rules
- nftables
	- `nft add table fwfilter`
	- `nft add chain fwfilter fwinput { type filter hook input input priority 0 \; }`
	- `nft add chain fwfilter fwoutput { type filter hook input output priority 0 \; }`
	- `nft add fwfilter fwinput tcp dport 22 accept`
	- `nft add fwfilter fwoutput tcp sport 22 accept`
### UFW
- Uncomplicated firewall
- `ufw allow 22/tcp`
- `ufw status` to check settings
## Remote Access (SSH)
- Attacks associated with remote access:
	- Password sniffing
	- Password guessing and brute-forcing
	- Exploiting the listening service
- Guidelines:
	- disable remote login as `root`
	- disable password authentication; force public key auth instead
- config of OpenSSH is controlled in `/etc/ssh/sshd_config`
	- disable root login by adding: `PermitRootLogin no`
- Create SSH key pair: `ssh-keygen -t rsa`
	- generates a private key saved in `id_rsa` and a public key saved in `id_rsa.pub`
- `ssh-copy-id username@server_ip` to copy public key to target SSH server
- have access to physical terminal before disabling password auth to avoid locking yourself out
 - Ensure two lines in `sshd_config`
	 - `PubkeyAuthenticaiton yes` to enable public key auth
	 - `PasswordAuthentication no` to disable password auth
## Securing User Accounts
- `usermod -aG sudo username`: add a user to sudoers group
	- `usermod` modifies user account
	- `-aG` appends to group
	- `sudo` name of group users who can use `sudo` on Debian-based distros
	- `username` name of user account to add
- Other distros (fedora, redhat): `usermod -aG wheel username`
	- sudoers group is called `wheel`
- disable root: modify `/etc/passwd` and change root shell to `/sbin/nologin`
	- `root:x:0:0:root:/root:/bin/bash` -> `root:x:0:0:root:/root:/sbin/nologin`
- enforce password policy: `libpwquality` (google documentation)
- disable unused accounts by changing to `/sbin/nologin`
- check groups by viewing `/etc/group`
## Software and Services
- more software = more possible vulns attacker can exploit 
- Tips
	- Disable unnecessary services
	- block unneeded network ports (firewall)
	- Avoid legacy protocols (ie: don't use old protocols like Telnet)
	- remove identification strings (ie: expose version number)
# Update and Upgrade Policies
- `apt update`: download package info from configed sources
- `apt upgrade` install available upgrades for all packages from configed sources
- use `dnf` or `yum` on different distros
- `uname -a` to view info about host
# Audit and Log Configuration
- logs are stored in `/var/log`
- `/var/log/messages` - general log for linux
- `/var/log/auth.log`- lists auth attempts (debian)
- `/var/log/secure` - log file lists all auth attempts (red hat and fedora)
- `/var/log/utmp` - access log contains info regarding users currently logged in
- `/var/log/wtmp` - access log contains info for all users that have logged in and out of system
- `/var/log/kern.log` - contains messages from kernal
- `/var/log/boot.log` - log file contains start-up messages and boot info

