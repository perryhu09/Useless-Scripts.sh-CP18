#cybersec #linux 
# Files, Perms, Timestamps
- `ls -la` to see perms, owner, and group of file
- Common writeable directories that attackers target to upload malicious files:
	- `/tmp`- writeable by all users
	- `/var/tmp` - another tmp directory commonly with write perms
	- `/dev/shm` - shared memory file system, normally writeable by all users
- Use `find` to identify files that match criteria, ie:
	```
	find / -user www-data -type f 2>/dev/null | less
	```
	- ^ lists all files www-data user owns starting from root directory
- `find / -group GROUPNAME 2>/dev/null` - files and dirs owned by group
- `find / -perm -o+w 2>/dev/null` - retrieve list of all world-writable files and dirs
- `find / -type f -cmin -5 2>/dev/null` - retrieve files created or changed within last 5 minutes
-  Metadata: use *Exiftool: `exiftool /var/www/html/assets/reverse.elf`
- Checksums: `md5sum`, `sha256sum`
	-  can submit hashes to VirusTotal for further analysis
## Timestamps
- Modify Timestamp (mtime) - last modified
	- `ls -l`
- Change Timestamp (ctime) - last time file's **metadata** was changed, ie: perms, ownership, filename, etc
	- `ls -lc`
- Access Timestamp (atime): indicates last time file was accessed or read
	- `ls -lu`
- Can also use `stat` command to see all three timestamps at once
# Users and Groups
- `/etc/` stores config files and system-wide settings
```
cat /etc/passwd | cut -d: -f1,3 | grep ':0$'
```
- cut with delimiter colon (:), fields 1 and 3, and then grep ones with 0 at the end which means root privileges (NOT ALL ENCOMPASSING)
- Groups of interest:
	- sudo or wheel
	- adm - has read access to sys log files
	- shadow - group that manages user auth and pwd info, can read `/etc/shadow`
	- disk - unrestricted read and limited write access inside system
- view `/etc/group`
- Determine users's group: `groups <USERNAME>`
- List members of specific group: `getent group adm`
	- can also provide id instead of group name (sudo is typically 27)
## User Logins and Activity
- `last` - examines user logins and sessions, works by reading `/var/log/wtmp`
- `lastb` tracks failed logins by reading `/var/log/btmp`
	 - helps identify login and password attacks
- `lastlog` - info on users most recent login activity reads from `/var/log/lastlog`
- `who` - display users currently logged into system
- `/etc/sudoers` determines which users have sudo privileges
	- [[etc slash sudoers entries]] 
# User Directories and Files
- `ls -l /home` - view user home dirs which contain personalised settings, config, and user specific data
- `ls -la` to view hidden files
# Binaries and Executables
- identify suspicious binaries and executables
- find all executables: `find / -type f -executable 2>/dev/null`
- `debsums` compares MD5 checksum of files installed from debian packages against known checksums
	- `sudo debsumes -e -s` -e for only config file check, -s to silence error output
- **Binary Perms**: SUID and SGID (See [[Linux Privesc]]), perm bits change behavior of executables allowing them to run with privileges of file owner or group rather that privileges of user who executes the file
	- `find / -perm -u=s -type f 2>/dev/null`
# Rootkits
- malware designed to get admin level control of a system and remain undetected
- use `chkrootkit`
```
~$ sudo chkrootkit
```
- `rkhunter`: update it `rkhunter --update` for latest rootkit signatures
- run: `sudo rkhunter -c -sk`