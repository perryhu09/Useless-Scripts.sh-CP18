#cybersec/dfir/linux
# Overview
- Running Processes
	- programs and scripts that were executing, normal and malicious
- Open Files
	- reveals what data is being accessed or modified
- In-Memory Data Structures
	- ie: Kernel structures, process heaps, stacks which contain system and app state info
	- may contain sensitive info such as encryption keys, passwords, or evidence of memory corruption exploits
- Network Connections
	- ie: IP addresses, ports, and status of connections
	- may reveal connections to sus IP and data exfiltration
- Listening Services
	- which network accessible apps are running, may include unauthorized backdoors/compromised services
- Logged-in User Sessions
	- info about users currently logged in, login times, and terminals they are using
	- can indicate unauthorized access
- User Activity
	- record of user executed commands, ie: shell history
- In Memory Logs
	- logs temporarily stored in memory before written to disk
	- provide real-time snapshot of system events and app behavior
- Interface Configurations
	- IP addr, MAC addr, routing info, etc
- Temporary Files and Cache
	- `/tmp` and `/var/tmp`
	- can contain transient data from apps, ie: temp copies of sensitive docs or scripts used in attack
# Osquery
Essentially SQL (see: [[SQL Injection]]) for a tool that can query an OS database for information
- `osqueryi` 
- `.help`
- Example Commands
	- `Select usernmae, uid, description from users;`
	- `Select pid, name, parent, path from processes;`
	- `select * from etc_hosts where address='0.0.0.0';`
# System Profiling
- switch to root using `sudo su`
- `uname -a` - info about system, kernel version, architecture, hostname, data and time when kernel was compiled
- `hostnamectl` - info about system hostname and other settings
 - `uptime` - gives quick snapshot of system current status, time, how long its been running, num users logged in, how busy system is
 - `lscpu` - info about cpu architecture
 - `df -h` - reports disk space used and available on system
 - `lsblk` - info about block devices, ie: disks and partitions
- `free -h` - display memory usage
- `dpkg -l` - list installed packages
- `apt list --installed | head -n 30`- first 30 installed packages
- `ifconfig` and `ip a`
- `ip r` or `route` - displays routing table
- `ss` or `netstat` - socket stats and active connections
# Process Hunting
- use the processes table in osquery
- `SELECT pid, name, path, state FROM processes;`- lists all processes running on host
- `SELECT pid, name, path FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%';` - look for processes running from tmp dir
- `SELECT pid, name, path, cmdline, start_time FROM processes WHERE on_disk=0;` - lists processes executing on host but not on disk, indicating potential fileless malware
- `SELECT pid, name, parent, path FROM processs WHERE parent NOT IN (SELECT pid from processes);` - lists processes without parent processes (hella sus)
- `SELECT pid, name, path, cmdline, start_time FROM processes WHERE path LIKE '/home/%' OR path LIKE '/Users/%';` - lists running processes from user directory as typically processes run from standard system directories
# Investigating Network Connections
- select entries from the `process_open_sockets` table
- `SELECT pid, family, remote_address, remote_port, local_address, local_port, state FROM process_open_sockets LIMIT 20;` - info about network connections established by processes on system
 - `SELECT pid, fd, socket, local_address, remote_address, local_port, remote_port FROM process_open_sockets WHERE remote_address is NOT NULL;` - remote network connections, possibly identify C2 server communication
 - DNS queries -`SELECT * FROM dns_resolvers;`
 - Listing Down Network Interfaces - `SELECT * FROM interface_addresses;`
- List Network Connections - `SELECT * FROM listening_ports;` 
# TTP Footprints on Disk
- `SELECT pid, fd, path FROM process_open_files;` - list all files opened
- `SELECT pid, fd, path, FROM process_open_files where path LIKE '/tmp/%';` - show files being accessed from `/tmp/` directory
- If you identify a PID that looks suspicious, trace it to get the name of the process: `select pid, name, path from processes where pid = '<pid>';`
- `SELECT filename, path, directory, size, type FROM file WHERE path LIKE '/.%';` - examine root dir for hidden files and folders
- `SELECT filename, path, directory, type, size FROM file WHERE path LIKE '/etc/%' AND (mtime > (strftime('%s', 'now') - 86400));` - recently modified files
- `SELECT filename, path, directory, mtime FROM file WHERE path LIKE '/opt/%' OR path LIKE '/bin/' AND (mtime > (strftime('%s', 'now') - 86400));` - files and binaries updated within last 24 hours in /opt/ or /bin/ directories
## Packages
- Latest installed packages: `grep "install" /var/log/dpkg.log`
- `dpkg -l | grep <package-name>` - for more info on sus package
# Persistence
- attackers initiate services, placed in `/etc/systemd/system` so `ls` the dir to look for sus services
- `select username, directory from users;` - look for backdoor account
- can also use `cut -d : -f1 /etc/password` to list names of users
- `crontab -l` - examine cron tables