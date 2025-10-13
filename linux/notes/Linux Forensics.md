#cybersec/dfir/linux #notes 
# Basic Forensics
Long files can be read using `tail`, `head`, `more`, or `less`
## OS and Account Information
- OS version:`cat /etc/os-release`
- User Accounts: `cat /etc/passwd`
	- `cat /etc/passwd | column -t -s :`
- user created accounts have uids 1000+
- Group info: `cat /etc/group`
- Sudoers List: `sudo cat /etc/sudoers`

- In /var/log there are log files like `wtmp` and `btmp`. btmp saves info about failed logins, while wtmp keeps data about historical logins
- `sudo last -f /var/log/wtmp`

- Auth Logs: `cat /var/log/auth.log | tail`
## System Configuration
- Hostname: `cat /etc/hostname`
- Timezone: `cat /etc/timezone`
- Network Configs: `cat /etc/network/interfaces`
- MAC/IP addr: `ip address show`, `ip a`, `ifconfig`
- Active Network Connections: `netstat -natp`
- Running Processes: `ps aux`
- DNS Info: `cat /etc/hosts`
 - DNS Servers info: `cat /etc/resolv.conf`
## Persistence Mechanisms
- ways a program can survive after a system reboot
-  **Cronjobs**
	- commands that run periodically after a set amount of time
	- `cat /etc/crontab` to view list of cronjobs
- Service Startup
	- services that run in background after every system boot
	- `ls /etc/init.d`
- .Bashrc - run when a bash shell is spawned, ie: startup list of actions
	- `cat ~/.bashrc`
	- Systemwide settings: `/etc/bash.bashrc` and `/etc/profile`
## Evidence of Execution
- Sudo Execution History: `cat /var/log/auth.log* |grep -i COMMAND|tail`
- Bash History: any commands other except run by sudo
	- `cat ~/.bash_history`
- `cat ~/.viminfo` contains opened files using `vim`
## Log Files
- Syslog: contains messages recorded by host about system activity
	- `cat /var/log/syslog* | head`
- `cat /var/log/auth.log* |head`
- Third party logs: webserver, db, fileshare sever logs, etc
	- `ls /var/log`
# Linux Incident Surface
- Attack surface is various entry points where an attack can attempt to enter system
	- ie: Open ports, running services, software or apps with vulns, network communications.
- Incident surface is where incident could occur or traces of incident can be found
	-  ie: sys logs, auth.log, syslog, krnl.log, Network traffic, running processes, running services, integrity of files and proceses.
## Processes and Network Communication
- `ps aux`: provides snapshot of running processes
	- `a`: shows processes for all users
	- `u`: displays user-oriented format
	- `x`: includes processes not attached to terminal (ie: background processes)
	- grep to find specific processes
	- Output:
		- USER: The user who owns the process.
		- PID: Process ID.
		- %CPU: CPU usage percentage.
		- %MEM: Memory usage percentage.
		- VSZ: Virtual memory size.
		- RSS: Resident Set Size (memory currently used).
		- TTY: Terminal associated with the process.
		- STAT: Process state (e.g., R for running, S for sleeping, Z for zombie).
		- START: Start time of the process.
		- COMMAND: Command that started the process
- `lsof -p <pid>`: examine files/resources connected with this process
- `lsof -i P -n`
	- `lsof`: List Open Files, displays info about files opened by processes
	- `-i`: shows info about network connections, ie: sockets, open network files
	- `-P`: shows port numbers
	- `-n`: shows IP instead of hostname
- `osquery`: run with `osqueryi`, like SQL idk
	- `SELECT pid, fd, socket, local_address, remote_address FROM process_open_sockets WHERE pid = 267490;`
## Persistance
- One way is to create a backdoor account using:
```
sudo useradd attacker -G sudo
sudo passwd attacker
echo "attacker All=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers
```
- Blue team side:
	- `cat /var/log/auth.log | grep useradd`
	- `cat /etc/passwd` and look at users
- Persistence mechanism two is Cron
	- `crontab -e`
- Example Crontab Entry:
	- `@reboot /path/to/malicious/script.sh`: executes at every reboot
	- `* * * * * root /path/to/malicious/script.sh`: executes every minute with root privileges
	- Explore: `/var/spool/cron/crontabs/[username]` to explore cronjobs associated with each user
- Examining Running Services:
	- `ls /etc/systemd/system`
	- `cat /var/log/syslog | grep suspicious`
	- `sudo journalctl -u suspicious`
## Disk
- `dpkg -l`: lists all installed packages on disk
- `grep " install " /var/log/dpkg.log`