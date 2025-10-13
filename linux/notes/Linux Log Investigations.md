#cybersec 
2 primary types:
- Kernel logs - messages related to hardware events, driver operations, sys errors
- User logs - capture user interactions between users, apps, and OS. Include login attempts, command executions and app specific activities.
# Logging Levels (of importance)
- EMERGENCY - system is unusable/crashes (0)
- ALERT -  user attention is required immediately (1)
- CRITICAL -  critical errors, both hardware and software (2)
- ERROR - noncritical errors, ie: failed device recognition, driver issues. (3)
- WARNING - default level, displays warnings about non-imminent errors (4)
- NOTICE - events worth having a look at (5)
- INFO - info msgs about system actions and operations (6)
- DEBUG - detailed info used for debug (7)

- Kernel Logging
	- `/var/log/kern.log`
	- Done through kernel ring buffer to avoid data loss.   
# /var/log
- `kern.log`  
	- records kernel messages, used for hardware failures and deeper sys issues attackers can exploit. 
- `dmesg`
	- helps detect unusual system startup messages, may indicate tampering/hardware issues.
- `/var/log/auth.log`
	- for everything authentication related, records every auth attempt and commands executed with elevated privileges and SSH logins
	- grep keywords like 'Accepted Password', 'sudo', etc
- `/var/log/syslog`
	- catch-all for various system messages, includes cronjob executions, kernel activities, etc
	- can grep keywords like 'CRON', 'kernel', etc
- `btmp` and `wtmp`
	- btmp logs failed login attempts, wtmp records every login and logout
	- can be used to identify bruteforce attacks
# User Logging with Syslog
 - user space logging captures messages gen by apps, services, and user activities
 - syslog is a protocol and a system for centralized logging, three parts:
	 - syslog daemon - rsyslogd daemon handles logging and routing messages
	 - config file: `/etc/rsyslog.conf` (`/etc/syslog.conf`) defines rules for logging, including log file locations, filtering, and message forwarding
	 - log files - actual logs stored in `/var/log`
# Journalctl
- `journal` is binary logging system used by systemd-based distros, isn't text based, it provides structured, indexed logs which allow for efficient querying/filtering.
- `/etc/systemd/journald.conf` - normally journal logs are volatile, change that by setting Storage parameter to "persistent" and restarting journal daemon
- `journalctl` is cli tool to interact with systemd journal.
![[Screenshot 2025-09-21 at 9.32.32 AM.png]]
- Journal also understands relative time values, ie: today, now, yesterday, 2 hours ago
	- `sudo journalctl -S "2 hours ago"`
# Auditd
- Linux auditing system - audit daemon (auditd) collects and writes log files to disk, includes info about file access, user logins, process execution, etc
- rules are specified in `/etc/audit/audit.rules` added using the `auditctl` utility (only temporary though)
## Examples
- track changes to file `/etc/passwd` by creating following rule`
```
sudo auditctl -w /etc/passwd -p wra -k users
```
- -w is watch, for (-p wra) read write change attributes, tag it as 'users' (-k key option)
```
sudo auditctl -a always,exit -F arch=b64 -S execve -k execve_syscalls
```
## Reviewing Audit Logs
- `ausearch` 
	- `sudo ausearch -k users`
	- `sudo ausearch -k execve_syscalls`
- `aureport` gens summary of audit events
- `audispd` for real time monitoring
# Examining Auth Logs
- `sudo grep -i "failure" /var/log/auth.log`
- `sudo grep -i "session opened" /var/log/auth.log`
- `sudo grep -i "sudo" /var/log/auth.log`
- `sudo awk '/2024-06-04 15:30:00/,/2024-06-05 15:29:59/'`
	- displays log entries between June 4, 2024, 15:30:00 and June 5, 2024, 15:29:59
- relative time filtering: `sudo grep "$(date --date='2 hours ago' '+%b %e %H:')" /var/log/auth.log`
	 - uses `date` utility to identify cur date and time and extract time in format of abbreviated month (%b), day of month (%e) and hour (%H)
# Analysing Application Logs
 - stored in /var/log
## Example: Understanding Apache2 Logs
- 2 types of logs: access and error logs
- generally placed in /var/log/apache2
	- 2 files: `/var/log/apache2/access.log` and `/var/log/apache2/error.log`
- grep specific IP: `grep "10.10.24.106" /var/log/apache2/access.log`
- grep HTTP status code: `grep "404" /var/log/apache2/access.log`
- grep error codes: `grep "error" /var/log/apache2/error.log`
- use awk for advanced filtering, ie; counting number of requests from specific IP
	- `awk '{print $1}' /var/log/apache2/access.log* | sort |uniq -c | sort -nr`
- summarize HTTP status codes from access log
	- `awk '{print $9}' /var/log/apache2/access.log* | sort | uniq -c | sort -nr`