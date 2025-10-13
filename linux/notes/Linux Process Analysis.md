#cybersec #linux 
# Processes
- `ps` - gets info from reading files in `/proc` virtual file system
	- `TTY` - terminal associate with process
	- `TIME` - cumulative CPU time consumed by process
- `ps -u username`
- `ps -eFH`
	- `-e` - all processes
	- `-F` - extra full format
	- `-H` - show process hierarchy
- `lsof` - List open files, lists info about files opened by processes
	- `sudo lsof -p <pid>`
- `pstree` - shows tree structure, tells where process originated 
	- `pstree -p -s <pid>` - list parent processes (-s) and corresponding PIDs (-p)
	- `ps -f` - more details than just ps, provide multiple PIDs, ie: sus process and its parent process(es)
- `top` - continuously updated display of sys processes (`htop`)
	- `top -d 5 -c -u username`, update every 5 seconds (-d), display full commands path (-c)
# Cronjobs
- `/var/spool/cron/crontabs` - crontab file stored for users
	- ls the dir and you will see files with name of each user containing their cronjobs
- `/etc/crontab` - system-wide cronjobs
- `*/5` means every fifth (minute,hour,day,etc)
- Look for specific cronjobs
	- `/etc/cron.hourly/`
	- `/etc/cron.daily/`
	- `/etc/cron.weekly/`
	- `/etc/cron.monthly`
	- `/etc/cron.d/` - additional custom system cronjobs
	- note these are directories and you `ls` them.
## Execution Logs
- stored in `/var/log/syslog`for debian
- Other distros maybe in: `/var/log/cron`
- `sudo grep cron /var/log/syslog | grep -E 'failed|error|fatal'` - filter out failed job executions, useful method to catch anomalies
- `sudo grep cron /var/log/syslog | grep -i 'bob'` - filter cron entries specifically associated with Bob
## Pspy
- monitors linux processes without need for root
- `sudo apt install pspy64`
- goofy ahh lwk
# Services
- services refer to background processes/daemons that run continuously
- perform tasks like: managing system resources, providing network services, handling user requests
- typically configured using system's service management utility - **systemd** or **init**
- `systemctl start <service>`
- `systemctl stop <service>`
- `systemctl restart <service>`
- `systemctl enable <service>` - auto start service at boot
- `systemctl disable <service>` - disable service from auto starting from boot
- `systemctl status <service>` - display status (active, inactive, failed)
 - `sudo systemctl list-units --all --type=service` - list : display all services
	 - can add `--state=running` to limit to only running services
 - `/etc/systemd/system` contains service unit files for custom services
 - `/usr/lib/systemd/system/` for system services
 - `sudo journalctl -f -u <service-name>` (-f for real time), use this command for investigating service logs from systemd journal
# Autostart Scripts
- scrips/commands that automatically execute when system boots or user logs in
- System-wide Scripts found in:
	- `/etc/init.d/`
	- `/etc/rc.d/`
	- `/etc/systemd/system/`
- User-specific scripts:
	- `~/.config/autostart`
		- usually in form of `.desktop` files
		- `ls -a /home/*/.config/autostart`
	- `~/.config/`
# Application Artefacts
- includes data generated and stored by apps during operation including config files, logs, cache files, etc
- `sudo dpkg -l` - determine what apps/programs are isntalled
- `find /home/ -type f -name ".viminfo" 2>/dev/null`
	- same with `.nano_history`, `.emacs`, `.emacs.d`
## Browser Artefacts
- Firefox: `~/.mozilla/firefox/`
- Chrome: `~/.config/google-chrome/`
- dumpzilla tool
	- use `--Help`
	- `sudo python3 <pathto>/dumpzilla.py /home/bren/.mozilla/firefox/niijyovp.default-release --Cookies`
		- can use other options rather/with --Cookies