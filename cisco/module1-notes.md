#cybersec #networking #cisco #cyberpatriot 
# Basic Switch and End Device Configuration
## IOS Navigation
- **User EXEC Mode** - limited capabilities for basic operations
```
Switch>
Router>
```
- **Privileged EXEC Mode** - network admin privileges (ie: sudo)
```
Switch#
Router#
```
Subconfiguration Modes
- User is at first in global config mode (`Switch(config)#`) and from there, user can enter different **subconfiguration modes**. 
- **Line Configuration Mode** - used to configure console, SSH, telnet, aux access (`Swtich(config-line)#`)
- **Interface Configuration Mode** - config switch port or router network interface (`Switch(config-if)#`)
Navigating between IOS Modes
- `enable` -> Priv Exec Mode -> `disable` -> User Exec Mode
- Priv Exec Mode ->`configure terminal` -> global config mode -> `exit`
- To escape all subconfig modes and return to priv exec mode use `end` or ctrl+Z
## Basic Device Configuration
`show version` - display useful information
Device Name
- `configure terminal` -> `hostname <new name>`
Configure Passwords
- secure User Exec Mode:
 ```
 configure terminal
 line console 0
 password cisco
 login
 exit
 ```
  - secure Priv exec mode
```
configure terminal
enable secret class
exit
```
- Virtual Terminal (VTY) for Telnet/SSH
```
configure terminal
line vty 0 15
password cisco
login
exit
```
Encrypt passwords
```
configure terminal
service password-encryuption
```
 - use `show running-config` to verify passwords are encrypted
Banner Messages
```
configure terminal
banner motd #Authorized Access Only#
```
## Save Configurations
Two types:
- startup-config - all commands used to startup, stored on NVRAM
- running-config - current config, stored in RAM and is lost when device powers off
```
# show running-config
# show startup-config
```
- use `copy running-config startup-config` to save changes in priv exec mode
- to restore startup-config (ie: revert unwanted changes) use `reload` priv exec cmd
	- note: it restarts the device causing brief network downtime
- if you saved unwanted changes then `erase startup-config` priv exec cmd. 
## IP Address Configuration
Manual config IPv4 on Windows: 
- control panel > network sharing center > change adapter settings (choose adapter) -> right click select properties > Local Area Connection Properties > highlight Internet Protocol Version 4 (TCP/IPv4) > Properties > IPv4 Properties 
- `ipconfig` to display IP config settings on Windows PC 
Config DHCP
- select Obtain IP address automatically and Obtain DNS server address automatically
Switch IP config:
```
configure terminal
interface vlan 1
ip address 192.168.1.20 255.255.255.0
no shutdown
exit
ip default-gateway 192.168.1.1
``` 
## Verifying Connectivity
- `show ip interface brief`
- `ping <ip addr>`