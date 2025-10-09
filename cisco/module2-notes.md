#cyberpatriot #cybersec #cisco #networking 
# Data Link Layer
## LLC Sublayer
- Logical Link Control (LLC) - communicates with upper layer and lower layer
- identifies protocol being used (IPv4 or IPv6)
- handles flow control and error control
## MAC Sublayer
- controls NIC and hardware that sends and receives data
- Provides data encapsulation
	- Frame delimiting - delimiters to identify fields within frame
	- Addressing - source and dest MAC
	-  Error detection - trailer used to detect transmission errors (Frame Check Sequence)
- Access Control - allows communication through half-duplex medium (full duplex doesn't require access control)
## Access Control Methods
-  **Contention-based access** - all nodes half duplex, only one can send at a time. u
- **Controlled Access** - each node has own time to use medium, inefficient as each device must wait for its own turn.
	- Example networks that use: Legacy Token Ring, Legacy ARCNET
## CSMA/CD
- Used by legacy bus-topology and ethernet LANs using a hub
- These networks operate in half-duplex requires process to determine which device can send and what happens when multiple devices send at same time
- If 2 devices transmit at same time, collision occurs, data sent by both devices will be corrupted and need to be resent (Collision Detection / CD)
- When PC has ethernet frame to send, NIC determines if any device is transmitting by detecting a carrier signal. If not, assumes network is available to send
- When hub broadcasts to all devices, a PC that wants to send a frame is currently receiving, and therefore must wait until channel is clear.
- Only device with destination MAC will accept and copy in the frame, rest devices ignore the frame
## CSMA/CA
- Carrier Sense Multiple Access / collision avoidance
- Wireless environment may not be possible to detect collision, so devices avoid them by waiting before transmitting.
- Each device transmits includes the time duration needed for transmission, all other devices receive this info and know how long medium will be unavailable
## Data Link Frame
- Preamble - alt. pattern in binary used for synchronization
- Start Frame Delimiter - `10101011` indicates start of frame
- Type / Length - size of payload, identifies upper layer protocol encapsulated in frame
	- `0x800` for IPv4, `0x86DD` for IPv6, `0x806` for ARP
- Pad - brings total bytes up to minimum of 46 bytes if needed
- Frame Check Seq - 4 byte CRC (Cyclic Redundancy Check) value for error checking, CRC performed on bits between dest MAC and pad fields, error detected = frame discarded
- Minimum frame size is 64 bytes, Max is 1518 bytes
- Header + FCS account for 18 bytes so payload must be between 46 and 1500 bytes
![[Pasted image 20251004110027.png]]
- MAC Address
	- 48 bit, 12 hex digits, 6 bytes
	- First 6 Hex is organizationally unique identifier (OUI) and last 6 is a unique value
	- Multicast frame - starts with`01-00-5E` 
		- devices in multicast group belong are assigned to multicast group IP address (class D). Last 3 bytes convert to IP addr group to send to.
## Switching
- Switch learns MAC - Port by examining source MAC addr. If incoming frame comes through port from unknown MAC, then it is added to table along with incoming port number.
- Default: switches keep entry in table for 5 minutes
- If switch doesn't know dest mac address, then it forwards to all ports except incoming port, called **unknown unicast**
- Switching Methods:
	- **Store and forward Switching** - receives entire frame and computes CRC. If CRC is valid then lookup dest addr and forward.
	- **Cut-through Switching** - forwards frame before entirely received, must read dest addr before forwarding. (no error checking)
		- Fast-forward - immediately forwards after reading dest addr
		- Fragment free - stores first 64 bytes before forwarding
- Autonegotiation - auto negotiate best speed and duplex capabilities
### Memory Buffering	
- store frames before forwarding them, used when dest port is too busy bc of congestion
- **Port-based memory** - frame stored in queues linked to specific ports
	- frame is transmitted through outgoing port only when all frames ahead have been transmitted
- **Shared Memory** - all frames in common memory buffer shared by all switch ports
	- mem is allocated dynamically
	- frames in buffer are dynamically linked to dest port enabling packet to be received and transmitted without moving it to a different queue
### Auto-MDIX
- Same device - cross over cable
- Different device - straight-through cable
- Note: direct connection between router and host requires cross over
# ICMP
## ICMP Messages
- **ping** - tests reachability of host on IP network, sends ICMP Echo Request to host, if up, dest host responds with Echo Reply.
- when device receives packet it can't deliver (because dest is down) it sends **ICMP Destination Unreachable message** to notify the source that dest or service is unreachable
	- Dest Unreachable codes for ICMPv4
		- 0 - Net unreachable
		- 1 - Host unreachable
		- 2 - Protocol unreachable
		- 3 - Port unreachable
	- Dest Unreachable codes for ICMPv6
		- 0 - No route to destination
		- 1 - Communication w/dest is administratively prohibited (ie: firewall)
		- 2 - Beyond scope of source addr
		- 3 - Addr unreachable
		- 4 - Port unreachable
- Time Exceeded - used by router to indicate packet cannot be forwarded bc Time to Live (TTL) of packet was decremented to 0
	- used by traceroute tool
## ICMPv6
- adds 4 new protocols as part of Neighbor Discovery Protocol (ND/NDP) which replaces ARP, IGMP, router discovery and other essential IPv4 network functions. 
- IPv6 Router and IPv6 device
	- Router Solicitation (RS) message
		- router responds to RS message with RA message
		- host is asking router to send its info so it can function
		- ie: "any routers out there????"
	- Router Advertisement (RA) message
		- every 200 seconds to provide addressing info to IPv6 enabled hosts
		- basically says: Im the Router! heres the info: prefix, prefix len, DNS address, domain name
		- host using Stateless Address Autoconfiguration (SLAAC) will set default gateway to link-local addr of router that send RA
- bet IPv6 devices (ARP for IPv6)
	- Neighbor Solicitation (NS) message
		- Who has IPv6 address `fe80::1`
		- ARP and checks uniqueness of address before using it (if no one else is)
	- Neighbor Advertisement (NA) message
		- `fe80::1 is at MAC AA:BB:CC:DD:EE:FF`
## Ping and Traceroute
- Can ping loopback, default gateway, remote host, local host to test connectivity.
- Traceroute (`tracert`) - generates list of hops that were successfully reached along path
	- Round Trip Time (RTT) - time for each hop along path and indicates if hop failes to respond
	- Uses IPv4 TTL and IPv6 Hot limit along with ICMP Time Exceeded message
		- Traceroute will start with TTL of 1 so that ICMP Time Exceeded will cause first hop to send that message back and so it identifies that first hop device
		- Continues to increment until it gets to the destination and each time it increments the ICMP time Exceeded msg is sent by a different hop so it can identify all hops between source and dest.
# Address Resolution
- for IPv6 Address Resolution see ICMPv6 above
## ARP
- stored in RAM
- `show ip arp` - used to show ARP table on cisco router
- `arp -a` - display arp table on windows
- see [[Wireshark Traffic Analysis]] for info on ARP Poisoning
 