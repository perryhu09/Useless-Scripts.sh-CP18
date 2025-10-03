#### Host Roles

Hosts: Computers connected to a network and participate directly in network communication
- Can be called end devices, clients,
- Refers to devices on a[[ ]]network that are assigned a number for communication purposes
	- IP (Internet Protocol) address identifies the host and the network to which the host is connected to

Servers: Computers with software that allow them to provide information like email or web pages, to other end devices on the network
- Each service requires separate software. 

Clients: Have software for requesting and displaying the information obtained from the server.

![[Screenshot 2025-09-20 at 22.19.27.png]]

Client Software 
- Chrome, Firefox
- A single computer can run multiple types of client software
	- Ex: can check emails and view a web page while instant messaging and listening to audio.
![[Screenshot 2025-09-20 at 22.21.45.png]]

##### Peer to Peer Network
Possible for one computer to be used for both client and server software at the same time. 
- Many computers function like this in small homes/businesses
- Called Peer-to-Peer Network

**Advantages**
- Easy to set up
- Less Complex
- Lower cost because network devices and dedicated servers may not be required
- Can be used for simple tasks

**Disadvantages**
- No centralized administration
- Not as secure
- Not scalable
- Can show slowed performance

**End Devices**
- Source or destination of a message transmitted over the network


##### Intermediary Devices
- Connect individual end devices to the network
	- Can form an internetwork
- Provide connectivity and ensure that data flows across the network
- Can use destination end device address, along with info from network interconnections, to determine the path that messages should take through the network.

![[Screenshot 2025-09-20 at 22.30.01.png]]

Performs these functions
- Regenerate and retransmit communication signals
- Maintain information about what pathways exist through the network and internetwork
- Notify other devices of errors and communication failures
- Direct data along alternate pathways when there is a failure
- Classify and direct messages based on priorities
- Permit/deny flow of data based on security settings

##### Network Media
- Modern networks uses 3 types of media
	- Metal wires within cables: Data is encoded into electrical impulses
	- Fiber-Optic Cable (Glass/plastic fibers within cable) - Data is encoded into pulses of light
	- Wireless transmission - Data is encoded via modulation of specific frequencies of electromagnetic waves.
- Questions to ponder about choosing media
	- Maximum distance for data integrity?
	- Environment where the media is installed?
	- Amount of Data and what speed?
	- Cost of media/installation?

NIC (Network Interface Card) ==> Connects the end device physically to a network
Physical Port ==> Connector/Outlet where media connects to an end device or another networking device
Interface/Port ==> Specialized ports on a network device that connects to individual networks

Logical Topology ==> Connections between devices
Physical Topology ==> Actual location of devices

![[Screenshot 2025-09-25 at 08.20.52.png]]
##### Network Types
- **Small Home Networks**
	- Connects a few computers to each other and the internet
- **Small Office and Home Office Networks (SOHO)**
	- Allows computers in a home/remote office to connect to a corporate network or access centralized resources
- **Medium to Large Networks**
	- Many locations with hundreds of thousands of interconnected hosts
- **World Wide Networks**
	- Internet is a network of networks that connects hundreds of millions of computers world-wide


##### LANs 
- Network infrastructure that spans a small geographical area
	- Interconnect end devices in a limited area such as a home, school, office building, or campus
	- Administered by a single individual or organization
		- Control is enforced at the network level and governs security + access control policies.
	- Provide high-speed bandwidth to internal end devices and intermediary devices.
![[Screenshot 2025-09-25 at 08.23.39.png]]

##### WANs
- Network Infrastructure that spans a wide geographical area 
- Managed by service providers (SP) or Internet Service Providers (ISPs)
	- Interconnected LANs over wide geographical areas such as between cities, states, provinces, countries, or continents
	- Administered by multiple service providers.
	- Slower speed links between LANs.

Internet ==> Interconnected LANs and WANs (LANs using WAN services to connect)

**Intranets**
- Private connection of LANs and WANs that belongs to an organization
- Only accessible by members, employees or authorized users.

**Extranets**
- Provide secure/safe access to individuals not connected with the organization, but requires access to organization's data.![[Screenshot 2025-09-25 at 11.05.37.png]]

#### Connection Types

---

**Cable**
- Offered by cable television service
- High bandwidth, high availability, always connected to Internet

**DSL - Digital Subscriber Line**
- High bandwidth, high availability, always connected to internet
- Runs over a telephone line
- Usually SOHO users use ADSL(Asymmetrical DSL) ==> download speed > upload speed

**Cellular**
- Uses a cell phone network to connect
- Find cellular signal == cellular internet access
- Performance limited by cell phone tower and phone

**Satellite**
- Available anywhere in the world
- Clear line of sight to satellite

**Dial-up Telephone**
- Uses a phone line and a modem
- Low bandwidth from modem connection is not sufficient for large data transfer
- Useful for mobile access while traveling


---
**Dedicated Leased Line**
- Reserved circuits within the service provider's network that connect geographically separated offices for private voice/data networking.
- Rented monthly/yearly

**Metro Ethernet**
- Ethernet WAN as well
- Extend LAN access tech into the WAN. Ethernet is LAN as well

**Business DSL**
- Available in various formats
- SDSL (Symmetric Digital Subscriber Line)
	- Similar to consumer version of DSL, but uploads = download speeds

**Satellite**
- Connection when wired solution is not available.

Converged Networks took over Traditional Networks with the Rule Agreement Standard in the middle instead of at the end
![[Screenshot 2025-09-25 at 11.23.46.png]]

##### Network Architecture

4 Basic Characteristics of Network Architecture
- Fault Tolerance
- Scalability
- Quality of Service (QoS)
- Security

**Fault Tolerance**
- Limits the number of affected devices during a failure
- Quick recovery when failure occurs
- Implements redundancy
	- Packet-switched network splits traffic into packets that are shipped over a shared network.
	- All packets can come at different paths and times, but it will be fine

**Scalability**
- Expands quickly to support new users and applications.
- Does this without degrading the performance of services

![[Screenshot 2025-09-25 at 11.38.53.png]]

**Powerline**
- Connecting a device to the network using an electrical outlet