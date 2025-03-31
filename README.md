# YRN-SOC-LAB
## Overview

<details>
<summary>View Detailed Information</summary>
	
### Architecture Diagram Diagram
![HSW Forwarder Architecture](https://github.com/user-attachments/assets/d05ab181-0200-4a9f-bd02-aa929e3ead79)	
### Virtual Machines
	- Ubuntu Server 24.04 LTS - x64 Gen2
	- Windows Server 2022 Datacenter: Azure Edition - x64 Gen2
	- Windows 10 Pro, version 22H2 - x64 Gen2
	- Kali 2024.4 (Latest Packages available for pentesting applications)
 ### Software
 	- Sysmon
	- Kali Pentesting Tools
	- File Analysis Tools
	- Atomic Red Team
</details>

## Network Configuration
<details>
<summary>View Detailed Information</summary>
	
### vNet-YRN-SOC-LAB (10.55.0.0/16)

Do not attempt to interact with public IP addresses disclosed in this repository, this infrastructure has since been shutdown and resources reprovisioned. As this lab was built inside Azure they are owned by Microsoft, do so at your own risk.

	SUBNET-SDCI (10.55.5.0/24)
		- Ubuntu Linux Server (10.55.5.3)
		- Windows 2022 Server (10.55.5.6)

	SUBNET-MI (10.55.10.0/24)
		- Kali Attack Box (10.55.10.3)
		- Windows 10 PC (10.55.10.6)
		- SOC Analyst PC (10.55.10.9)

	SUBNET-SEI (10.55.15.0/24)
		- Wazuh Instance (10.55.15.3)
		- Shuffle Instance (10.55.15.6)
		- TheHive Instance (10.55.15.9)

   	NAT-GATEWAY-MI
		- 172.190.154.106 (Public IP Address for All 3 Machines)
      
    	NAT-GATEWAY-SEI
		- 172.172.175.82 (Wazuh)
		- 20.83.145.60 (Shuffle)
		- 52.249.220.86 (TheHive)
  
</details>

## Network Security Groups
<details>
<summary>View Detailed Information</summary>

### Technical Consideration
SUBNET-SDCI indirectly exposed to internet via SUBNET-MI, attack vector exists by allowing SUBNET-MI internet access and thus option to pivot into SUBNET-DCI. Risk Mitigation includes preventing all unnecessary traffic, attempted to include NSG, but was unable to resolve network issues to W10PC (Domain Enrolled), only allowed following traffic.

Type; TCP, UDP, ICMP

Port; 53-DNS, 88-KERBEROS, 135-RPC-ENDPOINT-MAPPER, 138-NETBIOS, 139-NETBIOS, 389-LDAP, 445-SMB, 464-KERBEROS-ADMIN,514-SPLUNK-SYSLOG, 636-LDAP-SSL, 9389-AD-WEB-SERVICES, 3269-LDAP-GLOBAL-CATALOG-SSL, 9997-SPLUNK-EVENT-FORWARDING
	
### Subnet-SDCI (Prevent Internet Access) (Inbound Rule)
| Priority | Rule Name            | Source | Source IPs | Dest. | Dest. IPs      | Port | Protocol | Action |
|----------|---------------------|--------|------------|-------|---------------|------|----------|--------|
| 200      | Deny-Internet-To-SDCI | Any    | Any        | IPs   | Subnet-SDCI   | Any  | Any      | Deny   |

### Subnet-SDCI (Prevent Subnet-SEI Access) (Inbound Rule)
| Priority | Rule Name        | Source  | Source IPs  | Dest. | Dest. IPs      | Port | Protocol | Action |
|----------|----------------|---------|------------|-------|---------------|------|----------|--------|
| 250      | Deny-SEI-To-SDCI | IPs     | 10.55.15.X/24 | IPs   | 10.55.5.X/24   | Any  | Any      | Deny   |

### Subnet-SEI (Prevent Subnet-SDCI Access) (Inbound Rule)
| Priority | Rule Name        | Source  | Source IPs  | Dest. | Dest. IPs      | Port | Protocol | Action |
|----------|----------------|---------|------------|-------|---------------|------|----------|--------|
| 300      | Deny-SDCI-To-SEI | IPs     | 10.55.5.X/24 | IPs   | 10.55.15.X/24    | Any  | Any      | Deny   |

### SOC-ANALYST-SPLUNK (Allow Slpunk Management Access) (Inbound Rule)
| Priority | Rule Name        | Source  | Source IPs  | Dest. | Dest. IPs      | Port | Protocol | Action |
|----------|----------------|---------|------------|-------|---------------|------|----------|--------|
| 350      | Allow-Splunk-MGR | IPs     | 10.55.10.9 | IPs   | 10.55.5.3    | 8000  | Any      | Allow   |
</details>

## Services Deployment
<details>
<summary>View Detailed Information</summary>

### Splunk Instance (Indexer & Deployment Server)
Registered for splunk enterprise trial, downloaded .deb file onto Kali VM, transfered and deployed onto Ubuntu Linux VM. (Before NSG's)
  
 	- sudo apt-get update 
 	- sudo apt-get upgrade
 	- scp splunk-9.4.1-ddff1c41e5cf-linux-2.6-amd64.deb Yarinet@10.55.5.3:/home/ (OpenSSH Installed on Kali VM)
 	- sudo dpkg -i splunk9.4.1-ddff1c41e5cf-linux-2.6-amd64.deb
 	- sudo ./splunk start
 	- sudo ./splunk enable boot-start
 	- systemctl enable splunk
 	- systemctl start splunk

### Active Directory Deployment

Deployed Active Directory Domain Services on Windows 2022 server.
Configured Windows 2022 server as the domain controller (YRN-DC1) & Windows 10 PC enrolled as (YRN-X0Y0Z)
Replicated the Sysmon installation process on WS2022 and W10 PC, in preparation for Lab expansion (Domain Controller Hardening & Attacks)

https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

http://github.com/SwiftOnSecurity/sysmon-config

 	Navigate to saved directory > Run (Sysmon64.exe) As Administrator
  	sysmon.exe -accepteula -i sysmonconfig-export.xml (Powershell)
   	
Navigate to following directory after Splunk Universal Forwarder is installed, enter the attached logs forwarding, this process is doubling up as will already be present with out SUF setup, last lines are primary concern as they allow for the forwarding of sysmon logs into splunk. 
	
 	C:\Program Files\SpunkUniversalForwarder\etc\local\inputs.conf
  
  	[WinEventLog://Application]
	index = endpoint
	disabled = false

	[WinEventLog://Security]
	index = endpoint
	disabled = false

	[WinEventLog://System]
	index = endpoint
	disabled = false

	[WinEventLog://Microsoft-Windows-Sysmon/Operational]
	index = endpoint
	disabled = false

	renderXml = true
	source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
	### Splunk Universal Forwarder

Management Portal

	Splunk > Receive Data > Listen on 9997
	Splunk > Add Data > Local Event Logs (All) (After Universal Forwarder Configured)
Splunk Universal Forwarder (SUF)

	Download version 9.4.1 MSI File
	Configure SUF settings (Receiving Indexer) (10.55.5.3) (9997)
	Configure SUF settings (Deployment Server) (10.55.5.3) (8089)
	Windows Event Logs (Application Logs, Security Logs, System Logs)
Windows Defender Firewall (Outbound Rule)

	Splunk-Traffic (TCP) (9997) (Allow)

</details>


