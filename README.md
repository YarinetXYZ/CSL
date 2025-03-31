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
	SUBNET-SDCI (10.55.5.0/24)
		- Ubuntu Linux Server (10.55.5.1)
		- Windows 2022 Server (10.55.5.2)

	SUBNET-MI (10.55.10.0/24)
		- Kali Attack Box (10.55.10.1)
		- Windows 10 PC (10.55.10.2)
		- SOC Analyst PC (10.55.10.3)

	SUBNET-SEI (10.55.15.0/24)
		- Wazuh Instance (10.55.15.1)
		- Shuffle Instance (10.55.15.2)
		- TheHive Instance (10.55.15.3)

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
</details>




