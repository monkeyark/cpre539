# CPRE 539 - Lab 1: Network Discovery with Port Scanning Module

## Network Scan Overview

The analyzed network spans multiple subnets:
- 52.135.80.0/24 subnet (3 hosts)
- 6.87.151.0/24 subnet (3 hosts)
- 6.87.152.0/24 subnet (4 hosts)
- 6.87.153.0/24 subnet (3 hosts)

## Initial Observations

1. The IP address distribution suggests this might be a distributed infrastructure, possibly spanning multiple geographic locations or network segments.
2. The 52.135.80.x range appears to be separate from the 6.87.x.x ranges, which could indicate:
   - Different cloud providers or regions
   - Separation between internal and external-facing services
   - DMZ and internal network separation

## Potential Security Concerns

Without specific service version information from the nmap scan, here are general security considerations:

1. **Network Topology Exposure**
   - The ability to scan these IPs indicates potential gaps in perimeter security
   - Network segmentation details are exposed
   - Attackers could map the network infrastructure

2. **Reconnaissance Vulnerability**
   - Successful nmap scans suggest no firewall rules blocking port scanning
   - This could enable attackers to gather detailed infrastructure information
   - Version scanning (-sV) exposure could reveal outdated services

3. **Attack Surface**
   - Multiple network segments increase the potential attack surface
   - Gateway IPs (ending in .254) could be targeted for network pivoting
   - The .1 address in 6.87.152.0/24 might indicate a router/gateway

## Security Recommendations

1. **Firewall Hardening**
   - Implement strict firewall rules to limit scanning capabilities
   - Consider implementing IDS/IPS to detect and block scanning attempts
   - Use rate limiting for connection attempts

2. **Network Segmentation Review**
   - Verify if current network segmentation is appropriate
   - Implement additional VLANs if needed
   - Consider microsegmentation for critical services

3. **Monitoring and Detection**
   - Deploy network monitoring tools
   - Implement logging for unauthorized scanning attempts
   - Set up alerts for suspicious network behavior

Note: A more detailed security analysis would be possible with the actual nmap service version scan results.

# CPRE 539 - Lab 2: Vulnerability Assessment with OpenVAS Module

## Network Scan Analysis

### Corporate Network (52.135.80.0/24)
1. Host 52.135.80.110
   - Running OpenSSH 7.2p2 on Ubuntu
   - Potential vulnerability: Older SSH version with known CVEs
   - Limited attack surface with only SSH exposed

2. Host 52.135.80.210 (Windows Server)
   - Multiple exposed services including RPC, SMB, RDP
   - Running older Windows Server (2003/2008)
   - High-risk services: NetBIOS, RDP (3389)
   - Multiple filtered high ports (60xxx-65xxx)

3. Host 52.135.80.254 (Gateway)
   - Critical services: DNS, HTTP/HTTPS, SSH
   - Running nginx web server
   - Potential gateway/router device

### Control Network (6.87.151.0/24)
1. Host 6.87.151.110
   - Similar configuration to corporate Ubuntu host
   - OpenSSH 7.2p2 exposed

2. Host 6.87.151.210
   - Windows XP system (highly vulnerable)
   - Exposed SMB and NetBIOS services
   - SafeNet Sentinel Protection Server 7.3
   - Sybase database port open (2638)

3. Host 6.87.151.254
   - Gateway configuration similar to corporate network
   - Running nginx and OpenSSH 7.9

### Substation Networks (6.87.152.0/24 and 6.87.153.0/24)
1. Notable Systems:
   - 6.87.152.1: BGP router (port 179)
   - Multiple Windows systems with RPC/SMB exposure
   - Consistent gateway configurations (*.*.*.254)
   - Sybase database instances (port 2638)

2. Common Services:
   - Microsoft RPC (135/tcp)
   - SMB/NetBIOS (139/tcp, 445/tcp)
   - X11 services (6002/tcp)
   - Web services on gateways (80/tcp, 443/tcp)

## Critical Vulnerabilities

1. **Legacy Systems**
   - Windows XP detected (6.87.151.210)
   - Windows Server 2003/2008 (52.135.80.210) 
   - These systems are beyond end-of-life and likely unpatched
   - BGP router (6.87.152.1) potentially running outdated firmware
   - Gateway systems running mixed SSH versions

2. **Exposed Critical Services**
   - SMB/NetBIOS exposure across Windows hosts
   - RDP access on corporate Windows server
   - Database services (Sybase) directly accessible
   - BGP router with closed but visible port
   - Daytime and Time services exposed on Windows systems
   - Gateway systems exposing HTTP/HTTPS/DNS services

3. **Infrastructure Weaknesses**
   - Consistent gateway configurations make targeting easier
   - Older SSH versions on multiple Linux systems
   - Clear network segmentation but with similar vulnerabilities
   - BGP routing exposure could enable network disruption
   - DNS services on gateways potentially vulnerable to cache poisoning

## Potential Attack Scenarios

1. **Corporate Network Compromise**
   - Initial Vector: Target Windows Server 2003/2008 via SMB
   - Leverage RDP access for persistence
   - Pivot through corporate gateway to access control network
   
   Risk: HIGH - Legacy Windows Server with multiple exposed services provides an attractive entry point.

2. **Control System Access**
   - Initial Vector: Exploit Windows XP system in control network
   - Target Sybase databases for SCADA system information
   - Use compromised control network access to reach substations
   
   Risk: CRITICAL - Windows XP system with database access represents a severe vulnerability.

3. **Network Infrastructure Attack**
   - Initial Vector: Target BGP router at 6.87.152.1
   - Exploit routing protocols to redirect traffic
   - Potential for network-wide disruption
   
   Risk: HIGH - BGP exposure could allow network topology manipulation.

4. **Gateway Service Compromise**
   - Initial Vector: Target nginx web servers on gateway systems
   - Exploit DNS services for cache poisoning
   - Intercept and manipulate network traffic
   
   Risk: CRITICAL - Gateway compromise could affect entire network segments.

## Security Recommendations

1. **Immediate Actions**
   - Decommission or isolate Windows XP system
   - Upgrade Windows Server 2003/2008 to supported versions
   - Implement strict firewall rules for SMB/NetBIOS
   - Disable direct database access from external networks

2. **Infrastructure Improvements**
   - Implement jump hosts for administrative access
   - Deploy modern intrusion detection/prevention systems
   - Regular vulnerability scanning and patch management
   - Enhanced network segmentation between zones

3. **Service Hardening**
   - Upgrade OpenSSH to latest versions
   - Implement strict access controls for RDP
   - Review and secure BGP router configurations
   - Deploy web application firewalls for nginx servers

4. **Network Protocol Security**
   - Implement BGP authentication and filtering
   - Review and secure routing protocols
   - Monitor for unauthorized routing changes
   - Consider implementing RPKI for BGP security

5. **Gateway Security Hardening**
   - Implement DNSSEC on all DNS servers
   - Configure nginx with security best practices
   - Deploy WAF protection for web services
   - Implement strict access controls for gateway management

6. **Service Exposure Reduction**
   - Remove unnecessary services (Daytime, Time)
   - Restrict DNS recursion to internal networks
   - Implement strict firewall rules on gateway systems
   - Regular security audits of exposed services
