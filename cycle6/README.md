
# FloodFury - A Network disruptor

# Why I am interested in building this tool
I will be traveling this week to the East Coast and knowing that I will be connecting to several Wifi APs that provides DHCP/DNS automatic integration for IOT clients, it motivated me to create this tool before my trip (just for the class, not for use during my trip of course!).

Additionally, I have always enjoyed the title 10 activities causing disruption, and having worked with scapy on a similar tool a while back, I thought it would be a great idea to make a tool that have more than just 1 disruptive feature. Understanding the vulnerabilities within network protocols is essential for both offensive and defensive security so we learn how to prevent such attacks

# Background
FloodFury leverages the principles of DHCP starvation and DNS spoofing to exhaust the IP address pool of a DHCP server and also sniff traffic and redirect DNS requests to a specified IP. 
DHCP starvation is a form of denial-of-service (DoS) attack where the attacker floods the DHCP server with bogus DHCP requests, causing the server to allocate all its available IP addresses to fake devices. This prevents legitimate network clients from obtaining an IP address, disrupting network operations. 
DNS spoofing allows the attacker to intercept and alter DNS query responses, redirecting traffic intended for legitimate websites to malicious ones. I will be honest; I have never worked on the defensive side and I’m sure that this is a quick attack, which will be noticeable quickly, and disrupt the network temporarily until a SysAdmin can resolve it.


# Three main Tool Points
1. Prevent new clients from connecting to the network.  By sending numerous DHCP discover and request packets with random MAC addresses, FloodFury exhausts the IP address pool of a DHCP server, making it difficult for legitimate devices to connect to the network. (that’s why some computers uses static ip addresses to avoid such an attack).
2. Redirect traffic: FloodFury intercepts DNS requests on the network and responds with spoofed DNS replies, redirecting clients to a specified IP address. This can be used to redirect traffic to a malicious server for further exploitation. (several DNS servers might help prevent this).
3. Easy to implement, Persistent and Adaptive: The tool can be run in a persistent mode, continuously sending DHCP discover packets and handling DNS requests to maintain the attack over an extended period. It adapts to network conditions by retrying failed attempts and ensuring continuous pressure on the DHCP server!

# Requirements
- kali Linux, or other Linux flavored OS, or a Windows 7 or later.
- Python 3.6 or higher
- Install scapy python library 
- Permissions: Root or sudo privileges (to send and sniff network packets)

# Future Directions / Areas of Improvement
- Enhanced Evading Techniques: Incorporate more sophisticated evasion techniques to bypass network security measures such as intrusion detection systems (IDS) and intrusion prevention systems (IPS.
- Advanced DNS Spoofing: Implement more advanced DNS spoofing techniques, such as selective spoofing based on the queried domain.
- Integrate with other network penetration testing tools for comprehensive network security assessments.

# Design Considerations
- Easy implementation. Chosed to use Scapy for this, which implements an easier to use python-based API, and hides some of the  netowrking protocols complexities.
- Cross-Platform Compatibility.  Designed to work on both Windows and Linux systems, all thanks to Python.
- Modularity: Each function (DHCP discover, DHCP request, ARP reply, DNS spoofing) is modular, allowing for easy updates and modifications
- Adaptability: The tool is adaptable to different network environments, with options to specify the target DHCP server, network interface, and DNS spoof IP.

# Resources	

- Scapy Documentation: https://scapy.readthedocs.io/en/latest
- Python Official Website: Python.org
- Kali Linux: Kali Linux Official Site
- https://www.geeksforgeeks.org/mitigation-of-dhcp-starvation-attack


