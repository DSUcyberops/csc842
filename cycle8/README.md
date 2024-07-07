
# myNetScanR - A Simple network scanner

# Why I am interested in building this tool
I often wonder at times how many devices are actively connected to my home network, and I don’t’ always have the time to login to my router.  So, for this week, I have developed a simple network scanner tool as it provides a quick, and non-intrusive way to monitor and manage devices connected to my network.  This tool allows me to gain insights into the devices' operating systems, open ports, and connectivity status in my network without needing to access my router directly.


# Background
This network scanning tool leverages Scapy, a powerful Python library for packet manipulation and network scanning. It uses ARP and ICMP protocols to discover devices within specified IP ranges, performs OS fingerprinting based on TTL values and common port scans, and provides valuable insights into the devices' characteristics.


# Three main Tool Points
1. Device Discovery and Identification: It identifies all active devices on the network, including their IP and MAC addresses, allowing for easy inventory management.
2. OS Fingerprinting: By analyzing TTL values and common ports, it provides insights into the types of devices connected, whether they are running Windows, Linux, iOS, Android, or other operating systems.
3. Port Scanning Capabilities: It checks for open ports on discovered devices, which is crucial for security assessments and troubleshooting network connectivity issues.

# Requirements
- kali Linux, or other Linux flavored OS, or a Windows 7 or later.
- If using Windows, need to install NCAP ()
- Python 3.6 or higher
- Install scapy python library 
- Permissions: Root or sudo privileges (to send and sniff network packets)

# Future Directions / Areas of Improvement
- Integrate with an AI engine. I originally had it integrated to use OpenAI Chat GPT, but due to time, and the free tier being exhausted, I quit the OpenAI integration.
- Enhanced User Interface: Develop a graphical user interface (GUI) for easier interaction and visualization of scan results.
- Automation and Scheduled Scans: Implement features for automated scans at regular intervals or in response to network events.
- Integration with Security Tools: Integrate with security tools to enhance threat detection and response capabilities based on network scan results

# Design Considerations
- Performance Optimization: Optimize packet handling and response parsing for faster scan times and reduced network impact.
- Error Handling and Robustness: Implement robust error handling to manage network issues and ensure reliable scan results.
- Scalability: Design the tool to handle large networks efficiently, possibly leveraging parallel processing or distributed scanning techniques.

# Resources	
- Scapy Documentation: https://scapy.readthedocs.io/en/latest
- Python Official Website: Python.org
- Kali Linux: Kali Linux Official Site
- https://npcap.com
- https://www.geeksforgeeks.org/network-scanner-in-python
