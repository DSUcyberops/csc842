
# wifiDisco - A Wireless Deauth Tool

# Why I am interested in building this tool
Learning about wireless technologies in today’s digital age is a Must! With so many IOT devices, ensuring the integrity and security of these networks is a challenge that fascinates me. The opportunity to dive deep into wireless security, understand potential vulnerabilities, and develop tools to address them is both a personal passion and a professional pursuit. This led me to create this tool that leverages the powerful capabilities of Scapy to perform various wireless security tasks, including sniffing Wi-Fi networks and executing Deauthentication (Deauth) attack. How exciting!.

# Background
Scapy is a powerful Python-based network manipulation tool that allows users to send, sniff, and dissect network packets. Its versatility makes it ideal for developing custom network analysis and security tools. The inspiration for wifiDisco came from the capabilities demonstrated by tools like airoscapy and aircrack-ng. These tools have laid the groundwork for network security testing and have shown how effective and important it is to understand network behaviors and vulnerabilities.


# Three main Tool Points
1. Network Sniffing: wifiDisco.py uses Scapy to sniff Wi-Fi Beacon and Probe Response frames, identifying available networks within range. It captures and displays essential information such as the channel, ESSID, and BSSID of detected networks.
2. Channel Hopping: The tool incorporates a channel hopping mechanism to continuously switch between channels, ensuring a comprehensive scan of all available networks. This process is crucial for discovering networks operating on different channels.
3. Deauthentication Attacks: One of the key features of this tool is its ability to perform Deauth attacks. This involves sending Deauth packets to disconnect clients from a specified Wi-Fi network, effectively simulating a denial-of-service attack. This feature is useful for testing network security and resilience.

# Requirements
- kali Linux.
- If using a Kali VM, a USB Wireless Antenna must be used
- Python 3.x: Ensure that Python 3.x is installed on your system.
- Scapy: Install the Scapy module using pip install scapy.
- Root Privileges: The script requires root privileges to execute network sniffing and packet injection.
- Wireless Adapter. Monitor mode must be enabled in the wireless adapter.
    sudo airmon-ng
    sudo airmon-ng check kill
    sudo airmon-ng start wlan0

# Future Directions / Areas of Improvement
While this tool offers robust functionality, there are several areas where it can be enhanced:
1.	User Interface:	Developing a graphical user interface (GUI) could make the tool more user-friendly, allowing users to perform network scans and Deauth attacks through a visual interface.
2.	Advanced Attack Techniques:	Incorporating additional attack techniques, such as man-in-the-middle (MITM) attacks or more sophisticated denial-of-service (DoS) methods, could broaden the tool’s capabilities.
3.	Improved Network Detection:	Enhancing the network detection algorithm to handle hidden SSIDs more effectively and incorporating additional filtering options could improve accuracy and performance

# Design Considerations
When designing this tool, several key considerations were taken into account:
- Performance: The tool is designed to operate efficiently, with minimal impact on system resources. The use of multiprocessing for channel hopping ensures smooth operation.
- Extensibility: 	The script is modular writting in Python, allowing for easy extension and integration of new features. Functions are clearly defined, making it straightforward to add new capabilities.
- Security: Given the sensitive nature of the tool, it is crucial to emphasize ethical use. The script includes prompts and checks to ensure that users are aware of the legal implications and responsibilities associated with its use.
- Usability: Clear prompts and formatted outputs enhance the user experience, making it easy for users to interact with the tool and interpret results

Overall, creating this tool was fun, and having the ability to deauthenticate clients from BSSIDS due to the current protocol implementation is relatively easy.

# Resources	
- https://www.kali.org/
- https://scapy.net/
- https://www.geeksforgeeks.org/kali-linux-aircrack-ng/
