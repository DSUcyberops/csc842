
# myKeyLogger

# Why I am interested in building this tool
I have worked in many projects in the past, but mainly working on vulnerabilities, RE, among others. I have never built a keylogger and thought it would be fun to create one and see what it takes to build one.

# Background
Keylogging, which involves using a hidden program to record keystrokes sequentially, is one of the oldest tactics in cyber attacks and remains in use today with varying degrees of details and implementation. It's still popular among attackers due to its effectiveness in capturing sensitive information like credentials and conversations. In my implementation, I logged the keystrokes to a file and periodically encrypted it or encrypted it upon termination. This way, if the user opened the file, the data would be unreadable unless decrypted.

# Three main Tool Points
1. Easy to Create:  The primary motivation for this project is to broaden my expertise by creating a keylogger using Python and adding it to my toolbox.
2. Usefulness and Safety: Understanding it’s used and APIs in python which is crucial for developing more robust security measures against keyloggers. There are many ways and libraries to create a keylogger. This is just one way. Additionally good to create it if you have small kids and you are worry about their safety on line and need to see their activity.
3 . Defensive Measures.  Developing this tool allows me to explore and test it’s behavior in my environment which helps protect my systems from such attack. Overall, this is also a fun tool to create!

# Requirements
- A windows 10 machine or Kali Linux
- Python 3.6 or higher
- Install pynput python library (provides low level hardware abstraction)
- Install cryptography python library (provided file encryption capabilities)
- Install pyinstaller (optional if want to make it executable)

# Future Directions / Areas of Improvement
- Stealth Enhancements: Improve the stealth capabilities of the keylogger by obfuscating its process and making it harder to detect by antivirus software.
- Persistence Mechanisms: Implement mechanisms to ensure the keylogger remains active and reactivates after system reboots.
- File transfer. Provide a mechanism to either transfer the file or even better, create a reverse shell and read the file, where the attacker could see the typing real time.
- Cross-platform Compatibility: Ensure the code runs seamlessly across different platforms with minimal modifications.
- Screen Capture: Integrate screen capturing to log visual context along with keystrokes.
- Self-destruct Mechanism: Implement a feature to securely erase all logs if certain conditions are met (e.g., a specific keystroke sequence).

# Design Considerations
- Hardware Abstraction.  Use of python library such as pynput. The pynput library abstracts hardware-level interactions, allowing the keylogger to capture keyboard events without dealing directly with the hardware. Also, this abstraction simplifies development and ensures compatibility across different systems and hardware configurations. There are other libraries such as Pyhook, but, it’s dated.
- Cross-Platform Compatibility.  Designed to work on both Windows and Linux systems.
- Encryption: The cryptography library is used to encrypt and decrypt log data, ensuring that sensitive information captured by the keylogger is securely stored
- Periodic Encryption: Data is periodically encrypted and saved to disk, reducing the risk of sensitive information being exposed if the system crashes or is accessed by unauthorized users. Periodicity in seconds, can be adjusted.
- Background Processing: The keylogger uses background threads (via threading.Timer) to handle periodic encryption without blocking the main thread,.
- Graceful Shutdown: The atexit module is used to ensure that the log file is encrypted when the program exits, even if it terminates unexpectedly. This guarantees that sensitive data is always protected.

# Resources	
- https://pypi.org/project/pynput/
- https://pyinstaller.org/en/stable/
- https://www.geeksforgeeks.org/design-a-keylogger-in-python/

