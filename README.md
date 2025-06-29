# StrikeNet: A Comprehensive Cyber Offensive Tool
StrikeNet is a versatile cyber offensive tool that integrates multiple functionalities into a user-friendly graphical user interface (GUI). Designed for both ethical hacking and cybersecurity analysis, it combines the capabilities of several essential tools into a single application, including:
1. Keylogger: Captures keystrokes on a target system to monitor user activity or gather sensitive information.
2. Packet Sniffer: Analyzes network traffic to intercept and examine data packets, helping identify vulnerabilities or monitor communications.
3. Network Scanner: Discovers devices with their IP and MAC address, allowing the user to map the network structure.
4. MAC Changer: Modifies the Media Access Control (MAC) address of a device to anonymize activities or bypass access controls

# Key Features

- **Real-Time Output Display**  
  Each module provides real-time feedback within the GUI, eliminating the need to rely on external files for results and logs.

- **Integrated Control Panel**  
  A centralized interface allows users to start, stop, and configure each module independently, promoting flexibility and ease of use.

- **Lightweight Resource Usage**  
  StrikeNet is optimized for minimal CPU and memory consumption, ensuring smooth performance even on lower-end systems and during extended usage.

- **Modular Architecture**  
  The backend logic is structured modularly, enabling future scalability and customization—such as adding new tools or enhancements without overhauling the entire application.

- **Cross-Platform Compatibility**  
  Designed for both Linux and Windows environments, StrikeNet ensures broad accessibility for users across different infrastructures.

# System Architecture
![image](https://github.com/user-attachments/assets/fba96863-65ef-4446-95a2-8c72b1ea2674)

# Modules and Libraries Used

| Library       | Description                                                                 |
|---------------|-------------------------------------------------------------------------|
| `tkinter`     | Builds the graphical user interface (GUI) for user interaction          |
| `threading`   | Enables concurrent execution of modules without freezing the GUI        |
| `time`        | Records and formats timestamps, especially for keystroke logging        |
| `subprocess`  | Executes system-level commands for tasks like MAC address changes       |
| `re`          | Uses regular expressions for pattern matching, such as parsing MACs     |
| `scapy`       | Handles packet sniffing, network scanning, and low-level network analysis |
| `keyboard`    | Captures and logs user keystrokes for the keylogger module              |

# Conclusion
StrikeNet brings together essential cybersecurity tools into a unified, user-friendly platform aimed at ethical hackers, penetration testers, and learners. With features like real-time output, modular design, and cross-platform support, it offers a practical solution for basic network analysis and system monitoring tasks. Its lightweight build and simple interface make it suitable for both beginners and experienced users seeking a compact, functional toolkit.




