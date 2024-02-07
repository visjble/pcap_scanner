PCAP Analysis Script with Scapy
This Python script utilizes the Scapy module to delve into PCAP (Packet Capture) files, uncovering potential security threats within. Tailored for an initial "sanity check" on network traffic—accumulated through ring buffer captures over time—it adeptly parses through both encrypted and unencrypted data. In addition to identifying binary signatures characteristic of executable file formats, the script adeptly extracts RDS sequences from encrypted traffic and scans for specific byte-encoded text strings, pinpointing potential malicious scripts or commands. 

Features
Binary Signature Detection: Searches for signatures like MZ (PE files), PK (ZIP archives), ELF (Unix/Linux executables), and more to identify different types of data within network traffic.
Text String Search: Scans for specific strings within packet payloads, such as batch file commands (@echo off, rem ), PowerShell (powershell.exe), and more, which might indicate suspicious activity.
Flexible Analysis: Can be run against individual PCAP files or an entire directory of files for batch analysis.
RDS sequences: Extracts and analize from encrypted traffic
Exclusion Patterns: Incorporates regex patterns to exclude known benign domains and other irrelevant data from the analysis to reduce false positives.
Usage
Clone the repository or download the script.
Ensure you have Python and Scapy installed. If not, install Scapy using pip install scapy.
Run the script from the command line, providing a path to a PCAP file or directory as an argument:
bash
Copy code
python pcap_analysis.py /path/to/pcap_or_directory
Warning for Windows Users
Running PCAP files, especially those from untrusted sources, can pose security risks. This script is intended for use in controlled environments. Windows users should be particularly cautious, as executing or analyzing malicious PCAPs can inadvertently trigger malware execution or exploit vulnerabilities in the PCAP processing tools themselves.

Ensure your analysis environment is isolated and secure, preferably a virtual machine or a dedicated analysis system, to mitigate risks.

Contributions
This script is a "poor man's version" of many advanced SIEM (Security Information and Event Management) systems, created as a learning exercise and a tool for basic network traffic analysis. Contributions, suggestions, and improvements are welcome. Feel free to fork the repository and submit pull requests.

Files
The script and related resources are available on GitHub: https://github.com/pan-unit42/wireshark-workshop
