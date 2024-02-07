import subprocess
import os
import re
import sys
from scapy.all import rdpcap, Raw

# Compile regex patterns once at the beginning, including multiple exclude patterns
EXCLUDE_PATTERN = re.compile(r'(\.microsoft\.com|\.otherdomains\.net)$') # FILTER MORE DOMAINS AS NEEDED
GARBAGE_PATTERN = re.compile(r'\b\*?[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*\b')

# Define a list of binary signatures to search for at the beginning of payloads in network packets.
# These signatures are indicative of specific file formats and can be used to identify the type of data being transmitted.
# For example:
# - b"MZ" is the magic number for Windows executable files (PE format), typically found at the start of .exe and .dll files.
# - b"PK" is the magic number for ZIP archive files, used in many compression formats and package files like .zip, .jar, .docx, .xlsx, etc.
# - b"ELF" stands for Executable and Linkable Format, used in Unix and Unix-like systems for executables, object code, shared libraries, and core dumps.
binary_signatures = [
    b"MZ",  # PE file format (Windows executables and DLLs)
    b"PK",  # ZIP archive format (also for JAR, DOCX, XLSX, PPTX files)
    b"ELF",  # Executable and Linkable Format (Unix/Linux executables)
    b"\xCA\xFE\xBA\xBE",  # Java class files
    b"SQLite format 3\x00",  # SQLite database file header
    b"\x50\x4B\x03\x04\x14\x00\x06\x00",  # Office Open XML (Microsoft Office 2007 and later documents)
    b"%PDF",  # PDF file format
    b"Rar!\x1A\x07\x00",  # RAR archive format
    b"\x89PNG\r\n\x1a\n",  # PNG image format
    b"ID3",  # MP3 file format (ID3 tag)
    b"\xFF\xD8\xFF\xE0",  # JPEG image format
    b"OggS",  # OGG multimedia format
    b"\x25\x21\x50\x53\x2D\x41\x64\x6F\x62\x65",  # PostScript files
    b"\x52\x49\x46\x46",  # AVI and WAV file formats
    b"7z\xBC\xAF\x27\x1C"  # 7z archive format
]


# Define a list of byte-encoded text strings that might be found anywhere within the payload of network packets.
# These strings are associated with specific types of scripts or commands and can indicate the nature of the data or potential security threats.
# For example:
# - b"@echo off" is commonly used at the beginning of Windows batch files to prevent commands from being displayed in the command prompt, often used in scripting and automation.
# - b"rem " (short for remark) is used in batch files and some other scripting languages to denote a comment line, which is not executed as a command but might contain useful information or context.
text_strings = [
    b"@echo off",  # Common in batch files to hide command output
    b"rem ",  # Remark/comment in batch scripts
    b"powershell.exe",  # PowerShell execution
    b"cmd.exe /c",  # Command execution and termination in Windows
    b"wget ",  # File download in Unix/Linux
    b"curl ",  # File download or data transfer in Unix/Linux
    b"<script>",  # HTML/JavaScript injection
    b"base64_decode",  # Encoding/decoding in PHP, often for obfuscation
    b"[System.Reflection.Assembly]::Load",  # Loading .NET assemblies in PowerShell
    b"eval(",  # Code evaluation in PHP/JavaScript
    b"nc ",  # Netcat utility for networking tasks, potentially malicious
    b"netcat ",  # Another form of the netcat command
    b"msfvenom",  # Metasploit payload generator
    b"meterpreter"  # Metasploit shell
]


def is_garbage_text(text):
    # Check against the exclusion pattern
    if EXCLUDE_PATTERN.search(text):
        return False
    # Check against the general garbage pattern
    return bool(GARBAGE_PATTERN.search(text))

def extract_certificates_with_tshark(pcap_file):
    # Define the command to run tshark with necessary options:
    # '-r' specifies the input file.
    # '-Y' sets a display filter, here filtering for SSL/TLS handshake certificates.
    # '-T fields' tells tshark to output only the specified fields.
    # '-e' specifies the fields to extract: frame number and UTF8 strings in x509 Subject Alternative Name.
    # '-E separator=/' uses a custom field separator '/' for the output, for easier parsing.
    command = [
        'tshark', '-r', pcap_file, '-Y', 'ssl.handshake.certificate',
        '-T', 'fields', '-e', 'frame.number', '-e', 'x509sat.uTF8String',
        '-E', 'separator=/'  # Custom separator
    ]

    # Print a header to indicate the start of findings for a specific pcap file. Uses ANSI escape codes for colored output.
    print(f'\033[31mFindings RDASEquence for file:\n{pcap_file}\n\033[0m')

    try:
        # Execute the tshark command, capturing its output and errors, if any.
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Process the output, splitting by newline to get individual findings.
        findings = result.stdout.strip().split('\n')
        
        # Iterate through each finding.
        for finding in findings:
            # Split the finding into fields using the custom separator '/'.
            fields = finding.split('/')
            
            # Ensure that there is at least one field to process.
            if len(fields) >= 1:
                # Split the first field further by the '\' separator to separate frame number and text.
                output = fields[0].split('\\')
                
                # Check that there are at least two elements (frame number and text) and that the text is not empty or just whitespace.
                if len(output) > 1 and output[1].strip() and is_garbage_text(output[1]):
                    # Print the frame number and the extracted text, indicating potential findings.
                    print(f'Frame {output[0]}: {output[1]}')
                    # Provide a Wireshark filter suggestion for further manual analysis.
                    print(f'Wireshark filter is: frame.number eq {output[0]} && x509if.rdnSequence')
                    print()
        
        # Print footer lines to indicate the end of findings for this pcap file.
        print('----------- End finding -----------')
        print('-----------------------------------\n')
    except subprocess.CalledProcessError as e:
        # If tshark command execution fails, print an error message with the exception details.
        print(f"Error running tshark: {e}")


def process_packets_with_scapy(pcap_file):
    # Use Scapy to read all packets from the provided pcap file. This function loads the entire pcap file into memory.
    packets = rdpcap(pcap_file)

    # Iterate through each packet in the pcap file. The enumerate function is used to get both the index (i) and the packet.
    for i, packet in enumerate(packets):
        # Check if the current packet contains a Raw layer, which indicates the presence of a payload.
        if packet.haslayer(Raw):
            # Extract the payload from the Raw layer of the packet. The payload is where data is carried, and it's what we'll be inspecting.
            payload = packet[Raw].load

            # Iterate through each binary signature defined earlier. These signatures are indicative of certain file types or protocols.
            for signature in binary_signatures:
                # Check if the payload starts with any of the specified binary signatures. This is common for files or data streams.
                if payload.startswith(signature):
                    # If a signature is found, print a message indicating its presence, the packet number, and a summary of the packet.
                    print('\033[31mOther Magic Numbers and byte-encoded text strings:\033[0m')
                    print(f"\nBinary signature '{signature.decode()}' found at the beginning of packet {i+1}: {packet.summary()}")

            # Iterate through each text string defined earlier. These strings could be commands or text indicative of certain scripts or actions.
            for text_string in text_strings:
                # Check if the text string is present anywhere within the payload. This is a broader search than the binary signature check.
                if text_string in payload:
                    # If a text string is found, find its starting index within the payload. This can help in locating it within the packet.
                    start_index = payload.find(text_string)
                    # Print a message indicating the presence of the text string, its location within the packet, and a summary of the packet.
                    print(f"\nText string '{text_string.decode()}' found in packet {i+1} at byte offset {start_index}: {packet.summary()}")
                    # Here, you could add additional instructions for analyzing the packet in Wireshark, such as how to navigate to the specific packet and locate the string within the payload.

def main():
    if len(sys.argv) > 1:
        input_path = sys.argv[1]
    else:
        input_path = input("Enter the path of your pcap file or directory: ").strip().strip('"').strip("'")
    
    if os.path.isfile(input_path):
        extract_certificates_with_tshark(input_path)
        process_packets_with_scapy(input_path)
    elif os.path.isdir(input_path):
        for file_name in os.listdir(input_path):
            if file_name.endswith(('.pcap', '.pcapng')):
                pcap_file = os.path.join(input_path, file_name)
                extract_certificates_with_tshark(pcap_file)
                process_packets_with_scapy(pcap_file)
    else:
        print("The provided path is not a valid file or directory.")

if __name__ == '__main__':
    main()





# LEGEND:
#     for pcap in /home/q/Documents/cyber_security/U42-workshop/wireshark-workshop/*.pcap; do
#     echo "Processing $pcap for RDASequence..."
#     tshark -r "$pcap" \
#         -Y "ssl.handshake" \
#         -T fields \
#         -e frame.number \
#         -e x509sat.uTF8String
# done

# TODO:
# Expand Signature Lists: Continue to expand your binary_signatures and text_strings lists with more indicators of compromise (IoCs). Consider including common malware file markers, suspicious strings found in malware analysis reports, and other indicators from threat intelligence sources.

# Dynamic Loading of IoCs: Instead of hardcoding IoCs in the script, consider loading them from an external file or a database. This allows you to update your IoC list without modifying the script, making it easier to keep the script up-to-date with the latest threat intelligence.

# Enhance Output Formatting: For better readability, especially when dealing with large volumes of data, consider formatting the output more clearly, perhaps by writing findings to a structured format like CSV or JSON. This can help with further analysis, especially if you're integrating this script's output with other tools.

# Automate Exclusion List Updates: The EXCLUDE_PATTERN is a great idea to filter out known good domains. You might automate the process of updating this list by integrating with a service that provides lists of known good domains or by maintaining an external file that the script reads.

# Error Handling: Enhance error handling to manage unexpected inputs or failures more gracefully. This can include handling permissions errors, reading errors, or issues with the pcap files themselves.

# Integrate with a GUI or Web Interface: For ease of use, especially for those less comfortable with command-line tools, consider integrating your script with a simple graphical or web interface that allows users to upload pcap files and view the analysis results.

# Concurrency for Large Datasets: If you're dealing with very large pcap files or many files in a directory, consider using Python's multiprocessing or concurrent.futures modules to parallelize the analysis and speed up the processing time.

# Hash Checking: For binary data that matches known signatures, consider calculating and checking hashes (MD5, SHA-1, SHA-256) against a database of known malicious file hashes.

# Heuristic Analysis: Beyond static signatures, consider implementing simple heuristic checks to identify potentially malicious behavior patterns, such as unusual entropy levels (which might indicate obfuscation or encryption) or the presence of packed executable content.

# Logging and Reporting: Implement detailed logging and reporting mechanisms to keep track of the script's operations, findings, and any errors that occur. This can be invaluable for troubleshooting and for understanding the context of the findings.
