**Overview**

This script was written for the purpose of analyzing network packets from a specific PCAP file. It extracts information such as IP addresses, MAC addresses, protocols, and ports. 

**Features**

-Parses Ethernet frames, IPv4 packets, and ARP packets. 

-Extracts details including source/destination IP addresses, MAC addresses, protocols, and port information for TCP UDP.

-Utilizes lookup classes for Ethernet types, MAC addresses, transport protocols, and ports.

-Generates PrettyTables for IP Observation and Port Observations

**Usage**

-Make sure all of the correct libraries are installed on your system.

-Specify your target PCAP file in the "targetPCAP" variabel. 

-Execute the script

**Project Strucute**

-"pcap_processor.py" : Main script file.

-"LookupFiles1/": Directory containing lookup files (oui.pickle, protocol.pickle, ports.pickle).
