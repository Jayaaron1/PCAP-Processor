# Python Standard Library Module Imports
import sys               # System specifics
import platform          # Platform specifics
import os                # Operating/Filesystem Module
import pickle            # Object serialization
import time              # Basic Time Module
import re                # Regular expression library
from binascii import unhexlify

# 3rd Party Libraries
from prettytable import PrettyTable   # pip install prettytable
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import tcp
from pcapfile.protocols.transport import udp

# Script Constants
NAME    = "PYTHON PCAP PROCESSOR"
VERSION = "VERSION 1.0 AUGUST 2021"
DEBUG   = True

# Script Constants
DEBUG = True

# Script Local Functions

class ETH:
    '''LOOKUP ETH TYPE'''
    def __init__(self):
        self.ethTypes = {}
        self.ethTypes[2048]   = "IPv4"
        self.ethTypes[2054]   = "ARP"
        self.ethTypes[34525]  = "IPv6"
            
    def lookup(self, ethType):
        try:
            result = self.ethTypes[ethType]
        except:
            result = "not-supported"
        return result

# MAC Address Lookup Class
class MAC:
    ''' OUI TRANSLATION MAC TO MFG'''
    def __init__(self):
        # Open the MAC Address OUI Dictionary
        with open('LookupFiles1/oui.pickle', 'rb') as pickleFile:
            self.macDict = pickle.load(pickleFile)
            
    def lookup(self, macAddress):
        try:
            result = self.macDict[macAddress]
            cc  = result[0]
            oui = result[1]
            return cc+","+oui
        except:
            return "Unknown"
        
# Transport Lookup Class
class TRANSPORT:
    ''' PROTOCOL TO NAME LOOKUP'''
    def __init__(self):
        # Open the transport protocol Address OUI Dictionary
        with open('LookupFiles1/protocol.pickle', 'rb') as pickleFile:
            self.proDict = pickle.load(pickleFile)
    def lookup(self, protocol):
        try:
            result = self.proDict[protocol]
            return result
        except:
            return ["unknown", "unknown", "unknown"]

# PORTS Lookup Class
class PORTS:
    ''' PORT NUMBER TO PORT NAME LOOKUP'''
    def __init__(self):
        # Open the MAC Address OUI Dictionary
        with open('LookupFiles1/ports.pickle', 'rb') as pickleFile:
            self.portDict = pickle.load(pickleFile)
            
    def lookup(self, port, portType):
        try:
            result = self.portDict[(port, portType)]
            return result
        except:
            return "EPH"
ethOBJ = ETH()
traOBJ = TRANSPORT()
macOBJ = MAC()
portOBJ = PORTS()
# Create PrettyTables for IP Observations and Port Observations
ip_observations_table = PrettyTable()
ip_observations_table.field_names = ["SRC-IP", "DST-IP", "Protocol", "SRC-MAC", "DST-MAC", "SRC-MFG", "DST-MFG", "SRC-Port", "SRC-Port-Name", "DST-Port", "DST-Port-Name"]

port_observations_table = PrettyTable()
port_observations_table.field_names = ["IP", "Port", "Port-Description"]

# Open the PCAP file
targetPCAP = r"C:\Users\Administrator\Downloads\PCAP-SAMPLES1\ICS1.pcap"
try:
    pcapCapture = open(targetPCAP, 'rb')
    capture = savefile.load_savefile(pcapCapture, layers=0, verbose=False)
    print("PCAP Ready for Processing")
except: 
    
    # Unable to ingest pcap
    print("!! Unsupported PCAP File Format !! ")

# Process each packet
for pkt in capture.packets:
    # Extract packet information
    ethFrame = ethernet.Ethernet(pkt.raw())
    frameType = ethOBJ.lookup(ethFrame.type)

    # Check if the frame is IPv4
    if frameType == "IPv4":
        ipPacket = ip.IP(unhexlify(ethFrame.payload))
        srcIP = ".".join(map(str, ipPacket.src))
        dstIP = ".".join(map(str, ipPacket.dst))
        protocol = traOBJ.lookup(str(ipPacket.p))[0]
        srcMAC = "".join(map(chr, ethFrame.src))
        dstMAC = "".join(map(chr, ethFrame.dst))
        srcMACLookup = re.sub(':', '', srcMAC[0:8].upper())
        dstMACLookup = re.sub(':', '', dstMAC[0:8].upper())
        srcMFG = macOBJ.lookup(srcMACLookup)
        dstMFG = macOBJ.lookup(dstMACLookup)
        if protocol == "TCP":
            tcpPacket = tcp.TCP(unhexlify(ipPacket.payload))
            source_port = tcpPacket.src_port
            destination_port = tcpPacket.dst_port
            src_port_name = portOBJ.lookup(source_port, "TCP")
            dst_port_name = portOBJ.lookup(destination_port, "TCP")

            ip_observations_table.add_row([srcIP, dstIP, protocol, srcMAC, dstMAC, srcMFG, dstMFG, source_port, src_port_name, destination_port, dst_port_name])

        elif protocol == "UDP":
            udpPacket = udp.UDP(unhexlify(ipPacket.payload))
            source_port = udpPacket.src_port
            destination_port = udpPacket.dst_port
            src_port_name = portOBJ.lookup(source_port, "UDP")
            dst_port_name = portOBJ.lookup(destination_port, "UDP")

            ip_observations_table.add_row([srcIP, dstIP, protocol, srcMAC, dstMAC, srcMFG, dstMFG, source_port, src_port_name, destination_port, dst_port_name])

    # Process ARP packets
    elif frameType == "ARP":
        arp_payload = unhexlify(ethFrame.payload)
        dst_mac = ":".join("{:02x}".format(x) for x in arp_payload[:6])
        src_mac = ":".join("{:02x}".format(x) for x in arp_payload[6:12])
        arp_type = arp_payload[20:22]
        request_reply = arp_payload[22:24]
        pad = arp_payload[24:42]
        crc = arp_payload[42:44]

        ip_observations_table.add_row(["ARP", "ARP", "ARP", src_mac, dst_mac, "ARP", "ARP", "ARP", "ARP", "ARP", "ARP"])

        # Add ARP-related information to Port Observations
        port_observations_table.add_row([src_mac, "ARP", "ARP"])
        port_observations_table.add_row([dst_mac, "ARP", "ARP"])

# After processing all packets, print the PrettyTables:
print("IP Observations:")
print(ip_observations_table)

print("\nPort Observations:")
print(port_observations_table)

        
