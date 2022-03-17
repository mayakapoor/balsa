from csv import writer
from payload import *
import os
import pyshark
import nest_asyncio
nest_asyncio.apply()

def hexToChar(hex_string):
    hex_split = hex_string.split(':')
    hex_as_chars = map(lambda hex: chr(int(hex, 16)), hex_split)
    human_readable = ''.join(hex_as_chars)
    return human_readable

def parsePacket(output_path, input_path, label):
    try:
        packets = pyshark.FileCapture(input_path, use_json=True)
        print("Loading PCAP input file.")
        count = 0

        with open(output_path, "a", newline='') as my_csv:
            csv_writer = writer(my_csv)

            for packet in packets:
                count += 1
                sip = None
                dip = None
                prot = None
                d_proto = None
                dsfield = None
                ip_flags = None
                payload = None

                if hasattr(packet, 'ip'):
                    sip = packet.ip.src
                    dip = packet.ip.dst
                    dsfield = packet.ip.dsfield
                    ip_flags = packet.ip.flags

                if hasattr(packet, 'ipv6'):
                    sip = packet.ipv6.src
                    dip = packet.ipv6.dst

                if hasattr(packet, 'tcp'):
                    prot = 'tcp'
                    if hasattr(packet.tcp, "payload"):
                        payload = hexToChar(packet.tcp.payload)
                    #payload = packet.tcp.payload

                elif hasattr(packet, 'udp'):
                    prot = 'udp'
                    if hasattr(packet.udp, "payload"):
                        payload = hexToChar(packet.udp.payload)
                    #payload = packet.udp.payload

                else:
                    print("discarding non-TCP/UDP packet, detected: " + str(packet.highest_layer))
                    continue

                sport = packet[packet.transport_layer].srcport
                dport = packet[packet.transport_layer].dstport

                length = packet.length

                #if sip is None or dip is None or sport is None or dport is None or prot is None:
                #    pass
                properties = [sip, dip, sport, dport, prot, dsfield, ip_flags, length, label, payload]
                csv_writer.writerow(properties)

    except (UnicodeDecodeError):
        print("Could not load PCAP due to parsing error, skipping.")
        return count

    return count
