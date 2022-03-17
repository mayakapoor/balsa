#-----------------------------------------------------------------------------#
# This code is written to aid with pre-processing PCAPs, specifically creating
# labeled training data for supervised techniques.
#-----------------------------------------------------------------------------#

import sys
import os
import asyncio
import argparse
import pyshark

#----------------------#
#   Helper functions
#----------------------#

# convert a file of strings to a list of strings
# \aram[in] path the path of the file
# \return the list of strings
def fileToList(path):
    lst = []
    try:
        f = open(path, "r", encoding="latin-1")
    except:
        return lst
    for line in f:
        lst.append(line.rstrip())
    f.close()
    return lst

# write a line to the file at path
def writeToFile(path, line):
    f = open(path, 'a+')
    f.write(line + '\n')

def hexToChar(hex_string):
    hex_split = hex_string.split(':')
    hex_as_chars = map(lambda hex: chr(int(hex, 16)), hex_split)
    human_readable = ''.join(hex_as_chars)
    return human_readable

# extracts the data layers from a given pcap and puts their string payloads into a dictionary of label : strings
# \param[in] sourcePcap the pcap to extract data from
# \return the data dictionary
def parsePacket(sourcePcap, protocol):
    pkt = pyshark.FileCapture(sourcePcap, protocol)
    print("Loading PCAP input. This may take some time...")
    pkt.load_packets()
    print("Input loaded.")
    if not os.path.exists(os.getcwd() + "/output"):
        os.makedirs(os.getcwd() + "/output")

    outpath = os.getcwd() + "/output/" + str(protocol) + ".txt"
    count = 0

    # STEP 2: parse the strings based on type.
    #         we write these to file for error checking/bookkeeping.
    for i in range(len(pkt)):
        if (hasattr(pkt[i], 'tcp')):
            if hasattr(pkt[i], protocol):
                writeToFile(outpath, str(pkt[i].tcp.payload))
                print(pkt[i].tcp.payload)
                count += 1
        elif (hasattr(pkt[i], 'udp')):
            if hasattr(pkt[i], protocol):
                writeToFile(outpath, str(pkt[i].udp.payload))
                print(pkt[i].udp.payload)
                count += 1
        else:
            print("Detected non TCP/UDP packet, dropping: " + str(packet.highest_layer))

    return count

# the following functions extract payloads from protocols and sort them by types.

def extractSIP(pkt, path):
    if hasattr(pkt.sip, 'Request-Line'):
        writeToFile(path[0], pkt.sip.get_field_value('Request-Line'))
    elif hasattr(pkt.sip, 'Status-Line'):
        writeToFile(path[1], pkt.sip.get_field_value('Status-Line'))

def extractHTTP(pkt):
    #if hasattr(pkt.http, 'request') and "" in pkt.http._all_fields:
    if hasattr(pkt.http, 'request'):
        print(dir(pkt.http))
        print(pkt.http.get_field_value("request.line"))
        return 'request', hexToChar(pkt.http.request)
    if hasattr(pkt.http, 'response'):
        return 'response', hexToChar(pkt.http.response)
    else:
        return None, None

def extractFTP(pkt, path):
    if pkt.ftp.request == '1' and "" in pkt.ftp._all_fields:
        writeToFile(path[0], pkt.ftp._all_fields[""])
    if pkt.ftp.response == '1' and "" in pkt.ftp._all_fields:
        writeToFile(path[1], pkt.ftp._all_fields[""])

def extractSMTP(pkt, path):
    if hasattr(pkt.smtp, 'req'):
        writeToFile(path[0], str(pkt.smtp.command_line))
    elif hasattr(pkt.smtp, 'rsp'):
        writeToFile(path[1], str(pkt.smtp.response))

def extractPOP(pkt, path):
    if hasattr(pkt.pop, 'request'):
        writeToFile(path[0], pkt.pop.get_field_value('request'))
    if hasattr(pkt.pop, 'response'):
        writeToFile(path[1], pkt.pop.get_field_value('response'))

def extractIRC(pkt, path):
    if hasattr(pkt.irc, 'request'):
        writeToFile(path[0], pkt.irc.get_field_value('request'))
    if hasattr(pkt.irc, 'response'):
        writeToFile(path[1], pkt.irc.get_field_value('response'))

def extractRTSP(pkt, path):
    if hasattr(pkt.rtsp, 'request'):
        writeToFile(path[0], pkt.rtsp.get_field_value('request'))
    if hasattr(pkt.rtsp, 'response'):
        writeToFile(path[1], pkt.rtsp.get_field_value('response'))

def extractXMPP(pkt, path):
    if "xmpp.iq" in pkt.xmpp._all_fields:
        writeToFile(path[0], pkt.xmpp.iq)
    if "xmpp.message" in pkt.xmpp._all_fields:
        writeToFile(path[1], pkt.xmpp.message)

def extractPayload(pkt, path):
    writeToFile(path, str(pkt))
