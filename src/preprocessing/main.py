from preprocess import *
import os
import argparse
from csv import writer

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process pcap file and integer data.")
    parser.add_argument("-pcap", nargs="+", help="The pcap file. Multiple pcaps can be added when separated by a space.")
    parser.add_argument("-protocol", help ="The application layer protocol (ex: HTTP)")
    args = parser.parse_args()

    columns=["src_ip", "dst_ip", "src_port", "dst_port", "t_proto", "dsfield", "ip_flags", "length", "d_proto", "payload"]

    output_prefix = os.getcwd() + "/output"
    if not os.path.exists(output_prefix):
        os.makedirs(output_prefix)
    filecount = 0
    ext = str(filecount) + ".csv"
    filename = (output_prefix + "/" + str(args.protocol))

    with open(filename + ext, "w", newline='') as my_csv:
        csv_writer = writer(my_csv)
        csv_writer.writerow(columns)

    total = 0
    oldtotal = 0
    for f in args.pcap:
        total += parsePacket(filename + ext, f, str(args.protocol))
        if (oldtotal + 100000 <= total):
            filecount += 1
            oldtotal = total
            ext = str(filecount) + ".csv"
            with open(filename + ext, "w", newline='') as my_csv:
                csv_writer = writer(my_csv)
                csv_writer.writerow(columns)

    print("Number of packets processed: %d" % total)
