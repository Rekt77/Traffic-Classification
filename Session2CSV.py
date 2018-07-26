from scapy.all import *
import re
import glob
import csv

fieldnames = ['PROTO', 'S_IP', 'D_IP','S_PORT', 'D_PORT']
patterns = {"IP":"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):","PORT":":([0-9]+)","PROTO":"[A-Z]+",}

for pcap in glob.glob('*.pcap'):
    info = rdpcap(pcap)
    output = pcap.replace('.pcap','.csv')
    with open(output, 'w', newline='') as f:
        writer = csv.DictWriter(f,fieldnames=fieldnames)
        writer.writeheader()
        for sess in info.sessions():
            counter=1
            if sess.split(" ")[0] not in["TCP","UDP"]:
                continue
            if len(sess.split(" ")[1].split(":"))>2:
                continue
        
            print(sess)
            writer.writerow({'PROTO':re.findall(patterns["PROTO"],sess)[0],
                         'S_IP':re.findall(patterns["IP"],sess)[0],
                         'D_IP':re.findall(patterns["IP"],sess)[1],
                         'S_PORT':re.findall(patterns["PORT"],sess)[0],
                         'D_PORT':re.findall(patterns["PORT"],sess)[1]})
