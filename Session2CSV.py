import csv
from scapy.all import *
import re

fieldnames = ['PROTO', 'S_IP', 'D_IP','S_PORT', 'D_PORT']
patterns = {"IP":"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):","PORT":":([0-9]+)","PROTO":"[A-Z]+",}

path = ""

a = rdpcap(path)
with open('output.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f,fieldnames=fieldnames)
    writer.writeheader()
    for sess in a.sessions():
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
