__author__ = "Rekt77"

from PIL import Image
import os
import math
import random
import socket
import struct
from scapy.all import *
import glob
import argparse
import binascii
import numpy


def randomIP():
  
  return socket.inet_ntoa(struct.pack('>I',random.randint(1,0xffffffff)))

def randomMAC():
  
  return ':'.join(map(lambda x: "%02x" % x, [random.randint(0x00,0xff) for i in range(6)]))

#argument parsing
parser = argparse.ArgumentParser()
parser.add_argument("-i","--input",help="directory path of input",required=True)
parser.add_argument("-o","--output",help="directory path of output",required=True)
args = parser.parse_args()

if not os.path.isdir(args.input) :
  print("[-]Invalid input path")

if not os.path.exists(args.output) :
  try :
    os.mkdir(args.output)
    print("[+] Creating directory at " +args.output)
    
  except :
    print("[-] Invalid output path.")
    
  

pcapFiles = glob.glob(args.input+"/*.pcap")

#IP, MAC Address randomizing 
for file in pcapFiles:
  pktList = rdpcap(file)
  print("[+] TRAGET : "+os.path.basename(file))
  print("[+] IP Randomizing....")
  print("[+] MAC Randomizing....")
  for pkt in pktList:
    pkt[Ether].src = randomMAC()
    pkt[Ether].dst = randomMAC()
    pkt[IP].src = randomIP()
    pkt[IP].dst = randomIP()
  wrpcap(args.output+os.sep+os.path.basename(file), pktList, append=False)

pcapFiles = glob.glob(args.output+"/*.pcap")

#pcap binary to grayscale image
for file in pcapFiles:
  Pixel_List = [0 for i in range(65536)]
  try:
    with open(file, 'rb') as f_src:
      print("[+] PCAP -> GrayScale image : " + file)
      print("[+] Img Size %d*%d"%(256,256))
      s = f_src.read()
      hexst = binascii.hexlify(s)
      for i in (0,len(hexst),4):
        Pixel_List[int(hexst[i:i+2],16)+int(hexst[i+2:i+4])]
      print(len(Pixel_List))
      grayScaleImage = Image.new("L",(size,size),"black")
      
      grayScaleImage.putdata(Pixel_List)
      grayScaleImage.save(args.output+os.sep+os.path.basename(file)+".png")
      
  except IOError :
      print >> sys.stderr, '[-] Can\'t find file.'
