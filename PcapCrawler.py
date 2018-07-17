#!/usr/bin/python36
# __author__ = "Rekt77"
#__git__     = "https://github.com/Rekt77"

import requests
import hashlib
import re
import zipfile
import os,sys
import glob
import csv
import time
import tqdm
import argparse

vtkey = "6fee49fd689a59914422dd53180914819ef5c026ab19a5d5467d4fd47b953277"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
csvJson = {"malName":[],"fileHash":[],"totalRatio":[]}
success_flag = False

#argparsing
argument = argparse.ArgumentParser()
argument.add_argument("--page",required=True,help="page_number parmeter of Malware DB URL")
args= argument.parse_args()

#Make url requests & get response to parse
def urlParse(url):

    try :
        res = requests.get(url)
        http = res.text
        
    except :
        print( "[-] connection failed somehow")
        sys.exit()
        
    return http,type(http)

#Download compressed malware file
def malwareSave(url,filename):
    res = requests.get(url,stream=True)
    file_size = int(res.headers['Content-Length'])
    chunk = 1
    chunk_size=1024
    num_bars = int(file_size / chunk_size)
    print( "[+] Downloading file : " + filename.split(os.sep)[-1])
    print( "[+] Size : " + res.headers['Content-Length'])
    
    with open(filename,"wb") as fp:
        for chunk in tqdm.tqdm(res.iter_content(chunk_size=chunk_size),
                               total= num_bars,
                               unit = 'KB',
                               desc = filename,
                               leave = True): # progressbar stays
            fp.write(chunk)

#Interlock virustotal with apikey
def vtQuery(apikey,md5Hash):
    
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey':apikey,'resource':md5Hash}
    response = requests.get(url, params=params).json()
    num_of_detected = str(response['positives'])+"/"+str(response['total'])
    malName = response['scans']['Kaspersky']['result']
    return num_of_detected,malName

#Get all file list in BASE_DIR
def unZip(filepath,password,outputpath):
    
    #malwareDB password == byte(infected)
    with zipfile.ZipFile(filepath) as zf:
        zf.extractall(outputpath,pwd=password)
    

#main routine
if __name__ == "__main__" :
    
    #urlRegex.findall()
    #Value of page parameter can be modified; use it elasticly
    #try :
    html, typeHtml = urlParse("http://malwaredb.malekal.com/index.php?page="+str(args.page))

    result=set(re.findall(">([a-z0-9]{32})<",html))
    
    #mkdir if path is exists
    if not os.path.exists(os.path.abspath("zipped")):
        os.mkdir(os.path.abspath("zipped"))
        print("[+] Make dir : "+os.path.abspath("zipped"))
                     
    for realUrl in result:
        #urlretrieve; Download Zipfile, which listed in malwareDB
        try :
            malwareSave("http://malwaredb.malekal.com/files.php?file="+realUrl,"./zipped"+os.sep+realUrl+".zip")
            print("[+] Download success : "+realUrl+".zip")

            #virus total API
            #get response by virus total report on json
            success_flag=False
            while not success_flag:
                
                try:
                    num_of_detected , malName = vtQuery(vtkey,realUrl)
                    print("[+] Malware name : "+malName)
                    print("[+] Detection ratio : "+num_of_detected)
                    print("\n")
                    success_flag=True
                #routine of when virustotal API response doesn't return
                #go to sleep for 10 seconds & retry request
                except:
                    print("[-] Virustotal API doesn't work right with : "+realUrl )
                    print("[-] API request fell on sleep for 10 seconds...")
                    time.sleep(10)
                    print("[+] Retry API request...")
                    print("\n")
                    success_flag=False
            
            #data to Json
            for keys in csvJson.keys() :
                if keys == 'malName':
                    csvJson[keys].append(malName)
                elif keys == 'fileHash' :
                    csvJson[keys].append(realUrl)
                elif keys == 'totalRatio' :
                    csvJson[keys].append(num_of_detected)
                    
        except :
            print("[-] Download failed : "+realUrl+".zip")

            
    #mkdir if path exists
    if not os.path.exists(os.path.abspath("unzipped")):
        os.mkdir(os.path.abspath("unzipped"))
        print("[+]Make dir : "+os.path.abspath("unzipped"))
        
    for malzip in glob.glob(os.path.abspath("zipped")+os.sep+"*.zip"):

        #try unzip with password
        try:
            unZip(malzip,b"infected","./unzipped")
            print("[+] Unzip success : "+malzip.split(os.sep)[-1])
            
        except :
            print("[-] Unzip failed : "+malzip.split(os.sep)[-1])
        
    #CSV Writer
    #if CSV exists
    if os.path.exists(os.path.join(BASE_DIR,'Malfile.csv')):
        with open(os.path.join(BASE_DIR,'Malfile.csv'),'a',newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')

            for i in range(0,len(csvJson['malName'])) :
                writer.writerow([csvJson['malName'][i],csvJson['fileHash'][i],csvJson['totalRatio'][i]])
            
    #if CSV doesn't exist          
    else :
        with open(os.path.join(BASE_DIR,'Malfile.csv'),'w',newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            writer.writerow(['malName']+['fileHash'] + ['totalRatio'])
            for i in range(0,len(csvJson['malName'])) :
                writer.writerow([csvJson['malName'][i],csvJson['fileHash'][i],csvJson['totalRatio'][i]])
       



        

