#!/usr/bin/env python3
import sys,os,argparse
from termcolor import colored
import re,json,requests,time,threading
from urllib.parse import urlparse

class Service:
    def ccFetch(self,ind,last,domain,pages):
        for c in pages[ind:last]:
            try:
                r = requests.get(f"https://index.commoncrawl.org/{c}-index?url=*.{domain}/*&output=json")
                data = [json.loads(x) for x in r.text.strip().split('\n')]
                u=[x["url"] for x in data]
                Log(f"Found {str(len(u))} urls from index {c}, Service: 'CommonCrawl'","inf")
                self.CCUrls+= u
            except KeyboardInterrupt:
                exit()
            except:
                Log(f"Couldn't find any urls from {c}","err")
        self.wait+=1

    def getCommonCrawlURLs(self,domain):
        try:
            CCS=[(x["id"]) for x in json.loads(requests.get("http://index.commoncrawl.org/collinfo.json").content)]
            if self.quick:
                self.ccFetch(0,1,domain,CCS)
            else:
                self.wait=0
                tPer = len(CCS)//self.CCThreads
                tLeft = len(CCS)-(tPer*self.CCThreads)
                tIndex = 0
                for t in range(self.CCThreads):
                    last=tIndex+tPer
                    if t==self.CCThreads-1:
                        last+=tLeft

                    threading.Thread(target=self.ccFetch,args=(tIndex,last,domain,CCS)).start()
                    tIndex+=tPer
                while self.wait!=self.CCThreads:
                    pass
            Log(f"Found total {str(len(self.CCUrls))} urls from 'CommonCrawl'","inf")
            return self.CCUrls
        except KeyboardInterrupt:
            exit()
    def getVirusTotalURLs(self,domain,apikey):
        urls=[]
        while 1:
            try:
                Log(f"Trying to collect urls from 'VirusTotal'","ok")
                r = requests.get(f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={apikey}&domain={domain}")
                data = json.loads(r.text)
                for u in data["undetected_urls"]:
                    urls.append(u[0])
                for u in data["detected_urls"]:
                    urls.append(u["url"])
                Log(f"Found total {str(len(urls))} urls from 'VirusTotal'","inf")
                return urls
            except KeyboardInterrupt:
                exit()
            except json.decoder.JSONDecodeError:
                Log(f"Waiting for 60 seconds to revoke 'VirusTotal' API.","err")
                time.sleep(60)

    def getWaybackURLs(self,domain):
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&&collapse=urlkey"
            data=json.loads(requests.get(url).text)
            urls=[x[2] for x in data]
            Log(f"Found total {str(len(urls))} urls from 'WebArchive'","inf")
            return urls
        except KeyboardInterrupt:
            exit()
        except:
            Log(f"Error with 'WebArchive'","err")
            return []

    def otxFetch(self,ind,last,domain,pages):
        for p in range(ind,last):
            data=json.loads(requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page={str(p+1)}").text)
            u=[data["url_list"][i]["url"] for i in range(len(data["url_list"]))]
            self.OTXCollected+=1
            Log(f"Collected {str(self.OTXCollected)}/{str(pages)} from 'OTX'","inf")
            self.OTXUrls +=u
        self.wait+=1

    def getOTXURLs(self,domain):
        try:
            data=json.loads(requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1").text)
            full_size = data["full_size"]
            if full_size < 500:
                Log(f"Found total {str(full_size)} urls from 'OTX'","inf")
                return [data["url_list"][i]["url"] for i in range(full_size)]
            else:
                left=full_size%500
                pages=(full_size-left)//500 if left==0 else (full_size-left)//500+1
                self.wait=0
                tPer = pages//self.OTXThreads
                tLeft = pages-(tPer*self.OTXThreads)
                tIndex = 0
                Log(f"Found {str(pages)} pages for {domain} from 'OTX'","ok")
                for t in range(self.OTXThreads):
                    last=tIndex+tPer
                    if t==self.OTXThreads-1:
                        last+=tLeft

                    threading.Thread(target=self.otxFetch,args=(tIndex,last,domain,pages)).start()
                    tIndex+=tPer
                while self.wait!=self.OTXThreads:
                    pass
                Log(f"Found total {str(len(self.OTXUrls))} urls from 'OTX'","inf")
                return self.OTXUrls
        except KeyboardInterrupt:
            exit()
        except Exception as e:
            print(e)
            Log(f"Error with 'OTX'","err")
            return []

    def Get(self,domain):
        uri=[]
        Log(f"Collecting urls from 'WebArchive'","ok")
        o=self.getWaybackURLs(domain)
        uri+=o
        Log(f"Collecting urls from 'CommonCrawl'","ok")
        o=self.getCommonCrawlURLs(domain)
        uri+=o
        if self.virustotal != None:
            Log(f"Collecting urls from 'VirusTotal'","ok")
            o=self.getVirusTotalURLs(domain,self.virustotal)
            uri+=o
        Log(f"Collecting urls from 'OTX'","ok")
        o=self.getOTXURLs(domain)
        uri+=o
        return uri
    
    def __init__(self,quick,virustotal):
        self.quick = quick
        self.virustotal = virustotal
        self.OTXThreads = 5
        self.OTXUrls = []
        self.OTXCollected = 0
        self.CCThreads = 10
        self.CCUrls = []
        self.CCCollected = 0
        self.wait = 0

class Log:
    def __init__(self,txt,mode):
        if not args.silent:
            if mode=="ok":
                print(self.tx("[+] "+txt,"green"), file=sys.stderr)
            elif mode=="inf":
                print(self.tx("[0] "+txt,"yellow"), file=sys.stderr)
            elif mode=="err":
                print(self.tx("[-] "+txt,"red"), file=sys.stderr)
            else:
                print(txt)
        
    def tx(self,text,clr):
        if os.name!="nt":
            return colored(text,clr)
        return text
    
def exit():
    Log("Exiting...","err")
    sys.exit(0)
    
def print_banner():
    banner="""             _                 _ 
            | |               | |
  _   _ _ __| | __ _  ___   __| |
 | | | | '__| |/ _` |/ _ \ / _` |
 | |_| | |  | | (_| | (_) | (_| |
  \__,_|_|  |_|\__, |\___/ \__,_|
                __/ |            
               |___/             
               
                    v2.0 | by @EnesSaltk7\n"""
    print(banner, file=sys.stderr)


parser = argparse.ArgumentParser(description='urlgod - Fetches URLs from various services.')

parser.add_argument('-d', '--domain', help="Domain")
parser.add_argument('-o', '--output', required=False, help="Output filename")
parser.add_argument('-v', '--virustotal', required=False, help="Virustotal API Key")
parser.add_argument('-q', '--quick', action='store_true', help="Quick scan")
parser.add_argument('-s', '--silent', action='store_true', help="Silent mode")

if len(sys.argv)<2:
    print_banner()
    parser.print_help(sys.stderr)
    sys.exit(0)

args = parser.parse_args()

if not args.silent:
    print_banner()
Log("Fetching urls for "+args.domain,"ok")
o=Service(args.quick,args.virustotal).Get(args.domain)
Log(f"Final urls: {len(o)}","ok")
if args.output!=None:
    with open(args.output, 'w') as f:
        for item in o:
            f.write("%s\n" % item)

[print(x) for x in o]
Log("Good luck haxor!","ok")
