#!/usr/bin/env python3
import sys,os,argparse
try:
    from termcolor import colored
except:
    pass
import re,json,requests,time,threading
from urllib.parse import urlparse

class Service:

    def getCommonCrawlURLs(self,domain):
        try:
            CCS=[(x["id"]) for x in json.loads(requests.get("http://index.commoncrawl.org/collinfo.json").content)][:5]
            for page in CCS:
                Log(f"Fetching urls from {page}","inf")
                r = requests.get(f"https://index.commoncrawl.org/{page}-index?url=*.{domain}/*&output=json")
                data = [json.loads(x) for x in r.text.strip().split('\n')]
                [print(x["url"],flush=True) for x in data]
        except KeyboardInterrupt:
            exit()
        except Exception as e:
            print(err,e,file=sys.stderr)
            pass

    def getVirusTotalURLs(self,domain,apikey):
        while 1:
            try:
                Log(f"Trying to collect urls from 'VirusTotal'","ok")
                r = requests.get(f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={apikey}&domain={domain}")
                data = json.loads(r.text)
                for u in data["undetected_urls"]:
                    print(u[0])
                for u in data["detected_urls"]:
                    print(u["url"],flush=True)
                return
            except KeyboardInterrupt:
                exit()
            except json.decoder.JSONDecodeError:
                Log(f"Waiting for 60 seconds to revoke 'VirusTotal' API.","err")
                time.sleep(60)

    def getWaybackURLs(self,domain):
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&&collapse=urlkey"
            data=json.loads(requests.get(url).text)[1:]
            [print(x[2],flush=True) for x in data]
        except KeyboardInterrupt:
            exit()
        except:
            Log(f"Error with 'WebArchive'","err")

    def otxFetch(self,ind,last,domain,pages):
        for p in range(ind,last):
            while 1:
                try:
                    data=json.loads(requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page={str(p+1)}").text)
                    [print(data["url_list"][i]["url"],flush=True) for i in range(len(data["url_list"]))]
                    self.OTXCollected+=1
                    Log(f"Collected {str(self.OTXCollected)}/{str(pages)} from 'OTX'","inf")
                    break
                except KeyboardInterrupt:
                    exit()
                except:
                    time.sleep(20)
        self.wait+=1

    def getOTXURLs(self,domain):
        try:
            data=json.loads(requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1").text)
            full_size = data["full_size"]
            if full_size < 500:
                [print(x,flush=True) for x in [data["url_list"][i]["url"] for i in range(full_size)]]
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
        except KeyboardInterrupt:
            exit()
        except Exception as e:
            Log(f"Error with 'OTX'"+e,"err")

    def Get(self,domain):
        Log(f"Collecting urls from 'WebArchive'","ok")
        self.getWaybackURLs(domain)
        Log(f"Collecting urls from 'CommonCrawl'","ok")
        self.getCommonCrawlURLs(domain)
        if self.virustotal != None:
            Log(f"Collecting urls from 'VirusTotal'","ok")
            self.getVirusTotalURLs(domain,self.virustotal)
        Log(f"Collecting urls from 'OTX'","ok")
        self.getOTXURLs(domain)
        return 1
    
    def __init__(self,threads,virustotal):
        self.virustotal = virustotal
        self.OTXThreads = threads
        self.OTXCollected = 0
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
               
                    v2.1 | by @EnesSaltk7\n"""
    print(banner, file=sys.stderr)


parser = argparse.ArgumentParser(description='urlgod - Fetches URLs from various services.')

parser.add_argument('-d', '--domain', help="Domain")
parser.add_argument('-v', '--virustotal', required=False, help="Virustotal API Key")
parser.add_argument('-s', '--silent', action='store_true', help="Silent mode")
parser.add_argument('-t', '--threads', default=5,help="Default 5")

if len(sys.argv)<2:
    print_banner()
    parser.print_help(sys.stderr)
    sys.exit(0)

args = parser.parse_args()

if not args.silent:
    print_banner()
Log("Fetching urls for "+args.domain,"ok")
o=Service(int(args.threads),args.virustotal).Get(args.domain)
Log("Good luck haxor!","ok")
