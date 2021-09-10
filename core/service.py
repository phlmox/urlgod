import re,sys,json,requests,time
from urllib.parse import urlparse
from core.log import *

class Service:
    def getCommonCrawlURLs(self,domain):
        try:
            CCS=[(x["id"]) for x in json.loads(requests.get("http://index.commoncrawl.org/collinfo.json").content)]
            if self.quick:
                CCS=[CCS[0]]
            urls=[]
            for c in CCS:
                try:
                    r = requests.get(f"https://index.commoncrawl.org/{c}-index?url=*.{domain}/*&output=json")
                    data = [json.loads(x) for x in r.text.strip().split('\n')]
                    u=[x["url"] for x in data]
                    Log(f"Found {str(len(u))} urls from index {c}, Service: 'CommonCrawl'","inf")
                    urls+= u
                except KeyboardInterrupt:
                    exit()
                except:
                    Log(f"Couldn't find any urls from {c}","err")
            Log(f"Found total {str(len(urls))} urls from 'CommonCrawl'","inf")
            return urls
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

    def getOTXURLs(self,domain):
        try:
            data=json.loads(requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=50&page=1").text)
            full_size = data["full_size"]
            if full_size < 50:
                Log(f"Found total {str(full_size)} urls from 'OTX'","inf")
                return [data["url_list"][i]["url"] for i in range(full_size)]
            else:
                left=full_size%50
                pages=(full_size-left)//50 if left==0 else (full_size-left)//50+1
                urls=[]
                Log(f"Found {str(pages)} pages for {domain} from 'OTX'","ok")
                for p in range((full_size-left)//50):
                    data=json.loads(requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=50&page={str(p+1)}").text)
                    u=[data["url_list"][i]["url"] for i in range(50)]
                    Log(f"Page {str(p+1)}: Found {str(len(u))} urls from 'OTX'","inf")
                    urls+=u
                data=json.loads(requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=50&page={str((full_size-left)//50+1)}").text)
                u=[data["url_list"][i]["url"] for i in range(left)]
                Log(f"Page {str((full_size-left)//50+1)}: Found {str(len(u))} urls from 'OTX'","inf")
                urls+=u
                Log(f"Found total {str(len(urls))} urls from 'OTX'","inf")
                return urls
        except KeyboardInterrupt:
            exit()
        except:
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