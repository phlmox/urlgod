from termcolor import colored
import os,sys

class Log:
    def __init__(self,txt,mode):
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
               
                    v1.0 | by @EnesSaltk7\n"""
    print(banner, file=sys.stderr)
