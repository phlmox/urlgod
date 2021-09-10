import sys,argparse
from core.service import *
from core.log import *

parser = argparse.ArgumentParser(description='urlgod - Fetchs URLs from various services.')

parser.add_argument('-d', '--domain', help="Domain")
parser.add_argument('-o', '--output', required=False, help="Output filename")
parser.add_argument('-v', '--virustotal', required=False, help="Virustotal API Key")
parser.add_argument('-q', '--quick', action='store_true', help="Quick scan")

if len(sys.argv)<2:
    print_banner()
    parser.print_help(sys.stderr)
    sys.exit(0)

args = parser.parse_args()

print_banner()
Log("Fetching urls for "+args.domain,"ok")
o=Service(args.quick,args.virustotal).Get(args.domain)
Log(f"Final urls: {len(o)}","ok")
if args.output!=None:
    with open(args.output, 'w') as f:
        for item in o:
            f.write("%s\n" % item)

[print(x) for x in o]