#!/usr/bin/python
#
# Name: Passive.py
# By:   Frankie Li
# Created:  Dec 25, 2014
# Modified: May 26, 2015
# Function: a caller script to query pdns.py class of Maltelligence Tool from bash shell
# See the file 'LICENSE' for copying permission.
#

import sys
import os
import ConfigParser
from optparse import OptionParser
from pdns import pdns

print """
    __________________    _______    _________
    \______   \______ \   \      \  /   _____/
    |     ___/|    |   \  /   |   \ \_____  \\
    |    |    |    `    \/    |    \/        \\
    |____|    /_______  /\____|__  /_______  /
                      \/         \/        \/
    Passive DNS tool (Virustotal + Mnemonic version)
    
    """


def main():
    #   parse command line
    
    
    parser = OptionParser(usage="usage: %prog [options], version=%prog 1.0")
    
    parser.add_option("-d", "--download", action="store_true", dest="download", default=False, help="Download samples from VirusTotal, e.g. -d [hash] [tag]")

    parser.add_option("-m", "--mnemonic", action="store_true", dest="mnemonic", default=False, help="Make queries  from mnemonic Pdns, e.g. -m [dns|ip]")
    parser.add_option("-q", "--query", dest="query", help="Make queries from VirusTotal, e.g. -q [dns|ip]", metavar="dns")


    (options, args) = parser.parse_args()

    if options.query:
        print "[+] Now make VirusTotal queries"
        if len(args) > 1 and len(args) == 0:
            print "[*] You need to provide ONLY [dns|ip]"
        else:
            p = pdns()
            data = options.query
            p.findPassive(data)


    if options.mnemonic:
        print "[+] Now make mnemonic Pdns queries"
        if len(args) > 1 and len(args) == 0:
            print "[*] You need to provide ONLY [dns|ip]"
        else:
            p = pdns()
            data = args[0]
            p.get_mnPdns(data)


    if options.download:
        print "[+] Download samples from VirusTotal"
        if len(args) != 2:
            print "[*] You need to provide 2 variables [hash] [tag]"
        else:
            hash = args[0]
            tag = args[1]
            p = pdns()
            p.get_download(hash, tag)


if __name__ == '__main__':
    main()


