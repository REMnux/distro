#!/usr/bin/env python2

"""
This is a version of fakedns based on the original scripted by Francisco Santos, which was published at
https://code.activestate.com/recipes/491264-mini-fake-dns-server

The new version can accept a configuration file that controls whether to ignore a specific host or domain, respond 
with an IP Address specifically for that host or domain, or respond with the default IP Address that can be supplied 
with the '-a' option.

Usage: fakedns.py -a <ip address> -f <file name>

        Use the -h option for help

Modified by Kevin Murray
"""

import socket
import sys
import getopt
import subprocess

class DNSQuery:
    def __init__(self, data):
        self.data=data
        self.domainFQDN=''
        self.domainPortion = ''

        tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
        if tipo == 0:                     # Standard query
            ini=12
            lon=ord(data[ini])
            first = True
            while lon != 0:
                   
                # skip the host portion of the domain name request
                if not first:
                    self.domainPortion += data[ini+1:ini+lon+1]+'.'
                      
                self.domainFQDN+=data[ini+1:ini+lon+1]+'.'
                ini+=lon+1
                lon=ord(data[ini])
                first = False

    def response(self, ip):
        packet=''
        if self.domainFQDN:
            packet+=self.data[:2] + "\x81\x80"
            packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
            packet+=self.data[12:]                                         # Original Domain Name Question
            packet+='\xc0\x0c'                                             # Pointer to domain name
            packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
            packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
        return packet

# Let user know how to use this program
def usage():
    print "Usage:" + sys.argv[0] + " [-a <IP Address>] [-I <IP Addresss>] [-f <Configuration File>]"
    print ""
    print "      Configuration file consists of lines containing either a Fully Qualified Domain Name"
    print "      or the Domain Name with the hostname removed. When the hostname is removed any hostname"
    print "      in that Domain will match. These Domains must begin with a '.'"
    print ""
    print "      If the line contains a second entry it must be an IP address to resolve the name to. If no IP"
    print "      Address is entered, that indicates that the name is to be ignored. Host actions take precedence."
    print ""
    print "Configuration file example lines:"
    print ""
    print ".microsoft.com"
    print "host.example.com 1.2.3.4"
    print ".example.com"
    print "host.company.com"
    print ".company.com 2.3.4.5"
    print ""
    print "This configuration file will ignore all requests made for microsoft.com hostnames. It will cause"
    print "host.example.com to resolve to 1.2.3.4 and ignore requests for any other host in the domain example.com."
    print "A DNS request for host.company.com will be ignored but all other requests for hosts in the domain"
    print "company.com will resolve to 2.3.4.5"
    print ""
    print "All other requests will resolve to either the default ip address " + ip + "or the address set with"
    print "the -a option."
    print ""
    print "If you have multiple NICs, you can specify on which ip address to bind with the -I option."
    print ""
    sys.exit(1)
    
if __name__ == '__main__':
    # Use the first local IP by default. Can be overridden with the -a option
    first_ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True)
    ip = first_ip
    ignoredDomains = []  # List of domains/sundomains to be ignored
    ignoredFQDNs = []    # List of fully qualified domain names to be ignored
    resolvedDomains = {} # Dictionary to map domains/subdomains to specific ip addresses
    resolvedFQDNs = {}   # Dictionary to map fully qualified domain names to specific ip addresses
    try:
        opts, args = getopt.getopt(sys.argv[1:],"a:I:f:")
    except getopt.GetoptError as err:
        usage()
 
    for option, option_value in opts:
        if option == "-a":
            ip = option_value
        elif option == '-I':
            first_ip = option_value
        elif option == "-f":
            for line in open(option_value, 'r'):
                tokens = line.split()
                if len(tokens) >= 3:
                    usage()
                elif len(tokens) == 2:
                    if tokens[0][0] == '.':
                        resolvedDomains[tokens[0][1:]] = tokens[1]
                    else:
                        resolvedFQDNs[tokens[0]] = tokens[1]
                else:
                    if tokens[0][0] == '.':
                        ignoredDomains.append(tokens[0][1:])
                    else:
                        ignoredFQDNs.append(tokens[0])
    print ""
    print "fakedns:: dom.query. 60 IN A %s" % ip
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # The original script attempted to bind to the default interface,
    # but this caused problems on Ubuntu 18.04, because there's already
    # a UDP port 53 listener, so we'll bind to the first IP instead.
    udps.bind((first_ip,53))

    try:
        while 1:
            data, addr = udps.recvfrom(1024)
            p=DNSQuery(data)
            domainFQDN = p.domainFQDN[:-1]
            domainPortion = p.domainPortion[:-1]
            """
            # debug code
            print "domain " + domainPortion
            print "host   " + domainFQDN
            print ""
            print "hosts to ignore"
            print ignoredFQDNs
            print ""
            print "hosts to respond specifically to"
            print resolvedFQDNs
            print ""
            print "domains to ignore"
            print ignoredDomains
            print ""
            print "domains to respond specifically to"
            print resolvedDomains
            print ""
            """
            if domainFQDN in ignoredFQDNs:
                print "Ignoring request for " + domainFQDN
            elif domainFQDN in resolvedFQDNs:
                temp_ip = resolvedFQDNs[domainFQDN]
                udps.sendto(p.response(temp_ip), addr)
                print 'Response: %s -> %s' % (domainFQDN, temp_ip)
            elif domainPortion in ignoredDomains:
                print "Ignoring request for " + domainFQDN
            elif domainPortion in resolvedDomains:
                temp_ip = resolvedDomains[domainPortion]
                udps.sendto(p.response(temp_ip), addr)
                print "Response: %s -> %s" % (domainFQDN, temp_ip)
            else:
                udps.sendto(p.response(ip), addr)
                print "Response: %s -> %s" % (domainFQDN, ip)
    except KeyboardInterrupt:
        print 'Done...'
        udps.close()
