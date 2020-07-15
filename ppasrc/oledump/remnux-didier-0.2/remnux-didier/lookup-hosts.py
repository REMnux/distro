#!/usr/bin/env python

__description__ = 'Lookup hosts'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2013/02/21'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2013/01/31: start
  2013/02/17: Added File2Strings, expression and options
  2013/02/21: Added file option and FixPipe
  2013/02/22: Replaced option notresolved with nounresolved
  2013/02/25: Remove doubles returned by getaddrinfo; changed port getaddrinfo to None

Todo:
"""

import optparse
import socket
import re
import sys
import signal

DEFAULT_SEPARATOR = ','
NOTRESOLVED = '<NOTRESOLVED>'

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

def LogLine(line, logFileName):
    try:
        outfile = open(logFileName, 'a')
    except:
        return
    try:
        outfile.write(line + '\n')
    except:
        return
    finally:
        outfile.close()

def Output(row, options):
    if options.resultonly:
        line = options.separator.join(row[1:])
    else:
        line = options.separator.join(row)
    print(line)
    if options.output:
        LogLine(line, options.output)

def Lookup(host, options):
    try:
        ips = []
        for result in socket.getaddrinfo(host, None):
            if not result[4][0] in ips:
                ips.append(result[4][0])
        for ip in ips:
            if ip == '67.215.65.132': # handle opendns not found result
                if not options.nounresolved:
                    Output([host, NOTRESOLVED], options)
            else:
                Output([host, ip], options)
    except KeyboardInterrupt:
        print('Interrupted by user')
        sys.exit()
    except:
        if not options.nounresolved:
            Output([host, NOTRESOLVED], options)

def LookupExpression(expression, options):
    oMatch = re.match(r'(.*)\[(\d+)-(\d+)(:(\d+))?\](.*)', expression, re.IGNORECASE)
    if oMatch:
        start = int(oMatch.groups()[1])
        end = int(oMatch.groups()[2])
        if oMatch.groups()[4] != None:
            formatString = '%s%0' + oMatch.groups()[4] + 'd%s'
        else:
            formatString = '%s%d%s'
        if start < end:
            for iIter in range(start, end + 1):
                Lookup(formatString % (oMatch.groups()[0], iIter, oMatch.groups()[5]), options)
    else:
        Lookup(expression, options)

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

def ClearFile(filename):
    try:
        f = open(filename, 'w')
    except:
        return None
    finally:
        f.close()

def Lookups(arguments, options):
    FixPipe()
    if options.output:
        ClearFile(options.output)
    if options.headers:
        Output(['Host', 'IP'], options)
    if arguments == ['']:
        fIn = sys.stdin
        for line in [line.strip('\n') for line in fIn.readlines()]:
            LookupExpression(line, options)
        fIn.close()
    else:
        for argument in arguments:
            if options.file:
                expressions = File2Strings(argument)
            else:
                expressions = [argument]
            for expression in expressions:
                LookupExpression(expression, options)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [host|file] ...\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-n', '--nounresolved', action='store_true', default=False, help='Also produce output result when host not resolved')
    oParser.add_option('-o', '--output', help='Write output to file')
    oParser.add_option('-s', '--separator', default=DEFAULT_SEPARATOR, help='Separator character to use for output (default separator character is %s)' % DEFAULT_SEPARATOR)
    oParser.add_option('-H', '--headers', action='store_true', default=False, help='Add header to output')
    oParser.add_option('-f', '--file', action='store_true', default=False, help='Interpret the argument as a file')
    oParser.add_option('-r', '--resultonly', action='store_true', default=False, help='Only output the result')
    (options, args) = oParser.parse_args()

    if len(args) == 0 and options.file:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 0:
        Lookups([''], options)
    else:
        Lookups(args, options)

if __name__ == '__main__':
    Main()
