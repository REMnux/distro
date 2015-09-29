#!/usr/bin/python
#
# brxor is a tool for bruteforcing encoded strings
# within a boundary defined by a regular expression. It
# will bruteforce the key value range of 0x1 through 0x255
# It will use PyEnchant to check strings against known english language words
#
# Version 0.01b - still need to test passing regular expressions
# 
# brutexor.py Created by Alexander Hanel (Alexander.Hanel@gmail.com)
# Modified by Trenton Tait (tretait@gmail.com)
#
# Usage: brxor.py [options] <file>
#
# Options:
#   -h, --help            show this help message and exit
#   -k KEY, --key=KEY     Static XOR key to use
#   -f, --full            XOR full file
#   -d DICT, --dict=DICT  User supplied dictionary, one word per line (Default: 'en_us')
#   -l LEN, --length=LEN  Minimum word length to use (Default: 4)
# 
# TODO: case insensitive matches  

import string
import re 
import sys
import os
from optparse import OptionParser 
try:
    import enchant
except:
    print 'PyEnchant not found. Please install using \'pip install enchant\''
    sys.exit(1)

def valid_ascii(char):
    if char in string.printable[:-3]:
        return True
    else:
        return None 

def xor(data, key):
    decode = ''
    if isinstance(key, basestring):
        key = int(key,16)
        
    for d in data:
        decode = decode + chr(ord(d) ^ key)
    return decode

# http://stackoverflow.com/questions/14678132/python-hexadecimal
def twoDigitHex(num):
    return '0x%02x' % num

def parse_options():
    parser = OptionParser()
    usage = 'usage: brxor.py [options] <file>'
    parser  =  OptionParser(usage=usage)
    parser.add_option('-k', '--key', action='store', dest='key', type='string', help='Static XOR key to use')
    parser.add_option('-f', '--full', action='store_true', dest='full', help='XOR full file')
    parser.add_option('-d', '--dict', action='store', dest='user_dict', help="User supplied dictionary, one word per line (Default: 'en_us')")
    parser.add_option('-l', '--length', action='store', dest='length', default=4, help="Minimum word length to use (Default: 4)")
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='Increase verbosity of output.')
    (options, args) = parser.parse_args()

    global word_dict
    
    # Test for Args 
    if len(sys.argv) < 2:
        parser.print_help()
        return
    # Test that the full option contains a XOR Key
    if options.full != None and options.key == None:
        print '[ERROR] --FULL OPTION MUST INCLUDE XOR KEY'
        return
    # XOR the full file with key 
    if options.full != None and options.key != None:
        sys.stdout.write(xor(f.read(), options.key))
        return
    if options.user_dict:
        # check for file
        if os.path.isfile(options.user_dict) and os.access(options.user_dict, os.R_OK):
            word_dict = enchant.request_pwl_dict(options.user_dict)
        else:
            print '[ERROR] FILE CAN NOT BE OPENED OR READ!\n'
            print usage
            sys.exit(1)
    else:
        word_dict = enchant.Dict('en_US')

    # Parse file for regular expressions 
    return options
    
def main(argv):
    options = parse_options()
    regex = re.compile(r'\x00(?!\x00).+?\x00') 
    buff = ''

    try:
        f = open(sys.argv[len(sys.argv)-1],'rb')
    except Exception:
        print '[ERROR] FILE CAN NOT BE OPENED OR READ!'
        return
    # for each regex pattern found
    for match in regex.finditer(f.read()):
        if len(match.group()) < 8:
            continue 
        # for XOR key in range of 0x0 to 0xff
        for key in range(1,0x100):
            # for each byte in match of regex pattern 
            for byte in match.group():
                if byte == '\x00':
                    buff = buff + '\x00'
                    continue 
                else:
                    tmp = xor(byte,key)
                    if valid_ascii(tmp) == None:
                        buff = ''
                        break
                    else:
                        buff = buff + tmp
            if buff != '':
                words = re.findall(r'\b[a-zA-Z]{%s,}\b' % options.length,buff)
                # TODO: case insensitive matches
                enchants = [x for x in words if word_dict.check(x.lower()) == True]
                if len(enchants) > 0:
                        # if verbose, show human-readable match along with decode str
                        if options.verbose:
                            output = '[%s (%s)] %s %s\n' % (hex(match.start()),twoDigitHex(key),enchants,buff)
                        else:
                            output = '[%s (%s)] %s\n' % (hex(match.start()),twoDigitHex(key),buff)
                        # avoid line breaks in the middle of a string
                        output = output.strip().replace('\n', '\\n')
                        sys.stdout.write(output + '\n')
                buff = ''
    f.close()
    return 

if __name__== '__main__':
    main(sys.argv[1:])
