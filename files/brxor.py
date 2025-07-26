#!/opt/brxor/bin/python3
#
# brxor is a tool for bruteforcing encoded strings
# within a boundary defined by a regular expression. It
# will bruteforce the key value range of 0x1 through 0x255
# It will use PyEnchant to check strings against known english language words
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

import string
import re
import sys
import os
from argparse import ArgumentParser
try:
    import enchant
except:
    print('PyEnchant not found. Please install using \'pip install enchant\'')
    sys.exit(1)

def valid_ascii(char):
    if char in string.printable[:-3]:
        return True
    else:
        return None

def xor(data, key):
    decode = ''
    if isinstance(key, str):  # Fixed basestring to str for Python 3
        key = int(key, 16)

    for d in data:
        if isinstance(d, int):  # Handle bytes in Python 3
            decode = decode + chr(d ^ key)
        else:
            decode = decode + chr(ord(d) ^ key)
    return decode

def twoDigitHex(num):
    return '0x%02x' % num

def main():
    usage = 'usage: brxor.py [options] <file>'
    parser = ArgumentParser(usage=usage, description='Python 3 XOR brute-forcer ')
    parser.add_argument('file', action='store', help='file')
    parser.add_argument('-k', '--key', action='store', dest='key',help='Static XOR key to use')
    parser.add_argument('-f', '--full', action='store_true', dest='full', help='XOR full file')
    parser.add_argument('-d', '--dict', action='store', dest='user_dict', help="User supplied dictionary, one word per line (Default: 'en_us')")
    parser.add_argument('-l', '--length', action='store', dest='length', default=4, help="Minimum word length to use (Default: 4)")
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='Increase verbosity of output.')
    args = parser.parse_args()

    global word_dict

    # Test for Args
    if len(sys.argv) < 2:
        parser.print_help()
        return
        
    # XOR the full file with key if both full and key are provided
    if args.full and args.key:
        with open(args.file, 'rb') as f:
            sys.stdout.write(xor(f.read(), args.key))
        return
        
    if args.user_dict:
        # check for file
        if os.path.isfile(args.user_dict) and os.access(args.user_dict, os.R_OK):
            word_dict = enchant.request_pwl_dict(args.user_dict)
        else:
            print('[ERROR] FILE CAN NOT BE OPENED OR READ!\n')
            print(usage)
            sys.exit(1)
    else:
        word_dict = enchant.Dict('en_US')

    # Parse file for regular expressions
    # Removed "return options" line that was causing early exit

    regex = re.compile(rb'\x00(?!\x00).+?\x00')  # Changed to raw bytes pattern
    
    try:
        with open(args.file, 'rb') as f:
            file_content = f.read()
    except Exception:
        print('[ERROR] FILE CAN NOT BE OPENED OR READ!')
        return
        
    # for each regex pattern found
    for match in regex.finditer(file_content):
        if len(match.group()) < 8:
            continue
        # for XOR key in range of 0x0 to 0xff
        for key in range(1, 0x100):
            buff = ''
            # for each byte in match of regex pattern
            for byte in match.group():
                if byte == 0:  # Changed from '\x00' to 0 for Python 3 bytes
                    buff = buff + '\x00'
                    continue
                else:
                    tmp = chr(byte ^ key)  # Simplified XOR for Python 3
                    if valid_ascii(tmp) == None:
                        buff = ''
                        break
                    else:
                        buff = buff + tmp
                        
            if buff != '':
                words = re.findall(r'\b[a-zA-Z]{%s,}\b' % args.length, buff)
                # TODO: case insensitive matches
                enchants = [x for x in words if word_dict.check(x.lower()) == True]
                if len(enchants) > 0:
                    # if verbose, show human-readable match along with decode str
                    if args.verbose:
                        output = '[%s (%s)] %s %s\n' % (hex(match.start()), twoDigitHex(key), enchants, buff)
                    else:
                        output = '[%s (%s)] %s\n' % (hex(match.start()), twoDigitHex(key), buff)
                    # avoid line breaks in the middle of a string
                    output = output.strip().replace('\n', '\\n')
                    sys.stdout.write(output + '\n')

if __name__== '__main__':
    main()
