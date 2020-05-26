#!/usr/bin/python

#
# fakedns.py
# 
# Original script by Francisco Santos from
# https://code.activestate.com/recipes/491264-mini-fake-dns-server/
#
# Modified by Joe Ryan to support the optional ~/.fakedns configuration file. With this version,
# if you run fakedns.py without the configuration file, the tool will generate a sample file and
# save it as .fakedns.sample. Look at that file to replicate the syntax, which will allow you
# to define responses for specific domains that overwride the default response.
#

import socket
import sys
import json
import os.path
from os.path import expanduser

class DNSQuery:
  def __init__(self, data):
    self.data=data
    self.dominio=''

    tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
    if tipo == 0:                     # Standard query
      ini=12
      lon=ord(data[ini])
      while lon != 0:
        self.dominio+=data[ini+1:ini+lon+1]+'.'
        ini+=lon+1
        lon=ord(data[ini])

  def respuesta(self, ip):
    packet=''
    if self.dominio:
      packet+=self.data[:2] + "\x81\x80"
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
    return packet

def getanswer(conf, dominio, default_ip):
  dom_toks = dominio.split('.')
  dom_toks_len = len(dom_toks) - 1
  answer = '-'
  match = False

  if not 'tlds' in conf:
    conf['tlds'] = {}

  if len(conf['tlds'].keys()) > 0:
    for i in range(0, dom_toks_len):
      tld = '.'.join(dom_toks[i:dom_toks_len])
      if tld in conf['tlds']:
        match = True
        answer = conf['tlds'][tld]
        if not tld == dominio:
          conf['tlds'][dominio] = conf['tlds'][tld]
        break
  
  if answer == '-' or answer == '[default_ip]':
    answer = default_ip
    #conf['tlds'][dominio] = default_ip
  
  return conf, answer, match

if __name__ == '__main__':
  default_ip = '192.168.1.1'
  curr_file_dir = expanduser('~') #os.path.dirname(os.path.realpath(__file__)) 
  conf_file = os.path.join(curr_file_dir, '.fakedns')

  conf = {}
  #print 'Reading config from: %s' % conf_file
  if not os.path.isfile(conf_file):
    #print '%s does not exist' % conf_file
    conf_sample_file = conf_file + '.sample'
    conf_sample = { 'default_ip': default_ip, 'tlds': {'com': '1.1.1.1', 'example.com': '2.2.2.2', 'upload.example.com': '3.3.3.3'} }
    
    with open(conf_sample_file, 'w') as cf:
      cf.write(json.dumps(conf_sample, sort_keys=True, indent=4))
  else: #if os.path.isfile(conf_file):
    try:
      with open(conf_file) as data_file:
        conf = json.load(data_file)
    except Exception as e:
      print 'Error parsing .fakedns (invalid json)'

  ip=''
  try:
    ip=sys.argv[1]
  except:
    ip=''

  if ip == '':
    if 'default_ip' in conf:
      ip = conf['default_ip']

  if ip == '':
    #print 'Using default IP address in responses. To over-write; use a command line option or set in ~/.fakedns'
    ip = default_ip

  print 'pyminifakeDNS:: dom.query. 60 IN A %s' % ip
  
  
  udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udps.bind(('',53))
  
  try:
    while 1:
      data, addr = udps.recvfrom(1024)
      p=DNSQuery(data)

      #look up tld and respond with the configured IP, or don't respond at all!
      conf, answer, match = getanswer(conf, p.dominio, ip)

      if not answer == '':
        udps.sendto(p.respuesta(answer), addr)
      else:
        udps.sendto('', addr)
        answer = 'NO RESPONSE SENT'

      if match:
        answer += ' [%s]' % conf_file
      #else:
      #  answer += ' [default_ip]'

      print 'Respuesta: %s -> %s' % (p.dominio, answer)
  except KeyboardInterrupt:
    print 'Finalizando'
    udps.close()
