"""
Built on:
Architecture:        x86_64
Byte Order:          Little Endian
"""

import sys
import os
import json
import random
import struct
import select
import socket

CONF = {}

def usage():
    print sys.argv[0] + """:
    \t-f <file> <storage number> # send file
    \t-l  # list storages"""

def debug(message):
    global CONF
    if CONF['debug']:
        print "[*] "+str(message)

def ip2int(addr):
    return struct.unpack("I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("I", addr)) 

def read_conf():
    global CONF
    try:
        conf = json.loads(open('c2.json','r').read())
        CONF = conf
        debug("Loaded configs with values:")
        debug("\tstorages: " + str(conf['storages']))
        debug("\tfile_transfer: " + str(conf['file_transfer']))
        debug("\ttimeout: " + str(conf['timeout']))
        debug("\tlog_file: " + str(conf['log_file']))
        debug("\tdebug: " + str(conf['debug']))
    except Exception, e:
        print e
        sys.exit(1)

def available_storages():
    global CONF
    print "Available storages: "
    i = 0
    for storage in CONF['storages']:
        print str(i)+"-> "+storage['ip']+":"+storage['port']+" ("+storage['enc']+")"
        i += 1

def generate_init_message():
    nonce = ""
    for a in range(20):
        nonce += random.choice(['a','b','c','d','e','1','2','_','@'])
    return nonce

def check_file(data_file):
    return os.path.isfile(data_file) and os.access(data_file, os.R_OK)

def send_file(storage, data_file):
    global CONF
    # this generates an init message, a random nonce (random string)
    # it sends it to the file transfer and then the file transfers encrypts it
    # with the encryption, sends it to the file storages, the file storage decrypts it with the encryption it knows, add "ACK:" at the begining and encrypts
    #it back, then goes back to the file transfer, file transfer decrypts it with the encryption it has received from the client and send it back here to the
    # client
    # so if the client uses a different encryption than the storage it won't match
    # we can test that now
    nonce_init_message = generate_init_message()

    # little endian
    message = struct.pack(
        "<cIHH"+str(len(storage['enc']))+"s"+str(len(nonce_init_message))+"s",
        b'\x00',
        ip2int(storage['ip']),
        int(storage['port']),
        len(storage['enc']),
        storage['enc'].encode('ascii'),
        nonce_init_message.encode('ascii'))

    debug('sending init nonce')
    debug("init message: "+nonce_init_message)
    debug("UDP target IP:"+ CONF['file_transfer']['ip'])
    debug("UDP target port:"+ CONF['file_transfer']['udp_port'])

    clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSock.setblocking(0)
    clientSock.sendto(
        message,
        (CONF['file_transfer']['ip'], int(CONF['file_transfer']['udp_port'])))
    debug('waiting for init reply')
    ready = select.select([clientSock], [], [], CONF['timeout'])
    if not ready[0]:
        print "[!] Timeout"
        sys.exit(1)
    data = clientSock.recv(4096)
    if "ERROR" in data:
        print "Seems like there was an error along the way: " + data
        sys.exit(1)
    else:
        if "ACK:"+nonce_init_message ==  data[1:len(nonce_init_message)+5]:
            print "Successful inititialization"
        else:
            # ok, I wasn't exiting... edge case
            print "not matching initialization"
            sys.exit(1)

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.connect((CONF['file_transfer']['ip'], int(CONF['file_transfer']['tcp_port'])))

    f = open(data_file, 'rb')
    while 1:
        byte_s = f.read(256)
        if not byte_s:
            break
        tcp_sock.send(byte_s)
        data = tcp_sock.recv(3)
        #print str(data)
    tcp_sock.close()
    print "DONE"


if __name__ == "__main__":
    read_conf()
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)
    if sys.argv[1] == '-l':
        available_storages()
        sys.exit(1)
    else:
        if len(sys.argv) != 4 or sys.argv[1] != '-f':
            usage()
            sys.exit(1)
    storage = int(sys.argv[3])
    data_file = sys.argv[2]
    if storage < 0 or len(CONF['storages']) - 1 < storage:
        print "Invalid storage "+str(storage)
        available_storages()
        sys.exit(1)
    if not check_file(data_file):
        print "File no readable or not found"
        sys.exit(1)

    try:
        send_file(CONF['storages'][storage], data_file)
    except Exception, e:
        print e

