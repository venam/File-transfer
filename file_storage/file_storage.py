"""
Built on:
Architecture:        x86_64
Byte Order:          Little Endian
"""

import socket
import sys
import struct
import select
import thread
import threading
import time
import uuid

import encryption

#TODO: configuration file
IP = "127.0.0.1"
UDP_PORT = 12000
TCP_PORT = 12001
BUFFER_SIZE = 256
OUTPUT_STORAGE = "storage_dir"
# this is the encryption scheme of the file storage
NETWORK_ENCRYPTION = '~:4;^1:1;ror3:4;rol1:1'

def udp_service():
    global IP
    global UDP_PORT
    global TCP_PORT
    global NETWORK_ENCRYPTION

    sock = socket.socket(socket.AF_INET, # Internet
                         socket.SOCK_DGRAM) # UDP
    sock.bind((IP, UDP_PORT))

    print "UDP Service"
    while True:
        data, addr = sock.recvfrom(4096)
        if len(data)<3:
            continue
        print "UDP"+str(addr)
        message = struct.unpack("c"+str(len(data)-1)+"s", data)
        pkt_type = ord(message[0])
        if pkt_type != 1:
            continue
        decrypted = encryption.decrypt(bytearray(message[1]), NETWORK_ENCRYPTION)
        print "INIT MESSAGE: "+decrypted
        reply = encryption.encrypt("ACK:"+decrypted,NETWORK_ENCRYPTION)
        formating = "<cH"+str(len(reply)+1)+"s"
        message = struct.pack(formating, b'\x02', TCP_PORT, str(reply)+" ")
        sock.sendto(message, addr)

def log_session():
    return

def handle_tcp(conn, addr):
    global OUTPUT_STORAGE
    print 'Connection address:', addr
    unique_filename = OUTPUT_STORAGE+"/"+str(uuid.uuid4())
    f = open(unique_filename,'ab')
    print "going to save to "+unique_filename
    while 1:
        data = conn.recv(BUFFER_SIZE)
        if not data: break
        #print "received data:", data
        decrypted = encryption.decrypt(bytearray(data), NETWORK_ENCRYPTION)
        #print "decrypted received"
        #print decrypted
        f.write(decrypted)
    conn.close()

def tcp_service():
    # TODO: on every new connection open a thread and wait for the file
    #       to be received and log where it was saved
    global IP
    global TCP_PORT
    global BUFFER_SIZE
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, TCP_PORT))
    s.listen(1)

    print "TCP Service"
    while 1:
        conn, addr = s.accept()
        print "TCP"+str(addr)
        tcp_thread = threading.Thread(None, handle_tcp, "handle_tcp", (conn, addr), None, False)
        tcp_thread.start()

udp_thread = threading.Thread(None, udp_service, "udp_service",(),None, False)
tcp_thread = threading.Thread(None, tcp_service, "tcp_service",(),None, False)
udp_thread.start()
tcp_thread.start()
