#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
import time
import random
import threading
import sys
import os
from enum import Enum

dns_server_replacement = {
	"gameboy.datacenter.ne.jp" : '127.0.0.1',
	"mail.gbaa.dion.ne.jp" : '127.0.0.1',
	"pop.gbaa.dion.ne.jp" : '127.0.0.1'
}

# BGBLinkCable class by TheZZAZZGlitch
class BGBLinkCable():
   
	
    def __init__(self,ip,port):
        self.ip = ip
        self.port = port
        self.ticks = 0
        self.frames = 0
        self.received = 0
        self.sent = 0
        self.transfer = -1
        self.lock = threading.Lock()
        self.exchangeHandler = None
	   
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((self.ip, self.port))
        except:
            print("Unable to connect to BGB emulator")
            sys.exit(1)

        threading.Thread(target=self.networkLoop, daemon=True).start()
   
    def queryStatus(self):
        status = [0x6a,0,0,0,0,0,0,0]
        self.ticks += 1
        self.frames += 8
        status[2] = self.ticks % 256
        status[3] = (self.ticks // 256) % 256
        status[5] = self.frames % 256
        status[6] = (self.frames // 256) % 256
        status[7] = (self.frames // 256 // 256) % 256
        return bytes(status)
       
    def getStatus(self):
        return (self.frames, self.ticks, self.received, self.sent)
   
    def networkLoop(self):
        global disable_smtp_resp
        while True:
            try:
                data = bytearray(self.sock.recv(8))
            except KeyboardInterrupt:
                raise
            if len(data) == 0:
                break
            if data[0] == 0x01:  #1
                self.sock.send(data)
                self.sock.send(b'\x6c\x03\x00\x00\x00\x00\x00\x00')
                continue
            if data[0] == 0x6C: #108
                self.sock.send(b'\x6c\x01\x00\x00\x00\x00\x00\x00')
                self.sock.send(self.queryStatus())
                continue
            if data[0] == 0x65: #101
                continue
            if data[0] == 0x6A: #106
                self.sock.send(self.queryStatus())
                continue
            if (data[0] == 0x69 or data[0] == 0x68): #105,104
                self.received+=1
                self.sent+=1
                data[1] = self.exchangeHandler(data[1], self)
                self.sock.send(data)
                self.sock.send(self.queryStatus())
                continue
            print("Unknown command " + hex(data[0]))
            print(data)
           
    def setExchangeHandler(self, ex):
        self.exchangeHandler = ex
pass

 
# Mobile Adapter GB implementation by Háčky
# Modified for External servers and SMTP by Arves100
class TransferState(Enum):
    Waiting     = 0  # Waiting for the first byte of the preamble (0x99).
    Preamble    = 1  # Expecting the second byte of the preamble (0x66).
    PacketStart = 2  # Expecting the packet start.
    Packet01    = 3  # Expecting packet offset 0x01 (unused?)
    Packet02    = 4  # Expecting packet offset 0x02 (unused?)
    PacketLen   = 5  # Expecting the packet length.
    PacketBody  = 6  # Expecting the packet body.
    Checksum1   = 7  # Expecting the first byte of the checksum.
    Checksum2   = 8  # Expecting the second byte of the checksum.
    DeviceID    = 9  # Expecting the device ID.
    StatusByte  = 10 # Expecting the status byte (0x00 for sender, 0x80 ^ packetID for receiver)
 
adapter_state = TransferState.Waiting
is_sender = False
packet_data = {'id': 0, 'size': 0, 'data': [], 'checksum': 0}
line_busy = False
port = 0
response_text = bytearray()

http_ready = True
pop_ready = True
smtp_ready = True

http_text = bytearray()
pop_text = bytearray()
smtp_text = bytearray()

working_socket = None

DEST_IP = ""

smtp_status = 0
pop_status = 0

def mobileAdapter(b, obj):
    global adapter_state, is_sender, packet_data
    if(is_sender):
        # This does not handle errors flagged by Game Boy!
        if(adapter_state == TransferState.Waiting):
            adapter_state = TransferState.Preamble
            return 0x99
 
        elif(adapter_state == TransferState.Preamble):
            adapter_state = TransferState.PacketStart
            return 0x66
 
        elif(adapter_state == TransferState.PacketStart):
            adapter_state = TransferState.Packet01
            return packet_data['id']
 
        elif(adapter_state == TransferState.Packet01):
            adapter_state = TransferState.Packet02
            return 0x00
 
        elif(adapter_state == TransferState.Packet02):
            adapter_state = TransferState.PacketLen
            return 0x00
 
        elif(adapter_state == TransferState.PacketLen):
            if(packet_data['size'] > 0):
                adapter_state = TransferState.PacketBody
            else:
                adapter_state = TransferState.Checksum1
            return packet_data['size']
 
        elif(adapter_state == TransferState.PacketBody):
            packet_data['size'] -= 1
            if(packet_data['size'] == 0):
                adapter_state = TransferState.Checksum1
            return packet_data['data'][-1 - packet_data['size']]
 
        elif(adapter_state == TransferState.Checksum1):
            adapter_state = TransferState.Checksum2
            return packet_data['checksum'] >> 8
 
        elif(adapter_state == TransferState.Checksum2):
            adapter_state = TransferState.DeviceID
            return packet_data['checksum'] & 0xFF
 
        elif(adapter_state == TransferState.DeviceID):
            adapter_state = TransferState.StatusByte
            return 0x88
 
        elif(adapter_state == TransferState.StatusByte):
            adapter_state = TransferState.Waiting
            is_sender = False
            return 0x00
 
 
    else: # adapter is receiving
        if(adapter_state == TransferState.Waiting):
            if(b == 0x99):
                adapter_state = TransferState.Preamble
                packet_data = {'id': 0, 'size': 0, 'data': bytearray(), 'checksum': 0} # reset
 
        elif(adapter_state == TransferState.Preamble):
            if(b == 0x66):
                adapter_state = TransferState.PacketStart
            else: # fail
                adapter_state = TransferState.Waiting
                return 0xf1
 
        elif(adapter_state == TransferState.PacketStart):
            packet_data['id'] = b
            adapter_state = TransferState.Packet01
 
        elif(adapter_state == TransferState.Packet01):
            adapter_state = TransferState.Packet02
 
        elif(adapter_state == TransferState.Packet02):
            adapter_state = TransferState.PacketLen
 
        elif(adapter_state == TransferState.PacketLen):
            packet_data['size'] = b
            if(packet_data['size'] > 0):
                adapter_state = TransferState.PacketBody
            else:
                adapter_state = TransferState.Checksum1
 
        elif(adapter_state == TransferState.PacketBody):
            packet_data['data'].append(b)
            packet_data['size'] -= 1
            if(packet_data['size'] == 0):
                adapter_state = TransferState.Checksum1
 
        elif(adapter_state == TransferState.Checksum1):
            packet_data['checksum'] = b << 8
            adapter_state = TransferState.Checksum2
 
        elif(adapter_state == TransferState.Checksum2):
            packet_data['checksum'] += b
            adapter_state = TransferState.DeviceID
 
        elif(adapter_state == TransferState.DeviceID):
            adapter_state = TransferState.StatusByte
            return 0x88
 
        elif(adapter_state == TransferState.StatusByte):
            adapter_state = TransferState.Waiting
            is_sender = True
            return craftResponsePacket()
 
    # if nothing else, send 0x4B
    return 0x4B
 
 
def craftResponsePacket():
    global packet_data, configuration_data, line_busy, DION_IP, DION_PORT, port, expecting_ip, http_ready, response_text, system_type, pop_ready, smtp_ready, working_socket, DEST_IP
    rval = 0x80 ^ packet_data['id']
 
    if(packet_data['id'] == 0x10):
        print('>> 10 %s' % packet_data['data'].decode())
        print('<< 10 %s' % packet_data['data'].decode())
        port = 0
        # Echo that packet
 
    elif(packet_data['id'] == 0x11):
        print('>> 11 Closing session')
        print('<< 11 Closing session\n\n')
        port = 0
        line_busy = False
        # Echo that packet
 
    elif(packet_data['id'] == 0x12):
        #this contains the number that is dialed for P2P functionality. We will override this and use it as a way to input an IP address.
        x = packet_data['data'][1:].decode()
        if x != '#9677':
            x = x[0:3] + "." + x[3:6] + "." + x[6:9] + "." + x[9:12]
            x = '.'.join('{0}'.format(int(i)) for i in x.split('.'))
        DEST_IP = x

        print('<< 12 Dialed')
        # Empty response
        packet_data['data'] = bytearray()
        line_busy = True
 
    elif(packet_data['id'] == 0x13):
        print('>> 13 Hang up')
        print('<< 13 Hung up')
        line_busy = False
        # Echo that packet
 
    elif(packet_data['id'] == 0x15):
        if(port == 110): # POP
            if(len(packet_data['data']) <= 1):
                print('>> 15 No POP traffic to send')
            else:
                print('>> 15 Send POP traffic:')
                try:
                    print(packet_data['data'][1:].decode())
                except UnicodeDecodeError:
                    hexDump(packet_data['data'][1:])
 
            if(pop_ready or len(response_text) > 0):
                packet_data['id'] = 0x95
                packet_data['data'] = bytearray(b'\x00') + craftPOPResponse()

                if(len(packet_data['data']) <= 1):
                    print('<< 95 No POP traffic received')
                else:
                    print('<< 95 POP response received:')
                    try:
                        print(packet_data['data'][1:].decode())
                    except UnicodeDecodeError:
                        hexDump(packet_data['data'][1:])
            else:
                packet_data['id'] = 0x9F
                packet_data['data'] = bytearray(b'\x00')
                print('<< 9F POP server closed connection')
                working_socket.close()
                working_socket = None
                pop_status = 0
				
        elif(port == 25): # SMTP
            if(len(packet_data['data']) <= 1):
                print('>> 15 No SMTP traffic to send')
            else:
                print('>> 15 Send SMTP traffic:')
                try:
                    print(packet_data['data'][1:].decode())
                except UnicodeDecodeError:
                    hexDump(packet_data['data'][1:])
 
            if(smtp_ready or len(response_text) > 0):
                packet_data['id'] = 0x95
                packet_data['data'] = bytearray(b'\x00') + craftSMTPResponse()

                if(len(packet_data['data']) <= 1):
                    print('<< 95 No SMTP traffic received')
                else:
                    print('<< 95 SMTP response received:')
                    try:
                        print(packet_data['data'][1:].decode())
                    except UnicodeDecodeError:
                        hexDump(packet_data['data'][1:])
            else:
                packet_data['id'] = 0x9F
                packet_data['data'] = bytearray(b'\x00')
                print('<< 9F SMTP server closed connection')
                working_socket.close()
                working_socket = None
                smtp_status = 0
				
        elif(port == 80): # HTTP
            if(len(packet_data['data']) <= 1):
                print('>> 15 No HTTP traffic to send')
            else:
                print('>> 15 Send HTTP traffic:')
                try:
                    print(packet_data['data'][1:].decode())
                except UnicodeDecodeError:
                    hexDump(packet_data['data'][1:])
 
            if(http_ready or len(response_text) > 0):
                packet_data['id'] = 0x95
                packet_data['data'] = bytearray(b'\x00') + craftHTTPResponse()

                if(len(packet_data['data']) <= 1):
                    print('<< 95 No HTTP traffic received')
                else:
                    print('<< 95 HTTP response received:')
                    try:
                        print(packet_data['data'][1:].decode())
                    except UnicodeDecodeError:
                        hexDump(packet_data['data'][1:])
            else:
                packet_data['id'] = 0x9F
                packet_data['data'] = bytearray(b'\x00')
                print('<< 9F HTTP server closed connection')
                working_socket.close()
                working_socket = None
				
        else:
            print('>> 15 Unknown protocol %d' % port)
            print('<< 15 Echoing data')
 
    elif(packet_data['id'] == 0x17):
        print('>> 17 Check telephone line')
        if line_busy:
            print('<< 17 Line busy')
            packet_data['data'] = bytearray(b'\x05')
        else:
            print('<< 17 Line free')
            packet_data['data'] = bytearray(b'\x00')
 
    elif(packet_data['id'] == 0x19):
        offset = packet_data['data'][0]
        length = packet_data['data'][1]
        print('>> 19 Read %s bytes from offset %s of configuration data' % (length, offset))
        print('<< 19 Reading configuration data:')
        hexDump(configuration_data[offset : offset + length])
        packet_data['data'] = bytearray([offset]) + configuration_data[offset : offset + length]

    elif(packet_data['id'] == 0x1A):
        offset = packet_data['data'][0]
        length = len(packet_data['data']) - 1
        print('>> 1A Write %s bytes at offset %s of configuration data:' % (length, offset))
        hexDump(packet_data['data'][1:])
        configuration_data[offset : offset + length] = packet_data['data'][1:]
        print('<< 1A Configuration data written')
        # Null response
        packet_data['data'] = bytearray()
 
    elif(packet_data['id'] == 0x21):
        print('>> 21 Log in to DION')
        #dion_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #dion_socket.connect((DION_IP, DION_PORT))
        #dion_socket.send(packet_data['data'])
		
        #if dion_socket.recv(1) == b'0x01':
        #    print('<< 21 Logged in')
        #    packet_data['data'] = bytearray(b'\x00')
        #else:
        #    print('<< 21 Cannot log in')
        #    packet_data['id'] = 0x00
        
        packet_data['data'] = bytearray(b'\x00')
			
    elif(packet_data['id'] == 0x22):
        print('>> 22 Log out of DION')
        print('<< 22 Logged out')
        port = 0
        # Echo that packet
 
    elif(packet_data['id'] == 0x23):
        port = (packet_data['data'][4] << 8) + packet_data['data'][5]
        print('>> 23 Connect to %s.%s.%s.%s:%s' %
            (packet_data['data'][0], packet_data['data'][1], packet_data['data'][2], packet_data['data'][3], port))
        
        try:
            working_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            real_ip = '%s.%s.%s.%s' % (packet_data['data'][0], packet_data['data'][1], packet_data['data'][2], packet_data['data'][3])
            working_socket.connect((real_ip, port))
            packet_data['id'] = 0xA3
            packet_data['data'] = bytearray(b'\xFF')
            print('<< A3 Connected')
        except:
            print('<< 23 Cannot connect')
            packet_data['id'] = 0x23 ##TODO: Please find the packet to directly abort this
            packet_data['data'] = bytearray(b'\xFF')

        if port == 80:
            http_ready = True
            http_socket = None
        elif port == 25:
            smtp_ready = True
            smtp_socket = None
        elif port == 110:
            pop_ready = True
            pop_socket = None
			
    elif(packet_data['id'] == 0x24):
        print('>> 24 Close connection to server')
        print('<< 24 Connection closed')
        port = 0
        working_socket.close()
        working_socket = None
        # Echo that packet
 
    elif(packet_data['id'] == 0x28):
        print('>> 28 DNS query for %s' % packet_data['data'].decode())
        expecting_ip = dns_server_replacement.get(packet_data['data'].decode())
        if expecting_ip == None:
            try:
                expecting_ip = socket.gethostbyname(packet_data['data'].decode())
            except:
                print('<< Domain %s does not exists, replacing to 220.20.20.20' % (packet_data['data'].decode()))
                expecting_ip = '220.20.20.20'

        print("<< 28 Received DNS query %s" % expecting_ip)
        packet_data['data'] = bytearray([int(x) for x in expecting_ip.split('.')])
    else:
        print('>> %02x Unknown packet' % packet_data['id'])
        print('<< %02x Echoing that packet' % packet_data['id'])
 
    packet_data['size'] = len(packet_data['data'])
 
    checksum = packet_data['id'] + packet_data['size']
    for byte in packet_data['data']:
        checksum += byte
    packet_data['checksum'] = checksum
 
    return rval

retr_start = False

def craftPOPResponse():
    global packet_data, response_text, working_socket, retr_start, configuration_data
    pop_text = bytearray()
    if(len(response_text) == 0):
        if(len(packet_data['data']) > 1):
            pop_text = packet_data['data'][1:]

        if b'USER' in pop_text:
            pop_text = b'USER ' + configuration_data[0x2C : 0x4A] +  b'\r\n'
        working_socket.send(pop_text)
        
        response_text = working_socket.recv(4096)

        expect_tab = False
        expect_space = False
        real_recv = bytearray()
        can_continue = False

        if b'RETR' in pop_text:
            retr_start = True

        if retr_start:
            while can_continue == False:
                for line in response_text.split(b"\r\n"):
                    if expect_tab and line[0] == 9:
                        if b'; ' in line:
                            real_recv += line[1:].replace(b';', b'Date:') + b'\r\n'
                            continue
                        continue
                    elif expect_tab and line[0] != 9:
                        expect_tab = False
                    if expect_space and line[0] == 32:
                        continue
                    elif expect_space and line[0] != 32:
                        expect_space = False

                    if b"Return-Path" in line:
                        expect_tab = True
                        continue
                    elif b"Received:" in line:
                        expect_tab = True
                        continue
                    elif b"Message-ID:" in line:
                        continue
                    elif b"MIME-Version:" in line:
                        expect_space = True
                        continue
                    elif b' 1.0' in line:
                        continue

                    real_recv += line + b'\r\n'

                if len(real_recv) < 2:
                    response_text = pop_socket.recv(254)
                else:
                    can_continue = True

            response_text = real_recv

            if b'\r\n' in response_text:
                retr_start = False
 
        if not response_text or response_text == "E_FAIL":
            response_text = b'-ERR Invalid socket\r\n'

    bytes_to_send = min(254, len(response_text)) # Can’t send more than 254 bytes at once
    text_to_send = response_text[:bytes_to_send]
    response_text = response_text[bytes_to_send:]
    return text_to_send

def craftSMTPResponse():
    global packet_data, smtp_text, smtp_ready, response_text, working_socket, SMTP_HOST_IP, SMTP_HOST_PORT, smtp_status
    if(len(response_text) == 0):
        if(len(packet_data['data']) > 1):
            smtp_text += packet_data['data'][1:]
        else:
            smtp_ready = True

        if(smtp_ready):
            if len(smtp_text) > 1:
                working_socket.send(smtp_text)
				
            if smtp_status == 0:
                response_text = working_socket.recv(4096)
			
            if b'354 OK' in response_text:
                smtp_status = 1
            if b'\r\n.\r\n' in smtp_text:
                smtp_status = 0
				
            if(response_text is None)and(smtp_status==0):
                print('No response known for %s' % smtp_text.decode())
                response_text = b'503 Unknown response\r\n'
                smtp_ready = False
				
            if b'QUIT' in smtp_text:
                smtp_ready = False
				
            smtp_text = bytearray()

    bytes_to_send = min(254, len(response_text)) # Can’t send more than 254 bytes at once
    text_to_send = response_text[:bytes_to_send]
    response_text = response_text[bytes_to_send:]
    return text_to_send
	
def craftHTTPResponse():
    global packet_data, http_text, http_ready, response_text, working_socket, HTTP_HOST_IP, HTTP_HOST_PORT
    if(len(response_text) == 0):
        if(len(packet_data['data']) > 1):
            http_text += packet_data['data'][1:]
 
        http_data = parseHTTPRequest(http_text)
        if('request' in http_data):
            # if this is a POST request, is it done?
            if(http_data['request'].find(b'POST') == 0):
                if('Content-Length' in http_data['headers']):
                    content_length = int(http_data['headers']['Content-Length'])
                    if(len(http_data['content']) >= content_length):
                        http_ready = False # request is done
            else: # this is a GET request, so we’re definitely done
                http_ready = False
 
            if(not http_ready):
                # Clear http_text before the next request
                http_text = bytearray()		
                http_data['request'] = http_data['request'].replace(b'.cgi',b'.php').replace(b'index.html',b'index.php')
                if b'.php?' not in http_data['request']:
                    pos = http_data['request'].find(b'?')
                    if pos > 0:
                        http_data['request'] = http_data['request'][:pos] + b'.php' + http_data['request'][pos:]
				
                send_text = http_data['request'] + b'\r\n'
                for header, value in http_data['headers'].items():
                    send_text += header.encode() + b': ' + value + b'\r\n'
                send_text += b'\r\n' + http_data['content']
					
                working_socket.send(send_text)
                response_text = working_socket.recv(4096)

                if(response_text is None):
                    print('No response known for %s' % http_data['request'].decode())
                    response_text = b'HTTP/1.0 404 Not Found\r\n\r\n'

 
    bytes_to_send = min(254, len(response_text)) # Can’t send more than 254 bytes at once
    text_to_send = response_text[:bytes_to_send]
    response_text = response_text[bytes_to_send:]
    return text_to_send

def parseHTTPRequest(x):
    http_data = {}
    if(b'\r\n\r\n' in x): # if this is a complete request
        http_data['request'] = x.split(b'\r\n')[0]
 
        http_data['headers'] = {}
        if(x.find(b'\r\n') < x.find(b'\r\n\r\n')): # if there are headers
            headers = x[x.find(b'\r\n') + 2 : x.find(b'\r\n\r\n')]
            headers = headers.split(b'\r\n')
            for header in headers:
                header = header.split(b': ')
                http_data['headers'][header[0].decode()] = header[1]
 
        http_data['content'] = x[x.find(b'\r\n\r\n') + 4:]
 
    return http_data
 
def hexDump(x):
        for i in range(0, len(x), 16):
            print('   ' + ''.join('%02x ' % j for j in x[i : min(len(x), i + 16)]))
 
 
 
configuration_data = bytearray()
try:
    with open('mobilegb.cfg', 'rb') as f:
        configuration_data = bytearray(f.read())
    f.closed
except FileNotFoundError:
    pass
if(len(configuration_data) != 192):
    print("Configuration data file 'mobilegb.cfg' is invalid or does not exist.")
    print("Creating a blank configuration.\n")
    configuration_data = bytearray([0] * 192)
 
try:
    link = BGBLinkCable('127.0.0.1',8765)
    link.setExchangeHandler(mobileAdapter)
    link.start()
    while True:
        time.sleep(10)
except KeyboardInterrupt:
    print("Saving configuration to 'mobilegb.cfg'.")
    with open('mobilegb.cfg', 'wb') as out:
        out.write(configuration_data)
    out.closed