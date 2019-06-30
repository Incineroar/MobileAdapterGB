#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Mobile Apdater GB emulator script
# Version 1.4
#
# the original script was created by Háčky.
# the BGBLinkCable class was coded by TheZZAZZGlitch.
# the code that filter the ip based of the login was coded by eintei95.
# other changes were made by Arves100.
#
# Version 1.4:   Added SMTP authentication
# Version 1.3:   Added ability to choose an emulated POP3 and HTTP server (useful when faking login)
#                changed some variables name and added comments.
# Version 1.2:   Added SMTP server code.
# Version 1.1.1: IP destination code.
# Version 1.1:   Added DNS server replacement and ability to connect to external servers.
# Version 1.0:   Original script made by Háčky.
#

import socket
import time
import random
import threading
import sys
import os
import base64
from enum import Enum

# This variables can be adjusted by the user
# Note: migrate this to a configuration file if possible

## This variable sets a dictionary that can replace the DNS server IP to a desidered one,
## you can disable the DNS redirecting by removing the content of this dictionary.
## Do not completely remove the variable otherwise it the script will crash
dns_server_replacement = {
    "gameboy.datacenter.ne.jp" : '127.0.0.1',
    "mail.srv1.dion.ne.jp" : '127.0.0.1',
    "pop.srv1.dion.ne.jp" : '127.0.0.1',
}

## This variable rapresents the real email server (without mail. or pop.) that will be replaced to
## dion.ne.jp, this is usefull for those mail server that doesn't accept emails from dion.ne.jp
real_email_domain = b"dion.ne.jp"

## This variables sets the DION login server IP and port used to authenticate the account
## of the adapter, if you want to enable/disable this functionality, please edit the value of
## the variable "enable_dion_login_server"
dion_login_ip = "127.0.0.1"
dion_login_port = 7705
enable_dion_login_server = False

## If this variable is enabled, the script will connect to an external email server
## and process SMTP/POP functionality used by the Trainer, otherwise it will use an internal
## emulation of the POP server that will allow the adapter to be fully configured
enable_external_email_server = False

## If this variable is enabled, after the HELO command, the script will try to authenticate
## to the SMTP server.
## NOTE: You need to perform POP3 authentication first, otherwise the script won't be able to
## intercept the password
require_smtp_authentication = False

## If this variable is enabled, the script will try to resolve domain name by using
## the system default DNS server
enable_external_dns_server = False 

## This mode prints each byte received and sended to the adapter
verbose_mode = False

# End of configurable variables

# This class represents an emulated Gameboy that will connect to BGB emulator
class BGBLinkCable():
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.ticks = 0
        self.frames = 0
        self.received = 0
        self.sent = 0
        self.transfer = -1
        self.lock = threading.Lock()
        self.exchangeHandler = None
	   
    def start(self): # Starts the server
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
        while True:
            try:
                data = bytearray(self.sock.recv(8))
            except KeyboardInterrupt:
                raise
            if len(data) == 0:
                break
            if data[0] == 0x01:
                self.sock.send(data)
                self.sock.send(b'\x6c\x03\x00\x00\x00\x00\x00\x00')
                continue
            if data[0] == 0x6C:
                self.sock.send(b'\x6c\x01\x00\x00\x00\x00\x00\x00')
                self.sock.send(self.queryStatus())
                continue
            if data[0] == 0x65:
                continue
            if data[0] == 0x6A:
                self.sock.send(self.queryStatus())
                continue
            if (data[0] == 0x69 or data[0] == 0x68):
                self.received += 1
                self.sent += 1
                data[1] = self.exchangeHandler(data[1], self)
                self.sock.send(data)
                self.sock.send(self.queryStatus())
                continue

            print("Unknown command " + hex(data[0]))
            print(data)
           
    def setExchangeHandler(self, ex):
        self.exchangeHandler = ex
pass

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
 
# Do not alter this variables otherwise the adapter will fail to work
adapter_state = TransferState.Waiting
packet_data = {'id': 0, 'size': 0, 'data': [], 'checksum': 0}
response_text = bytearray()
configuration_data = bytearray()
is_adapter_sending_data = False
is_line_busy = False
http_session_started = False
pop_session_started = False
smtp_session_started = False
pop_start_command_sended = False
smtp_status = 0
pop_status = 0
http_text = bytearray()
pop_text = bytearray()
smtp_text = bytearray()
external_server_port = 0
external_server_socket = None
p2p_destination_ip = ""
is_retr_command_received = False
user_password = ""

# This function translate the state into a text, used in verbose mode
def AdapterStateToText(state):
    if state == TransferState.Waiting:
	    return "Waiting"
    if state == TransferState.Preamble:
	    return "Preamble"
    if state == TransferState.PacketStart:
	    return "PacketStart"
    if state == TransferState.Packet01:
	    return "Packet01"
    if state == TransferState.Packet02:
	    return "Packet02"
    if state == TransferState.PacketLen:
	    return "PacketLen"
    if state == TransferState.PacketBody:
	    return "PacketBody"
    if state == TransferState.Checksum1:
	    return "Checksum1"
    if state == TransferState.Checksum2:
        return "Checksum2"
    if state == TransferState.DeviceID:
	    return "DeviceID"
    if state == TransferState.StatusByte:
	    return "StatusByte"

# This function process all the data the adapter should send or receive
# Argument one (received_byte) is the byte that the GameBoy have sended
# Argument two (link_cable) is an instance of the BGBLinkCable class
def mobileAdapter(received_byte, link_cable):
    global adapter_state, is_adapter_sending_data, packet_data, verbose_mode

    if(is_adapter_sending_data): # If the adapter is sending the data
        if (verbose_mode):
            print("VERBOSE: Sended %d to serial port! Current state is %s" % (b, AdapterStateToText(adapter_state)))
	
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
            # Since checksum is a 2 byte variable type (with a maximium of 65535), we need to send the variable in two different bytes (each one with a maximium value of 255)
 
        elif(adapter_state == TransferState.Checksum2):
            adapter_state = TransferState.DeviceID
            return packet_data['checksum'] & 0xFF
 
        elif(adapter_state == TransferState.DeviceID):
            adapter_state = TransferState.StatusByte
            return 0x88
            # This device ID contains the real device id of the model xor 0x80. The GameBoy ID is 0x00
            # The device ID used here is the PDC model (0x08), the CDMA model ID is 0x09
 
        elif(adapter_state == TransferState.StatusByte):
            adapter_state = TransferState.Waiting
            is_adapter_sending_data = False
            return 0x00
 
    else: # The adapter is receiving data
        if (verbose_mode):
            print("VERBOSE: Received %d from serial port! Current state is %s" % (b, AdapterStateToText(adapter_state)))	

        if(adapter_state == TransferState.Waiting):
            if(received_byte == 0x99):
                adapter_state = TransferState.Preamble
                packet_data = {'id': 0, 'size': 0, 'data': bytearray(), 'checksum': 0} # Reset the packet data
 
        elif(adapter_state == TransferState.Preamble):
            if(received_byte == 0x66):
                adapter_state = TransferState.PacketStart
            else: # Wrong byte received
                adapter_state = TransferState.Waiting
                return 0xF1
 
        elif(adapter_state == TransferState.PacketStart):
            packet_data['id'] = received_byte
            adapter_state = TransferState.Packet01
 
        elif(adapter_state == TransferState.Packet01):
            adapter_state = TransferState.Packet02
 
        elif(adapter_state == TransferState.Packet02):
            adapter_state = TransferState.PacketLen
 
        elif(adapter_state == TransferState.PacketLen):
            packet_data['size'] = received_byte
            if(packet_data['size'] > 0):
                adapter_state = TransferState.PacketBody
            else:
                adapter_state = TransferState.Checksum1 # Skip to the checksum since there's nothing to send
 
        elif(adapter_state == TransferState.PacketBody):
            packet_data['data'].append(received_byte)
            packet_data['size'] -= 1
            if(packet_data['size'] == 0):
                adapter_state = TransferState.Checksum1
 
        elif(adapter_state == TransferState.Checksum1):
            packet_data['checksum'] = received_byte << 8
            adapter_state = TransferState.Checksum2
 
        elif(adapter_state == TransferState.Checksum2):
            packet_data['checksum'] += received_byte
            adapter_state = TransferState.DeviceID
 
        elif(adapter_state == TransferState.DeviceID):
            adapter_state = TransferState.StatusByte
            return 0x88
 
        elif(adapter_state == TransferState.StatusByte):
            adapter_state = TransferState.Waiting
            is_adapter_sending_data = True
            return craftResponsePacket()  
 
    # if nothing else, send 0x4B
    return 0x4B

# This function generate the content that will be sended to the adapter
def craftResponsePacket():
    global packet_data, configuration_data, pop_start_command_sended, is_line_busy, dion_login_ip, dion_login_port, enable_external_dns_server, enable_dion_login_server, external_server_port, http_session_started, response_text, pop_session_started, smtp_session_started, external_server_socket, p2p_destination_ip, user_password

    return_byte = 0x80 ^ packet_data['id']
 
    if(packet_data['id'] == 0x10): # Command 0x10: NINTENDO
        print('>> 10 %s' % packet_data['data'].decode())
        print('<< 10 %s' % packet_data['data'].decode())
        external_server_port = 0
        # Echo that packet
 
    elif(packet_data['id'] == 0x11): # Command 0x11: Closing session
        print('>> 11 Closing session')
        print('<< 11 Closing session\n\n')
        external_server_port = 0
        is_line_busy = False ## Note: Check if this variable is correct, since hung up should free the line
        # Echo that packet
 
    elif(packet_data['id'] == 0x12): # Command 0x12: Dial the number
        # This contains the number that is dialed for P2P functionality. We will override this and use it as a way to input an IP address.
        x = packet_data['data'][1:].decode()

        if x != '#9677' and x != '0077487751': # PDC and CDMA numbers are ignored
            x = x[0:3] + "." + x[3:6] + "." + x[6:9] + "." + x[9:12]
            x = '.'.join('{0}'.format(int(i)) for i in x.split('.'))
            p2p_destination_ip = x

        print('<< 12 Dialed %s' % x)
        # Empty response
        packet_data['data'] = bytearray()
        is_line_busy = True
        # Note: Check if p2p functionality requires another variable to check the line status
 
    elif(packet_data['id'] == 0x13): # Command 0x13: Hang up
        print('>> 13 Hang up')
        print('<< 13 Hung up')
        is_line_busy = False
        # Echo that packet
 
    elif(packet_data['id'] == 0x15): # Command 0x15: Send traffic to external servers
        if(external_server_port == 110): # POP
            if(len(packet_data['data']) <= 1):
                print('>> 15 No POP traffic to send')
            else:
                print('>> 15 Send POP traffic:')
                try:
                    print(packet_data['data'][1:].decode())
                except UnicodeDecodeError:
                    hexDump(packet_data['data'][1:])
 
            if(pop_session_started or len(response_text) > 0): # Check if the adapter is ready to send data to the POP3 server
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
                external_server_socket.close()
                external_server_socket = None
                pop_status = 0
				
        elif(external_server_port == 25): # SMTP
            if(len(packet_data['data']) <= 1):
                print('>> 15 No SMTP traffic to send')
            else:
                print('>> 15 Send SMTP traffic:')
                try:
                    print(packet_data['data'][1:].decode())
                except UnicodeDecodeError:
                    hexDump(packet_data['data'][1:])
 
            if(smtp_session_started or len(response_text) > 0):
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
                external_server_socket.close()
                external_server_socket = None
                smtp_status = 0
				
        elif(external_server_port == 80): # HTTP
            if(len(packet_data['data']) <= 1):
                print('>> 15 No HTTP traffic to send')
            else:
                print('>> 15 Send HTTP traffic:')
                try:
                    print(packet_data['data'][1:].decode())
                except UnicodeDecodeError:
                    hexDump(packet_data['data'][1:])
 
            if(http_session_started or len(response_text) > 0):
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
                external_server_socket.close() # Close the external server socket since we are disconnected
                external_server_socket = None
				
        else:
            print('>> 15 Unknown protocol %d' % external_server_port)
            print('<< 15 Echoing data')
 
    elif(packet_data['id'] == 0x17): # Command 0x17: Check the current status of the telephone line
        print('>> 17 Check telephone line')
        if is_line_busy:
            print('<< 17 Line busy')
            packet_data['data'] = bytearray(b'\x05')
        else:
            print('<< 17 Line free')
            packet_data['data'] = bytearray(b'\x00')
 
    elif(packet_data['id'] == 0x19): # Command 0x19: Read configuration
        offset = packet_data['data'][0]
        length = packet_data['data'][1]
        print('>> 19 Read %s bytes from offset %s of configuration data' % (length, offset))
        print('<< 19 Reading configuration data:')
        hexDump(configuration_data[offset : offset + length])
        packet_data['data'] = bytearray([offset]) + configuration_data[offset : offset + length]

    elif(packet_data['id'] == 0x1A): # Command 0x1A: Write configuration
        offset = packet_data['data'][0]
        length = len(packet_data['data']) - 1
        print('>> 1A Write %s bytes at offset %s of configuration data:' % (length, offset))
        hexDump(packet_data['data'][1:])
        configuration_data[offset : offset + length] = packet_data['data'][1:]
        print('<< 1A Configuration data written')
        # Null response
        packet_data['data'] = bytearray()
 
    elif(packet_data['id'] == 0x21): # Command 0x21: Login to DION
        # Password interception
        length_of_password = packet_data['data'][packet_data['data'][0] + 1]
        user_password = packet_data['data'][packet_data['data'][0] + 1 : packet_data['data'][0] + length_of_password + 1]
		
        if enable_dion_login_server:
            dion_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dion_server_socket.connect((dion_login_ip, dion_login_port))
            dion_server_socket.send(packet_data['data']) # Send username (gXXXXXXX) and password to DION login server
		
            if dion_socket.recv(10) == b'VERIFY OK': # Account verified!
                print('<< 21 Logged in')
                packet_data['data'] = bytearray(b'\x00')
            else:
                print('<< 21 Unable to log in')
                packet_data['id'] = 0x00 # Note: replace the change of the ID with the change of 'data' bytearray
				
            dion_server_socket.close();
        else:
            print('>> 21 Log in to DION')
            packet_data['data'] = bytearray(b'\x00')
			
    elif(packet_data['id'] == 0x22): # Command 0x22: Logout to DION
        print('>> 22 Log out of DION')
        print('<< 22 Logged out')
        external_server_port = 0
        # Echo that packet
        # Note: should the adapter send something to the DION knew it has disconnected?
 
    elif(packet_data['id'] == 0x23): # Command 0x23: Connect to a server
        external_server_port = (packet_data['data'][4] << 8) + packet_data['data'][5]
        print('>> 23 Connect to %s.%s.%s.%s:%s' %
            (packet_data['data'][0], packet_data['data'][1], packet_data['data'][2], packet_data['data'][3], external_server_port))
        
        if enable_external_email_server == False and external_server_port == 110:
            packet_data['id'] = 0xA3
            packet_data['data'] = bytearray(b'\xFF')
            print('<< A3 Connected')
        else:
            try:
                external_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                external_server_ip = '%s.%s.%s.%s' % (packet_data['data'][0], packet_data['data'][1], packet_data['data'][2], packet_data['data'][3])
                external_server_socket.connect((external_server_ip, external_server_port))
                packet_data['id'] = 0xA3
                packet_data['data'] = bytearray(b'\xFF')
                print('<< A3 Connected')
            except:
                print('<< 23 Cannot connect')
                packet_data['id'] = 0x23 # Note: Please find the packet to directly abort this
                packet_data['data'] = bytearray(b'\xFF')

        if external_server_port == 80:
            http_session_started = True
        if external_server_port == 25:
            smtp_session_started = True
        if external_server_port == 110:
            pop_session_started = True
            pop_start_command_sended = False
			
    elif(packet_data['id'] == 0x24): # Command 0x24: Close connection to a server
        print('>> 24 Close connection to server')
        print('<< 24 Connection closed')
        external_server_port = 0
        if external_server_socket != None:
            external_server_socket.close()
        external_server_socket = None
        # Echo that packet
 
    elif(packet_data['id'] == 0x28): # Command 0x28: Query DNS server
        print('>> 28 DNS query for %s' % packet_data['data'].decode())
		
        expecting_ip = dns_server_replacement.get(packet_data['data'].decode())
        if expecting_ip == None and enable_external_dns_server == True:
            try:
                expecting_ip = socket.gethostbyname(packet_data['data'].decode())
            except:
                print('<< Domain %s does not exists, replacing to 220.20.20.20' % (packet_data['data'].decode()))
                expecting_ip = '220.20.20.20'
        elif expecting_ip == None:
            expecting_ip = '220.20.20.20'

        print("<< 28 Received DNS query %s" % expecting_ip)
        packet_data['data'] = bytearray([int(x) for x in expecting_ip.split('.')])
    else:
        print('>> %02x Unknown packet' % packet_data['id'])
        print('<< %02x Echoing that packet' % packet_data['id'])
 
    packet_data['size'] = len(packet_data['data'])
 
    # Calculate the checksum
    checksum = packet_data['id'] + packet_data['size']
    for byte in packet_data['data']:
        checksum += byte
    packet_data['checksum'] = checksum
 
    return return_byte # Send the return value (command XOR 0x80)

# Small function that wraps the switch between external and internal server
def craftPOPResponse():
    global enable_external_email_server
	
    if (enable_external_email_server):
        return craftExternalPOPResponse()
    else:
        return craftInternalPOPResponse()

# Small function that wraps the switch between external and internal server
def craftHTTPResponse():
    # Note: Háčky's script contained an internal version of "craftHTTPResponse"
    # if it's necessary to use it, the next update could contain that piece of code
    return craftExternalHTMLResponse()

# Small function that wraps the switch between external and internal server
def craftSMTPResponse():
    # Note: an internal SMTP server is not necessary since it's not required for setting up the adapter
    return craftExternalSMTPResponse()

# This function connect to an external POP server and process the data
def craftExternalPOPResponse():
    global packet_data, response_text, external_server_socket, is_retr_command_received, configuration_data, real_email_domain

    pop_text = bytearray()

    if(len(response_text) == 0):
        if(len(packet_data['data']) > 1):
            pop_text = packet_data['data'][1:]

        if b'USER' in pop_text: # Append to the user command the current email (fixes login issue with hMailServer)
            pop_text = b'USER ' + configuration_data[0x2C : 0x4A].replace(b'dion.ne.jp', real_email_domain) +  b'\r\n'

        external_server_socket.send(pop_text)
        
        response_text = external_server_socket.recv(4096)

        expect_tab_in_header = False
        except_space_in_header = False
        data_to_send = bytearray()
        filter_email_header = True

        if b'RETR' in pop_text: # Starts parsing the emails
            is_retr_command_received = True

        # This code remove the unused headers and append the headers that the mobile trainer require to receive an email
        if is_retr_command_received:
            while filter_email_header == True:
                for line in response_text.split(b"\r\n"):
                    if expect_tab_in_header and line[0] == 9:
                        if b'; ' in line:
                            data_to_send += line[1:].replace(b';', b'Date:') + b'\r\n'
                            continue
                        continue
                    elif expect_tab_in_header and line[0] != 9:
                        expect_tab_in_header = False
                    if except_space_in_header and line[0] == 32:
                        continue
                    elif except_space_in_header and line[0] != 32:
                        except_space_in_header = False

                    if b"Return-Path" in line:
                        expect_tab_in_header = True
                        continue
                    elif b"Received:" in line:
                        expect_tab_in_header = True
                        continue
                    elif b"Message-ID:" in line:
                        continue
                    elif b"MIME-Version:" in line:
                        except_space_in_header = True
                        continue
                    elif b' 1.0' in line:
                        continue

                    data_to_send += line + b'\r\n'

                if len(data_to_send) < 2:
                    response_text = pop_socket.recv(254)
                else:
                    filter_email_header = False

            response_text = data_to_send

            if b'\r\n' in response_text:
                is_retr_command_received = False
 
        if not response_text or response_text == "E_FAIL":
            response_text = b'-ERR Invalid socket\r\n' # Send this error if the connection is not valid

    bytes_to_send = min(254, len(response_text)) # Can’t send more than 254 bytes at once
    text_to_send = response_text[:bytes_to_send]
    response_text = response_text[bytes_to_send:]
    return text_to_send

# This function generate an fake POP response from a server
def craftInternalPOPResponse():
    global packet_data, pop_start_command_sended, response_text, email
    pop_text = bytearray()
    if(len(response_text) == 0):
        if(len(packet_data['data']) > 1):
            pop_text = packet_data['data'][1:]
 
        if(pop_text.find(b'STAT') == 0 or pop_text.find(b'LIST 1') == 0):
            response_text += b'+OK 0 0' # No email here
        elif(pop_text.find(b'LIST ') == 0):
            response_text += b'-ERR\r\n'
        elif(pop_text.find(b'LIST') == 0):
            response_text += b'+OK Mailbox scan listing follows\r\n.\r\n'
        elif(len(pop_text) > 0 or not pop_start_command_sended): # Reply +OK at start of session or to any other command
            pop_start_command_sended = True
            response_text += b'+OK\r\n'
        else: # something went wrong?
            response_text += b'-ERR\r\n'
        
    bytes_to_send = min(254, len(response_text)) # Can’t send more than 254 bytes at once
    text_to_send = response_text[:bytes_to_send]
    response_text = response_text[bytes_to_send:]
    return text_to_send

# This function connect to an external SMTP server and process the data
def craftExternalSMTPResponse():
    global packet_data, smtp_text, smtp_session_started, response_text, external_server_socket, smtp_status, real_email_domain, require_smtp_authentication
    if(len(response_text) == 0):
        if(len(packet_data['data']) > 1):
            smtp_text += packet_data['data'][1:]
        else:
            smtp_session_started = True

        if(smtp_session_started):
            if len(smtp_text) > 1: # Send the content of the emails
                if b'MAIL FROM' in smtp_text:
                    smtp_text = smtp_text.replace(b'dion.ne.jp', real_email_domain)

                external_server_socket.send(smtp_text)

            if smtp_status == 0: # Receive a result
                response_text = external_server_socket.recv(4096)
			
                if b'HELO' in smtp_text:
                    print("SMTP Authentication: Start!")
                    if len(user_password) < 1:
                        print("SMTP Authentication: Fail! No password was intercepted")
                    else:
                        last_response = response_text
                        my_username = configuration_data[0x2C : 0x44]
                        chiocciola = my_username.find(b'@')
                        my_username = my_username[:chiocciola]
                        ## We're ready to send the authentication. Thanks nintendo
                        external_server_socket.send(b'AUTH LOGIN\r\n')
                        response_text = external_server_socket.recv(4096)
                        print("SMTP Authentication: Response for AUTH LOGIN: " + response_text.decode("utf-8"))
                        external_server_socket.send(base64.b64encode(my_username) + b'\r\n')
                        response_text = external_server_socket.recv(4096)
                        print("SMTP Authentication: Response for username: " + response_text.decode("utf-8"))
                        external_server_socket.send(base64.b64encode(user_password) + b'\r\n')
                        response_text = external_server_socket.recv(4096)
                        print("SMTP Authentication: Response for password: " + response_text.decode("utf-8"))
                        print("SMTP Authentication: Finish!")
                        response_text = last_response
                        ## TODO: Check results
            if b'354 ' in response_text:
                smtp_status = 1 # Status 1: Writing email to the server
            if b'\r\n.\r\n' in smtp_text:
                smtp_status = 0
				
            if(response_text is None) and (smtp_status == 0):
                print('No response known for %s' % smtp_text.decode())
                response_text = b'503 Unknown response\r\n'
                smtp_session_started = False
				
            if b'QUIT' in smtp_text: # Close the connection if the QUIT command is received
                smtp_session_started = False
				
            smtp_text = bytearray()

    bytes_to_send = min(254, len(response_text)) # Can’t send more than 254 bytes at once
    text_to_send = response_text[:bytes_to_send]
    response_text = response_text[bytes_to_send:]
    return text_to_send
	
# This function connect to an external SMTP server and process the data
def craftExternalHTMLResponse():
    global packet_data, http_text, http_session_started, response_text, working_socket, HTTP_HOST_IP, HTTP_HOST_PORT
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
                        http_session_started = False # request is done since the length of the data parsed from the header is greater or equal to the counted length
            else: # this is a GET request, so we’re definitely done
                http_session_started = False
 
            if(not http_session_started):
                # Clear http_text before the next request
                http_text = bytearray()		
                http_data['request'] = http_data['request'].replace(b'.cgi',b'.php').replace(b'index.html',b'index.php') # Replace .cgi scripts with .php, and index.html with index.php
                if b'.php?' not in http_data['request']: # Change requested file URL from 'folder/?arg=xxxx' to 'folder.php?arg=xxxx'
                    pos = http_data['request'].find(b'?')
                    if pos > 0:
                        http_data['request'] = http_data['request'][:pos] + b'.php' + http_data['request'][pos:]
				
                send_text = http_data['request'] + b'\r\n'
                for header, value in http_data['headers'].items(): # Add headers
                    send_text += header.encode() + b': ' + value + b'\r\n'
                send_text += b'\r\n' + http_data['content']
					
                external_server_socket.send(send_text)
                response_text = external_server_socket.recv(4096)

                if(response_text is None):
                    print('No response known for %s' % http_data['request'].decode())
                    response_text = b'HTTP/1.0 404 Not Found\r\n\r\n'

 
    bytes_to_send = min(254, len(response_text)) # Can’t send more than 254 bytes at once
    text_to_send = response_text[:bytes_to_send]
    response_text = response_text[bytes_to_send:]
    return text_to_send

# This function format the passed HTTP response/request into a dictionary
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

# This function dumps a 16 byte hex array into the console
def hexDump(x):
        for i in range(0, len(x), 16):
            print('   ' + ''.join('%02x ' % j for j in x[i : min(len(x), i + 16)]))

# Try to parse the adapter config, if it's invalid or does not exist, it creates one			
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
 
# Setup the link cable and connect to BGB
# Note: add a switch for this
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