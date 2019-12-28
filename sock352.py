import binascii
import socket as syssock
import struct
import sys
import time
import threading
import math
import random

#functions are global to class and define UDP ports all messages are sent and recieved from

#constants

SOCK352_SYN = 0x01
SOCK352_ACK = 0x04
SOCK352_FIN = 0x02
SOCK352_RESET = 0x08
SOCK352_HAS_OPT = 0xA0

send_port = -1   #client
recv_port = -1   #server

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from
#version = 0x1
#flags = -1
#opt_ptr = 0
#protocol = 0
#checksum = 0
#source_port = 0
#dest_port = 0
#seq_no = 0
#ack_no = 0
#window = 0
#payload_len = 0

MAX_PAYLOAD_SIZE = 64000
HEADER_LEN = 40
PACKET_SIZE = MAX_PAYLOAD_SIZE + HEADER_LEN


def init(UDPportTx, UDPportRx): #initialize UDP socket
    global send_port, recv_port
    send_port = UDPportTx
    recv_port = UDPportRx
    

class socket:
    def __init__(self): #initialize socket and fields
        sock352PktHdrData = '!BBBBHHLLQQLL'
        self.struct = struct.Struct(sock352PktHdrData)
        self.socket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
        #what is being requested to me
        self.rn = 0
        #what I am requesting
        self.my_rn = 0
        #tells me if I got FIN packet
        self.done = False
        self.lock = threading.Lock()
        #tells me if I had timeout
        self.timeout = False
#bind the server to the recvaddress, never use the port again
    def bind(self, address):
        global recv_port
        self.recv_address = (address[0], int(recv_port))
        self.socket.bind(self.recv_address)
#client side of the three way handshake
    def connect(self, address):
        #first bind and set both incoming and outgoing addresses
        global send_port, recv_port
        self.recv_address = (syssock.gethostname(), int(recv_port))
        #print (self.recv_address)
        self.socket.bind(self.recv_address)
        self.send_address = (str(address[0]), int(send_port))
        #print(self.send_address)
        #any function where I recv packets needs to redefine timeout
        #set timeout so packets can timeout
        self.socket.settimeout(0.2)
        #keep sending the SYN packet until we get a SYN|ACK packet back
        done = False
        #important to do this outside of while loop
        self.rn = random.randint(1,1000)
        while not done:
            self.send_packet(seq_no = self.rn, flags = SOCK352_SYN)
            syn_ack = self.get_packet()
            if (syn_ack['flags'] == SOCK352_SYN | SOCK352_ACK):
                done = True
                self.my_rn = syn_ack['seq_no'] + 1
                self.rn = syn_ack['ack_no']
                self.send_packet(ack_no = self.my_rn, flags = SOCK352_ACK)
        return
    
    def listen(self, backlog):
        return 
    
    def accept(self):
        global send_port
        #first keep trying to get the first packet
        done = False
        while not done:
            first_packet = self.get_packet()
            if first_packet['flags'] == SOCK352_SYN:
                done = True
                self.my_rn = first_packet['seq_no'] + 1
            else:
                self.send_packet(dest = first_packet['address'], ack_no = self.my_rn, flags = SOCK352_RESET)
        #now we set the timeout so all future packets can timeout
        self.socket.settimeout(0.2)
        #set the address so we don't have to keep checking it
        self.send_address = (first_packet['address'][0], int(send_port))
        #next send the SYN-ACK packet waiting for an ACK, not that this ack might be send from a method other than connect
        done = False
        self.rn = random.randint(1,1000)
        while not done:
            self.send_packet(seq_no = self.rn, ack_no = self.my_rn, flags = SOCK352_SYN | SOCK352_ACK)
            second_packet = self.get_packet()
            if (second_packet['flags'] == SOCK352_ACK and second_packet['ack_no'] == self.rn + 1):
                self.rn = second_packet['ack_no']
                done = True
            else:
                self.send_packet(ack_no = self.rn, flags = SOCK352_RESET)
        return (self, self.send_address)
    
    def close(self): 
        self.socket.settimeout(0.2)
        fin_sent = False
        while not self.done or not fin_sent:
            self.send_packet(seq_no = self.my_rn, flags = SOCK352_FIN)
            fin_pack = self.get_packet()
            if (fin_pack['flags'] == SOCK352_FIN):
                self.send_packet(ack_no = fin_pack['seq_no'] + 1, flags = SOCK352_ACK)
                self.done = True
            elif (fin_pack['flags'] == SOCK352_ACK and fin_pack['ack_no'] == self.my_rn + 1 ):
                fin_sent = True
        self.socket.settimeout(1)
        timeout = 0
        while True:
            fin_pack  = self.get_packet()
            timeout = fin_pack['payload_len']
            if (timeout == -1):
                return
            else:
                if (fin_pack['flags'] == SOCK352_FIN):
                    self.send_packet(ack_no = fin_pack['seq_no'] + 1, flags = SOCK352_ACK)
    
    def send(self, buffer):
        self.socket.settimeout(0.2)
        goal = self.rn + len(buffer)
        ack_thread = threading.Thread(target = self.recv_acks, args = (goal,))
        num_left = len(buffer)
        start_rn = self.rn
        #this is the packet we think will be requested soon, this is the main optimization of go back N
        imagined_rn = self.rn
        ack_thread.start()
        while ack_thread.isAlive():
            with self.lock:
                if self.timeout:
                    imagined_rn = self.rn
                    self.timeout = False
            if(imagined_rn >= goal):
                imagined_rn = max(imagined_rn - MAX_PAYLOAD_SIZE, start_rn)
            start_index = imagined_rn - start_rn
            num_left = goal - imagined_rn
            end_index = start_index + min(num_left, MAX_PAYLOAD_SIZE)
            payload = buffer[start_index : end_index]
            self.send_packet(seq_no = imagined_rn, payload = payload)
            imagined_rn = imagined_rn + len(payload)
        return len(buffer)
    
    def recv(self, nbytes):
        packetList = []
        self.socket.settimeout(None)
        goal_length = int(math.ceil(float(nbytes) / MAX_PAYLOAD_SIZE))
        while len(packetList) < goal_length:
            if len(packetList) == goal_length:
                num_to_get = HEADER_LEN + nbytes - ((goal_length) * MAX_PAYLOAD_SIZE)
            else:
                num_to_get = HEADER_LEN + MAX_PAYLOAD_SIZE
            data_pack = self.get_packet(size = num_to_get)
            if data_pack['flags'] != 0:
                print('Probably getting extra from handshake', data_pack['flags'])
            elif data_pack['seq_no'] == self.my_rn:
                self.my_rn += data_pack['payload_len']
                packetList.append(data_pack['payload'])
            self.send_packet(ack_no = self.my_rn, flags = SOCK352_ACK)
        print(packetList)
        final_string = b''.join(packetList)
        return final_string
    def register_timeout(self):
        with self.lock:
            self.timeout = True
    def recv_acks(self, goal_rn):
        timer = time.time()
        while self.rn < goal_rn:
            ack_pack = self.get_packet(timeout_func = self.register_timeout)
            if ack_pack['flags'] == SOCK352_ACK:
                if (ack_pack['ack_no'] > self.rn):
                    with self.lock:
                        self.rn = ack_pack['ack_no']
                    timer = time.time()
            elif ack_pack['flags'] == SOCK352_RESET:
                self.send_packet(ack_no = self.my_rn, flags = SOCK352_ACK)
            elif ack_pack['flags'] == SOCK352_FIN:
                self.done = True
                self.send_packet(ack_no = ack_pack['seq_no'] + 1, flags = SOCK352_ACK)
                return
            if(time.time() - timer > 0.2):
                self.register_timeout()
                
    #def recv_data(self, data):
        #global GLOBAL_BUFFER
        #how do I check
        #data += GLOBAL_BUFFER
        #self.send_packet(ack_no = self.my_rn, flags= SOCK352_ACK)
        #pass
        
    def doNothing():
        pass
    def get_packet(self, size = HEADER_LEN, timeout_func = doNothing):
        # time.sleep(1)
        try:
            packet, addr = self.socket.recvfrom(size)
        except syssock.timeout:
            timeout_func()
            return dict(zip(('version', 'flags', 'opt_ptr', 'protocol', 'checksum', 'header_len', 'source_port', 'dest_port', 'seq_no', 'ack_no', 'window', 'payload_len', 'payload', 'address'), (-1 for i in range(14))))
        header = packet[:HEADER_LEN]
        header_values = self.struct.unpack(header)
        if len(packet) > HEADER_LEN:
            payload = packet[HEADER_LEN:]
        else:
            payload = 0
        return_values = header_values + (payload, addr)
        return_dict = dict(zip(('version', 'flags', 'opt_ptr', 'protocol', 'checksum', 'header_len', 'source_port', 'dest_port', 'seq_no', 'ack_no', 'window', 'payload_len', 'payload', 'address'), return_values))
        #uncomment to see if packets recieved
        #print([(key, return_dict[key]) for key in return_dict if key != 'payload'])
        return return_dict
    #send the wrapper
    def send_packet(self, dest = None, seq_no = 0, ack_no = 0, payload = b'', flags = 0):
        #~ time.sleep(1)
        if dest == None:
            dest = self.send_address
        version = 0x01
        opt_ptr = 0x0
        protocol = 0x0
        checksum = 0x0
        source_port = 0x0
        dest_port = 0x0
        window = 0
        payload_len = len(payload)
        header_len = HEADER_LEN
        header = self.struct.pack(version, flags, opt_ptr, protocol, checksum, header_len, source_port, dest_port, seq_no, ack_no, window, payload_len)
        #uncomment to see if packets are being sent
        #print((version, flags, opt_ptr, protocol, checksum, header_len,source_port, dest_port, seq_no, ack_no, window, payload_len))
        packet = header + payload
        self.socket.sendto(packet, dest)
        #if random.randint(0,4):
            #self.socket.sendto(packet, dest)
                
        
