# sock352.py

# (C) 2018 by R. P. Martin, under the GPL license, version 2.

# this is the skeleton code that defines the methods for the sock352 socket library,
# which implements a reliable, ordered packet stream using go-back-N.
#
# Note that simultaneous close() is required, does not support half-open connections ---
# that is outstanding data if one side closes a connection and continues to send data,
# or if one side does not close a connection the protocol will fail.

import socket as ip
import random
import binascii
import threading
import time
import sys
import struct as st
import os
import signal

# The first byte of every packet must have this value
MESSAGE_TYPE = 0x44

# this defines the sock352 packet format.
# ! = big endian, b = byte, L = long, H = half word
HEADER_FMT = '!bbLLH'

# this are the flags for the packet header
SYN =  0x01    # synchronize
ACK =  0x02    # ACK is valid
DATA = 0x04    # Data is valid
FIN =  0x08    # FIN = remote side called close

# max size of the data payload is 63 KB
MAX_SIZE = (63*1024)

# max size of the packet with the headers
MAX_PKT = ((16+16+16)+(MAX_SIZE))

# these are the socket states
STATE_INIT = 1
STATE_SYNSENT = 2
STATE_LISTEN  = 3
STATE_SYNRECV = 4
STATE_ESTABLISHED = 5
STATE_CLOSING =  6
STATE_CLOSED =   7
STATE_REMOTE_CLOSED = 8

list_of_outstanding_packets = []
# function to print. Higher debug levels are more detail
# highly recommended
def dbg_print(level,string):
    global sock352_dbg_level
    if (sock352_dbg_level >=  level):
        print string
    return

# this is the thread object that re-transmits the packets
class sock352Thread (threading.Thread):

    def __init__(self, threadID, name, delay):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = float(delay)

    def run(self):
        dbg_print(3,("sock352: timeout thread starting %s delay %.3f " % (self.name,self.delay)) )
        scan_for_timeouts(self.delay)
        dbg_print(3,("sock352: timeout thread %s Exiting " % (self.name)))
        return

# Example timeout thread function
# every <delay> seconds it wakes up and re-transmits packets that
# have been sent, but not received. A received packet with a matching ack
# is removed from the list of outstanding packets.

def scan_for_timeouts(delay):



    time.sleep(delay)

    # there is a global socket list, although only 1 socket is supported for now
    while ( True ):

        time.sleep(delay)
        # example
        for packet in list_of_outstanding_packets:

            current_time = time.time()
            time_diff = float(current_time) - float(packet.time_sent)



            if (time_diff > delay):
                dbg_print(3,"sock352: packet timeout, retransmitting")
                packet.sock.transmit(packet)




    return


# This class holds the data of a packet gets sent over the channel
#
class Packet:
    def __init__(self):
        self.type = MESSAGE_TYPE    # ID of sock352 packet
        self.cntl = 0               # control bits/flags
        self.seq = 0                # sequence number
        self.ack = 0                # acknowledgement number
        self.size = 0               # size of the data payload
        self.data = b''             # data

    # unpack a binary byte array into the Python fields of the packet
    def unpack(self,bytes):
        # check that the data length is at least the size of a packet header
        data_len = (len(bytes) - st.calcsize('!bbLLH'))
        if (data_len >= 0):
            new_format = HEADER_FMT + str(data_len) + 's'
            values = st.unpack(new_format,bytes)
            self.type = values[0]
            self.cntl = values[1]
            self.seq  = values[2]
            self.ack  = values[3]
            self.size = values[4]
            self.data = values[5]
            # you dont have to have to implement the the dbg_print function, but its highly recommended
            dbg_print (1,("sock352: unpacked:0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data))))
        else:
            dbg_print (2,("sock352 error: bytes to packet unpacker are too short len %d %d " % (len(bytes), st.calcsize('!bbLLH'))))

        return

    # returns a byte array from the Python fields in a packet
    def pack(self):
        if (self.data == None):
            data_len = 0
        else:
            data_len = len(self.data)
        if (data_len == 0):
            bytes = st.pack('!bbLLH',self.type,self.cntl,self.seq,self.ack,self.size)
        else:
            new_format = HEADER_FMT + str(data_len) + 's'  # create a new string '!bbLLH30s'
            dbg_print(5,("cs352 pack: %d %d %d %d %d %s " % (self.type,self.cntl,self.seq,self.ack,self.size,self.data)))
            bytes = st.pack(new_format,self.type,self.cntl,self.seq,self.ack,self.size,self.data)
        return bytes

    # this converts the fields in the packet into hexadecimal numbers
    def toHexFields(self):
        if (self.data == None):
            retstr=  ("type:x%x cntl:x%x seq:x%x ack:x%x sizex:%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
        else:
            retstr= ("type:x%x cntl:x%x seq:x%x ack:x%x size:x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
        return retstr

    # this converts the whole packet into a single hexidecimal byte string (one hex digit per byte)
    def toHex(self):
        if (self.data == None):
            retstr=  ("%x%x%x%xx%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
        else:
            retstr= ("%x%x%x%x%xx%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
        return retstr


# the main socket class
# you must fill in all the methods
# it must work against the class client and servers
# with various drop rates
class buff():
    def __init__(self, socket, packet):
        self.sock = socket
        self.pkt = packet
        self.time_sent = 0.0



class Socket:

    def __init__(self):
        self.state = STATE_INIT
        self.recvclose = False
        self.from_address = ('', 0)
        self.to_address = ('', 0)
        self.sequence_no = 0
        self.next=0
        self.sock = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)


    # Print a debugging statement line
    #
    # 0 == no debugging, greater numbers are more detail.
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_debug_level(self, level):
        pass

    # Set the % likelihood to drop a packet
    #
    # you do not need to implement the body of this method,
    # but it must be in the library,
    def set_drop_prob(self, probability):

        pass

    # Set the seed for the random number generator to get
    # a consistent set of random numbers
    #
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_random_seed(self, seed):
        self.random_seed = seed


    # bind the address to a port
    # You must implement this method
    #
    def bind(self,address):
        self.from_address = address
        return self.sock.bind(address)

    # connect to a remote port
    # You must implement this method
    def acknowledgement(self, pkt, cntl):
        #print "inside acknowledgement\n"
        address= self.to_address
        ack = Packet()
        ack.type = MESSAGE_TYPE
        ack.cntl = cntl
        ack.seq = 0

        ack.ack = pkt.seq
        ack.size = 0
        ack.data = None
        ack_buff = buff(self, ack)
        self.transmit(ack_buff)
        return

    def connect(self,address):


        self.to_address = address
        sync_pkt = Packet()
        sync_pkt.type = MESSAGE_TYPE
        sync_pkt.ack = 0
        sync_pkt.size = 0
        sync_pkt.data = ''
        sync_pkt.cntl = SYN
        sync_pkt.seq = self.sequence_no

        buff_here = buff(self, sync_pkt)
        list_of_outstanding_packets.append(buff_here)
        self.transmit(buff_here)
        self.state = STATE_SYNSENT
        #print "here5\n"
        while self.state == STATE_SYNSENT:
            #print "here 6\n"
            data, address = self.sock.recvfrom(MAX_SIZE)
            newPkt = Packet()
            newPkt.unpack(data)
            #recived packet in connect without SYN or ACK set
            if newPkt.cntl != SYN | ACK:
                self.transmit(buff)
                continue
            #established connection
            if newPkt.ack == self.sequence_no:
                if newPkt.cntl & ACK == ACK:
                    for i in range(len(list_of_outstanding_packets)):
                        p = list_of_outstanding_packets[i]
                        if p == newPkt.ack:
                            del list_of_outstanding_packets[i]
                            break
                self.acknowledgement(newPkt, ACK)
                self.next = newPkt.seq + 1
                self.state = STATE_ESTABLISHED
            else:
                self.transmit(syn_Skb)




    def transmit(self, buff):



        address = self.to_address
        pkt = buff.pkt

        bytes = pkt.pack()

        retval = self.sock.sendto(bytes, address)
        buff.time_sent = time.time()


        return retval

    #accept a connection
    def accept(self):
        #print "here20\n"
        self.state = STATE_LISTEN
        self.seq = 42

        while 1:

            if self.state == STATE_LISTEN:
                print "listening...\n"
                info, from_address = self.sock.recvfrom(MAX_SIZE)
                new_pkt = Packet()
                new_pkt.unpack(info)

            if new_pkt.cntl != SYN:
                continue


            #print "here 24\n"
            self.to_address = from_address
            self.next = new_pkt.seq
            ack = Packet()
            ack.type = MESSAGE_TYPE
            ack.cntl = SYN | ACK
            ack.seq = self.sequence_no
            ack.data = None
            ack.ack = self.next = new_pkt.seq
            ack2 = buff(self, ack)
            list_of_outstanding_packets.append(ack2)
            #print "here25\n"
            self.transmit(ack2)
            self.state = STATE_SYNRECV
            self.next = new_pkt.seq + 1
            #print "here26\n"
            return from_address


        return



    # send a message up to MAX_DATA
    # You must implement this method
    def sendto(self,buffer):
        new_packet = Packet()
        new_packet.type = MESSAGE_TYPE
        new_packet.cntl = DATA
        self.sequence_no = self.sequence_no + 1
        new_packet.seq = self.sequence_no

        if buffer == None:
            new_packet.size = 0
            new_packet.data = None
        else:
            new_packet.data = buffer
            new_packet.size = len(buffer)

        buff_this = buff(self, new_packet)
        list_of_outstanding_packets.append(buff_this)
        self.transmit(buff_this)



    # receive a message up to MAX_DATA
    # You must implement this method
    def recvfrom(self,nbytes):

        data_check = False
        while data_check == False:
            #print "Hi"
            #print len(list_of_outstanding_packets)

            #waiting for packet
            #print "here"
            byte_input, address = self.sock.recvfrom(nbytes + st.calcsize('!bbLLH'))

            new_pkt = Packet()
            new_pkt.unpack(byte_input)

            if new_pkt.type != MESSAGE_TYPE:

                data_check = False
                continue
            if new_pkt.cntl & ACK == ACK:
                #print "idkman"
                for i in range(len(list_of_outstanding_packets)):
                    p = list_of_outstanding_packets[i].pkt
                    if new_pkt.seq == p.ack:
                        del list_of_outstanding_packets[i]
                        break
            if new_pkt.cntl & DATA == DATA:
                if new_pkt.seq == self.next:
                    # print("got a packet regularly")
                    self.next = self.next + 1
                    self.acknowledgement(new_pkt, ACK)
                    return new_pkt.data
            if new_pkt.cntl & FIN == FIN:
                #print "31 success?? \n"
                self.recvclose = True
                self.acknowledgement(new_pkt, ACK)
                if self.state == STATE_CLOSING:
                    data_check = False
                    return
                data_check = False
                continue
        return

    # close the socket and make sure all outstanding
    # data is delivered
    # You must implement this method
    def close(self):
        #print "here 41\n"
        # print "here48\n"
        self.sequence_no = self.sequence_no + 1
        new_pkt = Packet()
        new_pkt.type = MESSAGE_TYPE
        new_pkt.cntl = FIN
        self.sequence_no = self.sequence_no
        new_pkt.seq = self.sequence_no
        buff_this = buff(self, new_pkt)

        list_of_outstanding_packets.append(buff_this)
        self.transmit(buff_this)
        self.state = STATE_CLOSING
        buff_no = len(list_of_outstanding_packets)
        # print "buff no: ", buff_no
        while buff_no > 1:
            # print "buff_no: Here:", buff_no
            info = self.recvfrom(MAX_SIZE)
            buff_no = len(list_of_outstanding_packets)

        # print "here here\n"
        while self.recvclose == False:
            info = self.recvfrom(MAX_SIZE)
        return

# Example how to start a start the timeout thread
global sock352_dbg_level
sock352_dbg_level = 0
dbg_print(3,"starting timeout thread")

# create the thread
thread1 = sock352Thread(1, "Thread-1", 0.25)

# you must make it a daemon thread so that the thread will
# exit when the main thread does.
thread1.daemon = True

# run the thread
thread1.start()
