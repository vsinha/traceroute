#!/usr/local/bin/python

import socket
import time
from struct import unpack

def parse_packet(packet):
    print packet

    ip_header = unpack("!BBHHHBBH4s4s", packet[0:20])

    version_raw = ip_header[0]
    version = version_raw >> 4

    ihl = (version_raw & 0xF) 
    ip_header_length = ihl * 4

    ttl = ip_header[5]
    protocol = ip_header[6]
    source_addr = socket.inet_ntoa(ip_header[8])
    dest_addr = socket.inet_ntoa(ip_header[9])

    print "Version: " + str(version) + "\nIP Header Length: " + str(ihl) + "\nTTL: " + str(ttl) + "\nProtocol: " + str(protocol) + "\nSource Address: " + str(source_addr) + "\nDestination Address: " + str(dest_addr)

    tcp_header = packet[ip_header_length:ip_header_length+20]
     
    #now unpack them :)
    tcph = unpack('!HHLLBBHHH' , tcp_header)
     
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
     
    print "Source Port : " + str(source_port) + "\nDest Port : " + str(dest_port) + "\nSequence Number : " + str(sequence) + "\nAcknowledgement : " + str(acknowledgement) + "\nTCP header length : " + str(tcph_length)
     
    h_size = ip_header_length + tcph_length * 4
    data_size = len(packet) - h_size
     
    #get data from the packet
    data = packet[h_size:]
     
    print 'Data : ' + data

def main (dest_name):
    hostname, aliaslist, ipaddrlist  = socket.gethostbyname_ex(dest_name)

    if len(ipaddrlist) >= 1:
        dest_addr = ipaddrlist[0]
        print "traceroute: Warning: " + dest_name + " has multiple addresses; using " + dest_addr
    elif len(ipaddrlist) == 0:
        print "traceroute: unknown host" + dest_name
        return

    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')

    ttl = 1
    port = 33434
    blocksize = 1024
    max_hops = 3

    print "traceroute to " + dest_name + " (" + dest_addr + "), " + str(max_hops) + " hops max, " + str(blocksize) + " byte packets"

    while True:
        # open sending and receiving connections
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)

        # use a ttl counter which begins with 1, increment every loop
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        recv_socket.bind(("", port))
        send_time = time.time()
        send_socket.sendto("", (dest_name, port))

        curr_addr = None
        try: 
            raw_packet_data, curr_addr = recv_socket.recvfrom(blocksize)
            recv_time = time.time()
            curr_addr = curr_addr[0]
            try:
                curr_hostname = socket.gethostbyaddr(curr_addr)[0]
            except socket.error:
                curr_hostname = curr_addr
        except socket.error:
            pass
        finally:
            send_socket.close()
            recv_socket.close()

        if curr_addr != None:
            parse_packet(raw_packet_data)
            print "send time " + str(send_time) + " recv time: " + str(recv_time)
            print str(ttl) + " " + curr_hostname + " (" + curr_addr + ")"

        ttl += 1
        
        if curr_addr == dest_addr or ttl > max_hops:
            break


if __name__ == "__main__":
    main("google.com")
