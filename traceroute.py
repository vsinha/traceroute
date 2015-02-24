#!/usr/local/bin/python

import socket
import time

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
            print "send time " + str(send_time) + " recv time: " + str(recv_time)
            print str(ttl) + " " + curr_hostname + " (" + curr_addr + ")"

        ttl += 1
        
        if curr_addr == dest_addr or ttl > max_hops:
            break


if __name__ == "__main__":
    main("google.com")
