#!/usr/local/bin/python

import socket

def main (dest_name):
    dest_addr = socket.gethostbyname(dest_name)
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')

    ttl = 1
    port = 33434
    blocksize = 52
    max_hops = 64

    while True:
        # open sending and receiving connections
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)

        # use a ttl counter which begins with 1, increment every loop
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        recv_socket.bind(("", port))
        send_socket.sendto("", (dest_name, port))

        curr_addr = None
        try: 
            _, curr_addr = recv_socket.recvfrom(blocksize)
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
            print str(ttl) + " " + curr_hostname + " (" + curr_addr + ")"

        ttl += 1

        
        if curr_addr == dest_addr or ttl > max_hops:
            break


if __name__ == "__main__":
    main("google.com")
