#!/usr/local/bin/python
import socket
import time
import sys

port = 33434
blocksize = 512
max_hops = 64

icmp = socket.getprotobyname('icmp')
udp = socket.getprotobyname('udp')


def timestamp_to_millis(start, end):
    return round((end - start)*1000, 3)


def send_and_recv_packet(dest_name, ttl):
    round_trips_attempted = 0
    curr_addr = None
    curr_hostname = None
    times = []

    # perform three round trips for a given ttl to get timing measurements
    while round_trips_attempted < 3:
        # open sending and receiving connections
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        recv_socket.bind(("", port))
        send_time = time.time()
        send_socket.sendto("", (dest_name, port))

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
            trip_time = timestamp_to_millis(send_time, recv_time)
            if trip_time is not None:
                times.append(trip_time)
            else:
                times.append("*")
            round_trips_attempted += 1

    return times, curr_addr, curr_hostname


def main (dest_name):
    hostname, aliaslist, ipaddrlist  = socket.gethostbyname_ex(dest_name)
    if len(ipaddrlist) > 1:
        dest_addr = ipaddrlist[0]
        print("traceroute: Warning: " + dest_name 
                + " has multiple addresses; using " + dest_addr)
    elif len(ipaddrlist) == 0:
        print "traceroute: unknown host" + dest_name
        return
    else:
        dest_addr = ipaddrlist[0]

    print("traceroute to " + hostname + " (" + dest_addr + "), " 
            + str(max_hops) + " hops max, " 
            + str(blocksize) + " byte packets")

    ttl = 1
    while True:
        times, curr_addr, curr_hostname = send_and_recv_packet(dest_addr, ttl)

        time_string = ""
        for t in times:
            time_string += str(t) + " ms "

        print(str(ttl) + " " + curr_hostname 
                + " (" + curr_addr + ") " + time_string)
        
        ttl += 1
        if curr_addr == dest_addr or ttl > max_hops:
            break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: ./traceroute.py <hostname>"
    else:
        main(sys.argv[1])
