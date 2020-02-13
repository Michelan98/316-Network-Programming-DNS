from socket import *
import array
import struct
import sys
import re
from argparse import ArgumentParser
import time

class UDPPacket:

    # This constructor will hold all the needed packet fields
    def __init__(self,
                 src_host:  str,
                 src_port:  int,
                 dst_host:  str,
                 dst_port:  int,
                 data: str,
                 flags:     int = 0
                 ):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.data = data
        self.flags = flags


    def find_port(self):
        try:
            for port in range(5005,5050):
                source_address = ('127.0.0.1', port)
                self.src_port = port
                result = my_socket.connect_ex(source_address)
                if result == 0:
                    source_address = ('127.0.0.1', port)
                    print ("Source Port picked: " + str(port) + " \n")
                    my_socket.close()
                    break
        except KeyboardInterrupt:
            sys.exit()

        except gaierror:
            print('ERROR    Hostname could not be resolved. Exiting process \n')
            sys.exit()

        except error:
            print("ERROR    Couldn't connect to server. \n")
            sys.exit()
        return port

    # Encode the fields into a long bytes sequence
    def build(self) -> bytes:

        # https://www.techrepublic.com/article/exploring-the-anatomy-of-a-data-packet/

        packet = struct.pack(
            '!HHBH',        # format of the struct, each letter indicates format of an element
                            # i.e. src_port is H (unsigned short), length is B (unsigned char)
            self.src_port,  # Source Port (2 bytes)
            self.dst_port,  # Destination Port (2 bytes)
            0,              # Length (2 bytes)
            0,              # Checksum (initial value) (2 bytes)
        )

        pseudo_hdr = struct.pack(
            '!4s4sHH',
            inet_aton(self.src_host),    # Source Address
            inet_aton(self.dst_host),    # Destination Address
            IPPROTO_UDP,                 # PTCL
            len(packet)                         # UDP Length (Should also include length of message though)
        )

        length = len(pseudo_hdr) + len(self.data)

        cheksm = checksum(pseudo_hdr + packet)

        packet = struct.pack('H', find_port()) + packet[2:4] + struct.pack('B', length) + struct.pack('H', cheksm) + packet[8:]

        return packet

def checksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff


# should be a packet to send !!!
packet = UDPPacket(
    '127.0.0.1',
    0,
    '192.168.1.1',
    666,
    "Swaroop",
    0b000101001).build()

# Implementing command line parser to get optional command line arguments
cmd_parser = ArgumentParser(description= "DNS Client", prog='DnsClient.py')
cmd_parser.add_argument("-t", type=int, required=False, default=5, help='timeout (in seconds) for retransmitting')
cmd_parser.add_argument("-r", type=int, required=False, default=3, help='maximum number of retransmissions')
cmd_parser.add_argument("-p", type=int, required=False, default=53, help='port # of DNS server')
cmd_parser.add_argument("-mx", action='store_true', required=False, help='pick a single type of server query')
cmd_parser.add_argument("-ns", action='store_true', required=False, help='pick a single type of server query')
cmd_parser.add_argument("server", type=str, help='server IP Address') 
cmd_parser.add_argument("domain", type=str, help='domain name to query')
args = cmd_parser.parse_args()

# checking for single query type entry
if args.mx and args.ns:
    print('ERROR    Invalid arguments! Please specify a single query to send to the server. \n')
    exit()

if not re.match(r'^@\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$', args.server):
	print('ERROR    Invalid server address format! Please enter: @8.8.8.8 <domain name>. \n')
	exit()

# assigning values from command line arguments
max_retries = args.r
server_port = args.p 
server_ip = args.server[1:]
server_name = args.domain

#checking request type
request = 'NS' if args.ns else 'MX' if args.mx else 'A'

# Setting up output 
print("\nDnsClient sending request for " + server_name + "\n")
print("Server: " + str(server_ip) + "\n")
print("Request type: " + request + "\n")

# initializing UDP socket with timeout value
my_socket = socket(AF_INET, SOCK_DGRAM)         # creating an INet Client socket
my_socket.settimeout(args.t)                   # setting timeout value for Client socket

retry_count = 0
response = []
initial = time.time()

source_address = ()

# initializing UDP socket with timeout value
my_socket = socket(AF_INET, SOCK_DGRAM)         # creating an INet Client socket
my_socket.settimeout(args.t)                   # setting timeout value for Client socket

# Loop accounts for timeout and selected number of retries
while response is None or response == []:
    try:
        response, server_address = my_socket.recvfrom(1024)
    except timeout:
        if retry_count < args.r:
            print('ERROR    Not receiving response. Resending \n')
            retry_count += 1
            my_socket.sendto(packet, source_address)
        else:
            print('ERROR    Maximum number of retries reached! \n')
            exit()

time_elapsed = time.time() - initial            # calculating duration of packet sending process, including retries if it applies

print('Response (decoding partially done): ' + response[0].decode('utf8') + ' \n')
print("Response received after " + str(time_elapsed) + " seconds " + "(" + str(retry_count) + " retries) \n")

my_socket.close()
