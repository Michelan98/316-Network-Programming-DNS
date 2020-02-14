from socket import *
import struct
import sys
import re
import array
import time
from argparse import ArgumentParser


def formName(names):
	formatName = []
	for n in names:
		formatName.append(len(n))
		for c in n:
			formatName.append(ord(c))
	return formatName


def parseName(b):
    qname = ''
    for i in b:
        if i in range(33, 58) or i in range(65, 91) or i in range(97, 123):
            qname = qname + chr(i)
        else:
            qname = qname + '.'
    return qname


def checksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff

class UDPPacket:
    def __init__(self,
                 src_host:  str,
                 src_port:  int,
                 dst_host:  str,
                 dst_port:  int,
                 ):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port

    # Encode the fields into a long bytes sequence
    def build(self) -> bytes:
        packet: bytes = struct.pack(
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
            len(packet)                  # UDP Length (Should also include length of message though)
        )

        length = len(pseudo_hdr)
        cheksm = checksum(pseudo_hdr)

        packet = packet[0:4] + struct.pack('B', length) + struct.pack('H', cheksm) + packet[8:]
        return packet

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

if args.mx and args.ns:
    print('ERROR    invalid argument:could send mail server and name server at the same time')
    exit()

if not re.match(r'^@\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$', args.server):
    print('ERROR	invalid argument:format of server address is wrong')
    exit()

# assigning values from command line arguments
max_retries = args.r
server_port = args.p
server_ip = args.server[1:]
server_name = args.domain

type = 'NS' if args.ns else 'MX' if args.mx else 'A'
type_dict_query = {'A': 1,'NS':2,'MX':15, 'CNAME': 5}
print(bytes(type_dict_query[type]))

type_dict_response = {1: 'A', 2: 'NS', 15: 'MX', 5: 'CNAME'}

# packet = Packet(args.name, type)
# data = packet.generateData()

# Setting up output
print("\nDnsClient sending request for " + server_name + "\n")
print("Server: " + str(server_ip) + "\n")
print("Request type: " + type + "\n")

# initializing UDP socket with timeout value
my_socket = socket(AF_INET, SOCK_DGRAM)         # creating an INet Client socket
my_socket.settimeout(args.t)                   # setting timeout value for Client socket

retry_count = 0
response = []
initial = time.time()

packet = UDPPacket('127.0.0.1', 5355, args.server[1:], args.p)
data = packet.build()

print(int.to_bytes(1, 2, "big"))
r = my_socket.sendto(b'\x82\x7a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+
                     bytes(formName(server_name.split('.'))) +
                     b'\x00' +
                     int.to_bytes(type_dict_query[type], 2, "big") +
                     b'\x00\x01',
                     (packet.dst_host, packet.dst_port))

# Loop accounts for timeout and selected number of retries
while response is None or response == []:
    try:
        response, server_address = my_socket.recvfrom(2048)
    except timeout:
        if retry_count < args.r:
            print('ERROR    Not receiving response. Resending \n')
            retry_count += 1
            my_socket.sendto("hiantonio".encode(), (packet.dst_host, packet.dst_port))
        else:
            print('ERROR    Maximum number of retries reached! \n')
            exit()

print (response)

time_elapsed = time.time() - initial            # calculating duration of packet sending process, including retries if it applies

print("Response received after " + str(time_elapsed) + " seconds " + "(" + str(retry_count) + " retries) \n")


identification = int.from_bytes(response[0:2], "big")  # 2 bytes
print("Identification", identification)

control = int.from_bytes(response[2:4], "big")  # 2 bytes

# |QR| Opcode |AA|TC|RD|RA| Z | RCODE
control_str = format(control, "b") # for debugging purposes
print("Control", control_str)

# AA (bit 10 from the right) is the only one we're interested in
# Indicates whether (1) or not (0) the name server is an authority for a domain name in the question section
auth = 'auth' if control & 2**10 else 'non-auth'   # test

question_count = int.from_bytes(response[4:6], "big")  # 2 bytes
print("Question Count", question_count)

answer_count = int.from_bytes(response[6:8], "big")  # 2 bytes
print("Answer Count", answer_count)

authority_count = int.from_bytes(response[8:10], "big")  # 2 bytes
print("Authority Count", authority_count)

additional_count = int.from_bytes(response[10:12], "big") # 2 bytes
print("Additional Count", additional_count)

# Now the Question Section
question_names = []
question_types = []
question_classes = []
offset = 12

# A DNS question has the format

# 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
# +--+--+--+--+--+--+--+--+--+--+--+--+-
# |                                     |
# /             QNAME                   /
# /                                     /
# +--+--+--+--+--+--+--+--+--+--+--+--+--
# |             QTYPE                   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--
# |            QCLASS                   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--

for i in range(question_count):
    # The domain name is broken into discrete labels which are concatenated;
    # each label is prefixed by the length of that label.
    domain_name = ''
    # The domain name terminates with the zero length octet for the null label of the root
    # while response[offset+1] != b'\x00':
    while response[offset] != 0:
        label_length = response[offset]
        print(label_length)
        domain_name = domain_name + parseName(response[offset+1:offset+1+label_length]) + "."
        offset = offset + label_length + 1

    domain_name = domain_name[:-1]
    question_names.append(domain_name)  # removing the last dot
    print(domain_name)

    offset = offset + 1  # skipping null character that indicates end of domain name
    question_type = int.from_bytes(response[offset:offset+2], "big")
    print(question_type)
    question_types.append(question_type)

    question_classes.append(response[offset+2:offset+4])
    offset = offset + 4
    print(offset)
    print(response[offset:offset+1])

# Now the Answers Section, has the following format

# 1
# 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
# +--+--+--+--+--+--+--+--+--+--+--+--+--+
# | |
# / /
# /                 NAME /
# | |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+
# | TYPE |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+
# | CLASS |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+
# | TTL |
# | |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+
# | RDLENGTH |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+
# / RDATA /
# /                                        /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+
answer_names = []
answer_types = []
answer_classes = []
TTLs = []
RDLENGTHs = []
RDATAs = []

for i in range(answer_count):

    # The domain name is broken into discrete labels which are concatenated;
    # each label is prefixed by the length of that label.
    domain_name = ''
    print (response[offset])
    # The domain name terminates with the zero length octet for the null label of the root
    while response[offset] != 0:
        # Answer Name (skipping for now)
        offset = offset + 1

    # offset = offset + 1 # skipping null character
    print(response[offset])
    answer_names.append(domain_name[:-1])  # variable length

    answer_type = int.from_bytes(response[offset:offset+2], "big")
    print(answer_type)
    answer_types.append(type_dict_response[answer_type])
    answer_classes.append(response[offset+2:offset+4])

    print(response[offset+4:offset+8])
    TTL = int.from_bytes(response[offset+4:offset+8], "big")
    print(TTL)
    TTLs.append(TTL) # 32 bits

    RDLENGTH = int.from_bytes(response[offset+8:offset+10], "big")
    print('RD Length', RDLENGTH)
    RDLENGTHs.append(RDLENGTH)  # 16 bits

    offset = offset + 10

    # If type is 'A', then RDATA is the IP address (four octets)
    if type == 'A':
        IP_Address = ''
        for i in range(RDLENGTH):
            IP_Address = IP_Address + str(response[offset+i]) + "."

        IP_Address = IP_Address[:-1]
        print(IP_Address)
        RDATAs.append(IP_Address) # 16 bits

    # If type is 'NS', then RDATA is the name of the server specified using the same format as the QNAME field

    # if type is 'MX', then RDATA has the format

    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                 PREFERENCE                     |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # /                  EXCHANGE                      /
    # /                                                /
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    elif (type == 'NS') | (type == 'MX') | (type == 'CNAME'):
        if type == 'MX':
            preference = response[offset:offset + 2]
            offset = offset + 2
        name = ''
        # while response[offset] != 0:
        #     label_length = response[offset]
        #     print("Label length", label_length)
        #     name = domain_name + parseName(response[offset + 1:offset + 1 + label_length])
        #     offset = offset + label_length + 1

        print(name)
        RDATAs.append(name)
