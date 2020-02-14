import argparse
import re
import socket

def parseName(b):
    qname = ''
    for i in b:
        if i in range(33, 58) or i in range(65, 91) or i in range(97, 123):
            qname = qname + chr(i)
        else:
            qname = qname + '.'
    return qname


class Packet(object):
    def __init__(self, name, type):
        self.name = bytes(self.formName(name.split('.')))
        self.type = bytes([self.typeTransform(type)])

    def formName(self, names):
        formatName = []
        for n in names:
            formatName.append(len(n))
            for c in n:
                formatName.append(ord(c))
        return formatName

    def typeTransform(self, type):
        typemap = {'A': 1, 'NS': 2, 'MX': 15}
        return typemap[type]

    def generateData(self):
        return b'\x82\x7a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + self.name + b'\x00\x00' + self.type + b'\x00\x01'


parser = argparse.ArgumentParser(description='DNS client')
parser.add_argument('-t', type=int, default=5, help='time out of retransmit')
parser.add_argument('-r', type=int, default=3, help='max-retries')
parser.add_argument('-p', type=int, default=53, help='UDP port number of the DNS server')
parser.add_argument('-mx', action='store_true', help='send a mail server query')
parser.add_argument('-ns', action='store_true', help='send a name server query')
parser.add_argument('server')
parser.add_argument('name')
args = parser.parse_args()

if args.mx and args.ns:
    print('ERROR    invalid argument:could send mail server and name server at the same time')
    exit()

if not re.match(r'^@\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$', args.server):
    print('ERROR	invalid argument:format of server address is wrong')
    exit()

type = 'NS' if args.ns else 'MX' if args.mx else 'A'
packet = Packet(args.name, type)
print('DNS sending request for:', args.name)
print('Server:', args.server[1:])
print('Request type:', type)
data = packet.generateData()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(args.t)
s.sendto(data, (args.server[1:], args.p))
response = b''
serverAddr = ()
numOfTries = 0

while response == b'' or response is None:
    try:
        response, serverAddr = s.recvfrom(1024)
    except socket.timeout as e:
        if numOfTries < args.t:
            print('not receiving,resend the message')
            s.sendto(data, (args.server[1:], args.p))
            numOfTries = numOfTries + 1
        else:
            print('ERROR	message transfer:the number of resend the message has been used up')
            exit()

print(response)

identification = int.from_bytes(response[0:1], "big")  # 2 bytes

control = int.from_bytes(response[2:3], "big")  # 2 bytes

# |QR| Opcode |AA|TC|RD|RA| Z | RCODE
control_str = format(control, "b") # for debugging purposes

# AA (bit 11 from the right) is the only one we're interested in
# Indicates whether (1) or not (0) the name server is an authority for a domain name in the question section
auth = 'auth' if control & 11 else 'non-auth'

question_count = int.from_bytes(response[4:5], "big")  # 2 bytes
answer_count = int.from_bytes(response[6:7], "big")  # 2 bytes
authority_count = int.from_bytes(response[8:9], "big")  # 2 bytes
additional_count = int.from_bytes(response[10:11], "big") # 2 bytes

# Now the Question Section
question_names = []
question_types = []
question_classes = []
offset = 11

print(response[12])
type_dict = {1: 'A', 2: 'NS', 15: 'MX', 5: 'CNAME'}

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
    while response[offset+1] != b'0x00':

        label_length = int.from_bytes(response[offset+1], "big")
        domain_name = domain_name + parseName(response[offset+2:offset+2+label_length]) + "."
        offset = offset + 2

    question_names[i] = domain_name[:-1]  # removing the last dot
    question_types[i] = type_dict[response[offset+3:offset+4]]
    question_classes[i] = response[offset+5:offset+6]
    offset = offset + 6

# Now the Answers Section
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

    # The domain name terminates with the zero length octet for the null label of the root
    while response[offset+1] != b'0x00':

        label_length = int.from_bytes(response[offset+1], "big")
        domain_name = domain_name + parseName(response[offset+2:offset+2+label_length])
        offset = offset + 2

    answer_names[i] = domain_name  # variable length
    answer_types[i] = type_dict[int.from_bytes(response[offset+3:offset+4], "big")]
    answer_classes[i] = response[offset+5:offset+6]

    TTLs[i] = int.from_bytes(response[offset+7:offset+10], "big") # 32 bits
    RDLENGTHs[i] = int.from_bytes(response[offset+11:offset+12], "big")  # 16 bits
    RDATAs[i] = response[offset+13:offset+14] # 16 bits
    offset = offset + 14
