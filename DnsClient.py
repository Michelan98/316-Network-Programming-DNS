from socket import *
from argparse import ArgumentParser
import ipaddress
import time

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
    print('Error, invalid arguments! Please only specify a single query to send to the server. \n')
    exit(0)

# assigning values from command line arguments
timeout = args.t
max_entries = args.r
server_port = args.p 
server_ip = ipaddress.ip_address(args.server)
server_name = args.domain

def receive(sock, num_retries):
    retry_count = 0
    message = []
    initial = time.time()
    while retry_count < num_retries:
        if retry_count > num_retries:
            print("Maximum number of retries reached! \n")
            break   
        while ((time.time() - initial) < timeout):
            packet = sock.recvfrom(4096)
            if packet == '':
                print("Socket connection broken! \n")
                retry_count += 1
                break
            message.append(packet)
        message = "".join(message)
    
    time_elapsed = time.time() - initial
    return message, time_elapsed, retry_count

print("DnsClient sending request for " + server_name + "\n")
print("Server: " + server_ip + "\n")
request = ''
if args.mx:
    request = 'MX'
elif args.ns:
    request = 'NS'
else:
    request = 'A'

print("Request type: " + request + "\n")

# creating an INet client socket
my_socket = socket(AF_INET, SOCK_DGRAM)

# connecting socket to localhost
my_socket.connect(('localhost', 5000))

# sending/receiving message from server
server_address = (server_ip, server_port)
message = input('Enter your message (lowercase): ')
my_socket.sendto(message.encode(), server_address)
modified_message, time_passed, retries = receive(my_socket, max_entries)
output_message = modified_message.decode()

print("Response received after " + time_passed + " seconds " + "(" + retries + " retries) \n")

# if request == 'A':
#     print("IP   ")
# my_socket.close()