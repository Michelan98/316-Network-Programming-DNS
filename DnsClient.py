from socket import *
import re
from argparse import ArgumentParser
import time

# should be a packet to send !!!
packet = bytes("Hello, World!", "utf-8")

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
    exit()

if not re.match(r'^@\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$', args.server):
	print('Error, Invalid server address! format. Please enter: @8.8.8.8 <domain name>. \n')
	exit()

# assigning values from command line arguments
max_retries = args.r
server_port = args.p 
server_ip = args.server[1:]
server_name = args.domain
server_address = (server_ip, server_port)

#checking request type
request = 'NS' if args.ns else 'MX' if args.mx else 'A'

# Setting up output 
print("\nDnsClient sending request for " + server_name + "\n")
print("Server: " + str(server_ip) + "\n")
print("Request type: " + request + "\n")

my_socket = socket(AF_INET, SOCK_DGRAM)         # creating an INet Client socket
my_socket.settimeout(args.t)                   # setting timeout value for Client socket
my_socket.sendto(packet, server_address)

retry_count = 0
response = []
initial = time.time()

while response is None or response == []:
    try:
        response, server_address = my_socket.recvfrom(1024)
    except timeout:
        if retry_count < args.r:
            print('Error receiving response! Resending ... \n')
            retry_count += 1 
            my_socket.sendto(packet, server_address)
        else:
            print('Error, maximum number of retries reached! \n')
            exit()

time_elapsed = time.time() - initial

print('Response: ' + response)
# my_socket.sendto(response.encode(), server_address)
# modified_response = (my_socket, max_retries)
# output_response = modified_response.decode()

print("Response received after " + time_elapsed + " seconds " + "(" + retry_count + " retries) \n")

# if request == 'A':
#     print("IP   ")

my_socket.close()
