import array
import socket
import struct

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
            socket.inet_aton(self.src_host),    # Source Address
            socket.inet_aton(self.dst_host),    # Destination Address
            socket.IPPROTO_UDP,                 # PTCL
            len(packet)                         # UDP Length (Should also include length of message though)
        )

        length = len(pseudo_hdr) + len(self.data)

        cheksm = checksum(pseudo_hdr + packet)

        packet = packet[:4] + struct.pack('B', length) + struct.pack('H', cheksm) + packet[8:]

        return packet


if __name__ == '__main__':
    dst = '192.168.1.1'

    pak = UDPPacket(
        '192.168.1.42',
        20,
        dst,
        666,
        "Swaroop",
        0b000101001
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    s.sendto(pak.build(), (dst, 0))


def checksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff
