import socket
import struct
import textwrap
import time

TAB_1 = '\t - '
TAB_2 = '\t\t- '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


class Pcap:

    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
    
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()

def main():
    pcap = Pcap('capture.pcap')
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    while True:

        raw_data, address = connection.recvfrom(65536)
        pcap.write(raw_data)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print('\nEthernet Frame: ')

        print(TAB_1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            (version, header_length, TTL, protocol, source, target, data) = IPv4_packet(data)
            print(TAB_1 + "IPv4 packet: ")
            print(TAB_2 + "version: {}, Header Length: {}, TTL: {}".format(version, header_length, TTL))
            print(TAB_2 + "Protocol: {}, Source: {}, Target: {}".format(protocol, source, target))

            if protocol == 1:#icmp
                (icmp_type, code, checksum, data) = ICMP_packet(data)
                print(TAB_1 + 'ICMP packet:')
                print(TAB_2 + "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                print(TAB_2 + "Data:")
                print(format_multi_line(DATA_TAB_3, data))



            elif protocol == 6:#tcp
                (src_port, dest_port, sequence, acknowlegment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = TCP_segment(data)
                print(TAB_1 + 'TCP packet:')
                print(TAB_2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                print(TAB_2 + "Sequence: {}, Acknowlegment: {}".format(sequence, acknowlegment))
                print(TAB_2 + "Flags:")
                print(TAB_3 + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                # print(TAB_2 + "Data:")
                # print(format_multi_line(DATA_TAB_3, data))

                # HTTP
                if src_port == 80 or dest_port == 80 :
                    print(TAB_2 + 'HTTP Data:')
                    try:
                        try:
                            data = raw_data.decode('utf-8')
                        except:
                            data = raw_data
                        http_info = str(data).split('\n')
                        for line in http_info:
                            print(DATA_TAB_3 + str(line))
                    except:
                        print(format_multi_line(DATA_TAB_3, data))


                if  dest_port == 21 or dest_port == 20:# FTP
                    print(TAB_2 + 'FTP Data:')
                    print(format_multi_line(DATA_TAB_3, data))

                else:
                    print(TAB_2 + 'TCP Data:')

                    print(format_multi_line(DATA_TAB_3, data))



            elif protocol == 17:#udp
                src_port, dest_port, size, data = udp_segment(data)
                print(TAB_1 + 'UDP packet:')
                print(TAB_2 + "Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, size))


                if src_port == 53 or dest_port == 53: #DNS
                    (Total_questions, Total_answer_RRs, Total_Authority_RRs, Total_Additional_RRs, Questions, Answers_RRs, Authority_RRs,
                    Additional_RRs) = dns(data)
                    print(TAB_2 + 'DNS Data:')
                    print(TAB_2 + "Questions: {}, RRs Answers: {}, Authority RRs: {}, Additional_RRs: {}".format(Questions, Answers_RRs, Authority_RRs,
                                                                                           Additional_RRs))

            elif protocol == 2054:
                # arp
                (Hardware_type, Protocol_Type, Hardware_address_length, protocol_address_length,
                 Operation, Src_mac, Src_proto_address, Dest_mac, Dest_port_addr) = arp(data)
                print(TAB_1 + 'ARP packet:')
                print(TAB_2 + "Hardware Type: {}, Protocol Type: {}, Mac Address Length: {}".format(Hardware_type,
                                                                                                    Protocol_Type,
                                                                                                    Hardware_address_length))
                print(TAB_2 + "Source Mac Address: {}, Destination Mac Address: {}".format(Src_mac, Dest_mac))
                print(TAB_2 + "Sender Protocol Address: {}, Destination Protocl Address: {}".format(Src_proto_address,
                                                                                                    Dest_port_addr))

            else:
                print(TAB_1 + "Data: ")
                print(format_multi_line(DATA_TAB_2, data))



    pcap.close()

# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(protocol), data[14:]


def arp(data):
    (Hardware_type, Protocol_Type, Hardware_address_length, protocol_address_length,
            Operation, Src_mac, Src_proto_address, Dest_mac, Dest_port_addr, ) = struct.unpack("! H H B B H 6s 4s 6s 4s", data)

    Dest_mac = get_mac_address(Dest_mac)
    Src_mac = get_mac_address(Src_mac)

    return (Hardware_type, Protocol_Type, Hardware_address_length, protocol_address_length,
            Operation, Src_mac, Src_proto_address, Dest_mac, Dest_port_addr, )


def dns(data):
    Total_questions, Total_answer_RRs, Total_Authority_RRs, Total_Additional_RRs = struct.unpack("! H H H H", data[4:12])
    Questions, Answers_RRs, Authority_RRs, Additional_RRs = struct.unpack("! L L L L", data[12:])
    return (Total_questions, Total_answer_RRs, Total_Authority_RRs, Total_Additional_RRs, Questions, Answers_RRs, Authority_RRs,
            Additional_RRs)



# Return properly formatted MAC address
def get_mac_address(bytes_address):
    bytes_string = map('{:02x}'.format, bytes_address)
    return ":".join(bytes_string).upper()



# Unpack IPv4 packet
def IPv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4 # version number ==> shift four bit to right in order to get version in IP Header
    header_length = (version_header_length & 15)# Get total length in IP Header
    TTL, protocol, src, destination = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, TTL, protocol, IPv4(src), IPv4(destination), data[header_length:]

# return properly formatted IPv4 address
def IPv4(address):
    return ":".join(map(str, address))


# Unpack ICMP packet
def ICMP_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def TCP_segment(data):
    (src_port, dest_port, sequence, acknowlegment, offset_reserved_flag) = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flag >> 12) * 4 # offsets in tcp flags

    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = offset_reserved_flag & 1

    return src_port, dest_port, sequence, acknowlegment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]



def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string,bytes):
        string = ''.join(r"\x{:02x}".format(byte) for byte in string)
        if size % 2 :
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == "__main__":
    main()






