"""
 Nick Petersen
 Module to support pcap analysis using scapy's rdpcap and associated object classes.
"""
from scapy.all import *
import os
import pathlib

def get_pcap_files(pcap_dir:str, max_files:int = 0):
    if os.path.exists(pcap_dir):
        try:
            pcap_files = os.listdir(pcap_dir)
        except Exception as e:
            return e

        # check extension for some limited attempt to verify files are pcaps
        if len(pcap_files) > 0:
            for f in pcap_files:
                if pathlib.Path(f).suffix not in ['.pcap']:
                    pcap_files.remove(f)

        if len(pcap_files) > 0:
            # return at most the max requested number of pcap files
            if max_files == 0:
                return pcap_files
            else:
                # list slicing to only return list with files up to max files
                return pcap_files[0:max_files]
        else:
            return False
    else:
        return False


def check_tcp_flags(pkt):
    match pkt['TCP'].flags:
        case 0x01:
            return 'FIN'
        case 0x02:
            return 'SYN'
        case 0x04:
            return 'RST'
        case 0x08:
            return 'PSH'
        case 0x10:
            return 'ACK'
        case 0x20:
            return 'URG'
        case 0x40:
            return 'ECE'
        case 0x80:
            return 'CWR'


def get_l4_proto(pkt):
    match pkt[Ether][IP].proto:
        case 1:
            return 'icmp'
        case 6:
            return 'tcp'
        case 17:
            return 'udp'
        case 58:
            return 'icmpv6'
        case _:
            return False


def pkt_list_to_dict(p_list,):
    """
    Take scapy packet list created from rdpcap, pull out relevant data and add to dict() for faster searching.
    In this case we add the packet data as the key, and the reference to the pkt_list index as value. It seems
    that it is much more efficient to search dict() by key rather than value.  And we want to keep the index
    so that we can later get full packet details from the packet list if we chose to do so.
    :param p_list:     list of packets to process and add data to dictionary for
    :return: dict()
    """
    p_dict = {}
    for i, pkt in enumerate(p_list):
        if get_l4_proto(pkt) == 'udp':
            my_pkt = f'id={pkt[IP].id}, src={pkt[IP].src}, ' \
                     f'dst={pkt[IP].dst}, sport={pkt[UDP].sport}, ' \
                     f'dport={pkt[UDP].dport}, proto=udp'

            p_dict[my_pkt] = i

        if get_l4_proto(pkt) == 'tcp':
            my_pkt = f'id={pkt[IP].id}, src={pkt[IP].src}, ' \
                     f'dst={pkt[IP].dst}, sport={pkt[TCP].sport}, ' \
                     f'dport={pkt[TCP].dport}, proto=tcp'

            p_dict[my_pkt] = i

        if get_l4_proto(pkt) == 'icmp':
            my_pkt = f'id={pkt[IP].id}, src={pkt[IP].src}, ' \
                     f'dst={pkt[IP].dst}, type={pkt[ICMP].type}, ' \
                     f'code={pkt[ICMP].code}, proto=icmp'

            p_dict[my_pkt] = i

        if get_l4_proto(pkt) == 'icmpv6':
            my_pkt = f'id={pkt[IP].id}, src={pkt[IP].src}, ' \
                     f'dst={pkt[IP].dst}, type={pkt[ICMPv6].type}, ' \
                     f'code={pkt[ICMPv6].code}, proto=icmpv6'

            p_dict[my_pkt] = i

    return p_dict


def print_packet_details(pkt, pkt_label):
    """
    :param pkt: scapy Ether packet
    :param pkt_label: label for packet when details output
    :return: return True if is known packet format and can be printed or return False
    """
    if IP in pkt:
        print(f'    # packet {pkt_label} #')
        print(f'      ip-id: {pkt[IP].id}')
        print(f'      ip-src: {pkt[IP].src}')
        print(f'      ip-dst: {pkt[IP].dst}')
    elif IPv6 in pkt:
        print(f'    # packet {pkt_label} #')
        print(f'      ip-id: {pkt[IPv6].id}')
        print(f'      ip-src: {pkt[IPv6].src}')
        print(f'      ip-dst: {pkt[IPv6].dst}')
    else:
        return False

    match pkt[IP].proto:
        case 6:
            print(f'     l4-proto: tcp')
            print(f'     tcp-sport: {pkt[TCP].sport}')
            print(f'     tcp-dport: {pkt[TCP].dport}')
        case 17:
            print(f'     l4-proto: udp')
            print(f'     udp-sport: {pkt[UDP].sport}')
            print(f'     udp-dport: {pkt[UDP].dport}')
        case 1:
            print(f'     icmp_type: {pkt[ICMP].type}')
            print(f'     icmp_code: {pkt[ICMP].code}')
        case 58:
            print(f'     icmp_type: {pkt[ICMPv6].type}')
            print(f'     icmp_code: {pkt[ICMPv6].code}')
        case _:
            return False
    return True


def check_pkt_support(pkt):
    if IP in pkt:
        # Check layer4 protocol type for support
        if pkt[IP].proto in [1, 6, 17, 58]:
            return True
        else:
            return False
    elif IPv6 in pkt:
        # Check layer4 protocol type for support
        if pkt[IPv6].proto in [1, 6, 17, 58]:
            return True
        else:
            return False
    else:
        return False
