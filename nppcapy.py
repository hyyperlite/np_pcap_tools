"""
 Nick Petersen
 Module to support pcap analysis using scapy's rdpcap and associated object classes.
"""
from scapy.all import *


def check_packet_attributes(pkt: scapy.layers.l2.Ether, pkt_label='pkt', debug=False):
    """
    :param pkt: scapy packet from rdpcap read of pcap file
    :param pkt_label: label for packet when details output
    :return: True if packet meets criteria, False otherwise
    """

    # Get ethernet frame data
    try:
        ether_pkt = pkt[Ether]
    except Exception as e:
        if debug:
            print(f'   # packet {pkt_label}')
            print('      no ether header, could be STP')
        return False

    # Check for packets that are not IP
    if 'type' not in ether_pkt.fields:
        if debug:
            print(f'    # packet {pkt_label}')
            print('       lldp(probably) packet')
        return False

    # Check for packets that are ARP
    if ether_pkt.type == 0x0806:
        if debug:
            print(f'    # packet {pkt_label}')
            print('       arp packet')
        return False

    # Check ether type to ensure ipv4 or ipv6
    if ether_pkt.type != 0x0800 and ether_pkt.type != 0x86DD:
        if debug:
            print(f'    # packet {pkt_label}')
            print('       non-ip packet')
        return False

    # Check layer4 protocol type for support
    if pkt[Ether][IP].proto in [1, 6, 17, 58]:
        return True
    else:
        print(f'    # packet {pkt_label}')
        print(f'      layer 4 protocol not recognized: {pkt[IP].proto}')
        return False


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


def pkt_list_to_dict(p_list):
    """
    Take scapy packet list created from rdpcap, pull out relevant data and add to dict() for faster searching.
    In this case we add the packet data as the key, and the reference to the pkt_list index as value. It seems
    that it is much more efficient to search dict() by key rather than value.  And we want to keep the index
    so that we can later get full packet details from the packet list if we chose to do so.
    :param p_list:
    :return: dict()
    """
    p_dict = {}
    for p_idx, p_pkt in enumerate(p_list):
        if check_packet_attributes(p_pkt):
            if get_l4_proto(p_pkt) == 'udp':
                my_key = f'id={p_pkt[Ether][IP].id}, src={p_pkt[Ether][IP].src}, ' \
                                 f'dst={p_pkt[Ether][IP].id}, sport={p_pkt[Ether][IP][UDP].sport}, ' \
                                 f'dport={p_pkt[Ether][IP][UDP].dport}, proto=udp'
                p_dict[my_key] = p_idx

            if get_l4_proto(p_pkt) == 'tcp':
                my_key = f'id={p_pkt[Ether][IP].id}, src={p_pkt[Ether][IP].src}, ' \
                                f'dst={p_pkt[Ether][IP].id}, sport={p_pkt[Ether][IP][TCP].sport}, ' \
                                f'dport={p_pkt[Ether][IP][TCP].dport}, proto=tcp'
                p_dict[my_key] = p_idx

            if get_l4_proto(p_pkt) == 'icmp':
                my_key = f'id={p_pkt[Ether][IP].id}, src={p_pkt[Ether][IP].src}, ' \
                                f'dst={p_pkt[Ether][IP].id}, sport={p_pkt[Ether][IP][ICMP].type}, ' \
                                f'dport={p_pkt[Ether][IP][ICMP].code}, proto=icmp'
                p_dict[my_key] = p_idx

            if get_l4_proto(p_pkt) == 'icmpv6':
                my_key = f'id={p_pkt[Ether][IP].id}, src={p_pkt[Ether][IP].src}, ' \
                                f'dst={p_pkt[Ether][IP].id}, sport={p_pkt[Ether][IP][ICMPv6].type}, ' \
                                f'dport={p_pkt[Ether][IP][ICMPv6].code}, proto=icmpv6'
    return p_dict


def print_packet_details(pkt, pkt_label):
    """
    :param pkt: scapy Ether packet
    :param pkt_label: label for packet when details output
    :return: return True if is known packet format and can be printed or return False
    """
    print(f'    # packet {pkt_label} #')
    print(f'      ip-id: {pkt[Ether][IP].id}')
    print(f'      ip-src: {pkt[Ether][IP].src}')
    print(f'      ip-dst: {pkt[Ether][IP].dst}')

    match pkt[Ether][IP].proto:
        case 6:
            print(f'     l4-proto: tcp')
            print(f'     tcp-sport: {pkt[Ether][IP][TCP].sport}')
            print(f'     tcp-dport: {pkt[Ether][IP][TCP].dport}')
        case 17:
            print(f'     l4-proto: udp')
            print(f'     udp-sport: {pkt[Ether][IP][UDP].sport}')
            print(f'     udp-dport: {pkt[Ether][IP][UDP].dport}')
        case 1:
            print(f'     icmp_type: {pkt[Ether][IP][ICMP].type}')
            print(f'     icmp_code: {pkt[Ether][IP][ICMP].code}')
        case 58:
            print(f'     icmp_type: {pkt[Ether][IP][ICMPv6].type}')
            print(f'     icmp_code: {pkt[Ether][IP][ICMPv6].code}')
        case _:
            return False
    return True